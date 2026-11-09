"""觸發 ② 的第 1 層比對（純程式，$0）：新公告 × 已存的 daily 圖譜。

- 產品名稱先以 aliases 正規化；版本落在範圍內才算命中，命中才派發 sentinel.yml（scenario=advisory）
- 圖譜缺失或過期 → need_check，不能寫 not_affected
- 去重鍵＝公告 ID＋revision＋資產集合＋版本／設定雜湊；新增資產、版本回退或新利用條件會重評
- 狀態 checked／pending／running／done／failed；只有對應 A5 成功發布且完成宣告範圍後才 done
- 派工以參數陣列呼叫 gh，不把公告內容拼進 shell 指令
用法：python agents/tools/intel_watch.py [--advisories DIR ...] [--graph PATH] [--state PATH] [--dispatch] [--as-of ISO]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.aliases import normalize  # noqa: E402
from tools.common import INTEL_DIR, SENTINEL_ROOT, iso, parse_time, read_json, sha256_json, write_json  # noqa: E402
from tools.intel_verify import load_events  # noqa: E402
from tools.version_match import AFFECTED, match  # noqa: E402

GRAPH_MAX_AGE = timedelta(hours=36)
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,80}$")
DEFAULT_GRAPH = SENTINEL_ROOT / "dashboard" / "public" / "data" / "daily" / "graph.json"
DEFAULT_STATE = SENTINEL_ROOT / "dashboard" / "public" / "data" / "intel-watch.json"


def check_advisory(adv: dict, graph: dict | None, *, graph_fresh: bool) -> dict:
    if not graph or not graph_fresh:
        return {"advisory_id": adv["id"], "revision": adv.get("revision"), "status": "checked", "verdict": "need_check",
                "asset_ids": [], "reason": "daily 圖譜缺失或過期，不能判定不受影響"}
    hits, unknown, versions = [], [], {}
    for p in adv.get("products", []):
        name = normalize(p.get("name"))
        for n in graph.get("nodes", []):
            for c in n.get("components", []):
                if normalize(c.get("name")) != name:
                    continue
                v = match(c.get("version"), p.get("affected"), p.get("ecosystem", "generic"))
                versions[n["id"]] = {"component": name, "version": c.get("version"), "sapi": c.get("sapi")}
                if v == AFFECTED:
                    hits.append(n["id"])
                elif v != "not_affected":
                    unknown.append(n["id"])
    assets = sorted(set(hits) | set(unknown))
    key = sha256_json({"id": adv["id"], "revision": adv.get("revision"), "assets": assets,
                       "versions": {a: versions[a] for a in assets}})
    if hits:
        verdict, reason = "affected", f"命中 {', '.join(sorted(set(hits)))}"
    elif unknown:
        verdict, reason = "need_check", f"版本未知：{', '.join(sorted(set(unknown)))}"
    else:
        verdict, reason = "not_affected", "圖譜中沒有受影響版本的產品"
    return {"advisory_id": adv["id"], "revision": adv.get("revision"), "status": "checked", "verdict": verdict,
            "asset_ids": assets, "input_hash": key, "reason": reason,
            "matched_component": sorted({versions[a]["component"] for a in assets}) if assets else []}


def run(advisory_dirs: list[Path], graph_path: Path, state_path: Path, *, as_of: datetime, dispatch: bool = False,
        target_sha: str | None = None, runner=subprocess.run) -> dict:
    graph = read_json(graph_path)
    generated = parse_time((graph or {}).get("generated_at")) if graph else None
    fresh = bool(graph) and (generated is None or as_of - generated <= GRAPH_MAX_AGE)
    state = read_json(state_path, {"items": []}) or {"items": []}
    by_key = {i.get("input_hash"): i for i in state.get("items", []) if i.get("input_hash")}
    advisories = [a for d in advisory_dirs for a in load_events(d)]
    items, hits, dispatched = [], [], False
    for adv in advisories:
        res = check_advisory(adv, graph, graph_fresh=fresh)
        prev = by_key.get(res.get("input_hash"))
        if prev and prev.get("status") in ("done", "running", "pending") and res["verdict"] == "affected":
            items.append(prev)
            continue
        if res["verdict"] == "affected":
            hits.append({"advisory_id": adv["id"], "asset_ids": res["asset_ids"], "matched_component": res["matched_component"]})
            res["status"] = "pending"
            if dispatch:
                ok, err = _dispatch(adv, res, target_sha, runner)
                res["status"] = "pending" if ok else "failed"
                res["error"] = err
                dispatched = dispatched or ok
        items.append(res)
    result = {"checked_at": iso(as_of), "advisories_checked": len(advisories), "hits": hits, "dispatched": dispatched,
              "items": items, "graph_fresh": fresh}
    write_json(state_path, result)
    return result


def _mode() -> str:
    import os
    mode = os.environ.get("ADVISORY_EXECUTION_MODE", "replay")
    return mode if mode in ("replay", "live") else "replay"


def mark_done(state_path: Path, advisory_id: str, run_id: str) -> bool:
    """A5 成功發布且完成宣告範圍後，把對應公告標為 done。"""
    state = read_json(state_path)
    if not state:
        return False
    hit = False
    for item in state.get("items", []):
        if item.get("advisory_id") == advisory_id and item.get("status") in ("pending", "running", "failed"):
            item.update(status="done", run_id=run_id)
            hit = True
    if hit:
        write_json(state_path, state)
    return hit


def _dispatch(adv: dict, res: dict, target_sha: str | None, runner) -> tuple[bool, str | None]:
    if not ID_RE.match(adv["id"]) or not all(ID_RE.match(a) for a in res["asset_ids"]):
        return False, "公告或資產 ID 格式不符，拒絕派工"
    if target_sha and not re.fullmatch(r"[0-9a-f]{40}", target_sha):
        return False, "target_sha 格式不符"
    args = ["gh", "workflow", "run", "sentinel.yml", "-f", "scenario=advisory", "-f", "trigger_source=intel-watch",
            "-f", f"assets={','.join(res['asset_ids'])}", "-f", f"advisory_id={adv['id']}",
            "-f", f"advisory_revision={adv.get('revision') or ''}",
            "-f", f"execution_mode={_mode()}"]
    if target_sha:
        args += ["-f", f"target_sha={target_sha}"]
    proc = runner(args, capture_output=True, text=True)
    return (proc.returncode == 0), (None if proc.returncode == 0 else (proc.stderr or "dispatch failed")[:300])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--advisories", action="append", type=Path)
    ap.add_argument("--graph", type=Path, default=DEFAULT_GRAPH)
    ap.add_argument("--state", type=Path, default=DEFAULT_STATE)
    ap.add_argument("--dispatch", action="store_true")
    ap.add_argument("--target-sha")
    ap.add_argument("--as-of")
    a = ap.parse_args(argv)
    as_of = parse_time(a.as_of) if a.as_of else datetime.now(timezone.utc)
    res = run(a.advisories or [INTEL_DIR / "advisories"], a.graph, a.state, as_of=as_of, dispatch=a.dispatch,
              target_sha=a.target_sha)
    print(f"checked={res['advisories_checked']} hits={len(res['hits'])} dispatched={res['dispatched']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
