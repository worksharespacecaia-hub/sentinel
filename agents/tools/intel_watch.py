"""觸發 ② 的第 1 層比對（純程式，$0）：新公告 × 已存的 daily 圖譜。

- 產品名稱先以 aliases 正規化；版本落在範圍內才算命中，命中才派發 sentinel.yml（scenario=advisory）
- 圖譜缺失或過期 → need_check，不能寫 not_affected
- 去重鍵＝公告 ID＋revision＋資產集合＋版本／設定雜湊；新增資產、版本回退或新利用條件會重評
- 狀態 checked／queued／pending／running／done／failed；只有對應 A5 成功發布且完成宣告範圍後才 done
- 公告來源：repo 內手寫的公告，以及由 CISA KEV 新列入的 CVE 查 NVD 自動產生的公告（存在 intel-watch.json 的 auto_advisories）
  自動公告要先發布再派工（--defer-dispatch → 發布 → --dispatch-queued），被派工的執行才讀得到
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
AUTO_ID_RE = re.compile(r"^kev-cve-\d{4}-\d{4,7}$")
AUTO_WINDOW = timedelta(days=30)          # KEV 新列入 30 天內的 CVE 產生公告
RECHECK_AFTER = timedelta(hours=24)       # 已查過的 CVE 每 24 小時重查 NVD
MAX_NVD_PER_RUN = 20
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


def load_auto_advisories(state: dict | Path | None) -> list[dict]:
    """intel-watch 由 CISA KEV＋NVD 產生、已發布在 intel-watch.json 的公告（只接受程式產生的格式）。"""
    if isinstance(state, Path):
        state = read_json(state) or {}
    out = []
    for a in (state or {}).get("auto_advisories") or []:
        if (isinstance(a, dict) and a.get("generated_by") == "kev-nvd" and a.get("kind") == "advisory"
                and isinstance(a.get("id"), str) and AUTO_ID_RE.match(a["id"])):
            out.append(a)
    return out


def refresh_auto_advisories(state: dict, *, as_of: datetime, fetcher=None, pace=None, kev_raw: dict | None = None,
                            max_queries: int = MAX_NVD_PER_RUN) -> dict:
    """CISA KEV 近 30 天新列入的 CVE → 查 NVD → 涉及我們有 CPE 對照的產品才產生公告，寫回 state。

    - 未查過的優先（最近列入的先查）；查過的每 24 小時重查一次（NVD 範圍、修補版本可能更新 → revision 改變 → 重新比對與派工）
    - 每次最多查 max_queries 個（NVD 速率限制），其餘下次輪詢繼續
    - 網路失敗只記錄原因，保留既有公告，不刪除
    """
    from tools.safe_fetch import fetch
    from tools.vulndb import advisory_from_cve, fetch_kev, normalize_kev, query_cve
    fetcher = fetcher or fetch
    try:
        kev = normalize_kev(kev_raw if kev_raw is not None else fetch_kev(fetcher))
    except Exception as exc:                          # 網路錯誤、格式不符
        return {"status": "failed", "reason": f"CISA KEV：{type(exc).__name__}: {exc}"[:200]}
    cutoff = (as_of - AUTO_WINDOW).date().isoformat()
    checked = {k: v for k, v in (state.get("kev_checked") or {}).items()
               if k in kev["cves"] and kev["cves"][k]["added"] >= cutoff}
    advisories = {a["id"]: a for a in load_auto_advisories(state) if (a.get("date") or "") >= cutoff}

    def due(cve):
        t = parse_time((checked.get(cve) or {}).get("checked_at"))
        return t is None or as_of - t >= RECHECK_AFTER
    todo = [(c, e) for c, e in kev["cves"].items() if e["added"] >= cutoff and due(c)]
    # 沒查過的排前面；同一群內最近列入的先查
    todo.sort(key=lambda ce: (ce[0] in checked, _neg_date(ce[1]["added"]), ce[0]))
    new, updated, errors = [], [], []
    for cve, entry in todo[:max_queries]:
        try:
            raw = query_cve(cve, fetcher=fetcher, pace=pace)
        except Exception as exc:
            errors.append(f"{cve}：{type(exc).__name__}")
            continue
        adv = advisory_from_cve(raw, entry, as_of=as_of) if raw else None
        checked[cve] = {"checked_at": iso(as_of), "mapped": adv is not None, "revision": adv["revision"] if adv else None}
        if adv is None:
            continue
        old = advisories.get(adv["id"])
        if old is None:
            new.append(adv["id"])
        elif old.get("revision") != adv["revision"]:
            updated.append(adv["id"])
        same = old is not None and old.get("revision") == adv["revision"]
        adv["generated_at"] = old.get("generated_at") if same else iso(as_of)
        advisories[adv["id"]] = adv
    state["auto_advisories"] = sorted(advisories.values(), key=lambda a: a["id"])
    state["kev_checked"] = dict(sorted(checked.items()))
    state["kev_catalog"] = {"version": kev["tool_version"], "released": kev["database_revision"], "count": kev["count"]}
    return {"status": "partial" if errors else "ok", "new": new, "updated": updated,
            "remaining": max(0, len(todo) - max_queries), "errors": errors[:10]}


def _neg_date(d: str) -> tuple[int, ...]:
    """YYYY-MM-DD → 遞減排序用的鍵。"""
    try:
        return tuple(-int(x) for x in d.split("-"))
    except ValueError:
        return (0,)


def run(advisory_dirs: list[Path], graph_path: Path, state_path: Path, *, as_of: datetime, dispatch: bool = False,
        target_sha: str | None = None, runner=subprocess.run, defer_dispatch: bool = False, refresh=None) -> dict:
    """refresh：callable(state) → 狀態；有給時先更新 KEV／NVD 自動公告。

    defer_dispatch：命中只標 queued，不在這裡派工。自動公告只存在 intel-watch.json，被派工的 sentinel.yml 會 checkout
    派工當下的 main，所以必須先發布狀態、再以 dispatch_queued 派工，否則該次執行找不到公告。
    """
    graph = read_json(graph_path)
    generated = parse_time((graph or {}).get("generated_at")) if graph else None
    fresh = bool(graph) and (generated is None or as_of - generated <= GRAPH_MAX_AGE)
    state = read_json(state_path, {"items": []}) or {"items": []}
    auto_status = refresh(state) if refresh else state.get("auto_status")
    by_key = {i.get("input_hash"): i for i in state.get("items", []) if i.get("input_hash")}
    advisories = [a for d in advisory_dirs for a in load_events(d)] + load_auto_advisories(state)
    items, hits, dispatched = [], [], False
    for adv in advisories:
        res = check_advisory(adv, graph, graph_fresh=fresh)
        prev = by_key.get(res.get("input_hash"))
        if prev and prev.get("status") in ("done", "running", "pending", "queued") and res["verdict"] == "affected":
            items.append(prev)
            continue
        if res["verdict"] == "affected":
            hits.append({"advisory_id": adv["id"], "asset_ids": res["asset_ids"], "matched_component": res["matched_component"]})
            res["status"] = "queued" if defer_dispatch else "pending"
            if dispatch and not defer_dispatch:
                ok, err = _dispatch(adv, res, target_sha, runner)
                res["status"] = "pending" if ok else "failed"
                res["error"] = err
                dispatched = dispatched or ok
        items.append(res)
    result = {"checked_at": iso(as_of), "advisories_checked": len(advisories), "hits": hits, "dispatched": dispatched,
              "items": items, "graph_fresh": fresh}
    for k in ("auto_advisories", "kev_checked", "kev_catalog"):
        if k in state:
            result[k] = state[k]
    if auto_status is not None:
        result["auto_status"] = auto_status
    write_json(state_path, result)
    return result


def dispatch_queued(state_path: Path, advisory_dirs: list[Path], *, target_sha: str | None = None,
                    runner=subprocess.run) -> dict:
    """把 queued 的命中派工（狀態已發布之後才呼叫）。成功 → pending；失敗 → failed（下次輪詢重試）。"""
    state = read_json(state_path) or {}
    advisories = {a["id"]: a for a in [*(a for d in advisory_dirs for a in load_events(d)), *load_auto_advisories(state)]}
    sent, failed = [], []
    for item in state.get("items", []):
        if item.get("status") != "queued":
            continue
        adv = advisories.get(item.get("advisory_id"))
        if adv is None:
            item.update(status="failed", error="公告已不存在")
            failed.append(item.get("advisory_id"))
            continue
        ok, err = _dispatch(adv, item, target_sha, runner)
        item.update(status="pending" if ok else "failed", error=err)
        (sent if ok else failed).append(adv["id"])
    state["dispatched"] = bool(sent)
    write_json(state_path, state)
    return {"dispatched": sent, "failed": failed}


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
    ap.add_argument("--dispatch", action="store_true", help="命中立即派工（只適用 repo 內手寫的公告）")
    ap.add_argument("--defer-dispatch", action="store_true", help="命中只標 queued；發布狀態後再用 --dispatch-queued 派工")
    ap.add_argument("--dispatch-queued", action="store_true", help="派工 queued 的命中（狀態已發布後執行）")
    ap.add_argument("--refresh-kev", action="store_true", help="先由 CISA KEV＋NVD 更新自動公告")
    ap.add_argument("--target-sha")
    ap.add_argument("--as-of")
    a = ap.parse_args(argv)
    dirs = a.advisories or [INTEL_DIR / "advisories"]
    if a.dispatch_queued:
        res = dispatch_queued(a.state, dirs, target_sha=a.target_sha)
        print(f"dispatched={len(res['dispatched'])} failed={len(res['failed'])}")
        return 0
    as_of = parse_time(a.as_of) if a.as_of else datetime.now(timezone.utc)
    refresh = None
    if a.refresh_kev:
        from tools.vulndb import _sleep_pacer, pace_seconds

        def refresh(state):
            return refresh_auto_advisories(state, as_of=as_of, pace=_sleep_pacer(pace_seconds()))
    res = run(dirs, a.graph, a.state, as_of=as_of, dispatch=a.dispatch, target_sha=a.target_sha,
              defer_dispatch=a.defer_dispatch, refresh=refresh)
    auto = res.get("auto_status") or {}
    print(f"checked={res['advisories_checked']} hits={len(res['hits'])} dispatched={res['dispatched']} "
          f"auto={len(res.get('auto_advisories', []))} kev={auto.get('status', '-')} new={len(auto.get('new', []))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
