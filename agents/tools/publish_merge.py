"""發布合併（第 10.1 節）：把本次 run 的不可變候選產物套用到最新 main 的乾淨工作樹。

- 只處理允許的路徑；不使用 git add .
- index.json：依各 key 合併，較舊的 generated_at 不覆蓋較新的
- llm.json：合併不同 key；相同 key 不同值不靜默覆蓋，回報衝突
- output_dir：候選比現有新（generated_at）才覆蓋；較舊的 run 不覆蓋新狀態
用法：python agents/tools/publish_merge.py --candidate DIR --repo DIR --output-dir daily
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.cache import merge_cache  # noqa: E402
from tools.common import parse_time, read_json, write_json  # noqa: E402

DATA = Path("dashboard/public/data")
ALLOWED_PREFIXES = ("daily", "advisories/", "scenarios/", "failures/", "intel-watch")
STATUS_RANK = {"done": 4, "running": 3, "pending": 2, "failed": 1, "checked": 0}


def merge_watch(cand: dict | None, cur: dict | None) -> dict | None:
    """intel-watch.json：依 input_hash 合併；done 不會被較舊的 pending／failed 覆蓋。"""
    if not cand:
        return cur
    items = {i.get("input_hash") or i["advisory_id"]: i for i in (cur or {}).get("items", [])}
    for i in cand.get("items", []):
        key = i.get("input_hash") or i["advisory_id"]
        old = items.get(key)
        if old is None or STATUS_RANK.get(i.get("status"), 0) >= STATUS_RANK.get(old.get("status"), 0):
            items[key] = i
    newest = cand if _newer({"generated_at": cand.get("checked_at")}, {"generated_at": (cur or {}).get("checked_at")}) else (cur or cand)
    return {**newest, "items": list(items.values())}


def _newer(a: dict | None, b: dict | None) -> bool:
    ta, tb = parse_time((a or {}).get("generated_at")), parse_time((b or {}).get("generated_at"))
    return tb is None or (ta is not None and ta >= tb)


def merge_index(cand: dict, cur: dict) -> dict:
    out = dict(cur or {})
    for key in ("latest_daily", "latest_complete_daily"):
        if cand.get(key) and _newer(cand[key], out.get(key)):
            out[key] = cand[key]
    for group in ("advisories", "scenarios", "failures"):
        merged = dict(out.get(group) or {})
        for k, v in (cand.get(group) or {}).items():
            if _newer(v, merged.get(k)):
                merged[k] = v
        out[group] = merged
    out["schema_version"] = 1
    stamps = [x for x in (cand.get("updated_at"), (cur or {}).get("updated_at")) if x]
    out["updated_at"] = max(stamps) if stamps else None
    return out


def apply(candidate: Path, repo: Path, output_dir: str) -> dict:
    if ".." in Path(output_dir).parts or not output_dir.startswith(ALLOWED_PREFIXES):
        raise ValueError(f"不允許的 output_dir：{output_dir}")
    report = {"applied": [], "skipped": [], "conflicts": []}
    watch = merge_watch(read_json(candidate / DATA / "intel-watch.json"), read_json(repo / DATA / "intel-watch.json"))
    if watch:
        write_json(repo / DATA / "intel-watch.json", watch)
        report["applied"].append(str(DATA / "intel-watch.json"))
    if output_dir == "intel-watch":
        return report
    src, dst = candidate / DATA / output_dir, repo / DATA / output_dir
    if src.is_dir():
        if _newer(read_json(src / "report.json"), read_json(dst / "report.json")):
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
            report["applied"].append(str(DATA / output_dir))
        else:
            report["skipped"].append(f"{output_dir}：遠端已有較新的結果")
    for sub in ("history",):
        s = candidate / DATA / sub
        if s.is_dir():
            (repo / DATA / sub).mkdir(parents=True, exist_ok=True)
            for f in s.glob("*.json"):
                shutil.copy2(f, repo / DATA / sub / f.name)
    cidx = read_json(candidate / DATA / "index.json")
    if cidx:
        write_json(repo / DATA / "index.json", merge_index(cidx, read_json(repo / DATA / "index.json", {}) or {}))
        report["applied"].append(str(DATA / "index.json"))
    ccache = read_json(candidate / "agents" / "cache" / "llm.json")
    if ccache is not None:
        merged, conflicts = merge_cache(read_json(repo / "agents" / "cache" / "llm.json", {}) or {}, [ccache])
        write_json(repo / "agents" / "cache" / "llm.json", merged)
        report["conflicts"] += conflicts
    for rel in ("reports/intel",):
        s = candidate / rel
        if s.is_dir():
            shutil.copytree(s, repo / rel, dirs_exist_ok=True)
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate", type=Path, required=True)
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--output-dir", required=True)
    a = ap.parse_args(argv)
    rep = apply(a.candidate, a.repo, a.output_dir)
    print(json.dumps(rep, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
