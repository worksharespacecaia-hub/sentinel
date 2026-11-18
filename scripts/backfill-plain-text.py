"""把 v0.14.0 以前產生的報告補上白話文字（specs/plain-brief）。只用程式範本，不呼叫任何 LLM。

用法：python scripts/backfill-plain-text.py <報告資料夾> [<報告資料夾> ...]
例如：python scripts/backfill-plain-text.py dashboard/public/data/scenarios/php2shell

改動範圍（與 v0.14.0 的 A5 在「AI 沒寫白話」時的結果相同）：
- 中高風險的 solution：補 plain_title、if_ignored、plain_source；source 為 template 的，temporary 換成新版白話範本
  （AI 寫的 temporary 保留原文，不把範本文字標成 AI 寫的）
- ceo_summary、decisions：改用新版白話範本（數字一律由程式從報告內容計算）
- asset_labels、events[].brand：與 A5 相同的來源與過濾（清冊、圖譜、rules/asset-labels.json；品牌只來自人工整理的 archive）
- manifest.json 中 report.json 的檢查碼

不改：燈號、分數、等級、處理狀態、攻擊路徑、其他檔案。已補過的報告再跑一次結果相同。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents"))
sys.stdout.reconfigure(encoding="utf-8")

import yaml  # noqa: E402

from schemas import Report  # noqa: E402
from tools import digest  # noqa: E402
from tools.common import sha256_file, write_json  # noqa: E402
from tools.plain_text import exact_public, report_brands  # noqa: E402
from tools.report_builder import _referenced_ids  # noqa: E402
from tools.templates import LABEL_LIMIT, ceo_summary, decisions, solution_for  # noqa: E402

INVENTORY = ROOT / "agents" / "fixtures" / "target-baseline" / "ops" / "inventory"
ARCHIVE = ROOT / "agents" / "intel" / "archive"


def _yaml_list(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else None
    if isinstance(data, dict):            # 清冊可能是 {services: [...]} 的形式
        data = next((v for v in data.values() if isinstance(v, list)), [])
    return [x for x in data or [] if isinstance(x, dict)]


def _labels(nodes: dict) -> dict[str, str]:
    """與 report_builder.public_labels 相同：清冊 > 圖譜 display_name > rules/asset-labels.json，再經 R8 過濾。"""
    file_labels, _ = digest.load_asset_label_file()
    raw = digest.public_asset_labels(_yaml_list(INVENTORY / "services.yaml"), _yaml_list(INVENTORY / "vendors.yaml"),
                                     nodes, file_labels)
    return {k: v for k, v in raw.items() if exact_public(v, LABEL_LIMIT)}


def _archive_brands() -> dict[str, str]:
    out = {}
    for p in sorted(ARCHIVE.glob("*.yaml")):
        d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if isinstance(d, dict) and d.get("id") and d.get("brand"):
            out[d["id"]] = d["brand"]
    return out


def backfill(folder: Path) -> dict:
    report_path = folder / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    full = json.loads((folder / "state" / "risks.json").read_text(encoding="utf-8"))
    graph = json.loads((folder / "graph.json").read_text(encoding="utf-8"))
    nodes = {n["id"]: n for n in graph["nodes"]}
    labels = _labels(nodes)

    changed = {"solutions": 0, "kept_ai_temporary": 0}
    for r in report["risks"]:
        if r["level"] not in ("high", "medium") or r["status"] == "fixed" or not r.get("solution"):
            continue
        base = full.get(r["id"]) or {}
        tpl = solution_for({**base, **{k: r[k] for k in ("level", "status", "breakdown", "attack_path") if k in r}}, nodes, labels)
        sol = r["solution"]
        if sol.get("source") == "template":
            sol["temporary"] = tpl["temporary"]
        else:
            changed["kept_ai_temporary"] += 1
        if not (sol.get("plain_title") and sol.get("if_ignored")) or sol.get("plain_source") == "template":
            sol["plain_title"], sol["if_ignored"], sol["plain_source"] = tpl["plain_title"], tpl["if_ignored"], "template"
        changed["solutions"] += 1

    risks = report["risks"]
    report["ceo_summary"] = ceo_summary(report["light"], risks, report.get("intel_summary") or {}, nodes, labels)
    report["decisions"] = decisions(risks, labels)
    report["asset_labels"] = {i: labels[i] for i in sorted(_referenced_ids(risks, report.get("coverage") or {},
                                                                           report.get("reconcile") or []))
                              if i in labels}

    state_events = json.loads((folder / "state" / "intel.json").read_text(encoding="utf-8")).get("events") or []
    brands_by_id = _archive_brands()
    events = [{**e, "brand": brands_by_id.get(e.get("id"))} if e.get("kind") == "archive" else e for e in state_events]
    brands = report_brands(events)
    for e in report["events"]:
        e["brand"] = brands.get(e["id"])

    Report.model_validate(report)
    write_json(report_path, report)
    manifest_path = folder / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"]["report.json"] = sha256_file(report_path)
        write_json(manifest_path, manifest)
    return changed


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for arg in sys.argv[1:]:
        print(f"{arg}：{backfill(Path(arg))}")
