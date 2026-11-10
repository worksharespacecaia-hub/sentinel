"""A5 的確定性部分：組裝 report.json、情資比對報告、工程師報告與 state/，寫入指定的 output_dir。

LLM 撰寫的文字（CEO 摘要、建議解法、通知）只能覆蓋文字欄位；燈號、分數、結論、處理狀態每次由程式重算。
"""
from __future__ import annotations

from pathlib import Path

from schemas import Report
from tools.common import SCHEMA_VERSION, iso, sha256_file, sha256_json, write_json
from tools.intel_report import build_report, to_markdown
from tools.templates import ceo_summary, decisions, solution_for

PUBLIC_RISK_KEYS = ("id", "finding_ids", "asset_id", "title", "category", "level", "score", "raw_score", "score_level",
                    "level_reason", "breakdown", "attack_path", "matched_events", "deadline_hours", "solution", "status",
                    "first_seen", "last_evaluated", "verification_evidence", "explanation", "explanation_source",
                    "level_floor", "provisional_basis")


def assemble(result: dict, *, run_id: str, scenario: str, trigger_source: str, scope: str, generated_at,
             execution_mode: str = "template", daily_intel_status: str = "skipped", llm: dict | None = None,
             cost: dict | None = None, open_alerts: list[dict] | None = None) -> dict:
    llm = llm or {}
    nodes = dict(result["graph"].nodes(data=True))
    risks = []
    for r in result["risks"]:
        rr = {k: r.get(k) for k in PUBLIC_RISK_KEYS}
        rr["provisional_basis"] = bool(rr.get("provisional_basis"))
        if r["level"] in ("high", "medium") and r["status"] != "fixed":
            rr["solution"] = (llm.get("solutions") or {}).get(r["id"]) or solution_for(r, nodes)
        risks.append(rr)
    risks_by_id = {r["id"]: r for r in risks}
    observed = iso(result["data"].as_of)
    intel_reports = []
    for m in result["matches"]:
        rep = build_report(m, risks_by_id, nodes, verification=result["verification"].get(m["event"]["id"]),
                           observed_at=observed, llm_text=(llm.get("intel") or {}).get(m["event"]["id"]))
        intel_reports.append(rep)
    real = [r for r in intel_reports if r["event"]["kind"] in ("archive", "live")]
    intel_summary = {
        "checked": len(intel_reports), "affected": sum(1 for r in intel_reports if r["affected_count"] > 0),
        "by_kind": {k: sum(1 for r in intel_reports if r["event"]["kind"] == k) for k in ("live", "archive", "demo", "advisory")},
        "real_checked": len(real), "real_affected": sum(1 for r in real if r["affected_count"] > 0),
    }
    counts = {lv: sum(1 for r in risks if r["level"] == lv and r["status"] != "fixed") for lv in ("high", "medium", "low")}
    app_impact = next((i.get("app_impact") for m in result["matches"] for i in m["impacts"] if i.get("app_impact")), {}) or {}
    completeness = "complete" if result["complete"] else "partial"
    report = {
        "run_id": run_id, "scenario": scenario, "trigger_source": trigger_source, "scope": scope,
        "target_sha": result["data"].target_sha, "completeness": completeness, "data_issues": result["data_issues"],
        "generated_at": iso(generated_at), "as_of": observed, "light": result["light"], "light_reasons": result["light_reasons"],
        "ceo_summary": llm.get("ceo_summary") or ceo_summary(result["light"], risks, intel_summary, nodes),
        "decisions": llm.get("decisions") or decisions(risks), "counts": counts, "coverage": result["recon"]["coverage"],
        "risks": risks,
        "events": [{"id": r["event"]["id"], "kind": r["event"]["kind"], "title": r["event"]["title"],
                    "affected_count": r["affected_count"], "max_level": r["max_level"], "status": r["status"],
                    "demo": bool(r["event"].get("demo"))} for r in intel_reports],
        "proposed_controls": [pc for e in result["events"] for pc in e.get("proposed_controls", [])],
        "open_alerts": open_alerts or [], "intel_summary": intel_summary, "daily_intel_status": daily_intel_status,
        "cost": cost or {"total_usd": 0.0, "per_agent": {}, "cache_hit_rate": None},
        "signals": result["signals"], "reconcile": result["recon"]["records"], "app_impact": app_impact,
        "execution_mode": execution_mode, "scoring": result.get("scoring"),
    }
    Report.model_validate(report)
    return {"report": report, "intel_reports": intel_reports, "risks_full": result["risks"]}


def engineer_markdown(report: dict, result: dict) -> str:
    lines = [f"# 工程師報告（{report['scenario']}，{report['generated_at']}）", "",
             f"燈號：{report['light']}；" + "；".join(report["light_reasons"]), "",
             "| 等級 | 分數 | 風險 | 資產 | 期限 | 證據 |", "|---|---:|---|---|---|---|"]
    for r in result["risks"]:
        if r["status"] == "fixed":
            continue
        ev = "；".join((r.get("evidence") or [])[:2]).replace("|", "／")
        lines.append(f"| {r['level']} | {r['score']} | {r['title'].replace('|', '／')} | {r['asset_id']} | {r['deadline_hours']}h | {ev} |")
    lines += ["", "## 攻擊路徑"]
    for p in result["paths"]["paths"]:
        lines.append(f"- {' → '.join(p['nodes'])}" + (f"（{p['assumption']}）" if p["assumption"] else ""))
    return "\n".join(lines) + "\n"


def write_outputs(out_dir: Path, built: dict, result: dict, *, reports_md_dir: Path | None, run_id: str,
                  job: str = "a5-report", valid_hours: int = 24) -> dict:
    """寫入 output_dir；回傳 manifest。不寫任何金鑰值（掃描結果已遮蔽）。"""
    out_dir = Path(out_dir)
    report = built["report"]
    write_json(out_dir / "report.json", report)
    write_json(out_dir / "graph.json", {**result["graph_json"], "generated_at": report["generated_at"], "target_sha": report["target_sha"]})
    write_json(out_dir / "attack_paths.json", result["paths"])
    write_json(out_dir / "coverage.json", result["recon"]["coverage"])
    for rep in built["intel_reports"]:
        write_json(out_dir / "intel" / f"{rep['event']['id']}.json", rep)
    write_json(out_dir / "intel" / "index.json", [{"id": r["event"]["id"], "kind": r["event"]["kind"], "title": r["event"]["title"],
                                                     "affected_count": r["affected_count"], "max_level": r["max_level"],
                                                     "status": r["status"], "demo": bool(r["event"].get("demo"))}
                                                    for r in built["intel_reports"]])
    state = out_dir / "state"
    write_json(state / "risks.json", {r["id"]: r for r in built["risks_full"]})
    write_json(state / "findings.json", result["findings"])
    write_json(state / "intel.json", {"events": result["events"], "verification": result["verification"]})
    write_json(state / "signals.json", result["signals"])
    (out_dir / "engineer_report.md").write_text(engineer_markdown(report, result), encoding="utf-8", newline="\n")
    if reports_md_dir:
        for rep in built["intel_reports"]:
            p = Path(reports_md_dir) / f"{rep['event']['id']}.md"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(to_markdown(rep), encoding="utf-8", newline="\n")
    files = {str(p.relative_to(out_dir)).replace("\\", "/"): sha256_file(p) for p in sorted(out_dir.rglob("*"))
             if p.is_file() and p.name != "manifest.json"}
    from datetime import timedelta
    from tools.common import parse_time
    manifest = {"schema_version": SCHEMA_VERSION, "run_id": run_id, "job": job, "scope": report["scope"],
                "target_sha": report["target_sha"], "input_hash": sha256_json({"target_sha": report["target_sha"], "as_of": report["as_of"],
                                                                               "scenario": report["scenario"]}),
                "observed_at": report["as_of"], "valid_until": iso(parse_time(report["generated_at"]) + timedelta(hours=valid_hours)),
                "tool_version": {}, "database_revision": {}, "status": "ok" if report["completeness"] == "complete" else "reused",
                "reason": None if report["completeness"] == "complete" else "部分資料缺失或沿用", "files": files}
    write_json(out_dir / "manifest.json", manifest)
    return manifest
