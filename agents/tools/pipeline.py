"""確定性評估流程：不使用 LLM 也能從 Repo ① 資料產出完整的評估結果。

各 Agent（A0～A5）在 Phase 3 包裝這些步驟；這裡的結果是版本、分數、結論、燈號的唯一依據。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from tools.agent_plan import planner_checks
from tools.attack_path import find_paths
from tools.common import INTEL_DIR, iso
from tools.findings import build_findings
from tools.graph_builder import build_graph, graph_to_json
from tools.intel_match import inherit_updates, match_event, merge_findings, stack_complete
from tools.intel_verify import load_events, verify_event
from tools.lights import LABEL, compute_light
from tools.loaders import TargetData, load_target
from tools.reconcile import reconcile
from tools.risk_engine import attach_paths, build_risks, link_events, mark_fixed
from tools.scoring import load_weights
from tools.signals import evaluate as evaluate_signals


@dataclass
class EvalInput:
    target_root: Path
    as_of: datetime
    scanners_dir: Path | None
    intel_kinds: tuple[str, ...] = ("archive", "advisory")      # daily：真實已收錄事件＋已知公告
    extra_event_dirs: list[Path] = field(default_factory=list)
    live_events: list[dict] = field(default_factory=list)
    auto_advisories: list[dict] = field(default_factory=list)   # intel-watch 由 CISA KEV＋NVD 產生的公告（正式執行才帶入）
    deployments: list[dict] | None = None
    deployments_file: Path | None = None       # A0 Job 抓的 GitHub Deployments；沒有時用離線 fixture
    prev_risks: dict[str, dict] = field(default_factory=dict)
    open_alerts: list[dict] = field(default_factory=list)
    online_verify: bool = False
    signal_overrides: dict | None = None
    target_sha: str | None = None
    preverified: list[dict] | None = None      # A1 已驗證的 [{event, verification}]，避免重抓來源
    agent_plan: dict | None = None             # 動態派工：A1 計畫（已由 agent_plan.load_agent_plan 核對）；只追加呈現，不影響判定


def event_sources(inp: EvalInput) -> list[dict]:
    raw = []
    if "archive" in inp.intel_kinds:
        raw += load_events(INTEL_DIR / "archive")
    if "advisory" in inp.intel_kinds:
        raw += load_events(INTEL_DIR / "advisories")
        raw += inp.auto_advisories
    if "demo" in inp.intel_kinds:
        raw += load_events(INTEL_DIR / "demo-events")
    for d in inp.extra_event_dirs:
        raw += load_events(d)
    raw += inp.live_events
    return raw


def evaluate(inp: EvalInput) -> dict:
    data: TargetData = load_target(inp.target_root, as_of=inp.as_of, scanners_dir=inp.scanners_dir,
                                   deployments=inp.deployments, deployments_file=inp.deployments_file,
                                   target_sha=inp.target_sha)
    if inp.signal_overrides:
        for k, v in inp.signal_overrides.items():
            data.signals[k] = [*data.signals.get(k, []), *v]
    recon = reconcile(data)
    g = build_graph(data, recon)

    if inp.preverified is not None:
        verified = list(inp.preverified)
    else:
        verified = [verify_event(raw, as_of=inp.as_of, online=inp.online_verify) for raw in event_sources(inp)]
    events = [v["event"] for v in verified]
    verification = {v["event"]["id"]: v["verification"] for v in verified}
    sdk_advisories = [{**p, "event_id": e["id"]} for e in events for p in e.get("products", []) if p.get("target") == "app_sdk"]
    # 事件新進度沿用原事件的產品、利用條件與控制項（原事件本身不改）
    event_updates = inherit_updates(events)
    kev = {c for e in events for p in e.get("products", []) if p.get("known_exploited") for c in e.get("cves", [])}

    a2 = build_findings(data, g, recon, kev=kev, sdk_advisories=[])
    kev = a2["kev"]                                            # 已收錄事件宣告的 ∪ CISA KEV 全集
    findings = a2["findings"]
    matches = []
    for ev in events:
        m = match_event(ev, data=data, g=g, control_results=a2["controls"], findings=findings, coverage=recon["coverage"],
                        kev=kev)
        findings = merge_findings(findings, m["findings"])
        matches.append(m)
    # 第二輪：控制項／類別命中需要看到所有 finding（例如 clone_app）
    matches = [match_event(m["event"], data=data, g=g, control_results=a2["controls"], findings=findings,
                           coverage=recon["coverage"], kev=kev) for m in matches]
    for m in matches:
        mx = verification.get(m["event"]["id"], {}).get("max_level")
        if mx:
            for imp in m["impacts"]:
                imp["level_cap"] = mx
    # 動態派工的加查：只把核准的控制項轉成本次已算好的檢查結果，不進 impacts、事件連結與評分（R5）
    approved = [a for a in ((inp.agent_plan or {}).get("approved") or []) if isinstance(a, dict)]
    for m in matches:
        m["planner_checks"] = planner_checks(m["event"]["id"], approved, a2["controls"]) if approved else []

    paths = find_paths(g, findings)
    links = link_events(matches, findings)
    real_events = {m["event"]["id"] for m in matches if m["real"]}
    provisional = {e["id"] for e in events if e["confidence"] == "provisional"}
    weights, scoring, scoring_issue = load_weights()          # rules/scoring.json；無效時用預設權重並記錄
    risks = build_risks(findings, g, chain_ids=set(paths["chain_finding_ids"]), event_links=links,
                        real_events=real_events, provisional_events=provisional, as_of=inp.as_of, prev=inp.prev_risks,
                        weights=weights)
    attach_paths(risks, paths["paths"])
    signals = evaluate_signals(data.signals, inp.as_of)
    for s in signals:
        if s.get("suspected_breach"):
            risks.insert(0, {
                "id": s["id"], "finding_ids": [], "asset_id": "platform", "title": f"疑似已發生外洩：{s['summary']}",
                "category": "signal", "level": "high", "score": 3, "raw_score": 3, "score_level": "low",
                "level_reason": "規則下限：A3 已出事的訊號", "level_floor": "high", "breakdown": [{"factor": "基礎分：規則", "points": 3, "reason": "signal:confirmed"}],
                "attack_path": None, "matched_events": [s["related_event"]] if s.get("related_event") else [],
                "deadline_hours": 24, "solution": None, "status": "open", "first_seen": iso(inp.as_of),
                "last_evaluated": iso(inp.as_of), "verification_evidence": [], "evidence": s["evidence"]})

    # coverage_issues（KEV／NVD 涵蓋不足）只是註記：required=False，不影響完整性與燈號
    data_issues = [*data.data_issues, *a2["data_issues"], *a2["coverage_issues"], *([scoring_issue] if scoring_issue else [])]
    complete = not any(i.get("required") and i["status"] in ("missing", "stale") for i in data.data_issues) and not a2["data_issues"]
    evaluated = set(g.nodes) | set(recon.get("saas_registered", []))
    risks += mark_fixed(risks, inp.prev_risks, complete=complete, evaluated_assets=evaluated, as_of=inp.as_of)
    light, reasons = compute_light(risks=risks, signals=signals, open_alerts=inp.open_alerts,
                                   coverage=recon["coverage"], data_issues=data_issues)
    return {
        "data": data, "graph": g, "graph_json": graph_to_json(g), "recon": recon, "findings": findings,
        "secret_findings": a2["secret_findings"], "controls": a2["controls"], "events": events,
        "verification": verification, "matches": matches, "paths": paths, "risks": risks, "signals": signals,
        "light": light, "light_reasons": reasons, "light_label": LABEL[light], "data_issues": data_issues,
        "complete": complete, "stack_complete": stack_complete(data, recon["coverage"]), "sdk_advisories": sdk_advisories,
        "scoring": scoring, "event_updates": event_updates, "agent_plan": inp.agent_plan,
    }
