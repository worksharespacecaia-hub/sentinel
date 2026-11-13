"""A2 弱點掃描：解讀已遮蔽的掃描結果與規則檢查；Subagents 只補充說明。

- 必要任務：掃描產生的基礎 findings（build_findings），依類別每 12 項分一組解讀；快取鍵與 v0.12 相同
- 派工的追加任務（specs/orchestrator R3.2、R5.2）：依最終有效派工單核准的 (a2, dependency-analyst|runtime-analyst, event_id)，
  用政策上下文挑好的 finding（完整評估的結果，只用來挑對象）建立 event:<event_id>:<subagent> 任務；項目格式同必要任務，
  另附事件標題與去敏 attack_chain（最多 5 步）。結果另存 out/a2/event-explanations.json，不併入 finding 說明（R5.2a）
- 每個核准項目的執行結果寫 out/a2/dispatch-outcomes.json（R5.5）
"""
from __future__ import annotations

from agents.common import CATEGORY_SUBAGENT, explanation_tasks, finish, flatten_explanations, resolve, save
from context import RunCtx
from llm import Task
from tools import orchestration as o
from tools.findings import build_findings, redact
from tools.graph_builder import build_graph
from tools.loaders import load_target
from tools.reconcile import reconcile

EVENT_FILE = "event-explanations.json"
TEMPLATE_NOTE = "AI 說明未產生，以上為程式挑選的對象"


def run(ctx: RunCtx) -> dict:
    tr = ctx.tracer("a2")
    tr.emit("start", "弱點掃描解讀")
    data = load_target(ctx.target_root, as_of=ctx.as_of, scanners_dir=ctx.scanners_dir, target_sha=ctx.target_sha,
                       deployments_file=ctx.deployments_file)
    for tool in ("gitleaks", "trivy", "checkov", "kev", "nvd"):
        st = (data.scanners.get(tool) or {}).get("status", "missing")
        tr.emit("tool", f"{tool}：{st}")
    recon = reconcile(data)
    g = build_graph(data, recon)
    a2 = build_findings(data, g, recon, kev=set())   # CISA KEV 全集由 build_findings 從 kev 掃描結果併入
    tasks = explanation_tasks(a2["findings"], lambda f: CATEGORY_SUBAGENT.get(f["category"]))
    runner = ctx.runner("a2")
    results = runner.run(tasks)
    expl = flatten_explanations(results)
    save(ctx, "a2", "explanations.json", expl)
    save(ctx, "a2", "summary.json", {"findings": len(a2["findings"]), "data_issues": a2["data_issues"],
                                     "secret_findings": a2["secret_findings"]})
    try:
        extra = run_event_tasks(ctx, tr, runner, resolve(ctx, tr))
    except Exception as exc:                         # noqa: BLE001 - 追加任務失敗不影響必要任務（R1.5）
        tr.emit("error", f"派工的追加任務失敗（{type(exc).__name__}），只保留必要任務的結果")
        extra = 0
    tr.emit("result", f"{len(a2['findings'])} 個發現；{len(tasks)} 個 Subagent 任務（派工追加 {extra} 個）")
    finish(ctx, "a2")
    return {"findings": len(a2["findings"]), "event_tasks": extra}


def event_payload(event: dict, finding_ids: list[str], findings: dict[str, dict]) -> dict:
    """事件導向解讀的 payload：項目格式同 explanation_tasks（id、遮蔽後標題、前 3 筆證據），另附事件標題與去敏 attack_chain。"""
    items = [{"id": fid, "title": redact(findings[fid].get("title") or fid),
              "evidence": [redact(e) for e in (findings[fid].get("evidence") or [])[:3]]} for fid in finding_ids]
    # 事件文字去敏（遮蔽金鑰與個資，仍疑似機敏的整段不放）；與必要任務的項目一樣只給撰寫用的資料
    chain = [t for t in (o.safe_text(s) for s in (event.get("attack_chain") or [])[:o.MAX_CHAIN]) if t]
    return {"ids": list(finding_ids), "items": items,
            "event": {"id": event["id"], "title": o.safe_text(event.get("title")), "attack_chain": chain}}


def template_text(event: dict, subagent: str, finding_ids: list[str], findings: dict[str, dict]) -> str:
    """AI 沒有產出時的程式範本：列出挑選的元件與系統（不含證據）。"""
    names = []
    for fid in finding_ids:
        f = findings.get(fid) or {}
        comp = " ".join(str(x) for x in (f.get("component"), f.get("version")) if x) or fid
        label = f"{comp}（{f['asset_id']}）" if f.get("asset_id") else comp
        if label not in names:
            names.append(label)
    what = o.CATEGORY_ZH.get(o.A2_EVENT_CATEGORY.get(subagent), "發現")
    title = o.safe_text(event.get("title")) or event["id"]
    return f"依事件「{title}」挑出 {len(finding_ids)} 項相同產品的{what}：{'、'.join(names)}。{TEMPLATE_NOTE}。"


def run_event_tasks(ctx: RunCtx, tr, runner, resolved) -> int:
    """派工單核准的事件導向解讀。派工單停用時不建立任務，結果檔與執行結果都寫空的（不留舊檔）。回傳任務數。"""
    plan = resolved.dispatch
    scope = o.dispatch_scope(plan, resolved.policies.get("dispatch"), resolved.res)
    findings = {f["id"]: f for f in resolved.res.get("findings") or [] if isinstance(f.get("id"), str)}
    tasks, meta, outcomes = [], {}, []
    for item in o.approved_tasks(plan, "a2") if scope else []:
        tid = o.a2_task_id(item["event_id"], item["subagent"])
        target = scope.a2.get(tid)
        fids = [f for f in (target or {}).get("finding_ids") or [] if f in findings]
        if not fids:
            outcomes.append(o.outcome_row(item, "skipped", "no_target"))
            tr.emit("skip", f"派工：{item['event_id']} 沒有可解讀的對象（{item['subagent']}）", subagent=item["subagent"])
            continue
        event = resolved.policies["dispatch"].events[item["event_id"]]
        tasks.append(Task(id=tid, subagent=item["subagent"], payload=event_payload(event, fids, findings)))
        meta[tid] = (item, event, fids)
        tr.emit("tool", f"派工：依事件 {item['event_id']} 追加解讀 {len(fids)} 項（{tid}）", subagent=item["subagent"])
    results = runner.run(tasks) if tasks else {}
    items = []
    for tid, (item, event, fids) in meta.items():
        got = results.get(tid) or {}
        source = got.get("source") if got.get("source") in o.RESULT_SOURCES else "template"
        texts = {x["id"]: x["explanation"] for x in got.get("output") or []} if source != "template" else {}
        ok = bool(texts)
        items.append({"task_id": tid, "event_id": item["event_id"], "subagent": item["subagent"], "finding_ids": fids,
                      "source": source if ok else "template", "explanations": texts,
                      "template": template_text(event, item["subagent"], fids, findings)})
        outcomes.append(o.outcome_row(item, "completed", "done") if ok else o.outcome_row(item, "template", "llm_template"))
    save(ctx, "a2", EVENT_FILE, {"schema_version": 1, "dispatch_plan_sha256": scope.sha if scope else None, "items": items})
    o.write_outcomes(ctx.out, "a2", plan if scope else None, outcomes)
    return len(tasks)
