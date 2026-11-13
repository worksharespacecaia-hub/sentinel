"""A3 早期訊號：規則與計數由程式判斷；complaint-classifier 只說明候選客訴，retro-hunter 在公告情境是必要任務。

派工的追加任務（specs/orchestrator R3.3、R5.3）：每日與情境依最終有效派工單核准的 (a3, retro-hunter, event_id)，
用 tools/retro.py 依事件時間窗與政策上下文的系統篩出有特徵的紀錄，建立 retro:<event_id> 任務；沒有符合特徵的紀錄時不建立任務、
記錄原因。結果存 out/a3/retro.json，每個核准項目的執行結果寫 out/a3/dispatch-outcomes.json（R5.5）。
"""
from __future__ import annotations

from agents.common import finish, resolve, save
from context import RunCtx
from llm import Task
from tools import orchestration as o
from tools import retro
from tools.findings import redact
from tools.loaders import load_target
from tools.signals import ORDER_INFO_RE, evaluate

RETRO_FILE = "retro.json"


def run(ctx: RunCtx) -> dict:
    tr = ctx.tracer("a3")
    tr.emit("start", "早期訊號")
    data = load_target(ctx.target_root, as_of=ctx.as_of, scanners_dir=None, target_sha=ctx.target_sha,
                       deployments_file=ctx.deployments_file)
    inp = ctx.eval_input()
    for k, v in (inp.signal_overrides or {}).items():
        data.signals[k] = [*data.signals.get(k, []), *v]
    signals = evaluate(data.signals, ctx.as_of)
    candidates = [c for c in data.signals.get("complaints.csv", []) if ORDER_INFO_RE.search(c.get("text", ""))]
    tasks = []
    if candidates:
        rows = [{"id": c["id"], "brand_id": c["brand_id"], "text": redact(c["text"])[:120]} for c in candidates[:20]]
        tasks.append(Task(id="complaints", subagent="complaint-classifier", payload={"ids": [r["id"] for r in rows], "items": rows}))
    else:
        tr.emit("skip", "沒有含訂單資訊的候選客訴", subagent="complaint-classifier", source="template")
    if ctx.scope == "advisory":
        tasks.append(Task(id="retro", subagent="retro-hunter", payload={"ids": ["retro"], "assets": ctx.assets}))
    else:
        tr.emit("skip", "必要任務的 retro-hunter 只在公告情境執行（每日與情境由派工單追加）", subagent="retro-hunter",
                source="template")
    runner = ctx.runner("a3")
    results = runner.run(tasks) if tasks else {}
    try:
        extra = run_retro_tasks(ctx, tr, runner, resolve(ctx, tr))
    except Exception as exc:                         # noqa: BLE001 - 追加任務失敗不影響必要任務（R1.5）
        tr.emit("error", f"派工的追加任務失敗（{type(exc).__name__}），只保留必要任務的結果")
        extra = {}
    save(ctx, "a3", "signals.json", signals)
    save(ctx, "a3", "llm.json", {k: {"source": v["source"]} for k, v in {**results, **extra}.items()})
    tr.emit("result", f"{len(signals)} 個訊號（派工追加回溯搜查 {len(extra)} 件）")
    finish(ctx, "a3")
    return {"signals": len(signals), "retro_tasks": len(extra)}


def template_text(result: retro.RetroResult) -> str:
    """AI 沒有產出時的程式範本：回溯的系統、有特徵的紀錄數與各特徵筆數（不含紀錄內容與期間）。"""
    systems = "、".join(result.systems)
    if result.empty:
        return f"回溯 {systems} 在事件日期前 {retro.WINDOW_DAYS} 天到現在的登入與資料庫紀錄：{result.note or retro.NOTE_NO_RECORDS}。"
    per = {f: sum(1 for r in result.records if f in r["flags"]) for f in retro.FLAGS}
    flags = "、".join(f"{retro.FLAGS[f]} {n} 筆" for f, n in per.items() if n)
    shown = "" if result.flagged_total <= len(result.records) else f"（列出前 {len(result.records)} 筆）"
    return (f"回溯 {systems} 在事件日期前 {retro.WINDOW_DAYS} 天到現在的登入與資料庫紀錄：有特徵的紀錄 {result.flagged_total} 筆"
            f"{shown}，{flags}。AI 說明未產生，以上為程式統計。")


def run_retro_tasks(ctx: RunCtx, tr, runner, resolved) -> dict[str, dict]:
    """派工單核准的依事件回溯搜查。派工單停用時不建立任務，結果檔與執行結果都寫空的（不留舊檔）。回傳 {task_id: 結果}。"""
    plan = resolved.dispatch
    scope = o.dispatch_scope(plan, resolved.policies.get("dispatch"), resolved.res)
    signals = getattr(resolved.res.get("data"), "signals", None) or {}
    tasks, meta, outcomes = [], {}, []
    for item in o.approved_tasks(plan, "a3") if scope else []:
        tid = o.retro_task_id(item["event_id"])
        target = scope.a3.get(tid)
        if item.get("subagent") != "retro-hunter" or not target:
            outcomes.append(o.outcome_row(item, "skipped", "no_target"))
            tr.emit("skip", f"派工：{item['event_id']} 沒有可回溯的系統", subagent="retro-hunter")
            continue
        event = resolved.policies["dispatch"].events[item["event_id"]]
        hit = retro.hunt(signals, systems=target["systems"], event_date=event.get("date"), as_of=ctx.as_of)
        meta[tid] = (item, hit)
        if hit.empty:
            outcomes.append(o.outcome_row(item, "skipped", "no_records"))
            tr.emit("skip", f"派工：{item['event_id']} 的回溯搜查不建立任務：{hit.note}", subagent="retro-hunter", source="template")
            continue
        tasks.append(Task(id=tid, subagent="retro-hunter", payload=retro.task_payload(item["event_id"], hit)))
        tr.emit("tool", f"派工：依事件 {item['event_id']} 回溯 {len(hit.systems)} 個系統，有特徵的紀錄 {hit.flagged_total} 筆（{tid}）",
                subagent="retro-hunter")
    results = runner.run(tasks) if tasks else {}
    items = []
    for tid, (item, hit) in meta.items():
        got = results.get(tid) or {}
        source = got.get("source") if got.get("source") in o.RESULT_SOURCES else "template"
        texts = [x["explanation"] for x in got.get("output") or []] if source != "template" else []
        ok = bool(texts)
        items.append({"task_id": tid, "event_id": item["event_id"], "systems": list(hit.systems),
                      "flagged_total": hit.flagged_total, "records": [dict(r) for r in hit.records], "note": hit.note,
                      "task": not hit.empty, "source": source if ok else "template", "text": "；".join(texts) if ok else None,
                      "template": template_text(hit)})
        if not hit.empty:
            outcomes.append(o.outcome_row(item, "completed", "done") if ok else o.outcome_row(item, "template", "llm_template"))
    save(ctx, "a3", RETRO_FILE, {"schema_version": 1, "dispatch_plan_sha256": scope.sha if scope else None, "items": items})
    o.write_outcomes(ctx.out, "a3", plan if scope else None, outcomes)
    return results
