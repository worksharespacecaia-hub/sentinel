"""A4 攻擊鏈與風險：攻擊路徑與評分由程式計算；impact-analyst 只依分數拆解說明影響。

派工（specs/orchestrator R3.4、R3.6、R5.4）：評估快照與最終有效的派工單由 resolve_plans 取得（派工單有效時含其加查控制項）。
- 必要任務：前 10 個未修復的高風險（task_id 為風險 ID）。派工單的 priorities 只把指定風險移到最前面，其他維持原順序
- 追加說明：核准的 (a4, impact-analyst, event_id) 由程式挑選風險（每件事件最多 3 個，pick_extra_risks），task_id 為
  dispatch:<event_id>:<risk_id>，payload 帶派工單的 dispatch_plan_sha256；A5 依最終有效的派工單重算允許集合再採用
- explanations.json 每筆記錄 origin（baseline／dispatch）、task_id、dispatch_plan_sha256；不改分數
- 每個核准項目的執行結果寫 out/a4/dispatch-outcomes.json（R5.5）
"""
from __future__ import annotations

from agents.common import finish, resolve, save
from context import RunCtx
from llm import Task
from tools import orchestration as o
from tools.common import sha256_json
from tools.graph_query import GraphQuery


def _payload(r: dict) -> dict:
    return {"ids": [r["id"]], "title": r["title"], "breakdown": r["breakdown"], "attack_path": r["attack_path"]}


def _task(r: dict) -> Task:
    return Task(id=r["id"], subagent="impact-analyst", payload=_payload(r))


def run(ctx: RunCtx) -> dict:
    tr = ctx.tracer("a4")
    tr.emit("start", "攻擊鏈與風險")
    resolved = resolve(ctx, tr)
    res, plan = resolved.res, resolved.dispatch
    sha = sha256_json(plan) if plan is not None else None
    tr.emit("tool", f"attack_path：{len(res['paths']['paths'])} 條完整攻擊鏈")
    highs = [r for r in res["risks"] if r["level"] == "high" and r["status"] != "fixed"]
    tr.emit("tool", f"scoring：{len(res['risks'])} 個風險，高 {len(highs)}")
    prio = o.priority_ids(plan, "a4")
    baseline = o.prioritize(highs[:o.MAX_A4_BASELINE], prio)
    moved = [rid for rid in prio if rid in {r["id"] for r in baseline}]
    if moved:
        tr.emit("tool", f"派工排優先：先說明 {'、'.join(moved)}（只調整順序）"[:300], subagent="impact-analyst")
    tasks = [_task(r) for r in baseline]
    targets = o.a4_dispatch_targets(plan, res)
    extra: list[Task] = []
    for item, picked in targets:
        title = item["event_id"]
        if not picked:
            tr.emit("skip", f"派工：{title} 沒有符合條件的風險", subagent="impact-analyst")
            continue
        extra += [Task(id=o.a4_task_id(item["event_id"], r["id"]), subagent="impact-analyst",
                       payload={**_payload(r), "dispatch_plan_sha256": sha}) for r in picked]
        tr.emit("tool", f"派工：為 {title} 追加 {len(picked)} 個風險說明（{'、'.join(r['id'] for r in picked)}）"[:300],
                subagent="impact-analyst")
    scope_risks = [*highs, *(r for _, picked in targets for r in picked)]
    scope = {r["asset_id"] for r in scope_risks} | {n for r in scope_risks for n in (r["attack_path"] or [])}
    gq = GraphQuery(res["graph_json"], res["paths"], scope=scope)
    runner = ctx.runner("a4")
    results = runner.run(tasks, graph_query=gq)              # 必要任務先跑：追加說明不會影響必要說明的預算與結果
    extra_results = runner.run(extra, graph_query=gq) if extra else {}
    expl = {}
    for t in tasks:
        got = results.get(t.id) or {}
        for item in got.get("output") or []:
            expl[item["id"]] = {"text": item["explanation"], "source": got["source"], "origin": "baseline", "task_id": t.id,
                                "dispatch_plan_sha256": sha}
    for t in extra:
        got = extra_results.get(t.id) or {}
        rid = t.payload["ids"][0]
        for item in got.get("output") or []:              # 回覆的 ID 可能是風險 ID 或 task_id，一律對應到這個風險
            expl[rid] = {"text": item["explanation"], "source": got["source"], "origin": "dispatch", "task_id": t.id,
                         "dispatch_plan_sha256": sha}
    save(ctx, "a4", "explanations.json", expl)
    o.write_outcomes(ctx.out, "a4", plan, _outcomes(plan, targets, extra_results, moved=set(moved)))
    save(ctx, "a4", "summary.json", {"risks": len(res["risks"]), "high": len(highs), "paths": len(res["paths"]["paths"]),
                                     "dispatch_extra": len(extra), "priorities": len(moved)})
    tr.emit("result", f"{len(tasks) + len(extra)} 個 impact-analyst 任務（派工追加 {len(extra)} 個、排優先 {len(moved)} 項）")
    finish(ctx, "a4")
    return {"risks": len(res["risks"])}


def _outcomes(plan: dict | None, targets, extra_results: dict, *, moved: set[str]) -> list[dict]:
    """派工單每個 A4 核准項目的執行結果：追加說明（完成／範本／挑不到對象）、排優先（已調整順序）。"""
    rows = []
    for item, picked in targets:
        if not picked:
            rows.append(o.outcome_row(item, "skipped", "no_target"))
            continue
        got = [extra_results.get(o.a4_task_id(item["event_id"], r["id"])) or {} for r in picked]
        ok = all(g.get("source") in ("live", "replay") and g.get("output") for g in got)
        rows.append(o.outcome_row(item, "completed", "done") if ok else o.outcome_row(item, "template", "llm_template"))
    for a in (plan or {}).get("approved") or []:
        if a.get("type") == "priority" and a.get("agent") == "a4":
            done = a.get("risk_id") in moved
            rows.append(o.outcome_row(a, "completed", "reordered") if done else o.outcome_row(a, "skipped", "no_target"))
    return rows
