"""A4 攻擊鏈與風險：攻擊路徑與評分由程式計算；impact-analyst 只依分數拆解說明影響。

動態派工：A1 核准的「請 A4 說明相關風險」由程式挑選風險（每件事件最多 3 個），以原本的任務格式追加說明；不改分數。
"""
from __future__ import annotations

from agents.common import finish, load_a1, save
from context import RunCtx
from llm import Task
from tools.agent_plan import pick_extra_risks
from tools.graph_query import GraphQuery
from tools.pipeline import evaluate


def _task(r: dict) -> Task:
    return Task(id=r["id"], subagent="impact-analyst",
                payload={"ids": [r["id"]], "title": r["title"], "breakdown": r["breakdown"], "attack_path": r["attack_path"]})


def run(ctx: RunCtx) -> dict:
    tr = ctx.tracer("a4")
    tr.emit("start", "攻擊鏈與風險")
    pre, plan = load_a1(ctx, tr)
    res = evaluate(ctx.eval_input(preverified=pre, agent_plan=plan))
    tr.emit("tool", f"attack_path：{len(res['paths']['paths'])} 條完整攻擊鏈")
    highs = [r for r in res["risks"] if r["level"] == "high" and r["status"] != "fixed"]
    tr.emit("tool", f"scoring：{len(res['risks'])} 個風險，高 {len(highs)}")
    tasks = [_task(r) for r in highs[:10]]
    scope_risks = list(highs)
    extra = _extra_tasks(tr, plan, res, already={t.id for t in tasks})
    tasks += [_task(r) for r in extra]
    scope_risks += extra
    scope = {r["asset_id"] for r in scope_risks} | {n for r in scope_risks for n in (r["attack_path"] or [])}
    gq = GraphQuery(res["graph_json"], res["paths"], scope=scope)
    results = ctx.runner("a4").run(tasks, graph_query=gq)
    expl = {}
    for res_ in results.values():
        for item in res_.get("output") or []:
            expl[item["id"]] = {"text": item["explanation"], "source": res_["source"]}
    save(ctx, "a4", "explanations.json", expl)
    save(ctx, "a4", "summary.json", {"risks": len(res["risks"]), "high": len(highs), "paths": len(res["paths"]["paths"]),
                                     "planner_extra": len(extra)})
    tr.emit("result", f"{len(tasks)} 個 impact-analyst 任務（動態派工追加 {len(extra)} 個）")
    finish(ctx, "a4")
    return {"risks": len(res["risks"])}


def _extra_tasks(tr, plan: dict | None, res: dict, *, already: set[str]) -> list[dict]:
    if not plan:
        return []
    matches = {m["event"]["id"]: m for m in res["matches"]}
    picked_all: list[dict] = []
    for item in [a for a in plan.get("approved") or [] if a.get("type") == "task"]:
        if (item.get("agent"), item.get("subagent")) != ("a4", "impact-analyst"):
            continue
        m = matches.get(item["event_id"])
        title = (m or {}).get("event", {}).get("title") or item["event_id"]
        picked = pick_extra_risks(item["event_id"], res["risks"], (m or {}).get("planner_checks") or [], already)
        if not picked:
            tr.emit("skip", f"動態派工：{title} 沒有符合條件的風險", subagent="impact-analyst")
            continue
        already.update(r["id"] for r in picked)
        picked_all += picked
        tr.emit("tool", f"動態派工：為 {title} 追加 {len(picked)} 個風險說明（{'、'.join(r['id'] for r in picked)}）"[:300],
                subagent="impact-analyst")
    return picked_all
