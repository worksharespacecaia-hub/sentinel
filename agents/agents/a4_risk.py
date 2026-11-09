"""A4 攻擊鏈與風險：攻擊路徑與評分由程式計算；impact-analyst 只依分數拆解說明影響。"""
from __future__ import annotations

from agents.common import finish, load, save
from context import RunCtx
from llm import Task
from tools.graph_query import GraphQuery
from tools.pipeline import evaluate


def run(ctx: RunCtx) -> dict:
    tr = ctx.tracer("a4")
    tr.emit("start", "攻擊鏈與風險")
    pre = load(ctx, "a1", "verified.json")
    if pre is None:
        tr.emit("error", "A1 結果缺失：改由本 Job 重新驗證情資（離線）")
    res = evaluate(ctx.eval_input(preverified=pre))
    tr.emit("tool", f"attack_path：{len(res['paths']['paths'])} 條完整攻擊鏈")
    highs = [r for r in res["risks"] if r["level"] == "high" and r["status"] != "fixed"]
    tr.emit("tool", f"scoring：{len(res['risks'])} 個風險，高 {len(highs)}")
    tasks = [Task(id=r["id"], subagent="impact-analyst",
                  payload={"ids": [r["id"]], "title": r["title"], "breakdown": r["breakdown"], "attack_path": r["attack_path"]})
             for r in highs[:10]]
    scope = {r["asset_id"] for r in highs} | {n for r in highs for n in (r["attack_path"] or [])}
    gq = GraphQuery(res["graph_json"], res["paths"], scope=scope)
    results = ctx.runner("a4").run(tasks, graph_query=gq)
    expl = {}
    for res_ in results.values():
        for item in res_.get("output") or []:
            expl[item["id"]] = {"text": item["explanation"], "source": res_["source"]}
    save(ctx, "a4", "explanations.json", expl)
    save(ctx, "a4", "summary.json", {"risks": len(res["risks"]), "high": len(highs), "paths": len(res["paths"]["paths"])})
    tr.emit("result", f"{len(tasks)} 個 impact-analyst 任務")
    finish(ctx, "a4")
    return {"risks": len(res["risks"])}
