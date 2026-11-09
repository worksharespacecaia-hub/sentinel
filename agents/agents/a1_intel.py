"""A1 外部情資：驗證所有來源的事件與公告（intel_verify），公告情境以 advisory-extractor 抽取。"""
from __future__ import annotations

from agents.common import finish, save
from context import RunCtx
from llm import Task
from tools.intel_verify import verify_event
from tools.pipeline import event_sources


def run(ctx: RunCtx) -> dict:
    tr = ctx.tracer("a1")
    tr.emit("start", "外部情資驗證與比對")
    inp = ctx.eval_input()
    raw_events = event_sources(inp)
    advisories = [e for e in raw_events if e.get("kind") == "advisory" and e.get("text")]
    tasks = [Task(id=a["id"], subagent="advisory-extractor", payload={"ids": [a["id"]], "text": a["text"]}) for a in advisories]
    llm = ctx.runner("a1").run(tasks) if tasks else {}
    for a in advisories:
        res = llm.get(a["id"]) or {}
        # LLM 抽取只是初步結果；程式比對以結構化欄位與 intel_verify 為準
        a["extraction_source"] = res.get("source", "template")
    verified = []
    for raw in raw_events:
        online = ctx.mode == "live" and raw.get("kind") == "live"
        verified.append(verify_event(raw, as_of=ctx.as_of, online=online))
    kinds = {}
    for v in verified:
        kinds[v["event"]["kind"]] = kinds.get(v["event"]["kind"], 0) + 1
    tr.emit("tool", f"intel_verify：{len(verified)} 件（{', '.join(f'{k} {n}' for k, n in sorted(kinds.items()))}）")
    if not tasks:
        tr.emit("skip", "本次沒有需要抽取的公告原文", subagent="advisory-extractor", source="template")
    save(ctx, "a1", "verified.json", verified)
    tr.emit("result", f"已驗證 {len(verified)} 件情資")
    finish(ctx, "a1")
    return {"verified": len(verified)}
