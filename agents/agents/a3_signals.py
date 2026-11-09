"""A3 早期訊號：規則與計數由程式判斷；complaint-classifier 只說明候選客訴，retro-hunter 只在公告情境。"""
from __future__ import annotations

from agents.common import finish, save
from context import RunCtx
from llm import Task
from tools.findings import redact
from tools.loaders import load_target
from tools.signals import ORDER_INFO_RE, evaluate


def run(ctx: RunCtx) -> dict:
    tr = ctx.tracer("a3")
    tr.emit("start", "早期訊號")
    data = load_target(ctx.target_root, as_of=ctx.as_of, scanners_dir=None, target_sha=ctx.target_sha)
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
        tr.emit("skip", "retro-hunter 只在公告情境執行", subagent="retro-hunter", source="template")
    results = ctx.runner("a3").run(tasks) if tasks else {}
    save(ctx, "a3", "signals.json", signals)
    save(ctx, "a3", "llm.json", {k: {"source": v["source"]} for k, v in results.items()})
    tr.emit("result", f"{len(signals)} 個訊號")
    finish(ctx, "a3")
    return {"signals": len(signals)}
