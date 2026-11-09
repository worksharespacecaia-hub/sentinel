"""A0 資產探索與對帳：圖譜、技術棧摘要 stack.json、近 14 天已知事件 seen.json。"""
from __future__ import annotations

from agents.common import finish, save
from context import RunCtx
from llm import Task
from tools.common import INTEL_DIR, read_json, write_json
from tools.graph_builder import build_graph, graph_to_json
from tools.graph_diff import diff
from tools.intel_verify import load_events
from tools.loaders import load_target
from tools.reconcile import reconcile
from tools.stack import build_seen, build_stack


def run(ctx: RunCtx) -> dict:
    tr = ctx.tracer("a0")
    tr.emit("start", "資產探索與對帳")
    data = load_target(ctx.target_root, as_of=ctx.as_of, scanners_dir=ctx.scanners_dir, target_sha=ctx.target_sha)
    recon = reconcile(data)
    g = build_graph(data, recon)
    gj = graph_to_json(g)
    tr.emit("tool", f"graph_builder：{g.number_of_nodes()} 節點、{g.number_of_edges()} 邊；未登記對外資產 "
                    f"{recon['coverage']['unregistered_exposed']} 個")
    prev = read_json(ctx.data_dir / "daily" / "graph.json")
    d = diff(prev, gj)
    tr.emit("tool", f"graph_diff：{'首次執行' if d['first_run'] else ('有變化' if d['changed'] else '無變化')}")

    tasks = [Task(id=dev["asset_id"], subagent="device-identifier",
                  payload={"ids": [dev["asset_id"]], "ip": dev["ip"], "identified": dev["identified"]})
             for dev in recon["devices"] if dev["needs_llm"]]
    llm = ctx.runner("a0").run(tasks) if tasks else {}
    if not tasks:
        tr.emit("skip", "所有設備都已由特徵規則辨識，不呼叫 device-identifier", subagent="device-identifier", source="template")

    stack = build_stack(g, as_of=ctx.as_of)
    seen = build_seen(read_json(INTEL_DIR / "seen.json"), load_events(INTEL_DIR / "archive"), as_of=ctx.as_of)
    write_json(ctx.out / "stack.json", stack)
    write_json(ctx.out / "seen.json", seen)
    save(ctx, "a0", "result.json", {"coverage": recon["coverage"], "graph_diff": d, "devices": recon["devices"],
                                    "device_llm": {k: v["source"] for k, v in llm.items()}})
    tr.emit("result", f"stack.json {len(stack['products'])} 項產品")
    finish(ctx, "a0")
    return {"graph_changed": d["changed"], "first_run": d["first_run"]}
