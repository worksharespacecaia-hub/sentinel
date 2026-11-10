"""A2 弱點掃描：解讀已遮蔽的掃描結果與規則檢查；Subagents 只補充說明。"""
from __future__ import annotations

from agents.common import CATEGORY_SUBAGENT, explanation_tasks, finish, flatten_explanations, save
from context import RunCtx
from tools.findings import build_findings
from tools.graph_builder import build_graph
from tools.loaders import load_target
from tools.reconcile import reconcile


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
    results = ctx.runner("a2").run(tasks)
    expl = flatten_explanations(results)
    save(ctx, "a2", "explanations.json", expl)
    save(ctx, "a2", "summary.json", {"findings": len(a2["findings"]), "data_issues": a2["data_issues"],
                                     "secret_findings": a2["secret_findings"]})
    tr.emit("result", f"{len(a2['findings'])} 個發現；{len(tasks)} 個 Subagent 任務")
    finish(ctx, "a2")
    return {"findings": len(a2["findings"])}
