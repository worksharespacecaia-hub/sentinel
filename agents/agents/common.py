"""Agent 模組共用：任務分組、結果存取、去敏。"""
from __future__ import annotations

from context import RunCtx
from llm import Task
from tools.common import read_json, write_json
from tools.findings import redact

CATEGORY_SUBAGENT = {
    "secret": "secret-analyst", "vuln": "dependency-analyst", "eol": "runtime-analyst", "identity": "identity-analyst",
    "backup": "backup-analyst", "config": "compliance-checker", "mobile": "mobile-analyst", "shadow_it": "compliance-checker",
    "shadow_api": "compliance-checker", "clone_app": "mobile-analyst",
}


def explanation_tasks(items: list[dict], subagent_for, *, max_per_task: int = 12) -> list[Task]:
    """把同一 Subagent 的項目合成一個任務（輸入由程式先準備好，Subagent 一次就回答）。"""
    groups: dict[str, list[dict]] = {}
    for it in items:
        sub = subagent_for(it)
        if sub:
            groups.setdefault(sub, []).append({"id": it["id"], "title": redact(it["title"]),
                                               "evidence": [redact(e) for e in (it.get("evidence") or [])[:3]]})
    tasks = []
    for sub, rows in sorted(groups.items()):
        for i in range(0, len(rows), max_per_task):
            chunk = rows[i:i + max_per_task]
            tasks.append(Task(id=f"{sub}#{i // max_per_task}", subagent=sub, payload={"ids": [r["id"] for r in chunk], "items": chunk}))
    return tasks


def flatten_explanations(results: dict[str, dict]) -> dict[str, dict]:
    out = {}
    for res in results.values():
        for item in res.get("output") or []:
            out[item["id"]] = {"text": item["explanation"], "source": res["source"], "subagent": res["subagent"]}
    return out


def save(ctx: RunCtx, agent: str, name: str, value) -> None:
    write_json(ctx.out / agent / name, value)


def load(ctx: RunCtx, agent: str, name: str, default=None):
    return read_json(ctx.out / agent / name, default)


def finish(ctx: RunCtx, agent: str) -> None:
    ctx.cache.save_delta(ctx.out / agent / "llm-delta.json")
    # 改用範本的任務：claude-analysis Job（訂閱方案）會撰寫，A5 再採用通過驗證的結果
    write_json(ctx.out / agent / "llm-tasks.json", [t for t in ctx.llm_plan if t["agent"] == agent])
    write_json(ctx.out / agent / "cost.json", {"agent": agent, "usd": ctx.cost["per_agent"].get(agent, 0.0)})
