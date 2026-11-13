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


PLAN_ZH = {"dispatch": "派工單", "review": "驗收單"}
PLAN_OFF = {"dispatch": "只跑必要任務，不採用派工的追加任務與排優先", "review": "不做驗收的追加任務與排優先"}


def resolve(ctx: RunCtx, tr, *, want: tuple[str, ...] = ("dispatch",)):
    """讀 A1 verified 並載入核對 Orchestrator 的計畫（A2～A5、llm-plan 共用；specs/orchestrator R5.1、R5.1a）。

    回傳 tools.orchestration.Resolved：res 是評估快照（派工單有效時含其加查控制項），dispatch／review 是最終有效的計畫
    （停用為 None）。停用原因寫入 trace。verified 缺失或損壞時評估由本 Job 離線重建，兩份計畫都停用；
    核對本身出錯時也只停用計畫（必要任務的評估照常），不讓 Job 失敗。
    """
    from tools import orchestration as o
    verified, _ = o.load_verified(ctx)
    if verified is None:
        tr.emit("error", "A1 結果缺失或無法讀取：改由本 Job 重新驗證情資（離線）")
    base = o.base_inputs(ctx)
    try:
        r = o.resolve_plans(ctx, verified=verified, want=want, base=base)
    except Exception as exc:                         # noqa: BLE001 - 計畫核對失敗只停用計畫
        tr.emit("error", f"計畫核對失敗（{type(exc).__name__}）：{PLAN_ZH['dispatch']}與{PLAN_ZH['review']}停用，只跑必要任務")
        r = o.Resolved(res=o.evaluate_snapshot(base, verified, None), dispatch=None, review=None,
                       reasons={m: "resolve_error" for m in want})
    for mode in want:
        plan, why = getattr(r, mode), r.reasons.get(mode)
        if plan is None:
            tr.emit("skip", f"{PLAN_ZH[mode]}停用（{why or 'plan_missing'}）：{PLAN_OFF[mode]}")
        else:
            n, m, k = o.counts(plan)
            tr.emit("tool", f"{PLAN_ZH[mode]}有效：AI 建議 {n} 項、程式核准 {m} 項、拒絕 {k} 項（{o.SOURCE_TEXT.get(plan['source'])}）")
    return r


def finish(ctx: RunCtx, agent: str) -> None:
    ctx.cache.save_delta(ctx.out / agent / "llm-delta.json")
    # 改用範本的任務：claude-analysis Job（訂閱方案）會撰寫，A5 再採用通過驗證的結果
    write_json(ctx.out / agent / "llm-tasks.json", [t for t in ctx.llm_plan if t["agent"] == agent])
    write_json(ctx.out / agent / "cost.json", {"agent": agent, "usd": ctx.cost["per_agent"].get(agent, 0.0),
                                                "usage": ctx.cost.get("usage", {}).get(agent)})
