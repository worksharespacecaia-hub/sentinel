"""A1 外部情資：驗證所有來源的事件與公告（intel_verify），公告情境以 advisory-extractor 抽取。

v0.13.0 起 A1 不再派工：依情資追加任務、排優先改由 Orchestrator（orchestrator-dispatch，specs/orchestrator）在 A1 之後執行，
A1 不呼叫 planner、不寫 out/a1/agent-plan.json。下游以 A1 的 verified.json 核對 Orchestrator 的計畫。
"""
from __future__ import annotations

from agents.common import finish, save
from context import RunCtx
from llm import Task
from tools.common import read_json
from tools.daily_intel import load_daily_snapshot
from tools.intel_verify import verify_event
from tools.news_collect import collected_texts
from tools.pipeline import event_sources


class _LazyRunner:
    """A1 最多建立一個 runner（只用於公告抽取）：預算狀態與預留序號只取得一次。"""

    def __init__(self, ctx: RunCtx):
        self.ctx, self.runner = ctx, None

    def get(self):
        if self.runner is None:
            self.runner = self.ctx.runner("a1")
        return self.runner


def run(ctx: RunCtx) -> dict:
    tr = ctx.tracer("a1")
    tr.emit("start", "外部情資驗證與比對")
    snapshot = load_daily_snapshot(ctx.out / "intel-daily.json") if ctx.scenario == "daily" else None
    inp = ctx.eval_input(daily_events=snapshot.events) if snapshot is not None else ctx.eval_input()
    raw_events = event_sources(inp)
    advisories = [e for e in raw_events if e.get("kind") == "advisory" and e.get("text")]
    tasks = [Task(id=a["id"], subagent="advisory-extractor", payload={"ids": [a["id"]], "text": a["text"]}) for a in advisories]
    runner = _LazyRunner(ctx)
    llm = runner.get().run(tasks) if tasks else {}
    for a in advisories:
        res = llm.get(a["id"]) or {}
        # LLM 抽取只是初步結果；程式比對以結構化欄位與 intel_verify 為準
        a["extraction_source"] = res.get("source", "template")
    collected = {}
    if snapshot is not None:
        issues = list(snapshot.issues)
        news = read_json(ctx.out / "news.json")
        collected = collected_texts(news)
        if news:
            failed = [s.get("name", "?") for s in news.get("sources", []) if s.get("status") != "ok"]
            tr.emit("tool", f"news_collect：{len(news.get('items', []))} 篇文章（來源失敗 {len(failed)} 個）")
            if failed:
                issues.append(f"新聞來源抓取失敗：{'、'.join(failed)}")
        for issue in issues:
            tr.emit("error", f"daily-intel：{issue}", source="template")
        save(ctx, "a1", "daily-intel-issues.json", issues)
    verified = []
    for raw in raw_events:
        # 每日情資的新事件：引用先比對同一次執行抓到的原文，其餘（Claude 搜尋補充的）實際抓頁面確認（不是 LLM 呼叫）
        verified.append(verify_event(raw, as_of=ctx.as_of, online=raw.get("kind") == "live", collected=collected))
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
