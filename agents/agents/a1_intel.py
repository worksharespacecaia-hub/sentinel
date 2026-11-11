"""A1 外部情資：驗證所有來源的事件與公告（intel_verify），公告情境以 advisory-extractor 抽取。

動態派工（specs/dynamic-planner）：驗證完情資後，依新同業事件取得 AI 建議並由程式核准，寫出 out/a1/agent-plan.json。
- daily：優先採用 daily-intel（訂閱方案）寫在 intel-daily.json 的 agent_plan，不呼叫 API
- 其他情況或訂閱方案沒有可用建議：A1 planner（live 呼叫 API；replay 查錄製／快取，沒有就範本）
- 建議只能追加工作，不影響分數、燈號與結論；核准規則見 tools/agent_plan.py
"""
from __future__ import annotations

from agents.common import finish, save
from context import RunCtx
from llm import Task
from tools.agent_plan import (NOTE_PENDING, PLAN_FILE, SOURCE_TEXT, approve, build_payload, effective_events, empty_plan,
                              new_peer_events, prev_daily_ids, write_plan)
from tools.common import read_json, sha256_json
from tools.controls import load_controls
from tools.daily_intel import load_daily_plan, load_daily_snapshot
from tools.intel_verify import verify_event
from tools.news_collect import collected_texts
from tools.pipeline import event_sources

PLANNER_TIMEOUT_S = 60      # planner 每次嘗試的上限（最多兩次）
MAX_REJECT_TRACE = 10


class _LazyRunner:
    """A1 最多建立一個 runner：公告抽取與 planner 共用預算狀態與預留序號。"""

    def __init__(self, ctx: RunCtx):
        self.ctx, self.runner = ctx, None

    def get(self):
        if self.runner is None:
            self.runner = self.ctx.runner("a1")
        return self.runner


def run(ctx: RunCtx) -> dict:
    tr = ctx.tracer("a1")
    tr.emit("start", "外部情資驗證與比對")
    plan_path = ctx.out / "a1" / PLAN_FILE
    # 先覆寫成本次的「處理未完成」空計畫：下游不會讀到上一次留下的舊檔
    write_plan(plan_path, empty_plan(ctx, status="pending", source="template", note=NOTE_PENDING))
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
    saved = read_json(ctx.out / "a1" / "verified.json")          # 雜湊以下游實際讀到的內容計算
    plan = _dynamic_plan(ctx, tr, saved, snapshot, runner)
    write_plan(plan_path, plan)
    n, m, k = plan["suggested"], len(plan["approved"]), len(plan["rejected"])
    tr.emit("result", f"已驗證 {len(verified)} 件情資；AI 建議 {n} 項、程式核准 {m} 項、拒絕 {k} 項"
                      f"（來源：{SOURCE_TEXT[plan['source']]}）")
    finish(ctx, "a1")
    return {"verified": len(verified), "agent_plan": {"source": plan["source"], "approved": m, "rejected": k}}


def _dynamic_plan(ctx: RunCtx, tr, verified: list[dict], snapshot, runner: _LazyRunner) -> dict:
    sha = sha256_json(verified)
    events = effective_events(verified)
    prev = prev_daily_ids(ctx.data_dir) if ctx.scope == "daily" else set()
    selected, note = new_peer_events(events, prev)
    notes = [note] if note else []
    if note:
        tr.emit("skip", note, subagent="planner")
    ids = [e["id"] for e in selected]
    if not selected:
        tr.emit("skip", "沒有新同業事件，不需要 AI 建議", subagent="planner")
        return empty_plan(ctx, status="complete", source="skipped", note="；".join(notes) or None, verified_sha256=sha)

    controls = [{"id": c["id"], "title": c["title"]} for c in load_controls()]
    output, source = None, None
    if snapshot is not None:
        sub, why = load_daily_plan(snapshot)
        if sub is not None:
            output, source = sub, "subscription"
            tr.emit("subagent", "採用每日情資（訂閱方案）的 AI 建議", subagent="planner")
        else:
            notes.append(f"訂閱方案未提供可用建議（{why}），改用 A1 planner")
            tr.emit("skip", notes[-1], subagent="planner")
    if output is None:
        payload = build_payload(selected, controls)
        if payload is None:
            notes.append("無法安全組成 planner 輸入，改用範本")
            tr.emit("skip", notes[-1], subagent="planner", source="template")
        else:
            r = runner.get()
            old_timeout, r.timeout_s = r.timeout_s, PLANNER_TIMEOUT_S
            try:
                res = r.run([Task(id="plan", subagent="planner", payload=payload)]).get("plan") or {}
            finally:
                r.timeout_s = old_timeout
            if res.get("output") is not None:
                output, source = res["output"], res["source"]
    note_text = "；".join(notes) or None
    if output is None:
        return empty_plan(ctx, status="complete", source="template", note=note_text, verified_sha256=sha, events=ids)

    result = approve(output, events=selected, controls=controls)
    titles = {e["id"]: e.get("title") or e["id"] for e in selected}
    ctrl_titles = {c["id"]: c["title"] for c in controls}
    for a in result["approved"]:
        if a["type"] == "control":
            tr.emit("tool", f"核准：{titles[a['event_id']]} 加查「{ctrl_titles[a['control_id']]}」", subagent="planner")
        else:
            tr.emit("tool", f"核准：請 A4 說明 {titles[a['event_id']]} 的相關風險", subagent="planner")
    for r in result["rejected"][:MAX_REJECT_TRACE]:
        tr.emit("skip", f"拒絕：{r['reason']}", subagent="planner")
    if len(result["rejected"]) > MAX_REJECT_TRACE:
        tr.emit("skip", f"另有 {len(result['rejected']) - MAX_REJECT_TRACE} 筆拒絕，詳見建議明細", subagent="planner")
    plan = empty_plan(ctx, status="complete", source=source, note=note_text, verified_sha256=sha, events=ids)
    plan.update(result)
    return plan
