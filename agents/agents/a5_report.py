"""A5 報告與建議：流程的最後一步。只產出報告與建議，不開 PR、不修改任何系統。

即使上游失敗也要執行：確定性評估由程式重算；缺少的上游產物記錄為 data_issues，LLM 文字缺少時用範本。
"""
from __future__ import annotations

from datetime import timedelta

from agents.common import finish, load
from context import RunCtx
from llm import Task, _validate
from tools.cache import merge_cache
from tools.common import AGENTS_DIR, iso, read_json, write_json
from tools.graph_query import GraphQuery
from tools.pipeline import evaluate
from tools.report_builder import assemble, write_outputs
from tools.trace import merge_traces

UPSTREAM = ["orchestrator", "a0", "a1", "a2", "a3", "a4"]


def _llm_texts(ctx: RunCtx, res: dict, built_template: dict) -> dict:
    runner = ctx.runner("a5")
    tr = runner.tracer
    risks = [r for r in res["risks"] if r["level"] in ("high", "medium") and r["status"] != "fixed"]
    tasks = [Task(id="remediation", subagent="remediation-advisor",
                  payload={"ids": [r["id"] for r in risks[:12]],
                           "risks": [{"id": r["id"], "title": r["title"], "level": r["level"], "breakdown": r["breakdown"],
                                      "category": r["category"]} for r in risks[:12]]})]
    secrets = [r for r in risks if r["category"] in ("secret", "identity")]
    if secrets:
        tasks.append(Task(id="key-rotation", subagent="key-rotation-advisor",
                          payload={"ids": [r["id"] for r in secrets], "items": [{"id": r["id"], "title": r["title"]} for r in secrets]}))
    rep = built_template["report"]
    tasks.append(Task(id="ceo", subagent="ceo-briefer", payload={"ids": ["ceo"], "light": rep["light"], "counts": rep["counts"],
                                                                "light_reasons": rep["light_reasons"],
                                                                "top": [r["title"] for r in risks[:5]]}))
    affected = [r for r in built_template["intel_reports"] if r["affected_count"] > 0]
    for r in affected:
        tasks.append(Task(id=f"intel:{r['event']['id']}", subagent="intel-report-writer",
                          payload={"ids": [f"intel:{r['event']['id']}"], "event": r["event"]["title"],
                                   "conclusion": r["conclusion"],
                                   # 不放觀察時間：撰寫不需要，且會讓每個 Job 算出的任務鍵不同
                                   "rows": [{k: v for k, v in row.items() if k != "observed_at"}
                                            for row in r["blocks"].get("3_affected", [])]}))
    notices = [r for r in affected if (r.get("notice") or {}).get("needed")]
    for r in notices:
        tasks.append(Task(id=f"notice:{r['event']['id']}", subagent="brand-notice-writer",
                          payload={"ids": [f"notice:{r['event']['id']}"], "event": r["event"]["title"]}))
    scope = {r["asset_id"] for r in risks} | {n for r in risks for n in (r.get("attack_path") or [])}
    results = runner.run(tasks, graph_query=GraphQuery(res["graph_json"], res["paths"], scope=scope))
    llm: dict = {"solutions": {}, "intel": {}}
    sol = results.get("remediation", {})
    for s in sol.get("output") or []:
        llm["solutions"][s["risk_id"]] = {**s, "source": sol["source"], "suggested_owner": s.get("suggested_owner")}
    ceo = (results.get("ceo") or {}).get("output")
    if ceo:
        llm["ceo_summary"], llm["decisions"] = ceo["ceo_summary"], ceo.get("decisions") or []
    for r in affected:
        out = (results.get(f"intel:{r['event']['id']}") or {})
        items = out.get("output") or []
        if items:
            llm["intel"][r["event"]["id"]] = {"summary": items[0]["explanation"], "source": out["source"]}
    sources = {k: v["source"] for k, v in results.items()}
    tr.emit("result", "文字來源：" + "、".join(f"{k}={v}" for k, v in sorted(sources.items())))
    return llm


def _collected_explanations(ctx: RunCtx, tr) -> dict:
    """A2、A4 改用範本的說明：claude-analysis Job（訂閱方案）撰寫的結果，再以原任務的範圍與格式驗證一次。"""
    results = ctx.llm_results()
    if not results:
        return {}
    out, used = {}, {}
    for agent in ("a2", "a4"):
        for t in load(ctx, agent, "llm-tasks.json", []) or []:
            got = results.get(t.get("key"))
            if got is None:
                continue
            try:
                items = _validate(t["output"], got, set(t["ids"]))
            except ValueError as exc:
                tr.emit("error", f"{agent}/{t['subagent']} 的 Claude 結果未通過驗證，改用範本：{exc}"[:200], source="template")
                continue
            for item in items:
                out[item["id"]] = {"text": item["explanation"], "source": "live", "subagent": t["subagent"]}
            used[(agent, t["subagent"])] = used.get((agent, t["subagent"]), 0) + len(items)
    for (agent, sub), n in sorted(used.items()):
        tr.emit("subagent", f"{agent} 的 {sub} 採用 Claude（訂閱方案）撰寫的說明（{n} 項）", subagent=sub, source="live")
    return out


def prepare(ctx: RunCtx) -> dict:
    """確定性評估與範本報告（A5 與 claude-analysis Job 的任務規劃共用，不寫任何輸出）。"""
    tr = ctx.tracer("a5")
    plan = load(ctx, "orchestrator", "plan.json")
    issues = []
    for up in UPSTREAM:
        if not (ctx.out / up / "trace.jsonl").is_file():
            issues.append({"source": f"job/{up}", "status": "missing", "required": False,
                           "impact": "上游產物缺失：確定性評估已重算，相關說明改用範本"})
    output_dir = ctx.output_dir if plan else f"failures/{ctx.run_id}"
    pre = load(ctx, "a1", "verified.json")
    res = evaluate(ctx.eval_input(preverified=pre))
    res["data_issues"] = [*res["data_issues"], *issues]

    expl = {**(load(ctx, "a2", "explanations.json", {}) or {}), **(load(ctx, "a4", "explanations.json", {}) or {}),
            **_collected_explanations(ctx, tr)}
    for r in res["risks"]:
        e = expl.get(r["id"])
        if e and e.get("source") != "template":
            r["explanation"], r["explanation_source"] = e["text"], e["source"]

    daily_intel = "skipped"
    if ctx.scenario == "daily":
        if plan and plan.get("daily_intel"):       # 排程或手動 daily：不論執行模式都會跑訂閱方案的每日情資
            daily_intel = "ok" if (ctx.out / "intel-daily.json").is_file() else "failed"
        elif ctx.mode == "replay":
            daily_intel = "replay"
    common = dict(run_id=ctx.run_id, scenario=ctx.scenario, trigger_source=ctx.trigger_source, scope=ctx.scope,
                  generated_at=ctx.as_of, execution_mode=ctx.mode, daily_intel_status=daily_intel)
    template = assemble(res, **common)
    return {"plan": plan, "output_dir": output_dir, "res": res, "common": common, "template": template, "daily_intel": daily_intel}


def run(ctx: RunCtx) -> dict:
    tr = ctx.tracer("a5")
    tr.emit("start", f"報告與建議 → {ctx.output_dir}")
    p = prepare(ctx)
    plan, output_dir, res, common, template, daily_intel = (p[k] for k in ("plan", "output_dir", "res", "common", "template", "daily_intel"))
    llm = _llm_texts(ctx, res, template)
    cost = {"total_usd": ctx.cost["total_usd"], "per_agent": _collect_costs(ctx), "cache_hit_rate": ctx.cache.hit_rate}
    built = assemble(res, llm=llm, cost=cost, **common)
    if daily_intel == "failed":
        built["report"]["data_issues"].append({"source": "daily-intel", "status": "failed", "impact": "今日新聞情資未更新"})
    skipped = load(ctx, "a1", "daily-intel-issues.json") or []
    if daily_intel == "ok" and skipped:
        built["report"]["data_issues"].append({"source": "daily-intel", "status": "partial",
                                               "impact": f"每日情資有 {len(skipped)} 項問題（格式不符略過或來源抓取失敗，詳見 A1 執行紀錄）"})

    out_dir = ctx.data_dir / output_dir
    scope_dir = ctx.scope if ctx.scope != "scenario" else f"scenario/{ctx.scenario}"   # 情境之間也不互相覆蓋
    md_dir = ctx.reports_dir / "intel" / scope_dir / ctx.as_of.strftime("%Y-%m-%d") / ctx.run_id
    tr.emit("result", f"燈號 {built['report']['light']}；{len(built['intel_reports'])} 份情資比對報告")
    manifest = write_outputs(out_dir, built, res, reports_md_dir=md_dir, run_id=ctx.run_id)
    # daily-intel、claude-analysis（訂閱方案的 Claude）的執行紀錄由各 Job 以程式整理，有執行時一併放進執行樹
    merge_traces([ctx.out / up / "trace.jsonl" for up in [*UPSTREAM, "daily-intel", "claude-analysis", "a5"]], out_dir / "trace.jsonl")
    if ctx.scope == "daily" and ctx.scanners_dir and ctx.scanners_dir.is_dir() and "fixtures" not in ctx.scanners_dir.parts:
        import shutil
        dest = out_dir / "state" / "scanners"
        dest.mkdir(parents=True, exist_ok=True)
        for f in ctx.scanners_dir.glob("*.json"):      # 已遮蔽的掃描結果與 manifest，供下次沿用
            shutil.copy2(f, dest / f.name)
    _merge_cache(ctx)
    _update_index(ctx, output_dir, built["report"], manifest)
    if ctx.scope == "advisory" and ctx.advisory_id and built["report"]["completeness"] == "complete":
        from tools.intel_watch import mark_done
        mark_done(ctx.data_dir / "intel-watch.json", ctx.advisory_id, ctx.run_id)
    finish(ctx, "a5")
    return {"output_dir": output_dir, "light": built["report"]["light"]}


def _collect_costs(ctx: RunCtx) -> dict:
    per = {}
    for up in [*UPSTREAM, "a5"]:
        c = read_json(ctx.out / up / "cost.json")
        if c:
            per[up] = c["usd"]
    per.update({k: v for k, v in ctx.cost["per_agent"].items()})
    return per


def _merge_cache(ctx: RunCtx) -> None:
    deltas = [read_json(ctx.out / up / "llm-delta.json", {}) or {} for up in [*UPSTREAM, "a5"]]
    deltas.append(ctx.cache.new)
    merged, conflicts = merge_cache(read_json(AGENTS_DIR / "cache" / "llm.json", {}) or {}, deltas)
    write_json(AGENTS_DIR / "cache" / "llm.json", merged)
    if conflicts:
        ctx.tracer("a5").emit("error", f"快取衝突 {len(conflicts)} 筆：保留既有值")


def _update_index(ctx: RunCtx, output_dir: str, report: dict, manifest: dict) -> None:
    path = ctx.data_dir / "index.json"
    index = read_json(path, {}) or {"schema_version": 1, "advisories": {}, "scenarios": {}}
    entry = {"run_id": ctx.run_id, "generated_at": report["generated_at"], "target_sha": report["target_sha"],
             "completeness": report["completeness"], "path": output_dir, "light": report["light"],
             "execution_mode": report["execution_mode"]}
    if output_dir.startswith("failures/"):
        index.setdefault("failures", {})[ctx.run_id] = entry
    elif ctx.scope == "daily":
        index["latest_daily"] = entry
        if report["completeness"] == "complete":
            index["latest_complete_daily"] = entry
        hist = ctx.data_dir / "history" / f"{ctx.as_of:%Y-%m-%d}-daily.json"
        write_json(hist, {"date": f"{ctx.as_of:%Y-%m-%d}", "light": report["light"], "counts": report["counts"],
                          "cost": report["cost"].get("total_usd")})
        cutoff = ctx.as_of - timedelta(days=30)
        for p in (ctx.data_dir / "history").glob("*-daily.json"):
            if p.name[:10] < f"{cutoff:%Y-%m-%d}":
                p.unlink()
    elif ctx.scope == "advisory":
        index.setdefault("advisories", {})[ctx.advisory_id] = entry
    else:
        index.setdefault("scenarios", {})[ctx.scenario] = entry
    index["updated_at"] = iso(ctx.as_of)
    write_json(path, index)
