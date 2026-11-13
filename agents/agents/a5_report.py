"""A5 報告與建議：流程的最後一步。只產出報告與建議，不開 PR、不修改任何系統。

即使上游失敗也要執行：確定性評估由程式重算；缺少的上游產物記錄為 data_issues，LLM 文字缺少時用範本。

Orchestrator（specs/orchestrator R5.1a、R5.2a、R5.6、R5.7）：
- resolve_plans(want=("dispatch","review"))：兩份計畫各自核對；評估快照 res 在派工單有效時含其加查控制項
- 驗收單有效時：priorities 只重排解法清單（前 12）與 CEO 摘要參考清單（前 5）；追加任務 intel-extra:<event_id>
  （需確認事件的摘要）、key-rotation:extra（金鑰輪替建議）、notice-extra:<event_id>（程式未要求的通知草稿）
- 派工的追加結果（A2 event-explanations.json、A3 retro.json、A4 的 dispatch: 說明）只採用最終有效派工單重算的允許集合內、
  派工單 sha 相符的項目；派工單停用時全部捨棄，必要說明不受影響
- orchestrator_results：派工（A2、A3）與驗收（A5）的追加結果，文字去敏 600 字內；報告頂層放全部，情資報告只放該事件的
prepare 與 claude-analysis 的 llm-plan 共用同一條路徑（llm_texts），任務鍵一致。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agents.common import finish, load, resolve
from context import RunCtx
from llm import Task, _validate
from tools import digest
from tools import orchestration as o
from tools.cache import merge_cache
from tools.common import AGENTS_DIR, iso, read_json, write_json
from tools.findings import redact
from tools.graph_query import GraphQuery
from tools.report_builder import assemble, write_outputs
from tools.templates import notice_draft, summary_facts, unsourced_numbers
from tools.trace import merge_traces

# 上游 Job 的 out/<名稱>/（trace、成本、快取 delta）。router 是原 orchestrator（開工路由）；orchestrator-dispatch／review 是
# Orchestrator 的派工與驗收（specs/orchestrator）。缺少的上游記為 data_issues（required=False，不影響完整性與燈號）
UPSTREAM = ["router", "a0", "a1", "orchestrator-dispatch", "a2", "a3", "a4", "orchestrator-review"]
KEYROT_TEMPLATE = "此金鑰風險與本次事件相關，建議依輪替程序處理：確認使用範圍、建立新金鑰並更新相關服務、撤銷舊金鑰與長效授權。（自動範本）"
INTEL_TEMPLATE = "AI 摘要未產生，事件摘要沿用程式範本。"


def _source(got: dict) -> str:
    return got.get("source") if got.get("source") in o.RESULT_SOURCES else "template"


def _review_tasks(review: dict | None, res: dict, built_template: dict, tr) -> tuple[list[Task], dict]:
    """驗收單核准的 A5 追加任務（R5.6）。回傳（任務, {task_id: (subagent, 對象)}）；任務依核准順序，金鑰輪替合成一個任務。"""
    reports = {r["event"]["id"]: r for r in built_template["intel_reports"]}
    risks = {r["id"]: r for r in res["risks"]}
    tasks, meta, keyrot = [], {}, []
    for item in o.approved_tasks(review, "a5"):
        sub = item.get("subagent")
        if sub == "key-rotation-advisor":
            rid = item.get("risk_id")
            if rid in risks and rid not in keyrot:
                if not keyrot:
                    tasks.append(None)                     # 位置保留給合成的金鑰輪替任務
                keyrot.append(rid)
            continue
        rep = reports.get(item.get("event_id"))
        if rep is None:
            tr.emit("skip", f"驗收：{item.get('event_id')} 沒有情資報告，略過（{sub}）", subagent=sub)
            continue
        eid = rep["event"]["id"]
        if sub == "intel-report-writer":
            tid = f"{o.TASK_INTEL_EXTRA}{eid}"
            rows = rep["blocks"]["4_unaffected_and_check"]["need_check"]
            # 需確認項目的投影（R5.6）：我們的狀況、判定與查核建議的白話；不放 asset_id、risk_id、observed_at
            payload = {"ids": [tid], "event": rep["event"]["title"], "conclusion": rep["conclusion"],
                       "rows": [{"our_state": redact(row.get("our_state") or ""), "verdict": row.get("verdict"),
                                 "suggestions": [p for p in (o.public_safe(s.get("plain"), 80) for s in row.get("suggestions") or []
                                                             if isinstance(s, dict)) if p]} for row in rows]}
            tasks.append(Task(id=tid, subagent=sub, payload=payload))
            meta[tid] = (sub, rep)
        elif sub == "brand-notice-writer":
            tid = f"{o.TASK_NOTICE_EXTRA}{eid}"
            tasks.append(Task(id=tid, subagent=sub, payload={"ids": [tid], "event": rep["event"]["title"]}))
            meta[tid] = (sub, rep)
    if keyrot:
        tid = o.TASK_KEYROT_EXTRA
        task = Task(id=tid, subagent="key-rotation-advisor",
                    payload={"ids": list(keyrot), "items": [{"id": rid, "title": risks[rid]["title"]} for rid in keyrot]})
        tasks[tasks.index(None)] = task
        meta[tid] = ("key-rotation-advisor", list(keyrot))
    tasks = [t for t in tasks if t is not None]
    return tasks, {t.id: meta[t.id] for t in tasks}                # 結果依核准順序列出


def _review_results(meta: dict, results: dict, llm: dict) -> list[dict]:
    """驗收追加任務的結果採用（R5.6）：需確認事件摘要 → llm["intel"]；通知草稿 → llm["notice_extra"]；全部另列 orchestrator_results。"""
    out = []
    for tid, (sub, target) in meta.items():
        got = results.get(tid) or {}
        source = _source(got)
        items = (got.get("output") or []) if source != "template" else []
        if sub == "key-rotation-advisor":
            texts = {}
            for it in items:
                texts.setdefault(it["id"], it["explanation"])
            for rid in target:
                text = texts.get(rid)
                out.append(o.result_entry("review", "a5", sub, "risk", rid, text or KEYROT_TEMPLATE,
                                          source if text else "template"))
            continue
        eid = target["event"]["id"]
        text = items[0]["explanation"] if items else None
        if sub == "intel-report-writer":
            if text:
                llm["intel"][eid] = {"summary": text, "source": source}
            out.append(o.result_entry("review", "a5", sub, "event", eid, text or INTEL_TEMPLATE, source if text else "template"))
        else:
            draft = text or notice_draft(target["event"]["title"])
            llm["notice_extra"][eid] = {"text": draft, "source": source if text else "template"}
            out.append(o.result_entry("review", "a5", sub, "event", eid, draft, source if text else "template"))
    return [r for r in out if r is not None]


def _llm_texts(ctx: RunCtx, res: dict, built_template: dict, review: dict | None = None) -> dict:
    runner = ctx.runner("a5")
    tr = runner.tracer
    risks = [r for r in res["risks"] if r["level"] in ("high", "medium") and r["status"] != "fixed"]
    # 驗收單的 priorities 只重排兩份清單的順序（R4.3）；沒有驗收單時與必要任務相同（任務鍵不變）
    prio = o.priority_ids(review, "a5")
    remediation = o.prioritize(risks[:o.MAX_A5_REMEDIATION], prio)
    top = o.prioritize(risks[:o.MAX_A5_CEO], prio)
    if prio:
        tr.emit("tool", f"驗收排優先：先寫 {'、'.join(prio)}（只調整順序）"[:300])
    tasks = [Task(id="remediation", subagent="remediation-advisor",
                  payload={"ids": [r["id"] for r in remediation],
                           "risks": [{"id": r["id"], "title": r["title"], "level": r["level"], "breakdown": r["breakdown"],
                                      "category": r["category"]} for r in remediation]})]
    secrets = [r for r in risks if r["category"] in ("secret", "identity")]
    if secrets:
        tasks.append(Task(id="key-rotation", subagent="key-rotation-advisor",
                          payload={"ids": [r["id"] for r in secrets], "items": [{"id": r["id"], "title": r["title"]} for r in secrets]}))
    rep = built_template["report"]
    tasks.append(Task(id="ceo", subagent="ceo-briefer", payload={"ids": ["ceo"], "light": rep["light"], "counts": rep["counts"],
                                                                "light_reasons": rep["light_reasons"],
                                                                "top": [r["title"] for r in top],
                                                                # 程式範本的白話版本（確定性）：Claude 以此為底改寫，數字以上方欄位為準
                                                                "draft_summary": rep["ceo_summary"],
                                                                "draft_decisions": rep["decisions"]}))
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
    gq = GraphQuery(res["graph_json"], res["paths"], scope=scope)
    results = runner.run(tasks, graph_query=gq)             # 必要任務先跑：追加任務不影響必要任務的預算與結果
    extra, meta = _review_tasks(review, res, built_template, tr)
    extra_results = runner.run(extra, graph_query=gq) if extra else {}
    llm: dict = {"solutions": {}, "intel": {}, "notice_extra": {}}
    sol = results.get("remediation", {})
    for s in sol.get("output") or []:
        llm["solutions"][s["risk_id"]] = {**s, "source": sol["source"], "suggested_owner": s.get("suggested_owner")}
    ceo = (results.get("ceo") or {}).get("output")
    if ceo:
        # 摘要裡的數字必須都能對應程式結果（網站會把數字連到來源）；對不上就用程式範本
        facts = summary_facts(rep["risks"], rep["intel_summary"])
        bad = unsourced_numbers([*ceo["ceo_summary"], *(ceo.get("decisions") or [])], facts)
        if bad:
            tr.emit("skip", f"CEO 摘要的數字 {sorted(set(bad))} 對不上程式結果，改用程式範本", subagent="ceo-briefer", source="template")
        else:
            llm["ceo_summary"], llm["decisions"] = ceo["ceo_summary"], ceo.get("decisions") or []
    for r in affected:
        out = (results.get(f"intel:{r['event']['id']}") or {})
        items = out.get("output") or []
        if items:
            llm["intel"][r["event"]["id"]] = {"summary": items[0]["explanation"], "source": out["source"]}
    llm["review_results"] = _review_results(meta, extra_results, llm)
    sources = {k: v["source"] for k, v in {**results, **extra_results}.items()}
    tr.emit("result", "文字來源：" + "、".join(f"{k}={v}" for k, v in sorted(sources.items())))
    if extra:
        tr.emit("result", f"驗收追加任務 {len(extra)} 個，追加結果 {len(llm['review_results'])} 項")
    return llm


def llm_texts(ctx: RunCtx, p: dict) -> dict:
    """A5 與 claude-analysis 的 llm-plan 共用：用 prepare 解析出的同一份驗收單算任務，任務鍵一致（R7.1）。"""
    return _llm_texts(ctx, p["res"], p["template"], review=p["resolved"].review)


# ---------------------------------------------------------------- 派工的追加結果（R5.2a、R5.7）
def _collected_explanations(ctx: RunCtx, tr, scope: o.DispatchScope | None) -> tuple[dict, dict]:
    """A2、A4 改用範本的說明：claude-analysis Job（訂閱方案）撰寫的結果，再以原任務的範圍與格式驗證一次。

    依 task_id 分流（R5.2a）：event: 開頭的 A2 事件導向任務不併入 finding 說明，另依 task_id 收集；A4 的 dispatch: 任務
    只採用最終有效派工單允許集合內、sha 相符的；派工單停用時兩者都捨棄。回傳（finding／風險說明, {task_id: 事件導向結果}）。
    """
    results = ctx.llm_results()
    if not results:
        return {}, {}
    out, events, used, dropped = {}, {}, {}, 0
    for agent in ("a2", "a4"):
        for t in load(ctx, agent, "llm-tasks.json", []) or []:
            got = results.get(t.get("key"))
            if got is None:
                continue
            tid = t.get("task_id")
            if o.is_extra_task(tid) and (scope is None or not scope.allows(agent, t)):
                dropped += 1
                continue
            try:
                items = _validate(t["output"], got, set(t["ids"]))
            except ValueError as exc:
                tr.emit("error", f"{agent}/{t['subagent']} 的 Claude 結果未通過驗證，改用範本：{exc}"[:200], source="template")
                continue
            if agent == "a2" and o.is_extra_task(tid):
                events[tid] = {x["id"]: x["explanation"] for x in items}
            elif agent == "a4" and o.is_extra_task(tid):
                for item in items:
                    rid = scope.a4[tid]["risk_id"]
                    out[rid] = {"text": item["explanation"], "source": "live", "subagent": t["subagent"], "origin": "dispatch",
                                "task_id": tid, "dispatch_plan_sha256": scope.sha}
            else:
                for item in items:
                    out[item["id"]] = {"text": item["explanation"], "source": "live", "subagent": t["subagent"]}
            used[(agent, t["subagent"])] = used.get((agent, t["subagent"]), 0) + len(items)
    for (agent, sub), n in sorted(used.items()):
        tr.emit("subagent", f"{agent} 的 {sub} 採用 Claude（訂閱方案）撰寫的說明（{n} 項）", subagent=sub, source="live")
    if dropped:
        tr.emit("skip", f"訂閱方案撰寫的追加說明 {dropped} 項不屬於最終有效的派工單，已捨棄（必要說明不受影響）")
    return out, events


def _a4_explanations(ctx: RunCtx, tr, scope: o.DispatchScope | None) -> dict:
    """A4 的說明：必要說明一律採用；dispatch: 追加說明只採用最終有效派工單允許集合內、sha 相符的（R5.7）。"""
    raw = load(ctx, "a4", "explanations.json", {}) or {}
    out, dropped = {}, 0
    for rid, e in raw.items():
        if not isinstance(e, dict):
            continue
        if e.get("origin") == "dispatch" or o.is_extra_task(e.get("task_id")):
            target = scope.a4.get(e.get("task_id")) if scope is not None else None
            if target is None or target["risk_id"] != rid or e.get("dispatch_plan_sha256") != scope.sha:
                dropped += 1
                continue
        out[rid] = e
    if dropped:
        tr.emit("skip", f"A4 的追加說明 {dropped} 項不屬於最終有效的派工單，已捨棄（必要說明不受影響）", subagent="impact-analyst")
    return out


def _file_items(ctx: RunCtx, agent: str, name: str, scope: o.DispatchScope | None, tr) -> dict[str, dict]:
    """A2／A3 的追加結果檔：只有綁定最終有效派工單（sha 相符）時才讀，依 task_id 回傳。"""
    data = load(ctx, agent, name, None)
    data = data if isinstance(data, dict) else {}
    items = data["items"] if isinstance(data.get("items"), list) else []
    if scope is None or data.get("dispatch_plan_sha256") != scope.sha:
        if items:
            tr.emit("skip", f"{agent} 的追加結果 {len(items)} 項不屬於最終有效的派工單，已捨棄")
        return {}
    return {x["task_id"]: x for x in items if isinstance(x, dict) and isinstance(x.get("task_id"), str)}


def _dispatch_results(ctx: RunCtx, tr, scope: o.DispatchScope | None, collected: dict, res: dict) -> list[dict]:
    """派工的追加結果（A2 事件導向解讀、A3 回溯搜查）→ orchestrator_results。訂閱結果優先於 A2 的範本（R5.2a）。"""
    out = []
    labels = {f["id"]: " ".join(str(x) for x in (f.get("component"), f.get("version")) if x) or f["id"]
              for f in res.get("findings") or [] if isinstance(f.get("id"), str)}
    a2 = _file_items(ctx, "a2", "event-explanations.json", scope, tr)
    for tid, target in (scope.a2.items() if scope else []):
        item, allowed = a2.get(tid) or {}, {tid, *target["finding_ids"]}
        texts, source = collected.get(tid), "live"
        if not texts:
            got = item.get("explanations") if isinstance(item.get("explanations"), dict) else {}
            texts, source = (got, item.get("source")) if item.get("source") in ("live", "replay") else ({}, "template")
        if texts and not set(texts) <= allowed:
            texts, source = {}, "template"
        if texts:
            text = "；".join((f"{labels.get(k, k)}：{v}" if len(texts) > 1 else v) for k, v in texts.items())
        elif item:
            text = item.get("template")
        else:
            continue                                      # A2 沒有產出（例如 Job 失敗）：不列
        out.append(o.result_entry("dispatch", "a2", target["subagent"], "event", target["event_id"], text,
                                  source if texts else "template"))
    a3 = _file_items(ctx, "a3", "retro.json", scope, tr)
    for tid, target in (scope.a3.items() if scope else []):
        item = a3.get(tid)
        if not item:
            continue
        ai = item.get("source") in ("live", "replay") and isinstance(item.get("text"), str) and item["text"]
        out.append(o.result_entry("dispatch", "a3", "retro-hunter", "event", target["event_id"],
                                  item["text"] if ai else item.get("template"), item["source"] if ai else "template"))
    return [r for r in out if r is not None]


def prepare(ctx: RunCtx) -> dict:
    """確定性評估與範本報告（A5 與 claude-analysis Job 的任務規劃共用，不寫任何輸出）。"""
    tr = ctx.tracer("a5")
    plan = load(ctx, "router", "plan.json")
    issues = []
    for up in UPSTREAM:
        if not (ctx.out / up / "trace.jsonl").is_file():
            issues.append({"source": f"job/{up}", "status": "missing", "required": False,
                           "impact": "上游產物缺失：確定性評估已重算，相關說明改用範本"})
    output_dir = ctx.output_dir if plan else f"failures/{ctx.run_id}"
    resolved = resolve(ctx, tr, want=("dispatch", "review"))
    res = resolved.res
    res["data_issues"] = [*res["data_issues"], *issues]
    # 報告公開最終有效的派工單與驗收單（停用的那份為 null；public_plan 去掉執行識別與雜湊）
    res["agent_plan"] = {"dispatch": resolved.dispatch, "review": resolved.review}
    scope = o.dispatch_scope(resolved.dispatch, resolved.policies.get("dispatch"), res)
    collected, event_collected = _collected_explanations(ctx, tr, scope)
    expl = {**(load(ctx, "a2", "explanations.json", {}) or {}), **_a4_explanations(ctx, tr, scope), **collected}
    for r in res["risks"]:
        e = expl.get(r["id"])
        if e and e.get("source") != "template":
            r["explanation"], r["explanation_source"] = e["text"], e["source"]
    dispatch_results = _dispatch_results(ctx, tr, scope, event_collected, res)

    daily_intel = "skipped"
    if ctx.scenario == "daily":
        if plan and plan.get("daily_intel"):       # 排程或手動 daily：不論執行模式都會跑訂閱方案的每日情資
            daily_intel = "ok" if (ctx.out / "intel-daily.json").is_file() else "failed"
        elif ctx.mode == "replay":
            daily_intel = "replay"
    common = dict(run_id=ctx.run_id, scenario=ctx.scenario, trigger_source=ctx.trigger_source, scope=ctx.scope,
                  generated_at=ctx.as_of, execution_mode=ctx.mode, daily_intel_status=daily_intel)
    template = assemble(res, **common)
    return {"plan": plan, "output_dir": output_dir, "res": res, "common": common, "template": template, "daily_intel": daily_intel,
            "resolved": resolved, "scope": scope, "dispatch_results": dispatch_results}


def build(ctx: RunCtx, p: dict) -> dict:
    """撰寫文字並組裝報告（不寫檔）：派工與驗收的追加結果只放在 orchestrator_results 與另外標示的欄位，不影響判定（R8）。"""
    tr = ctx.tracer("a5")
    llm = llm_texts(ctx, p)
    results = [*p["dispatch_results"], *llm.pop("review_results", [])]
    if results:
        by = {}
        for r in results:
            by[f"{r['agent']}/{r['subagent']}"] = by.get(f"{r['agent']}/{r['subagent']}", 0) + 1
        tr.emit("result", f"Orchestrator 追加結果 {len(results)} 項：" + "、".join(f"{k} {n}" for k, n in sorted(by.items())))
    cost = {"total_usd": ctx.cost["total_usd"], "per_agent": _collect_costs(ctx), "cache_hit_rate": ctx.cache.hit_rate}
    built = assemble(p["res"], llm=llm, cost=cost, orchestrator_results=results, **p["common"])
    if p["daily_intel"] == "failed":
        built["report"]["data_issues"].append({"source": "daily-intel", "status": "failed", "impact": "今日新聞情資未更新"})
    skipped = load(ctx, "a1", "daily-intel-issues.json") or []
    if p["daily_intel"] == "ok" and skipped:
        built["report"]["data_issues"].append({"source": "daily-intel", "status": "partial",
                                               "impact": f"每日情資有 {len(skipped)} 項問題（格式不符略過或來源抓取失敗，詳見 A1 執行紀錄）"})
    return built


def run(ctx: RunCtx) -> dict:
    tr = ctx.tracer("a5")
    tr.emit("start", f"報告與建議 → {ctx.output_dir}")
    p = prepare(ctx)
    output_dir, res = p["output_dir"], p["res"]
    built = build(ctx, p)
    _digest(ctx, tr, built, res, output_dir)        # 報告寫出前：失敗原因要能寫進 daily 報告與合併後的 trace

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


def _clock() -> datetime:
    """整理實際產生時間（updated_at）；與評估的邏輯時間 as_of 分開。測試以 monkeypatch 凍結。"""
    return datetime.now(timezone.utc)


def _digest(ctx: RunCtx, tr, built: dict, res: dict, output_dir: str) -> None:
    """資安事件整理（純程式，不呼叫 LLM）：只有 daily 的 schedule／manual 來源產生新整理，輸出到 data_dir/digest（與 daily 同層）。

    web daily 與其他 scope 不寫 digest；到期移除由發布端（publish_merge）獨立執行。
    產生或寫入失敗時保留前一版整組檔案，安全錯誤碼記到 report 的 data_issues 與 trace，A5 照常完成。
    """
    if ctx.scope != "daily" or output_dir != "daily":
        return
    if not digest.eligible_run(ctx.scope, ctx.trigger_source):
        tr.emit("skip", "網站觸發的每日評估不更新資安事件整理（到期內容由發布端移除）")
        return
    stats: dict = {}
    try:
        file_labels, label_issues = digest.load_asset_label_file()        # 格式無效時忽略，不讓 A5 失敗
        labels = digest.public_asset_labels(res["data"].services, res["data"].vendors, dict(res["graph"].nodes(data=True)),
                                            file_labels)
        bundle = digest.prepare_bundle(ctx.data_dir / "digest", built["report"], built["intel_reports"], as_of=ctx.as_of,
                                       generated_at=_clock(), run_id=ctx.run_id, asset_labels=labels, stats=stats,
                                       exclude_ids=digest.fixture_ids(res["events"]), extra_issues=label_issues,
                                       internal_ids=set(res["graph"].nodes))
        for issue in label_issues:
            tr.emit("skip", f"資安事件整理：{issue['impact']}")
        digest.commit_bundle(ctx.data_dir / "digest", bundle, ctx.out / "a5" / "digest-staging")
    except Exception as exc:                         # noqa: BLE001 - 整理失敗不讓 A5 失敗
        code = digest.safe_error_code(exc)
        built["report"]["data_issues"].append({"source": "digest", "status": "failed", "required": False,
                                               "impact": f"資安事件整理未更新，保留前一版（{code}）"})
        tr.emit("error", f"資安事件整理未更新，保留前一版：{code}")
        return
    latest = {"rebuilt": "已重建", "pruned": "資料不完整，沿用前版並只移除到期內容", "absent": "尚未產生（資料不完整）"}[stats["latest"]]
    tr.emit("result", f"資安事件整理：新增 {stats['new']}、重新評估 {stats['assessed']}、沿用 {stats['observed_only']}、"
                      f"待評估 {stats['pending']}、到期移除 {stats['removed']}、容量省略 {stats['omitted']}；latest {latest}")


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
