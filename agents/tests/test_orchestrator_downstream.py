"""Orchestrator 的下游執行（specs/orchestrator R3.2～R3.6、R5.2～R5.7；design §3.4、§8 的「A2、A4、A5 下游」與「A4／A5 追加說明」）。

- A2：事件導向解讀的選取（normalize、分類、排序、12 筆上限）、event:<event_id>:<subagent> 任務、結果與 finding 說明分流
- A3：retro:<event_id> 任務與「回溯期間沒有符合特徵的紀錄」
- A4：priorities 只重排、dispatch:<event_id>:<risk_id> 任務、explanations.json 的 origin／task_id／sha；
  「A4 執行時派工單有效、A5 核對時失效」→ 追加文字消失、必要說明保留（含訂閱方案的結果）
- A5：三種追加任務與結果位置（需確認事件摘要、金鑰輪替、通知草稿）、notice.needed 不變、orchestrator_results 的呈現
用凍結資料與 replay；AI 的產出以替身模擬（不呼叫 LLM、不連網路）。
"""
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from agents import a0_assets, a1_intel, a2_scan, a3_signals, a4_risk, a5_report, router
from agents.common import CATEGORY_SUBAGENT
from context import build_ctx
from llm import LLMRunner
from schemas import IntelMatchReport, Report
from tools import orchestration as o
from tools import retro
from tools.cache import LLMCache, ReplayStore
from tools.common import sha256_json
from tools.templates import notice_draft
from tools.trace import Tracer, read_trace

ENV = {"TRIGGER_SOURCE": "manual", "EVENT_NAME": "workflow_dispatch", "AS_OF": "2026-11-09T01:00:00Z", "RUN_ID": "down-run"}
KEYROT = "mail-api-key:C-THIRD-PARTY-KEY-ROTATION"
DISPATCH = {
    "extra_controls": [{"event_id": "demo-erp-rce", "control_id": "C-NET-SEGMENT", "reason": "確認資料庫網段隔離"},
                       {"event_id": "demo-erp-rce", "control_id": "C-NOPE", "reason": "x"}],
    "extra_tasks": [
        {"agent": "a4", "subagent": "impact-analyst", "event_id": "demo-erp-rce", "reason": "補充相關風險"},
        {"agent": "a2", "subagent": "dependency-analyst", "event_id": "demo-push-sdk-rce", "reason": "依事件解讀 SDK 漏洞"},
        {"agent": "a3", "subagent": "retro-hunter", "event_id": "demo-cache-plaintext", "reason": "回溯後台紀錄"},
        {"agent": "a3", "subagent": "retro-hunter", "event_id": "demo-push-sdk-rce", "reason": "回溯 App 後台"},
        {"agent": "a2", "subagent": "runtime-analyst", "event_id": "demo-push-sdk-rce", "reason": "x"},          # 沒有對象：拒絕
    ],
    "priorities": [{"agent": "a4", "risk_id": "saas-quicksite-builder:shadow_it", "reason": "先說明未登記系統"},
                   {"agent": "a4", "risk_id": "storefront:next:vuln", "reason": "先說明對外系統"},
                   {"agent": "a4", "risk_id": "cache-redis:C-CACHE-TLS", "reason": "x"}],                         # 不在前 10：拒絕
}
REVIEW = {
    "extra_tasks": [{"agent": "a5", "subagent": "intel-report-writer", "event_id": "demo-cache-plaintext", "reason": "補寫摘要"},
                    {"agent": "a5", "subagent": "key-rotation-advisor", "risk_id": KEYROT, "reason": "補寫輪替建議"},
                    {"agent": "a5", "subagent": "intel-report-writer", "event_id": "demo-push-sdk-rce", "reason": "x"}],  # 不是需確認
    "priorities": [{"agent": "a5", "risk_id": "brand-app:android-debuggable", "reason": "先寫 App 設定"},
                   {"agent": "a5", "risk_id": "storefront:next:vuln", "reason": "先寫對外系統"}],
    "summary": "派工追加的任務已完成；需確認事件與相關金鑰請工程團隊確認。",
}


@pytest.fixture()
def ctx(monkeypatch, tmp_path):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    for k in ("EXECUTION_MODE", "GITHUB_OUTPUT", "TARGET_DIR", "ADVISORY_ID", "ASSETS", "TARGET_SHA", "SCANNERS_DIR",
              "DEPLOYMENTS_FILE", "GITHUB_RUN_ATTEMPT", "JOB_RESULTS"):
        monkeypatch.delenv(k, raising=False)
    import claude_agent_sdk
    monkeypatch.setattr(claude_agent_sdk, "query", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM")))

    async def no_query(self, pending, graph_query):
        raise AssertionError("不得呼叫 API")
    monkeypatch.setattr(LLMRunner, "_query", no_query)
    # 測試資料沒有符合條件的金鑰輪替候選：補一個（建立與載入同一份政策）；回溯對象補上有外部 IP 登入紀錄的系統
    real_keyrot, real_a3 = o.keyrot_candidates, o.a3_systems
    monkeypatch.setattr(o, "keyrot_candidates", lambda events, matches, risks: list(dict.fromkeys(
        [*real_keyrot(events, matches, risks), *(r["id"] for r in risks if r["id"] == KEYROT and events)])))

    def a3(events, matches, assets):
        out = real_a3(events, matches, assets)
        if "demo-cache-plaintext" in out:
            out["demo-cache-plaintext"] = sorted({*out["demo-cache-plaintext"], "admin-console"})
        return out
    monkeypatch.setattr(o, "a3_systems", a3)
    return replace(build_ctx(scenario="intel-demo"), out=tmp_path / "out", data_dir=tmp_path / "data",
                   reports_dir=tmp_path / "reports", cache=LLMCache(tmp_path / "cache.json"), replay=ReplayStore(tmp_path / "replay"))


class Writer:
    """LLMRunner.run 的替身：agents 內的 Agent 每個說明任務都有 AI 產出（模擬 replay 錄製），其他照原本流程（範本）。"""

    def __init__(self):
        self.agents: set[str] = set()
        self.calls: list[tuple[str, list]] = []


@pytest.fixture()
def writer(monkeypatch):
    w = Writer()
    real = LLMRunner.run

    def run(self, tasks, **kw):
        w.calls.append((self.agent, list(tasks)))
        if self.agent not in w.agents:
            return real(self, tasks, **kw)
        out = {}
        for t in tasks:
            if self.spec.subagents[t.subagent].output == "explanations":
                ids = [i for i in t.payload["ids"]]
                out[t.id] = {"output": [{"id": i, "explanation": f"AI 說明：{t.id}" if len(ids) == 1 else f"AI 說明：{t.id}／{i}"}
                                        for i in ids], "source": "replay", "subagent": t.subagent}
            else:
                out[t.id] = {"output": None, "source": "template", "subagent": t.subagent}
        return out
    monkeypatch.setattr(LLMRunner, "run", run)
    return w


def upstream(c):
    for m in (router, a0_assets, a1_intel):
        m.run(c)
    verified, _ = o.load_verified(c)
    return verified


def write_dispatch(c, proposal=DISPATCH):
    verified, _ = o.load_verified(c)
    plan = o.build_plan("dispatch", proposal, ctx=c, verified=verified, source="replay")
    o.write_plan(o.plan_path(c.out, "dispatch"), plan)
    return plan


def write_review(c, proposal=REVIEW):
    verified, _ = o.load_verified(c)
    r = o.resolve_plans(c, verified=verified, want=("dispatch",))
    plan = o.build_plan("review", proposal, ctx=c, verified=verified, source="replay", dispatch_res=r.res, dispatch_plan=r.dispatch)
    o.write_plan(o.plan_path(c.out, "review"), plan)
    return plan


def invalidate_dispatch(c):
    path = o.plan_path(c.out, "dispatch")
    o.write_plan(path, {**json.loads(path.read_text(encoding="utf-8")), "run_id": "other-run"})


def read(c, *parts):
    return json.loads((c.out.joinpath(*parts)).read_text(encoding="utf-8"))


def report(c):
    return json.loads((c.data_dir / c.output_dir / "report.json").read_text(encoding="utf-8"))


def intel(c, eid):
    return json.loads((c.data_dir / c.output_dir / "intel" / f"{eid}.json").read_text(encoding="utf-8"))


def markdown(c, eid):
    return next(c.reports_dir.rglob(f"{eid}.md")).read_text(encoding="utf-8")


def tasks_of(writer, agent):
    return [t for a, ts in writer.calls if a == agent for t in ts]


# ---------------------------------------------------------------- A2
def test_a2_event_selection_normalize_category_sort_cap(tmp_path):
    """選取以政策上下文為準：產品正規化相同、類別對應 Subagent、只限受影響或需確認的系統、依 (asset_id, id) 排序、最多 12 項。"""
    def imp(asset, verdict="affected"):
        return {"asset_id": asset, "verdict": verdict}

    def f(fid, asset, cat, comp, **kw):
        return {"id": fid, "asset_id": asset, "category": cat, "component": comp, "title": f"{comp} 的發現", **kw}
    events = [{"id": "e1", "title": "事件一", "attack_chain": [f"步驟 {i}" for i in range(7)], "date": "2026-11-08",
               "products": [{"name": "Next.js"}, {"name": "PHP-FPM"}]},
              {"id": "e2", "title": "事件二", "date": "2026-11-08", "products": [{"name": "lodash"}]}]
    matches = {"e1": {"event": events[0], "impacts": [imp("web-b"), imp("web-a", "need_check"), imp("web-z", "not_affected")]},
               "e2": {"event": events[1], "impacts": [imp("api")]}}
    findings = [f("web-b:next:vuln", "web-b", "vuln", "nextjs", evidence=["a", "b", "c", "d"]), f("web-a:next:vuln", "web-a", "vuln", "next"),
                f("web-z:next:vuln", "web-z", "vuln", "next"), f("web-a:php:eol", "web-a", "eol", "php"),
                f("web-a:php:secret", "web-a", "secret", "php"), *(f(f"api:lodash:{i:02d}", "api", "vuln", "lodash") for i in range(15))]
    policy = o.PolicyContext(mode="dispatch", events={e["id"]: e for e in events}, a2=o.a2_candidates(events, matches, findings))
    plan = {"approved": [{"type": "task", "agent": "a2", "subagent": s, "event_id": e, "reason": "r"}
                         for e, s in (("e1", "dependency-analyst"), ("e1", "runtime-analyst"), ("e2", "dependency-analyst"))]}
    resolved = o.Resolved(res={"findings": findings, "matches": [], "risks": []}, dispatch=plan, review=None,
                          policies={"dispatch": policy})
    seen = []

    class Runner:
        def run(self, tasks, **kw):
            seen.extend(tasks)
            return {t.id: {"output": [{"id": t.payload["ids"][0], "explanation": "AI"}], "source": "replay"} if t.id.endswith("runtime-analyst")
                    else {"output": None, "source": "template"} for t in tasks}
    c = SimpleNamespace(out=tmp_path)
    assert a2_scan.run_event_tasks(c, Tracer(tmp_path / "t.jsonl", "a2"), Runner(), resolved) == 3
    by = {t.id: t for t in seen}
    assert list(by) == ["event:e1:dependency-analyst", "event:e1:runtime-analyst", "event:e2:dependency-analyst"]
    assert by["event:e1:dependency-analyst"].payload["ids"] == ["web-a:next:vuln", "web-b:next:vuln"]      # 正規化、依系統排序
    assert by["event:e1:runtime-analyst"].payload["ids"] == ["web-a:php:eol"]                              # eol → runtime-analyst
    assert by["event:e2:dependency-analyst"].payload["ids"] == [f"api:lodash:{i:02d}" for i in range(o.MAX_A2_FINDINGS)]
    assert all(t.subagent == CATEGORY_SUBAGENT[o.A2_EVENT_CATEGORY[t.subagent]] for t in seen)
    p = by["event:e1:dependency-analyst"].payload
    assert p["items"][1] == {"id": "web-b:next:vuln", "title": "nextjs 的發現", "evidence": ["a", "b", "c"]}   # 項目格式同必要任務
    assert p["event"] == {"id": "e1", "title": "事件一", "attack_chain": [f"步驟 {i}" for i in range(o.MAX_CHAIN)]}
    data = json.loads((tmp_path / "a2" / "event-explanations.json").read_text(encoding="utf-8"))
    assert data["dispatch_plan_sha256"] == sha256_json(plan)
    got = {x["task_id"]: (x["source"], x["explanations"]) for x in data["items"]}
    assert got["event:e1:runtime-analyst"] == ("replay", {"web-a:php:eol": "AI"})
    assert got["event:e1:dependency-analyst"] == ("template", {})
    assert "next（web-a）" in next(x["template"] for x in data["items"] if x["task_id"] == "event:e1:dependency-analyst")
    outcomes = json.loads((tmp_path / "a2" / o.OUTCOME_FILE).read_text(encoding="utf-8"))
    assert [(r["event_id"], r["subagent"], r["status"], r["reason"]) for r in outcomes["items"]] == [
        ("e1", "dependency-analyst", "template", "llm_template"), ("e1", "runtime-analyst", "completed", "done"),
        ("e2", "dependency-analyst", "template", "llm_template")]
    assert not (tmp_path / "a2" / "explanations.json").exists()                                            # 不併入 finding 說明


def test_a2_keeps_baseline_keys_and_routes_event_results_separately(ctx, writer):
    upstream(ctx)
    a2_scan.run(ctx)
    base_keys = [t["key"] for t in read(ctx, "a2", "llm-tasks.json")]
    base_expl = read(ctx, "a2", "explanations.json")
    assert read(ctx, "a2", "event-explanations.json") == {"schema_version": 1, "dispatch_plan_sha256": None, "items": []}
    assert read(ctx, "a2", o.OUTCOME_FILE)["items"] == []
    plan = write_dispatch(ctx)
    a2_scan.run(replace(ctx, llm_plan=[]))
    tasks = read(ctx, "a2", "llm-tasks.json")
    assert [t["key"] for t in tasks if not t["task_id"].startswith("event:")] == base_keys                # 必要任務的快取鍵不變
    ev_task = next(t for t in tasks if t["task_id"].startswith("event:"))
    assert ev_task["task_id"] == "event:demo-push-sdk-rce:dependency-analyst"
    assert ev_task["payload"]["ids"] == ["brand-app:@demo-vendor/push-sdk:vuln"]
    assert read(ctx, "a2", "explanations.json") == base_expl
    data = read(ctx, "a2", "event-explanations.json")
    assert data["dispatch_plan_sha256"] == sha256_json(plan) and [x["task_id"] for x in data["items"]] == [ev_task["task_id"]]
    # AI 有產出：A5 放進 orchestrator_results，不進風險說明
    writer.agents = {"a2"}
    a2_scan.run(replace(ctx, llm_plan=[]))
    for m in (a3_signals, a4_risk, a5_report):
        m.run(ctx)
    rep = report(ctx)
    a2_results = [r for r in rep["orchestrator_results"] if r["agent"] == "a2"]
    assert a2_results == [{"stage": "dispatch", "agent": "a2", "subagent": "dependency-analyst", "target_type": "event",
                           "target_id": "demo-push-sdk-rce", "text": f"AI 說明：{ev_task['task_id']}", "source": "replay"}]
    assert not any("event:" in (r.get("explanation") or "") for r in rep["risks"])
    assert intel(ctx, "demo-push-sdk-rce")["orchestrator_results"][0] == a2_results[0]


def test_subscription_event_result_is_revalidated_and_beats_template(ctx):
    """claude-analysis（訂閱方案）的 event: 結果用同樣的分流規則重新驗證後，優先於 event-explanations.json 的範本（R5.2a）。"""
    upstream(ctx)
    write_dispatch(ctx)
    for m in (a2_scan, a3_signals, a4_risk):
        m.run(ctx)
    task = next(t for t in read(ctx, "a2", "llm-tasks.json") if t["task_id"].startswith("event:"))
    assert read(ctx, "a2", "event-explanations.json")["items"][0]["source"] == "template"
    good = {task["key"]: [{"id": task["payload"]["ids"][0], "explanation": "訂閱方案的事件導向解讀"}]}
    a5_report.run(replace(ctx, _llm_results=good, llm_plan=[]))
    res = next(r for r in report(ctx)["orchestrator_results"] if r["agent"] == "a2")
    assert (res["text"], res["source"]) == ("訂閱方案的事件導向解讀", "live")
    assert not any(r.get("explanation") == "訂閱方案的事件導向解讀" for r in report(ctx)["risks"])        # 不併入 finding 說明
    bad = {task["key"]: [{"id": "storefront:next:vuln", "explanation": "範圍外"}]}                     # 範圍外的 ID：不採用
    a5_report.run(replace(ctx, _llm_results=bad, llm_plan=[]))
    res = next(r for r in report(ctx)["orchestrator_results"] if r["agent"] == "a2")
    assert res["source"] == "template" and "挑出 1 項" in res["text"]


# ---------------------------------------------------------------- A3
def test_a3_builds_retro_tasks_and_skips_empty_windows(ctx, writer):
    upstream(ctx)
    plan = write_dispatch(ctx)
    a3_signals.run(ctx)
    tasks = [t for t in tasks_of(writer, "a3") if t.id.startswith("retro:")]
    assert [t.id for t in tasks] == ["retro:demo-cache-plaintext"]                       # demo-push-sdk-rce：沒有符合特徵的紀錄
    p = tasks[0].payload
    assert p["ids"] == ["retro:demo-cache-plaintext"] and p["systems"] == ["admin-console", "cache-redis"]
    assert p["flagged_total"] == 1 and [r["id"] for r in p["records"]] == ["auth-0002"]
    rec = p["records"][0]
    assert set(rec) == {"id", "time", "system", "account", "action", "flags", "ip_label"}
    assert rec["flags"] == ["external_ip"] and rec["ip_label"] == "外部 IP #1" and "198.51.100.20" not in json.dumps(p)
    data = read(ctx, "a3", "retro.json")
    assert data["dispatch_plan_sha256"] == sha256_json(plan)
    items = {x["task_id"]: x for x in data["items"]}
    assert items["retro:demo-push-sdk-rce"]["task"] is False and items["retro:demo-push-sdk-rce"]["note"] == retro.NOTE_NO_RECORDS
    assert items["retro:demo-cache-plaintext"]["source"] == "template"                  # replay 沒有錄製
    outcomes = {r["event_id"]: (r["status"], r["reason"]) for r in read(ctx, "a3", o.OUTCOME_FILE)["items"]}
    assert outcomes == {"demo-cache-plaintext": ("template", "llm_template"), "demo-push-sdk-rce": ("skipped", "no_records")}
    assert any(retro.NOTE_NO_RECORDS in e["detail"] for e in read_trace(ctx.out / "a3" / "trace.jsonl"))
    writer.agents = {"a3"}
    a3_signals.run(replace(ctx, llm_plan=[]))
    assert read(ctx, "a3", "retro.json")["items"][0]["text"] == "AI 說明：retro:demo-cache-plaintext"
    assert ("completed", "done") in {(r["status"], r["reason"]) for r in read(ctx, "a3", o.OUTCOME_FILE)["items"]}


def test_advisory_retro_baseline_is_unchanged(ctx, writer):
    adv = replace(ctx, scenario="advisory", scope="advisory", advisory_id="adv-opsbuilder-2026-001", assets=["internal-tool"],
                  output_dir="advisories/adv-opsbuilder-2026-001/down-run")
    upstream(adv)
    write_dispatch(adv, {"extra_tasks": [{"agent": "a3", "subagent": "retro-hunter", "event_id": "adv-opsbuilder-2026-001",
                                          "reason": "回溯"}]})
    a3_signals.run(adv)
    assert [(t.id, t.payload) for t in tasks_of(writer, "a3") if "retro" in t.id] == [
        ("retro", {"ids": ["retro"], "assets": ["internal-tool"]})]                      # 必要任務照舊；追加的被拒絕（必要任務已包含）


# ---------------------------------------------------------------- A4
def test_a4_priorities_only_reorder_and_dispatch_tasks_are_tagged(ctx, writer):
    upstream(ctx)
    a4_risk.run(ctx)
    base = [(t.id, t.payload) for t in tasks_of(writer, "a4")]
    base_keys = [t["key"] for t in read(ctx, "a4", "llm-tasks.json")]
    writer.calls.clear()
    plan = write_dispatch(ctx)
    writer.agents = {"a4"}
    a4_risk.run(replace(ctx, llm_plan=[]))
    calls = [ts for a, ts in writer.calls if a == "a4"]
    assert len(calls) == 2                                                               # 必要任務先跑，追加說明另一批
    ordered = [t.id for t in calls[0]]
    assert ordered[:2] == ["saas-quicksite-builder:shadow_it", "storefront:next:vuln"]
    assert sorted(ordered) == sorted(i for i, _ in base)                                 # 只重排，不新增或移除
    assert [i for i in ordered[2:]] == [i for i, _ in base if i not in ordered[:2]]    # 其他維持原順序
    assert {t.id: t.payload for t in calls[0]} == dict(base)                             # payload 不變（快取鍵不變）
    sha = sha256_json(plan)
    assert [(t.id, t.payload["ids"], t.payload["dispatch_plan_sha256"]) for t in calls[1]] == [
        ("dispatch:demo-erp-rce:order-db-prod:C-NET-SEGMENT", ["order-db-prod:C-NET-SEGMENT"], sha)]
    expl = read(ctx, "a4", "explanations.json")
    assert expl["order-db-prod:C-NET-SEGMENT"] == {"text": "AI 說明：dispatch:demo-erp-rce:order-db-prod:C-NET-SEGMENT",
                                                    "source": "replay", "origin": "dispatch",
                                                    "task_id": "dispatch:demo-erp-rce:order-db-prod:C-NET-SEGMENT",
                                                    "dispatch_plan_sha256": sha}
    assert expl["storefront:next:vuln"]["origin"] == "baseline" and expl["storefront:next:vuln"]["task_id"] == "storefront:next:vuln"
    assert {e["dispatch_plan_sha256"] for e in expl.values()} == {sha}
    outcomes = [(r["type"], r.get("event_id") or r.get("risk_id"), r["status"], r["reason"]) for r in read(ctx, "a4", o.OUTCOME_FILE)["items"]]
    assert outcomes == [("task", "demo-erp-rce", "completed", "done"), ("priority", "saas-quicksite-builder:shadow_it", "completed", "reordered"),
                        ("priority", "storefront:next:vuln", "completed", "reordered")]
    writer.agents = set()
    a4_risk.run(replace(ctx, llm_plan=[]))
    keys = [t["key"] for t in read(ctx, "a4", "llm-tasks.json") if not t["task_id"].startswith("dispatch:")]
    assert sorted(keys) == sorted(base_keys)


@pytest.mark.parametrize("subscription", [False, True])
def test_dispatch_text_disappears_when_plan_becomes_invalid_before_a5(ctx, writer, subscription):
    """A4 執行時派工單有效、A5 核對時失效：追加文字消失，必要說明保留（R5.7）；訂閱方案補寫的 dispatch: 結果也一樣被過濾。"""
    upstream(ctx)
    write_dispatch(ctx)
    writer.agents = set() if subscription else {"a4"}
    for m in (a2_scan, a3_signals, a4_risk):
        m.run(ctx)
    write_review(ctx)
    extra_rid, base_rid = "order-db-prod:C-NET-SEGMENT", "storefront:next:vuln"
    collected = None
    if subscription:
        collected = {t["key"]: [{"id": i, "explanation": f"訂閱：{t['task_id']}"} for i in t["ids"] if not i.startswith("dispatch:")]
                     for t in read(ctx, "a4", "llm-tasks.json")}
    c = replace(ctx, _llm_results=collected, llm_plan=[])
    expected = "訂閱：" if subscription else "AI 說明："
    source = "live" if subscription else "replay"
    a5_report.run(c)
    risks = {r["id"]: r for r in report(ctx)["risks"]}
    assert risks[extra_rid]["explanation"] == f"{expected}dispatch:demo-erp-rce:{extra_rid}"
    assert (risks[base_rid]["explanation"], risks[base_rid]["explanation_source"]) == (f"{expected}{base_rid}", source)
    assert report(ctx)["agent_plan"]["dispatch"] and any(r["stage"] == "dispatch" for r in report(ctx)["orchestrator_results"])
    invalidate_dispatch(ctx)
    a5_report.run(replace(c, _llm_results=collected))
    rep = report(ctx)
    risks = {r["id"]: r for r in rep["risks"]}
    assert risks[extra_rid].get("explanation") is None                                    # 追加文字消失
    assert risks[base_rid]["explanation"] == f"{expected}{base_rid}"                       # 必要說明保留
    assert rep["agent_plan"] is None and rep["orchestrator_results"] == []                 # 驗收單綁定失效的派工單：一併停用
    assert any("不屬於最終有效的派工單" in e["detail"] for e in read_trace(ctx.out / "a5" / "trace.jsonl"))


# ---------------------------------------------------------------- A5
def test_a5_review_tasks_results_and_report(ctx, writer):
    upstream(ctx)
    for m in (a2_scan, a3_signals, a4_risk):
        m.run(ctx)
    a5_report.run(ctx)
    before, before_nc = report(ctx), intel(ctx, "demo-cache-plaintext")
    base_tasks = {t.id: t.payload for t in tasks_of(writer, "a5")}
    writer.calls.clear()
    rplan = write_review(ctx)                                                             # 派工單缺失：驗收單綁定 null
    assert rplan["dispatch_plan_sha256"] is None and [r["reason"] for r in rplan["rejected"]] == [o.R_NOT_NEED_CHECK]
    writer.agents = {"a5"}
    a5_report.run(replace(ctx, llm_plan=[]))
    calls = [ts for a, ts in writer.calls if a == "a5"]
    assert len(calls) == 2
    first = {t.id: t.payload for t in calls[0]}
    assert first["remediation"]["ids"][:2] == ["brand-app:android-debuggable", "storefront:next:vuln"]      # 只重排前 12
    assert sorted(first["remediation"]["ids"]) == sorted(base_tasks["remediation"]["ids"])
    assert first["ceo"]["top"][0] == next(r["title"] for r in before["risks"] if r["id"] == "storefront:next:vuln")
    assert sorted(first["ceo"]["top"]) == sorted(base_tasks["ceo"]["top"])                # 前 5 只重排（android 不在前 5）
    assert set(first) == set(base_tasks)
    extra = {t.id: t for t in calls[1]}
    assert list(extra) == ["intel-extra:demo-cache-plaintext", o.TASK_KEYROT_EXTRA]
    p = extra["intel-extra:demo-cache-plaintext"].payload
    assert p["ids"] == ["intel-extra:demo-cache-plaintext"] and p["conclusion"] == before_nc["conclusion"]
    assert p["rows"] and all(set(r) == {"our_state", "verdict", "suggestions"} for r in p["rows"])           # 不含 asset_id 等
    assert extra[o.TASK_KEYROT_EXTRA].payload["ids"] == [KEYROT]
    rep = report(ctx)
    Report.model_validate(rep)
    nc = intel(ctx, "demo-cache-plaintext")
    IntelMatchReport.model_validate(nc)
    assert (nc["summary"], nc["summary_source"]) == ("AI 說明：intel-extra:demo-cache-plaintext", "replay")
    assert (nc["status"], nc["conclusion"], before_nc["summary_source"]) == ("need_check", before_nc["conclusion"], "template")
    review_results = [r for r in rep["orchestrator_results"] if r["stage"] == "review"]
    assert [(r["subagent"], r["target_type"], r["target_id"], r["source"]) for r in review_results] == [
        ("intel-report-writer", "event", "demo-cache-plaintext", "replay"), ("key-rotation-advisor", "risk", KEYROT, "replay")]
    assert nc["orchestrator_results"] == [review_results[0]]                               # 情資報告只放該事件的
    assert all(r["target_id"] != KEYROT for p_ in (ctx.data_dir / ctx.output_dir / "intel").glob("*.json")
               if p_.name != "index.json" for r in json.loads(p_.read_text(encoding="utf-8"))["orchestrator_results"])
    md = markdown(ctx, "demo-cache-plaintext")
    assert "## Orchestrator 追加結果" in md and "- 驗收・需確認事件的摘要（AI 撰寫（重播））：AI 說明：intel-extra:demo-cache-plaintext" in md
    assert rep["agent_plan"]["review"]["summary"] == REVIEW["summary"] and rep["agent_plan"]["dispatch"] is None
    for r in rep["risks"]:                                                                 # 分數、等級、狀態不變
        b = next(x for x in before["risks"] if x["id"] == r["id"])
        assert (r["score"], r["level"], r["status"]) == (b["score"], b["level"], b["status"])


@pytest.mark.parametrize("ai", [True, False])
def test_a5_notice_extra_goes_to_draft_extra_and_needed_is_unchanged(ctx, writer, ai):
    adv = replace(ctx, scenario="advisory", scope="advisory", advisory_id="adv-opsbuilder-2026-001", assets=["internal-tool"],
                  output_dir="advisories/adv-opsbuilder-2026-001/down-run")
    upstream(adv)
    for m in (a2_scan, a3_signals, a4_risk):
        m.run(adv)
    a5_report.run(adv)
    before = intel(adv, "adv-opsbuilder-2026-001")
    assert before["notice"] == {"needed": False, "draft": None}
    plan = write_review(adv, {"extra_tasks": [{"agent": "a5", "subagent": "brand-notice-writer", "event_id": "adv-opsbuilder-2026-001",
                                               "reason": "建議先備妥通知草稿"}]})
    assert len(plan["approved"]) == 1
    writer.agents = {"a5"} if ai else set()
    a5_report.run(replace(adv, llm_plan=[]))
    rep = intel(adv, "adv-opsbuilder-2026-001")
    IntelMatchReport.model_validate(rep)
    text = "AI 說明：notice-extra:adv-opsbuilder-2026-001" if ai else notice_draft(rep["event"]["title"])
    assert rep["notice"] == {"needed": False, "draft": None, "draft_extra": text, "draft_extra_source": "replay" if ai else "template"}
    assert rep["blocks"]["6_notice"] == rep["notice"]
    assert (rep["status"], rep["conclusion"], rep["complete"]) == (before["status"], before["conclusion"], before["complete"])
    entry = {"stage": "review", "agent": "a5", "subagent": "brand-notice-writer", "target_type": "event",
             "target_id": "adv-opsbuilder-2026-001", "text": text, "source": "replay" if ai else "template"}
    assert rep["orchestrator_results"] == [entry] and entry in report(adv)["orchestrator_results"]
    md = markdown(adv, "adv-opsbuilder-2026-001")
    assert "## AI 建議的通知草稿（程式未要求）" in md and text in md and "## 建議通知" not in md
    assert "## Orchestrator 追加結果" not in md                                           # 通知草稿只在自己的段落


def test_disabled_review_runs_only_baseline_tasks(ctx, writer):
    upstream(ctx)
    a5_report.run(ctx)
    base = {t.id: t.payload for t in tasks_of(writer, "a5")}
    rplan = write_review(ctx)
    o.write_plan(o.plan_path(ctx.out, "review"), {**rplan, "summary": "被改過的摘要"})     # 竄改：驗收單停用
    writer.calls.clear()
    a5_report.run(replace(ctx, llm_plan=[]))
    assert {t.id: t.payload for t in tasks_of(writer, "a5")} == base                       # 沒有追加任務、也沒有重排
    rep = report(ctx)
    assert rep["agent_plan"] is None and rep["orchestrator_results"] == []
    assert any("驗收單停用（plan_approved_invalid" in e["detail"] or "驗收單停用（plan_invalid" in e["detail"]
               for e in read_trace(ctx.out / "a5" / "trace.jsonl"))


def test_result_entry_is_sanitized_and_capped():
    e = o.result_entry("review", "a5", "key-rotation-advisor", "risk", "r1", "x" * 700, "live")
    assert len(e["text"]) == o.MAX_RESULT_TEXT and set(e) == set(o.RESULT_FIELDS)
    masked = o.result_entry("dispatch", "a3", "retro-hunter", "event", "e1", "聯絡 a.b@example.com 確認", "template")
    assert "a.b@example.com" not in masked["text"]
    assert o.result_entry("dispatch", "a3", "retro-hunter", "event", "e1", "   ", "template") is None
    with pytest.raises(ValueError):
        o.result_entry("other", "a5", "x", "event", "e1", "x", "live")


def test_public_plan_compat_and_dual_format():
    single = {"source": "replay", "note": None, "events": ["e"], "suggested": 1, "rejected": [],
              "approved": [{"type": "control", "event_id": "e", "control_id": "C-NET-SEGMENT", "reason": "r"}]}
    out = o.public_plan(single)                                                           # 舊的單一計畫：視為派工單
    assert out["review"] is None and out["dispatch"]["approved_count"] == 1 and "C-NET-SEGMENT" in out["dispatch"]["control_titles"]
    assert o.public_plan(None) is None and o.public_plan({"dispatch": None, "review": None}) is None
    review = {"source": "subscription", "note": None, "events": [], "suggested": 1, "rejected": [], "summary": "摘要",
              "approved": [{"type": "summary", "text": "摘要"}], "run_id": "x", "verified_sha256": "0" * 64,
              "dispatch_plan_sha256": None}
    out = o.public_plan({"dispatch": None, "review": review})
    assert out["dispatch"] is None and out["review"]["summary"] == "摘要" and out["review"]["mode"] == "review"
    assert "run_id" not in out["review"] and "verified_sha256" not in out["review"] and "dispatch_plan_sha256" not in out["review"]


# ---------------------------------------------------------------- 驗收輸入讀到 A2～A4 的執行結果；失敗只停用計畫
def test_review_input_reads_downstream_outcomes(ctx):
    from agents import orchestrator_agent as oa
    upstream(ctx)
    write_dispatch(ctx)
    for m in (a2_scan, a3_signals, a4_risk):
        m.run(ctx)
    oa.build_input(ctx, "review")
    data = json.loads(oa.input_path(ctx, "review").read_text(encoding="utf-8"))
    got = [(r["item"]["type"], r["item"].get("agent"), r["item"].get("event_id") or r["item"].get("risk_id") or r["item"].get("control_id"),
            r["status"], r["reason"]) for r in data["dispatch_outcomes"]]
    assert got == [("control", None, "demo-erp-rce", "completed", "check_fail"),
                   ("task", "a4", "demo-erp-rce", "template", "llm_template"),
                   ("task", "a2", "demo-push-sdk-rce", "template", "llm_template"),
                   ("task", "a3", "demo-cache-plaintext", "template", "llm_template"),
                   ("task", "a3", "demo-push-sdk-rce", "skipped", "no_records"),
                   ("priority", "a4", "saas-quicksite-builder:shadow_it", "completed", "reordered"),
                   ("priority", "a4", "storefront:next:vuln", "completed", "reordered")]


def test_resolve_failure_only_disables_plans(ctx, monkeypatch):
    upstream(ctx)
    write_dispatch(ctx)

    def boom(*a, **k):
        raise RuntimeError("核對失敗")
    monkeypatch.setattr(o, "resolve_plans", boom)
    a4_risk.run(ctx)                                                                      # 必要任務的評估照常
    assert read(ctx, "a4", "summary.json")["dispatch_extra"] == 0 and read(ctx, "a4", o.OUTCOME_FILE)["items"] == []
    assert any("計畫核對失敗" in e["detail"] for e in read_trace(ctx.out / "a4" / "trace.jsonl"))
    monkeypatch.undo()


def test_extra_task_failure_keeps_baseline_results(ctx, monkeypatch):
    upstream(ctx)
    write_dispatch(ctx)

    def boom(*a, **k):
        raise RuntimeError("追加任務失敗")
    monkeypatch.setattr(a2_scan, "run_event_tasks", boom)
    monkeypatch.setattr(a3_signals, "run_retro_tasks", boom)
    assert a2_scan.run(ctx)["event_tasks"] == 0 and a3_signals.run(ctx)["retro_tasks"] == 0
    assert (ctx.out / "a2" / "explanations.json").is_file() and (ctx.out / "a3" / "signals.json").is_file()
    assert (ctx.out / "a2" / "llm-tasks.json").is_file()                                  # 必要任務仍交給 claude-analysis
