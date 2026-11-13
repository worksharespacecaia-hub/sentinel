"""Orchestrator 的提案來源與計畫檔（specs/orchestrator R1.5、R4.4、R6.2；design §3.3、§8 的 test_orchestrator_flow）。

取代 v0.11.0 的 test_dynamic_planner_flow.py。提案來源的優先順序：accepted 標記相符才採用訂閱方案的提案、標記不符就退回
Agent SDK、replay 不呼叫 API；pending 先寫；提案格式錯誤、verified 缺失時降級。用 intel-demo 凍結資料，不呼叫 LLM、不連網路。
"""
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from agents import a0_assets, a1_intel, a2_scan, a3_signals, a4_risk, a5_report, router
from agents import orchestrator_agent as oa
from context import build_ctx
from llm import LLMRunner, Task
from tools import orchestration as o
from tools.cache import LLMCache, ReplayStore
from tools.common import sha256_json, write_json
from tools.intel_verify import verify_event
from tools.pipeline import event_sources
from tools.trace import read_trace

ENV = {"TRIGGER_SOURCE": "manual", "EVENT_NAME": "workflow_dispatch", "AS_OF": "2026-11-09T01:00:00Z", "RUN_ID": "orch-flow-run"}
# 部分核准、部分拒絕
DISPATCH = {
    "extra_controls": [{"event_id": "demo-erp-rce", "control_id": "C-NET-SEGMENT", "reason": "確認資料庫網段隔離"},
                       {"event_id": "demo-erp-rce", "control_id": "C-NOPE", "reason": "x"}],
    "extra_tasks": [{"agent": "a4", "subagent": "impact-analyst", "event_id": "demo-erp-rce", "reason": "補充相關風險"},
                    {"agent": "a2", "subagent": "secret-analyst", "event_id": "demo-push-sdk-rce", "reason": "x"}],
    "priorities": [{"agent": "a4", "risk_id": "storefront:next:vuln", "reason": "先說明對外系統"}],
}
REVIEW = {"extra_tasks": [{"agent": "a5", "subagent": "intel-report-writer", "event_id": "demo-cache-plaintext",
                           "reason": "補寫需確認事件摘要"}],
          "summary": "派工的追加任務已核准，需確認事件補寫摘要。"}


@pytest.fixture()
def ctx(monkeypatch, tmp_path):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    for k in ("EXECUTION_MODE", "GITHUB_OUTPUT", "TARGET_DIR", "ADVISORY_ID", "ASSETS", "TARGET_SHA", "SCANNERS_DIR",
              "DEPLOYMENTS_FILE", "GITHUB_RUN_ATTEMPT", "JOB_RESULTS", "SENTINEL_BASE_URL", "NOTIFY_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    import claude_agent_sdk
    monkeypatch.setattr(claude_agent_sdk, "query", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM")))

    async def no_query(self, pending, graph_query):
        raise AssertionError("不得呼叫 API")
    monkeypatch.setattr(LLMRunner, "_query", no_query)
    return replace(build_ctx(scenario="intel-demo"), out=tmp_path / "out", data_dir=tmp_path / "data",
                   reports_dir=tmp_path / "reports", cache=LLMCache(tmp_path / "cache.json"), replay=ReplayStore(tmp_path / "replay"))


@pytest.fixture()
def no_sdk(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("不應走 Agent SDK")
    monkeypatch.setattr(oa, "call_subagent", boom)


def a1_verified(c):
    verified = [verify_event(raw, as_of=c.as_of, online=False) for raw in event_sources(c.eval_input())]
    write_json(c.out / "a1" / "verified.json", verified)
    loaded, why = o.load_verified(c)
    assert why is None
    return loaded


def subscription(c, mode, proposal, *, mark=None, raw: bytes | None = None):
    """模擬訂閱步驟：寫提案檔；mark=None 時寫入正確的採用標記（提案檔的 sha256），mark="" 時不寫標記。"""
    data = raw if raw is not None else json.dumps(proposal, ensure_ascii=False).encode("utf-8")
    p = oa.proposal_path(c, mode)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    if mark != "":
        oa.accepted_path(c, mode).write_text(hashlib.sha256(data).hexdigest() if mark is None else mark, encoding="utf-8")


def plan_of(c, mode):
    return json.loads(o.plan_path(c.out, mode).read_text(encoding="utf-8"))


def details(c, mode):
    return [e["detail"] for e in read_trace(c.out / oa.AGENT[mode] / "trace.jsonl")]


# ---------------------------------------------------------------- 提案來源的優先順序
def test_accepted_subscription_proposal_is_used(ctx, no_sdk):
    verified = a1_verified(ctx)
    subscription(ctx, "dispatch", DISPATCH)
    got = oa.run(ctx, "dispatch")
    assert got == {"mode": "dispatch", "source": "subscription", "suggested": 5, "approved": 3, "rejected": 2}
    plan = plan_of(ctx, "dispatch")
    assert plan["status"] == "complete" and plan["source"] == "subscription" and plan["verified_sha256"] == sha256_json(verified)
    assert [a["type"] for a in plan["approved"]] == ["control", "task", "priority"]
    assert [r["reason"] for r in plan["rejected"]] == [o.R_CONTROL, o.R_TASK]
    r = o.resolve_plans(ctx, verified=verified)
    assert r.dispatch == plan and r.reasons == {"dispatch": None}                       # 建立後載入核對一致
    text = details(ctx, "dispatch")
    assert any("提案來源：訂閱方案" in d for d in text)
    assert any(d.startswith("派工：AI 建議 5 項、程式核准 3 項、拒絕 2 項") and "subscription" in d for d in text)
    assert sum(d.startswith("拒絕：") for d in text) == 2
    assert json.loads((ctx.out / "orchestrator-dispatch" / "cost.json").read_text(encoding="utf-8"))["agent"] == "orchestrator-dispatch"


@pytest.mark.parametrize("mark,why", [("", "沒有採用標記"), ("0" * 64, "採用標記與提案內容不符"), ("not-a-sha", "採用標記與提案內容不符")])
def test_marker_mismatch_falls_back_to_sdk(ctx, monkeypatch, mark, why):
    verified = a1_verified(ctx)
    oa.build_input(ctx, "dispatch")
    subscription(ctx, "dispatch", DISPATCH, mark=mark)
    calls = []

    def stub(c, mode, payload):
        calls.append((mode, payload))
        return {"output": {"priorities": DISPATCH["priorities"]}, "source": "live", "subagent": "planner"}
    monkeypatch.setattr(oa, "call_subagent", stub)
    got = oa.run(ctx, "dispatch")
    assert got["source"] == "live" and got["approved"] == 1 and len(calls) == 1
    mode, payload = calls[0]
    assert mode == "dispatch" and payload["available"] is True
    assert payload == json.loads(oa.input_path(ctx, "dispatch").read_text(encoding="utf-8"))   # 與公開輸入同一個投影
    assert why in plan_of(ctx, "dispatch")["note"]
    assert o.resolve_plans(ctx, verified=verified).dispatch is not None


def test_edited_proposal_after_marker_is_not_adopted(ctx, monkeypatch):
    a1_verified(ctx)
    subscription(ctx, "dispatch", {"priorities": DISPATCH["priorities"]})
    oa.proposal_path(ctx, "dispatch").write_text(json.dumps(DISPATCH, ensure_ascii=False), encoding="utf-8")   # 標記之後被改
    monkeypatch.setattr(oa, "call_subagent", lambda c, mode, payload: {"output": None, "source": "template"})
    got = oa.run(ctx, "dispatch")
    assert got["source"] == "template" and got["suggested"] == 0


def test_replay_uses_recording_and_never_calls_api(ctx):
    verified = a1_verified(ctx)
    base = o.base_inputs(ctx)
    payload = oa.snapshot(ctx, "dispatch", verified, base).payload
    runner = ctx.runner("orchestrator-dispatch")
    key = runner.key(Task(id="dispatch", subagent="planner", payload=payload))
    ctx.replay.put("orchestrator-dispatch", "planner", key, {"priorities": DISPATCH["priorities"]}, {"note": "test"})
    got = oa.run(ctx, "dispatch")                                                         # LLMRunner._query 會丟錯：不得呼叫
    assert got == {"mode": "dispatch", "source": "replay", "suggested": 1, "approved": 1, "rejected": 0}
    assert any("提案來源：重播錄製（planner）" in d for d in details(ctx, "dispatch"))


def test_replay_without_recording_is_template_and_never_calls_api(ctx):
    verified = a1_verified(ctx)
    got = oa.run(ctx, "dispatch")
    assert got == {"mode": "dispatch", "source": "template", "suggested": 0, "approved": 0, "rejected": 0}
    assert o.resolve_plans(ctx, verified=verified).dispatch == plan_of(ctx, "dispatch")    # 空計畫也是有效計畫（只跑必要任務）
    assert [t["subagent"] for t in ctx.llm_plan] == ["planner"]                         # 記下未錄製的任務（不交給 claude-analysis）
    tasks = json.loads((ctx.out / "orchestrator-dispatch" / "llm-tasks.json").read_text(encoding="utf-8"))
    assert [t["agent"] for t in tasks] == ["orchestrator-dispatch"]


@pytest.mark.parametrize("mode", ["dispatch", "review"])
def test_sdk_runner_dispatches_named_subagent_with_60s_timeout(ctx, monkeypatch, mode):
    a1_verified(ctx)
    seen = []

    def fake_run(self, tasks, **kw):
        seen.append((self.agent, self.timeout_s, [(t.id, t.subagent) for t in tasks]))
        return {mode: {"output": {}, "source": "live", "subagent": tasks[0].subagent}}
    monkeypatch.setattr(LLMRunner, "run", fake_run)
    got = oa.run(replace(ctx, mode="live"), mode)
    assert got["source"] == "live" and got["suggested"] == 0
    assert seen == [(oa.AGENT[mode], 60, [(mode, {"dispatch": "planner", "review": "reviewer"}[mode])])]


def test_subagent_names_are_written_in_the_dispatching_code():
    """網站測試（subagents.test.ts）以字串判斷 Subagent 有沒有被程式派發：planner、reviewer 要直接寫在派發它們的程式裡。"""
    src = Path(oa.__file__).read_text(encoding="utf-8")
    assert 'subagent="planner"' in src and 'subagent="reviewer"' in src


def test_dispatch_without_new_events_is_skipped_without_ai(ctx, no_sdk):
    daily = replace(ctx, scenario="daily", scope="daily", output_dir="daily")
    verified = a1_verified(daily)
    got = oa.run(daily, "dispatch")
    assert got["source"] == "skipped" and got["suggested"] == 0
    plan = plan_of(daily, "dispatch")
    assert plan["events"] == [] and "沒有新同業事件" in plan["note"] and o.NOTE_NO_PREV in plan["note"]
    assert o.resolve_plans(daily, verified=verified).dispatch == plan


# ---------------------------------------------------------------- pending 先寫、失敗降級
def test_pending_is_written_before_the_proposal(ctx, monkeypatch):
    verified = a1_verified(ctx)
    o.write_plan(o.plan_path(ctx.out, "dispatch"), o.build_plan("dispatch", DISPATCH, ctx=ctx, verified=verified, source="replay"))
    seen = {}
    real = oa.get_proposal

    def spy(c, mode, tr, **kw):
        seen["plan"] = plan_of(c, mode)
        return real(c, mode, tr, **kw)
    monkeypatch.setattr(oa, "get_proposal", spy)
    oa.run(ctx, "dispatch")
    assert seen["plan"]["status"] == "pending" and seen["plan"]["note"] == o.NOTE_PENDING   # 上一次的計畫已被覆寫
    assert plan_of(ctx, "dispatch")["status"] == "complete"


def test_failure_leaves_pending_and_downstream_disables_only_that_plan(ctx, monkeypatch):
    verified = a1_verified(ctx)

    def boom(*a, **k):
        raise RuntimeError("核准失敗")
    monkeypatch.setattr(o, "build_plan", boom)
    with pytest.raises(RuntimeError):
        oa.run(ctx, "dispatch")
    assert plan_of(ctx, "dispatch")["status"] == "pending"
    monkeypatch.undo()
    r = o.resolve_plans(ctx, verified=verified, want=("dispatch", "review"))
    assert r.dispatch is None and r.reasons["dispatch"] == "plan_pending" and r.res["risks"]   # 必要任務的評估照常


@pytest.mark.parametrize("raw", [json.dumps({"extra_tasks": "x"}).encode(), b"{not json", json.dumps([1, 2]).encode(),
                                 json.dumps({"priorities": [{"agent": "a4", "risk_id": "x", "reason": "DEMO-FAKE-ABCD-1234"}]}).encode()])
def test_bad_subscription_shape_becomes_empty_proposal(ctx, no_sdk, raw):
    verified = a1_verified(ctx)
    subscription(ctx, "dispatch", None, raw=raw)
    got = oa.run(ctx, "dispatch")
    assert got == {"mode": "dispatch", "source": "template", "suggested": 0, "approved": 0, "rejected": 0}
    plan = plan_of(ctx, "dispatch")
    assert "訂閱方案的提案格式無效" in plan["note"] and "DEMO-FAKE" not in json.dumps(plan, ensure_ascii=False)
    assert o.resolve_plans(ctx, verified=verified).dispatch == plan


def test_bad_sdk_shape_becomes_empty_proposal(ctx, monkeypatch):
    a1_verified(ctx)
    monkeypatch.setattr(oa, "call_subagent", lambda c, mode, payload: {"output": {"summary": 3}, "source": "live"})
    got = oa.run(ctx, "review")
    assert got["source"] == "template" and got["suggested"] == 0
    assert "即時呼叫的提案格式無效" in plan_of(ctx, "review")["note"]


@pytest.mark.parametrize("mode", ["dispatch", "review"])
def test_missing_verified_writes_template_plan(ctx, no_sdk, mode):
    got = oa.run(ctx, mode)                                                               # 沒有 A1 verified
    assert got == {"mode": mode, "source": "template", "suggested": 0, "approved": 0, "rejected": 0}
    plan = plan_of(ctx, mode)
    assert plan["status"] == "complete" and plan["verified_sha256"] is None and "verified_missing" in plan["note"]
    if mode == "review":
        assert plan["dispatch_plan_sha256"] is None and plan["summary"] is None
    assert any(e["kind"] == "result" for e in read_trace(ctx.out / oa.AGENT[mode] / "trace.jsonl"))
    a1_verified(ctx)                                                                      # 之後才出現的 verified：雜湊對不上，停用
    verified, _ = o.load_verified(ctx)
    r = o.resolve_plans(ctx, verified=verified, want=("dispatch", "review"))
    assert r.reasons[mode] == "plan_verified_mismatch"


# ---------------------------------------------------------------- 驗收綁定派工單（R4.4）
def test_review_binds_dispatch_sha_or_null(ctx, no_sdk):
    verified = a1_verified(ctx)
    subscription(ctx, "dispatch", DISPATCH)
    oa.run(ctx, "dispatch")
    dplan = plan_of(ctx, "dispatch")
    subscription(ctx, "review", REVIEW)
    got = oa.run(ctx, "review")
    assert got == {"mode": "review", "source": "subscription", "suggested": 2, "approved": 2, "rejected": 0}
    rplan = plan_of(ctx, "review")
    assert rplan["dispatch_plan_sha256"] == sha256_json(dplan) and rplan["summary"] == REVIEW["summary"]
    r = o.resolve_plans(ctx, verified=verified, want=("dispatch", "review"))
    assert r.reasons == {"dispatch": None, "review": None} and r.review == rplan
    # 派工單不可用：驗收照常執行，綁定 null
    o.plan_path(ctx.out, "dispatch").unlink()
    oa.run(ctx, "review")
    rplan = plan_of(ctx, "review")
    assert rplan["dispatch_plan_sha256"] is None and "派工單不可用（plan_missing）" in rplan["note"]
    r = o.resolve_plans(ctx, verified=verified, want=("dispatch", "review"))
    assert r.dispatch is None and r.review == rplan and r.reasons["review"] is None
    assert any("派工單不可用" in d for d in details(ctx, "review"))


# ---------------------------------------------------------------- 本機流程（run_agent all 的順序）
def test_local_flow_runs_orchestrator_between_agents(ctx):
    for step in (router, a0_assets, a1_intel):
        step.run(ctx)
    assert oa.build_input(ctx, "dispatch")["available"] is True
    assert oa.run(ctx, "dispatch")["source"] == "template"                                # replay 沒有錄製：空提案
    for step in (a2_scan, a3_signals, a4_risk):
        step.run(ctx)
    oa.build_input(ctx, "review")
    assert oa.run(ctx, "review")["source"] == "template"
    a5_report.run(ctx)
    rep = json.loads((ctx.data_dir / "scenarios" / "intel-demo" / "report.json").read_text(encoding="utf-8"))
    assert rep["completeness"] == "complete" and rep["cost"]["total_usd"] == 0
    assert not [i for i in rep["data_issues"] if i["source"].startswith("job/orchestrator")]   # 兩個 Job 都有產物
    agents = {e["agent"] for e in read_trace(ctx.data_dir / "scenarios" / "intel-demo" / "trace.jsonl")}
    assert {"router", "orchestrator-dispatch", "orchestrator-review", "a5"} <= agents
