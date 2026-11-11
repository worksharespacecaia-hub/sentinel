"""動態派工（specs/dynamic-planner）的端到端流程：replay、隔離快取與錄製，不呼叫 LLM、不連網路。"""
import json
import re
from dataclasses import replace

import pytest

from agents import a0_assets, a1_intel, a2_scan, a3_signals, a4_risk, a5_report, orchestrator
from llm import Task
from tests.test_agents_flow import ctx, run_all  # noqa: F401 - 共用 fixture
from tools import agent_plan as ap
from tools.cache import LLMCache, ReplayStore
from tools.controls import load_controls
from tools.trace import read_trace

SHA64 = re.compile(r"^[0-9a-f]{64}$")
LIVE_EVENT = {"id": "shop-x-2026-11", "title": "某電商會員資料外洩", "date": "2026-11-09", "confidence": "provisional",
              "sources": [{"url": "https://www.ithome.com.tw/news/2", "title": "iThome", "quote": "引用"}]}


@pytest.fixture()
def iso_ctx(ctx, tmp_path):  # noqa: F811
    """隔離 LLM 快取與錄製：不讀寫 agents/cache 與 fixtures/replay。"""
    return replace(ctx, cache=LLMCache(tmp_path / "cache" / "llm.json"), replay=ReplayStore(tmp_path / "replay"))


def _plan(c):
    return json.loads((c.out / "a1" / "agent-plan.json").read_text(encoding="utf-8"))


def _peer(c):
    return replace(c, scenario="peer-incident", scope="scenario", output_dir="scenarios/peer-incident")


def _trace(c, agent):
    return read_trace(c.out / agent / "trace.jsonl")


def _report(c, path):
    return json.loads((c.data_dir / path / "report.json").read_text(encoding="utf-8"))


def _planner_tasks(c):
    return [t for t in c.llm_plan if t["subagent"] == "planner"]


# ---------------------------------------------------------------- 情境（A1 planner）
def test_peer_incident_replay_without_recording_uses_empty_template(iso_ctx):
    c = _peer(iso_ctx)
    run_all(c)
    plan = _plan(c)
    assert plan["status"] == "complete" and plan["source"] == "template" and plan["approved"] == [] and plan["suggested"] == 0
    assert plan["events"] == ["demo-peer-mail-key"] and SHA64.match(plan["verified_sha256"])
    assert plan["run_id"] == c.run_id and plan["scenario"] == "peer-incident" and plan["run_attempt"] == 1
    last = [e for e in _trace(c, "a1") if e["kind"] == "result"][-1]
    assert "AI 建議 0 項、程式核准 0 項、拒絕 0 項（來源：程式範本）" in last["detail"]
    rep = _report(c, "scenarios/peer-incident")
    assert rep["agent_plan"]["source"] == "template" and rep["agent_plan"]["approved_count"] == 0
    assert len(_planner_tasks(c)) == 1                                       # replay 未錄製：記下任務，不呼叫 LLM


def _inject_planner(c, output):
    """把 planner 的建議放進隔離快取（模擬錄製／快取命中）。"""
    verified = json.loads((c.out / "a1" / "verified.json").read_text(encoding="utf-8"))
    selected, _ = ap.new_peer_events(ap.effective_events(verified), set())
    payload = ap.build_payload(selected, [{"id": x["id"], "title": x["title"]} for x in load_controls()])
    key = c.runner("a1").key(Task(id="plan", subagent="planner", payload=payload))
    c.cache.data[key] = {"output": output, "meta": {}}


def test_peer_incident_cached_suggestion_is_approved_without_changing_scores(iso_ctx):
    c = _peer(iso_ctx)
    run_all(c)
    base = _report(c, "scenarios/peer-incident")
    _inject_planner(c, {"extra_controls": [{"event_id": "demo-peer-mail-key", "control_id": "C-SECRET-IN-GIT", "reason": "金鑰外洩手法相近"},
                                           {"event_id": "demo-peer-mail-key", "control_id": "C-NOPE", "reason": "未知"}],
                        "extra_tasks": [{"agent": "a4", "subagent": "impact-analyst", "event_id": "demo-peer-mail-key",
                                         "reason": "補充相關風險"}]})
    for m in (a1_intel, a4_risk, a5_report):
        m.run(c)
    plan = _plan(c)
    assert plan["source"] == "replay" and len(plan["approved"]) == 2 and len(plan["rejected"]) == 1 and plan["suggested"] == 3
    rep = _report(c, "scenarios/peer-incident")
    assert rep["agent_plan"]["approved_count"] == 2 and rep["agent_plan"]["rejected_count"] == 1
    key = lambda r: (r["id"], r["score"], r["level"], tuple(r["matched_events"]), r["status"])   # noqa: E731
    assert sorted(map(key, rep["risks"])) == sorted(map(key, base["risks"])) and rep["light"] == base["light"]
    assert [(e["id"], e["status"], e["affected_count"]) for e in rep["events"]] == \
        [(e["id"], e["status"], e["affected_count"]) for e in base["events"]]
    intel = json.loads((c.data_dir / "scenarios" / "peer-incident" / "intel" / "demo-peer-mail-key.json").read_text(encoding="utf-8"))
    extra = intel["blocks"]["8_extra_checks"]
    assert [x["control_id"] for x in extra] == ["C-SECRET-IN-GIT"] and extra[0]["status_label"] in ("符合", "不符合", "資料不足")
    assert any("動態派工" in e["detail"] for e in _trace(c, "a4"))
    summary = json.loads((c.out / "a4" / "summary.json").read_text(encoding="utf-8"))
    assert summary["planner_extra"] == 1                                     # 命中此事件、且不在原本前 10 個的風險


# ---------------------------------------------------------------- daily（訂閱方案建議）
def _daily_with(c, monkeypatch, intel_daily):
    from tools import intel_verify
    from tools.safe_fetch import FetchResult
    monkeypatch.setattr(intel_verify, "fetch", lambda url, allowlist, **kw: FetchResult(url=url, status=200, text="<p>引用</p>",
                                                                                         content_type="text/html"))
    c.out.mkdir(parents=True, exist_ok=True)
    (c.out / "intel-daily.json").write_text(json.dumps(intel_daily, ensure_ascii=False), encoding="utf-8")


def _upto_a1(c):
    for m in (orchestrator, a0_assets, a1_intel):
        m.run(c)


def test_daily_subscription_suggestion_is_used_without_planner_task(iso_ctx, monkeypatch):
    _daily_with(iso_ctx, monkeypatch, {"events": [LIVE_EVENT], "impacts": [], "agent_plan": {
        "extra_controls": [{"event_id": "shop-x-2026-11", "control_id": "C-CLOUD-STORAGE-PUBLIC", "reason": "確認雲端儲存未公開"}],
        "extra_tasks": [{"agent": "a4", "subagent": "impact-analyst", "event_id": "live-shop-x-2026-11", "reason": "補充說明"}],
        "skip_agents": ["a2"]}})
    _upto_a1(iso_ctx)
    plan = _plan(iso_ctx)
    assert plan["source"] == "subscription" and plan["events"] == ["live-shop-x-2026-11"]
    assert [a["type"] for a in plan["approved"]] == ["control", "task"] and len(plan["rejected"]) == 1
    assert plan["note"] == ap.NOTE_NO_PREV                                   # 本機 data 目錄沒有上次的 daily 狀態（Q6）
    assert _planner_tasks(iso_ctx) == []                                     # 沒有建立 planner 任務
    a1 = _trace(iso_ctx, "a1")
    assert any(e["detail"] == "採用每日情資（訂閱方案）的 AI 建議" and e["source"] is None for e in a1)
    assert "（來源：訂閱方案）" in [e for e in a1 if e["kind"] == "result"][-1]["detail"]
    for m in (a2_scan, a3_signals, a4_risk, a5_report):
        m.run(iso_ctx)
    rep = _report(iso_ctx, "daily")
    assert rep["agent_plan"]["source"] == "subscription" and rep["agent_plan"]["approved_count"] == 2


@pytest.mark.parametrize("agent_plan,suggested", [({}, 0), ({"extra_controls": [{"event_id": "nope", "control_id": "C-A", "reason": "r"}]}, 1)])
def test_daily_valid_subscription_never_falls_back(iso_ctx, monkeypatch, agent_plan, suggested):
    _daily_with(iso_ctx, monkeypatch, {"events": [LIVE_EVENT], "impacts": [], "agent_plan": agent_plan})
    _upto_a1(iso_ctx)
    plan = _plan(iso_ctx)
    assert plan["source"] == "subscription" and plan["approved"] == [] and plan["suggested"] == suggested
    assert _planner_tasks(iso_ctx) == []


@pytest.mark.parametrize("agent_plan", ["missing", None, {"extra_tasks": "x"}])
def test_daily_unusable_subscription_falls_back_to_planner(iso_ctx, monkeypatch, agent_plan):
    data = {"events": [LIVE_EVENT], "impacts": []}
    if agent_plan != "missing":
        data["agent_plan"] = agent_plan
    _daily_with(iso_ctx, monkeypatch, data)
    _upto_a1(iso_ctx)
    plan = _plan(iso_ctx)
    assert plan["source"] == "template" and "改用 A1 planner" in plan["note"]
    assert len(_planner_tasks(iso_ctx)) == 1


def test_daily_without_new_peer_events_is_skipped(iso_ctx):
    iso_ctx.out.mkdir(parents=True, exist_ok=True)
    (iso_ctx.out / "intel-daily.json").write_text(json.dumps({"events": [], "impacts": [], "agent_plan": {"extra_tasks": "x"}}),
                                                  encoding="utf-8")
    _upto_a1(iso_ctx)
    plan = _plan(iso_ctx)
    assert plan["source"] == "skipped" and plan["suggested"] == 0 and plan["events"] == []
    assert any(e["detail"] == "沒有新同業事件，不需要 AI 建議" for e in _trace(iso_ctx, "a1"))
    assert _planner_tasks(iso_ctx) == []


def test_previous_daily_state_excludes_known_events(iso_ctx, monkeypatch):
    _daily_with(iso_ctx, monkeypatch, {"events": [LIVE_EVENT], "impacts": [], "agent_plan": {}})
    state = iso_ctx.data_dir / "daily" / "state" / "intel.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"events": [{"id": "live-shop-x-2026-11"}]}), encoding="utf-8")
    _upto_a1(iso_ctx)
    assert _plan(iso_ctx)["source"] == "skipped" and _plan(iso_ctx)["note"] is None


# ---------------------------------------------------------------- 計畫檔的保護
def test_a1_overwrites_stale_plan_with_pending_first(iso_ctx, monkeypatch):
    c = _peer(iso_ctx)
    (c.out / "a1").mkdir(parents=True, exist_ok=True)
    (c.out / "a1" / "agent-plan.json").write_text(json.dumps({"status": "complete", "source": "live"}), encoding="utf-8")
    monkeypatch.setattr(a1_intel, "verify_event", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        a1_intel.run(c)
    assert _plan(c)["status"] == "pending" and _plan(c)["note"] == ap.NOTE_PENDING


@pytest.mark.parametrize("tamper", ["garbage", "pending", "other_run", "sha", "bad_approved", "bad_counts", "verified_broken"])
def test_downstream_disables_untrusted_plan(iso_ctx, tamper):
    c = _peer(iso_ctx)
    _upto_a1(c)
    p = c.out / "a1" / "agent-plan.json"
    plan = _plan(c)
    if tamper == "garbage":
        p.write_text("{not json", encoding="utf-8")
    else:
        if tamper == "pending":
            plan["status"] = "pending"
        elif tamper == "other_run":
            plan["run_id"] = "other"
        elif tamper == "sha":
            plan["verified_sha256"] = "0" * 64
        elif tamper == "bad_approved":
            plan.update(source="replay", suggested=1, approved=[{"type": "control", "event_id": "demo-peer-mail-key",
                                                                   "control_id": "C-NOPE", "reason": "r"}])
        elif tamper == "bad_counts":
            plan.update(suggested=True)
        elif tamper == "verified_broken":
            (c.out / "a1" / "verified.json").write_text("[{", encoding="utf-8")
        p.write_text(json.dumps(plan), encoding="utf-8")
    for m in (a2_scan, a3_signals, a4_risk, a5_report):
        m.run(c)
    rep = _report(c, "scenarios/peer-incident")
    assert rep["agent_plan"] is None
    details = " ".join(e["detail"] for e in _trace(c, "a4"))
    assert "不採用動態派工計畫" in details or "A1 結果缺失或無法讀取" in details
