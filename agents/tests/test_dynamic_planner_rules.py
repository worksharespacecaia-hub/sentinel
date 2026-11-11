"""動態派工（specs/dynamic-planner）：不影響判定（R5）、快取與預算（R10）、Skill 與 reference 一致（R11.5）。"""
import json
import subprocess
import sys

import pytest

from llm import LLMRunner, Task
from tests.conftest import AS_OF
from tools.agent_plan import MAX_CTRL_PER_EVENT, MAX_CTRL_TOTAL, MAX_TASKS
from tools.cache import LLMCache, ReplayStore
from tools.common import SENTINEL_ROOT
from tools.pipeline import evaluate
from tools.report_builder import assemble
from tools.trace import Tracer


# ---------------------------------------------------------------- R5 不影響判定
def _peer(monkeypatch):
    from context import build_ctx
    for k in ("TARGET_DIR", "SCANNERS_DIR", "ADVISORY_ID", "ASSETS", "TARGET_SHA", "EXECUTION_MODE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AS_OF", AS_OF.isoformat())
    return build_ctx(scenario="peer-incident")


def _judgement(res, built):
    risks = sorted((r["id"], r["score"], r["level"], tuple(r["matched_events"]), r["status"]) for r in res["risks"])
    impacts = [(m["event"]["id"], json.dumps(m["impacts"], sort_keys=True, ensure_ascii=False, default=str)) for m in res["matches"]]
    reports = [(r["event"]["id"], r["status"], r["conclusion"], r["affected_count"], r["max_level"]) for r in built["intel_reports"]]
    return risks, impacts, reports, res["light"], res["complete"], sorted(f["id"] for f in res["findings"]), \
        [list(e.get("controls") or []) for e in res["events"]]


def test_approved_extra_checks_do_not_change_any_judgement(monkeypatch):
    ctx = _peer(monkeypatch)
    plan = {"source": "replay", "note": None, "events": ["demo-peer-mail-key"], "suggested": 2, "rejected": [],
            "approved": [{"type": "control", "event_id": "demo-peer-mail-key", "control_id": "C-SECRET-IN-GIT", "reason": "手法相近"},
                         {"type": "control", "event_id": "demo-peer-mail-key", "control_id": "C-BACKUP-ISOLATION", "reason": "一併確認"}]}
    kw = dict(run_id="t", scenario="peer-incident", trigger_source="manual", scope="scenario", generated_at=AS_OF)
    base = evaluate(ctx.eval_input())
    with_plan = evaluate(ctx.eval_input(agent_plan=plan))
    b0, b1 = assemble(base, **kw), assemble(with_plan, **kw)
    assert _judgement(base, b0) == _judgement(with_plan, b1)
    assert b0["report"]["light"] == b1["report"]["light"] and b0["report"]["counts"] == b1["report"]["counts"]
    rep = next(r for r in b1["intel_reports"] if r["event"]["id"] == "demo-peer-mail-key")
    checks = rep["blocks"]["8_extra_checks"]
    assert [c["control_id"] for c in checks] == ["C-SECRET-IN-GIT", "C-BACKUP-ISOLATION"]
    for c in checks:
        assert c["status_label"] == {"pass": "符合", "fail": "不符合", "unknown": "資料不足"}[c["status"]]
        assert c["status"] == with_plan["controls"][c["control_id"]]["status"]           # 直接取本次已算好的結果
    assert all("8_extra_checks" not in r["blocks"] for r in b1["intel_reports"] if r["event"]["id"] != "demo-peer-mail-key")
    assert "8_extra_checks" not in json.dumps([r["blocks"] for r in b0["intel_reports"]])
    assert b1["report"]["agent_plan"]["approved_count"] == 2 and b0["report"]["agent_plan"] is None


# ---------------------------------------------------------------- R10 快取與預算
def _runner(tmp_path, mode="replay", agent="a1", budget=None):
    return LLMRunner(agent=agent, mode=mode, scope="scenario", target_sha="a" * 40, advisory_revision=None,
                     tracer=Tracer(tmp_path / "trace.jsonl", agent), cache=LLMCache(tmp_path / "llm.json"),
                     replay=ReplayStore(tmp_path / "replay"), budget=budget)


PLAN_TASK = Task(id="plan", subagent="planner", payload={"ids": ["e"], "events": []})


@pytest.fixture()
def no_sdk(monkeypatch):
    import claude_agent_sdk
    monkeypatch.setattr(claude_agent_sdk, "query", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM")))


def test_invalid_recording_does_not_mask_valid_cache(tmp_path, no_sdk):
    r = _runner(tmp_path)
    k = r.key(PLAN_TASK)
    r.replay.put("a1", "planner", k, "not an object", {})
    assert r.run([PLAN_TASK])["plan"]["source"] == "template"                    # 兩者都無效 → 範本
    r.cache.data[k] = {"output": {"extra_controls": []}, "meta": {}}
    res = r.run([PLAN_TASK])["plan"]
    assert res["source"] == "replay" and res["output"] == {"extra_controls": []}


def test_payload_key_ignores_run_identity_but_not_scope(tmp_path):
    a, b = _runner(tmp_path), _runner(tmp_path)
    assert a.key(PLAN_TASK) == b.key(PLAN_TASK)
    b.scope = "daily"
    assert a.key(PLAN_TASK) != b.key(PLAN_TASK)


def test_calls_and_retries_only_use_remaining_budget(tmp_path, monkeypatch):
    r = _runner(tmp_path, mode="live")
    seen = []

    async def fake_query(self, pending, graph_query):
        seen.append(self._call_budget)
        return {"plan": "bad"}, 0.04                                              # 格式無效 → 重試一次
    monkeypatch.setattr(LLMRunner, "_query", fake_query)
    assert r.run([PLAN_TASK])["plan"]["source"] == "template"
    assert seen == [0.10, 0.06] and r.cost["per_agent"]["a1"] == 0.08
    seen.clear()
    r.cost["per_agent"]["a1"] = 0.10
    assert r.run([PLAN_TASK])["plan"]["source"] == "template" and seen == []      # 用完就不再呼叫


def test_options_receive_remaining_budget():
    from registry import options_for
    assert options_for("a1").max_budget_usd == 0.10
    assert options_for("a1", budget=0.03).max_budget_usd == 0.03
    assert options_for("a1", budget=5).max_budget_usd == 0.10                    # 不會超過上限


def test_a1_sets_planner_timeout(monkeypatch, tmp_path):
    from agents import a1_intel
    seen = []
    real_run = LLMRunner.run

    def spy(self, tasks, **kw):
        if any(t.subagent == "planner" for t in tasks):
            seen.append(self.timeout_s)
        return real_run(self, tasks, **kw)
    monkeypatch.setattr(LLMRunner, "run", spy)
    from dataclasses import replace
    ctx = replace(_peer(monkeypatch), out=tmp_path / "out", data_dir=tmp_path / "data", cache=LLMCache(tmp_path / "c.json"),
                  replay=ReplayStore(tmp_path / "r"))
    import claude_agent_sdk
    monkeypatch.setattr(claude_agent_sdk, "query", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM")))
    a1_intel.run(ctx)
    assert seen == [a1_intel.PLANNER_TIMEOUT_S] == [60]


# ---------------------------------------------------------------- R11.5 Skill 與 reference
def test_reference_matches_code():
    res = subprocess.run([sys.executable, str(SENTINEL_ROOT / "scripts" / "build-agent-plan-reference.py"), "--check"],
                         capture_output=True, text=True, encoding="utf-8")
    assert res.returncode == 0, res.stderr
    ref = (SENTINEL_ROOT / ".claude" / "skills" / "daily-intel" / "references" / "agent-plan.md").read_text(encoding="utf-8")
    assert f"最多 {MAX_CTRL_PER_EVENT} 個" in ref and f"總共最多 {MAX_CTRL_TOTAL} 個" in ref and f"總共最多 {MAX_TASKS} 項" in ref
    assert "| a4 | impact-analyst |" in ref


def test_reference_check_detects_stale_file(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_ref", SENTINEL_ROOT / "scripts" / "build-agent-plan-reference.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    stale = tmp_path / "agent-plan.md"
    stale.write_text("old", encoding="utf-8")
    monkeypatch.setattr(mod, "OUT_PATH", stale)
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    assert mod.main(["--check"]) == 1 and stale.read_text(encoding="utf-8") == "old"   # --check 不改檔


def test_daily_intel_skill_documents_agent_plan():
    skill = (SENTINEL_ROOT / ".claude" / "skills" / "daily-intel" / "SKILL.md").read_text(encoding="utf-8")
    assert '"agent_plan": {' in skill                                             # 有事件的範例
    assert '{"events": [], "impacts": [], "agent_plan": {}}' in skill            # 沒有事件的範例
    assert "references/agent-plan.md" in skill and "不要為此派發新的 Subagent" in skill


def test_daily_intel_boundaries_unchanged():
    guard = (SENTINEL_ROOT / ".claude" / "hooks" / "daily_intel_guard.py").read_text(encoding="utf-8")
    assert 'DAILY_SUBAGENTS = "news-scout,advisory-scout,incident-analyst,stack-impact-analyst"' in guard
    wf = (SENTINEL_ROOT / ".github" / "workflows" / "sentinel.yml").read_text(encoding="utf-8")
    assert wf.count('name: "${{ github.run_id }}-a1"') == 2                        # A1 上傳、A4 下載
    assert wf.count("${{ github.run_id }}-{orchestrator,a0,a1,a2,a3,a4,intel-daily}") == 2   # claude-analysis、A5
