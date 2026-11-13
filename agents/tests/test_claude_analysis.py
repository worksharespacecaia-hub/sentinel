"""A2、A4、A5 的說明文字改由 claude-analysis Job（claude-code-action，訂閱方案）撰寫：
規劃任務 → Claude 撰寫 → 程式驗證 → A5 採用。分數、等級與狀態一律以程式判定為準。"""
import importlib.util
import json
import subprocess
import sys
from dataclasses import replace

import pytest
import yaml

from agents import a0_assets, a1_intel, a2_scan, a3_signals, a4_risk, a5_report, llm_plan, router
from context import build_ctx
from llm import LLMRunner, Task
from tools.cache import LLMCache, ReplayStore
from tools.common import SENTINEL_ROOT
from tools.trace import Tracer, read_trace

ENV = {"SCENARIO": "daily", "TRIGGER_SOURCE": "manual", "EVENT_NAME": "local", "AS_OF": "2026-11-09T01:00:00Z", "RUN_ID": "ca-run"}


@pytest.fixture()
def ctx(monkeypatch, tmp_path):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    for k in ("EXECUTION_MODE", "GITHUB_OUTPUT", "TARGET_DIR", "DEPLOYMENTS_FILE", "ADVISORY_ID", "ASSETS", "TARGET_SHA"):
        monkeypatch.delenv(k, raising=False)
    import claude_agent_sdk
    monkeypatch.setattr(claude_agent_sdk, "query", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM")))
    return replace(build_ctx(), out=tmp_path / "out", data_dir=tmp_path / "data", reports_dir=tmp_path / "reports")


def _upstream(ctx):
    for m in (router, a0_assets, a1_intel, a2_scan, a3_signals, a4_risk):
        m.run(ctx)


def _fake_write(tasks):
    """依各任務的輸出格式產生合法結果（模擬 Claude 照 Skill 撰寫）。"""
    out = {}
    for t in tasks:
        if t["output"] == "explanations":
            out[t["key"]] = [{"id": i, "explanation": f"Claude 說明 {i}"} for i in t["ids"]]
        elif t["output"] == "solutions":
            out[t["key"]] = [{"risk_id": i, "temporary": "暫時", "permanent": "根本", "verify": "確認", "score": 0, "level": "low",
                              "options": [{"name": "緩解", "action": "做", "cost": "低", "timing": "今天"}]} for i in t["ids"]]
        elif t["output"] == "ceo":
            out[t["key"]] = {"ceo_summary": ["Claude 第一句。", "第二句。", "第三句。"], "decisions": ["決定事項"]}
    return out


def test_runner_records_template_tasks_and_uses_collected(tmp_path):
    def runner(**kw):
        return LLMRunner(agent="a2", mode="replay", scope="daily", target_sha="a" * 40, advisory_revision=None,
                         tracer=Tracer(tmp_path / "t.jsonl", "a2"), cache=LLMCache(tmp_path / "c.json"),
                         replay=ReplayStore(tmp_path / "replay"), **kw)
    t = Task(id="secret-analyst#0", subagent="secret-analyst", payload={"ids": ["f1"], "items": [{"id": "f1"}]})
    plan = []
    r = runner(plan=plan)
    assert r.run([t])[t.id]["source"] == "template"
    assert len(plan) == 1 and "f1" in plan[0]["ids"] and plan[0]["output"] == "explanations" and plan[0]["instructions"]
    key = plan[0]["key"]
    good = runner(collected={key: [{"id": "f1", "explanation": "說明"}]}, plan=[])
    res = good.run([t])[t.id]
    assert res["source"] == "live" and res["output"][0]["explanation"] == "說明" and good.plan == []
    bad = runner(collected={key: [{"id": "other", "explanation": "越界"}]})
    assert bad.run([t])[t.id]["source"] == "template"                        # 範圍以外的 ID：不採用
    assert any("未通過驗證" in e["detail"] for e in read_trace(tmp_path / "t.jsonl"))


def test_plan_validate_and_a5_adopt(ctx):
    _upstream(ctx)
    llm_plan.plan(ctx)
    doc = json.loads((ctx.out / "llm" / "tasks.json").read_text(encoding="utf-8"))
    agents = {t["agent"] for t in doc["tasks"]}
    assert agents == {"a2", "a4", "a5"} and doc["count"] == len(doc["tasks"]) > 10
    assert not (ctx.data_dir / "daily").exists()                              # 規劃不寫任何報告
    results = _fake_write(doc["tasks"])
    first = doc["tasks"][0]
    results[first["key"]] = [{"id": "not-in-scope", "explanation": "x"}]      # 一個不合格
    (ctx.out / "llm" / "results.json").write_text(json.dumps(results, ensure_ascii=False), encoding="utf-8")
    summary = llm_plan.validate(ctx)
    assert summary["rejected"] == 1 and summary["validated"] == len(results) - 1
    validated = json.loads((ctx.out / "llm" / "validated.json").read_text(encoding="utf-8"))
    sol = next(v for v in validated.values() if isinstance(v, list) and v and "risk_id" in v[0])
    assert "score" not in sol[0] and "level" not in sol[0]                   # Claude 不能改程式判定

    a5ctx = replace(ctx, _llm_results=None, llm_plan=[])
    a5_report.run(a5ctx)
    rep = json.loads((ctx.data_dir / "daily" / "report.json").read_text(encoding="utf-8"))
    assert rep["ceo_summary"][0] == "Claude 第一句。"
    assert sum(1 for r in rep["risks"] if r.get("explanation_source") == "live") > 5
    trace = read_trace(ctx.data_dir / "daily" / "trace.jsonl")
    assert any(e["agent"] == "a5" and e["source"] == "live" and "訂閱方案" in e["detail"] for e in trace)
    for r in rep["risks"]:                                                    # 等級與分數不受 Claude 影響
        assert r["level"] in ("high", "medium", "low")


def test_plan_keys_are_stable_across_jobs(ctx):
    _upstream(ctx)
    llm_plan.plan(ctx)
    a = [t["key"] for t in json.loads((ctx.out / "llm" / "tasks.json").read_text(encoding="utf-8"))["tasks"]]
    llm_plan.plan(replace(ctx, llm_plan=[]))
    b = [t["key"] for t in json.loads((ctx.out / "llm" / "tasks.json").read_text(encoding="utf-8"))["tasks"]]
    assert a == b                                                            # 同一個 AS_OF：規劃與 A5 算出相同的任務鍵


def test_validate_handles_missing_or_broken_results(ctx):
    _upstream(ctx)
    llm_plan.plan(ctx)
    assert llm_plan.validate(ctx)["validated"] == 0                          # 沒有 results.json
    (ctx.out / "llm" / "results.json").write_text("{broken", encoding="utf-8")
    assert llm_plan.validate(ctx)["validated"] == 0


HOOK = SENTINEL_ROOT / ".claude" / "hooks" / "daily_intel_guard.py"
ANALYSIS_ARGS = ["--write", "out/llm/results.json", "--agents", "", "--no-websearch", "--skill", "analysis-writer"]


def decide(tool, inp, args=()):
    proc = subprocess.run([sys.executable, str(HOOK), *args], input=json.dumps({"tool_name": tool, "tool_input": inp}),
                          capture_output=True, text=True, encoding="utf-8", cwd=SENTINEL_ROOT, check=True)
    return (json.loads(proc.stdout or "{}").get("hookSpecificOutput") or {}).get("permissionDecision", "allow")


@pytest.mark.parametrize("tool,inp,expected", [
    ("Read", {"file_path": "out/llm/tasks.json"}, "allow"),
    ("Read", {"file_path": ".claude/skills/risk-explain/SKILL.md"}, "allow"),
    ("Write", {"file_path": "out/llm/results.json"}, "allow"),
    ("Write", {"file_path": "out/llm/tasks.json"}, "deny"),
    ("Write", {"file_path": "out/intel-daily.json"}, "deny"),
    ("Skill", {"skill": "analysis-writer"}, "allow"),
    ("Skill", {"skill": "daily-intel"}, "deny"),
    ("Agent", {"subagent_type": "news-scout"}, "deny"),
    ("WebSearch", {"query": "x"}, "deny"),
    ("WebFetch", {"url": "https://www.ithome.com.tw/"}, "deny"),
    ("Bash", {"command": "ls"}, "deny"),
])
def test_analysis_hook(tool, inp, expected):
    assert decide(tool, inp, ANALYSIS_ARGS) == expected


def test_analysis_settings_use_restricted_hook():
    cfg = json.loads((SENTINEL_ROOT / ".claude" / "analysis-settings.json").read_text(encoding="utf-8"))
    assert cfg["env"]["CLAUDE_CODE_DISABLE_BACKGROUND_TASKS"] == "1"
    cmd = cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert cmd == "python3 .claude/hooks/daily_intel_guard.py --write out/llm/results.json --agents '' --no-websearch --skill analysis-writer"


def test_analysis_job_structure():
    wf = yaml.safe_load((SENTINEL_ROOT / ".github" / "workflows" / "sentinel.yml").read_text(encoding="utf-8"))
    job = wf["jobs"]["claude-analysis"]
    assert job["permissions"] == {"contents": "read"} and job["continue-on-error"] is True
    assert set(job["needs"]) >= {"a2-scan", "a4-risk"}
    steps = job["steps"]
    names = [s.get("name", s.get("uses", "")) for s in steps]
    plan = next(i for i, s in enumerate(steps) if "run_agent.py llm-plan" in str(s.get("run", "")))
    claude = next(i for i, s in enumerate(steps) if str(s.get("uses", "")).startswith("anthropics/claude-code-action"))
    validate = next(i for i, s in enumerate(steps) if "run_agent.py llm-validate" in str(s.get("run", "")))
    check = names.index("確認 Claude 只寫了 out/")
    upload = next(i for i, s in enumerate(steps) if str(s.get("uses", "")).startswith("actions/upload-artifact"))
    assert plan < claude < check < validate < upload and "if" not in steps[upload]
    assert steps[plan]["env"]["EXECUTION_MODE"] == "replay" and "ANTHROPIC_API_KEY" not in steps[plan]["env"]
    args = steps[claude]["with"]["claude_args"]
    assert '--tools "Read,Write,Skill"' in args and '--disallowedTools "Bash,Edit,NotebookEdit,WebFetch,WebSearch,Agent"' in args
    assert "--settings .claude/analysis-settings.json" in args and steps[claude]["with"]["prompt"] == "/analysis-writer"
    assert 'sha256sum -c --quiet "$RUNNER_TEMP/llm.sha256"' in steps[check]["run"]
    assert steps[upload]["with"]["name"] == "${{ github.run_id }}-llm"
    a5 = wf["jobs"]["a5-report"]["steps"]
    dl = [s for s in a5 if str(s.get("uses", "")).startswith("actions/download-artifact") and s["with"].get("name") == "${{ github.run_id }}-llm"]
    assert len(dl) == 1 and dl[0]["with"]["path"] == "out/llm/"


def test_all_agent_jobs_share_orchestrator_as_of():
    wf = yaml.safe_load((SENTINEL_ROOT / ".github" / "workflows" / "sentinel.yml").read_text(encoding="utf-8"))
    assert wf["jobs"]["orchestrator"]["outputs"]["as_of"] == "${{ steps.plan.outputs.as_of }}"
    for name, job in wf["jobs"].items():
        for s in job.get("steps", []):
            if "run_agent.py" in str(s.get("run", "")) and name != "orchestrator":
                assert s["env"]["AS_OF"] == "${{ needs.orchestrator.outputs.as_of }}", name


def test_analysis_trace_summarizes_counts_only():
    spec = importlib.util.spec_from_file_location("ces", SENTINEL_ROOT / "scripts" / "claude-error-summary.py")
    ces = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ces)
    tasks = {"tasks": [{"key": "k1", "agent": "a2", "subagent": "secret-analyst"}, {"key": "k2", "agent": "a2", "subagent": "secret-analyst"},
                       {"key": "k3", "agent": "a5", "subagent": "ceo-briefer"}]}
    msgs = [{"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "r", "name": "Read", "input": {"file_path": "x"}}]}},
            {"type": "result", "num_turns": 5, "duration_ms": 60000, "result": "撰寫內容不該出現"}]
    evs = ces.analysis_trace_events(msgs, tasks, {"k1": [], "k3": {}}, "2026-11-10T00:00:00+00:00")
    details = [e["detail"] for e in evs]
    assert "a2 的 secret-analyst：撰寫 2 個任務，程式驗證通過 1 個" in details
    assert "a5 的 ceo-briefer：撰寫 1 個任務，程式驗證通過 1 個" in details
    assert evs[-1]["detail"].startswith("通過驗證 2／3 個任務")
    assert "撰寫內容不該出現" not in json.dumps(evs, ensure_ascii=False)
    assert all(e["agent"] == "claude-analysis" for e in evs)
