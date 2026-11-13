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


def test_all_agent_jobs_share_router_as_of():
    """同一次執行的所有程式步驟（含 Orchestrator 派工與驗收）使用開工路由算出的同一個 AS_OF，任務鍵才會一致。"""
    wf = yaml.safe_load((SENTINEL_ROOT / ".github" / "workflows" / "sentinel.yml").read_text(encoding="utf-8"))
    assert wf["jobs"]["router"]["outputs"]["as_of"] == "${{ steps.plan.outputs.as_of }}"
    seen = set()
    for name, job in wf["jobs"].items():
        for s in job.get("steps", []):
            if "run_agent.py" in str(s.get("run", "")) and name != "router":
                assert s["env"]["AS_OF"] == "${{ needs.router.outputs.as_of }}", name
                seen.add(name)
    assert {"orchestrator-dispatch", "orchestrator-review", "claude-analysis", "a5-report"} <= seen


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


# ── v0.13.0 Orchestrator（specs/orchestrator R7）：llm-plan 讀派工單與驗收單，任務鍵與 A5 一致 ─────────────
from tools import orchestration as o  # noqa: E402

DISPATCH = {
    "extra_controls": [{"event_id": "demo-erp-rce", "control_id": "C-NET-SEGMENT", "reason": "確認資料庫網段隔離"}],
    "extra_tasks": [{"agent": "a4", "subagent": "impact-analyst", "event_id": "demo-erp-rce", "reason": "補充相關風險"},
                    {"agent": "a2", "subagent": "dependency-analyst", "event_id": "demo-push-sdk-rce", "reason": "依事件解讀"},
                    {"agent": "a2", "subagent": "secret-analyst", "event_id": "demo-push-sdk-rce", "reason": "x"}],   # 拒絕
    "priorities": [{"agent": "a4", "risk_id": "storefront:next:vuln", "reason": "先說明對外系統"}],
}
REVIEW = {"extra_tasks": [{"agent": "a5", "subagent": "intel-report-writer", "event_id": "demo-cache-plaintext", "reason": "補寫摘要"},
                          {"agent": "a5", "subagent": "brand-notice-writer", "event_id": "demo-push-sdk-rce", "reason": "x"}],  # 拒絕
          "priorities": [{"agent": "a5", "risk_id": "brand-app:android-debuggable", "reason": "先寫 App 設定"}],
          "summary": "需確認事件補寫摘要。"}


@pytest.fixture()
def demo(ctx, tmp_path):
    """intel-demo：router → a1 → 派工單 → a2～a4 → 驗收單（部分核准、部分拒絕），replay 範本。"""
    c = replace(ctx, scenario="intel-demo", scope="scenario", output_dir="scenarios/intel-demo",
                cache=LLMCache(tmp_path / "cache.json"), replay=ReplayStore(tmp_path / "replay"))
    for m in (router, a0_assets, a1_intel):
        m.run(c)
    verified, _ = o.load_verified(c)
    dplan = o.build_plan("dispatch", DISPATCH, ctx=c, verified=verified, source="replay")
    assert dplan["approved"] and dplan["rejected"]
    o.write_plan(o.plan_path(c.out, "dispatch"), dplan)
    for m in (a2_scan, a3_signals, a4_risk):
        m.run(c)
    r = o.resolve_plans(c, verified=verified, want=("dispatch",))
    rplan = o.build_plan("review", REVIEW, ctx=c, verified=verified, source="replay", dispatch_res=r.res, dispatch_plan=r.dispatch)
    assert rplan["approved"] and rplan["rejected"]
    o.write_plan(o.plan_path(c.out, "review"), rplan)
    return c


def _tasks(c):
    return json.loads((c.out / "llm" / "tasks.json").read_text(encoding="utf-8"))["tasks"]


SUBPROC = """
import sys
from dataclasses import replace
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from context import build_ctx
from tools.cache import LLMCache, ReplayStore
out, data, tmp, action = Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), sys.argv[5]
ctx = replace(build_ctx(scenario="intel-demo"), out=out, data_dir=data, reports_dir=tmp / "reports",
              cache=LLMCache(tmp / "cache.json"), replay=ReplayStore(tmp / "replay"))
if action == "plan":
    from agents import llm_plan
    llm_plan.plan(ctx)
else:
    from agents import a5_report
    a5_report.run(ctx)
"""


def _subprocess(tmp_path, c, action, seed):
    import os
    script = tmp_path / "llm_subproc.py"
    script.write_text(SUBPROC, encoding="utf-8")
    env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONIOENCODING": "utf-8", "EXECUTION_MODE": "replay"}
    proc = subprocess.run([sys.executable, str(script), str(SENTINEL_ROOT / "agents"), str(c.out), str(c.data_dir), str(tmp_path), action],
                          capture_output=True, text=True, encoding="utf-8", env=env, timeout=300)
    assert proc.returncode == 0, proc.stderr[-2000:]


def test_llm_plan_reads_both_plans_and_matches_a5_keys_across_hash_seeds(demo, tmp_path):
    """llm-plan 與 A5 用同一條 resolve 路徑與同一個 llm_texts：含派工與驗收的追加任務時任務鍵一致，不受 PYTHONHASHSEED 影響。"""
    _subprocess(tmp_path, demo, "plan", "0")
    first = _tasks(demo)
    _subprocess(tmp_path, demo, "plan", "4242")
    assert [t["key"] for t in _tasks(demo)] == [t["key"] for t in first]
    ids = [t["task_id"] for t in first]
    assert "event:demo-push-sdk-rce:dependency-analyst" in ids                                  # A2 事件導向任務（R7.1）
    assert "dispatch:demo-erp-rce:order-db-prod:C-NET-SEGMENT" in ids
    assert "intel-extra:demo-cache-plaintext" in ids and not any(i.startswith("notice-extra:") for i in ids)
    rem = next(t for t in first if t["task_id"] == "remediation")
    assert rem["payload"]["ids"][0] == "brand-app:android-debuggable"                           # 驗收單的排優先
    _subprocess(tmp_path, demo, "a5", "999")
    a5_keys = [t["key"] for t in json.loads((demo.out / "a5" / "llm-tasks.json").read_text(encoding="utf-8"))]
    assert [t["key"] for t in first if t["agent"] == "a5"] == a5_keys and len(a5_keys) > 5
    required = [t for t in first if not o.is_extra_task(t["task_id"])]
    assert first[:len(required)] == required                                                   # 必要任務在前


def test_llm_plan_drops_extra_tasks_of_disabled_plans(demo):
    llm_plan.plan(demo)
    assert any(o.is_extra_task(t["task_id"]) for t in _tasks(demo))
    path = o.plan_path(demo.out, "dispatch")
    o.write_plan(path, {**json.loads(path.read_text(encoding="utf-8")), "run_id": "other"})   # 派工單失效 → 驗收單也連帶停用
    llm_plan.plan(replace(demo, llm_plan=[]))
    tasks = _tasks(demo)
    assert tasks and not any(o.is_extra_task(t["task_id"]) for t in tasks)
    rem = next(t for t in tasks if t["task_id"] == "remediation")
    assert rem["payload"]["ids"][0] != "brand-app:android-debuggable"


def test_llm_plan_truncation_keeps_required_tasks_first(demo):
    llm_plan.plan(demo)
    full = _tasks(demo)
    required = [t for t in full if not o.is_extra_task(t["task_id"])]
    extra = [t for t in full if o.is_extra_task(t["task_id"])]
    assert len(extra) == 3 and len(full) < llm_plan.MAX_TASKS
    path = demo.out / "a2" / "llm-tasks.json"
    a2 = json.loads(path.read_text(encoding="utf-8"))
    pad = [{**a2[0], "task_id": f"pad#{i}", "key": f"pad-{i}"} for i in range(llm_plan.MAX_TASKS - 1 - len(required))]
    path.write_text(json.dumps(pad + a2, ensure_ascii=False), encoding="utf-8")               # 追加任務排在 a2 的最後
    got = llm_plan.plan(replace(demo, llm_plan=[]))
    tasks = _tasks(demo)
    assert got == {"tasks": llm_plan.MAX_TASKS, "dropped": 2} and len(tasks) == llm_plan.MAX_TASKS
    assert [t["task_id"] for t in tasks if o.is_extra_task(t["task_id"])] == [extra[0]["task_id"]]
    assert len([t for t in tasks if not o.is_extra_task(t["task_id"])]) == llm_plan.MAX_TASKS - 1   # 必要任務全部保留


def test_invalid_replay_does_not_mask_valid_cache_for_extra_task(demo):
    """R7.3：無效的錄製不得遮蔽同鍵的有效快取（A5 的驗收追加任務也一樣）。"""
    llm_plan.plan(demo)
    t = next(x for x in _tasks(demo) if x["task_id"] == "intel-extra:demo-cache-plaintext")
    demo.replay.put("a5", "intel-report-writer", t["key"], "not a list", {})
    demo.cache.data[t["key"]] = {"output": [{"id": t["task_id"], "explanation": "快取的需確認事件摘要"}], "meta": {}}
    a5_report.run(replace(demo, llm_plan=[]))
    rep = json.loads((demo.data_dir / demo.output_dir / "intel" / "demo-cache-plaintext.json").read_text(encoding="utf-8"))
    assert (rep["summary"], rep["summary_source"]) == ("快取的需確認事件摘要", "replay")
    llm_plan.plan(replace(demo, llm_plan=[]))
    assert "intel-extra:demo-cache-plaintext" not in [x["task_id"] for x in _tasks(demo)]       # 已有可用結果：不再請 Claude 撰寫
