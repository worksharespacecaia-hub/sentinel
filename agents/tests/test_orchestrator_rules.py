"""Orchestrator 的規則（specs/orchestrator design §8 的 test_orchestrator_rules；取代 v0.11.0 的 test_dynamic_planner_rules）：

- R8 不影響判定：有沒有派工單、驗收單（含部分核准、部分拒絕），daily 與各情境的判定逐欄完全相同
- 兩個 AgentSpec 的快取、預算與預留鍵（R6.3、R7.3）
- reference（.claude/skills/orchestrator/references/policy.md）與程式一致（design §3.6）

R8 的比對讀 A5 實際寫出的 report.json、intel/*.json、state/findings.json（流程：router → a0 → a1 →（派工單）→ a2 → a3 → a4 →
（驗收單）→ a5，replay、不呼叫 LLM、不連網路）。
"""
import json
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from agents import a0_assets, a1_intel, a2_scan, a3_signals, a4_risk, a5_report, router
from context import build_ctx
from llm import LLMRunner, Task
from schemas import OrchestratorResult, Report
from tools import orchestration as o
from tools.cache import LLMCache, ReplayStore
from tools.common import SENTINEL_ROOT
from tools.digest import RELATION
from tools.orchestration import (MAX_CTRL_PER_EVENT, MAX_CTRL_TOTAL, MAX_DISPATCH_TASKS, MAX_PRIORITIES, MAX_REVIEW_TASKS,
                                 MAX_SUMMARY, REASON_HELP)
from tools.trace import Tracer

ENV = {"TRIGGER_SOURCE": "manual", "EVENT_NAME": "workflow_dispatch", "AS_OF": "2026-11-09T01:00:00Z", "RUN_ID": "r8-run"}
SCENARIOS = ["daily", "intel-demo", "peer-incident", "early-signal", "php2shell", "advisory"]
ADVISORY = {"ADVISORY_ID": "adv-opsbuilder-2026-001", "ASSETS": "internal-tool"}
# daily：每日情資的一件新事件（本機沒有 intel-daily.json 時 daily 沒有可派工的事件）
DAILY_QUOTE = "攻擊者利用外掛漏洞取得後台權限"
DAILY_EVENT = {"id": "evt-r8-php-2026-11", "kind": "live", "title": "某電商後台遭入侵", "date": "2026-11-08", "confidence": "confirmed",
               "revision": "1", "attack_chain": ["外掛漏洞", "取得後台權限", "匯出會員資料"],
               "products": [{"name": "php", "ecosystem": "php", "affected": [{"introduced": "8.2.0", "fixed": "8.2.35"}]}],
               "sources": [{"url": "https://www.ithome.com.tw/news/r8", "title": "iThome", "quote": DAILY_QUOTE}]}
VARIANTS = ["none", "dispatch", "review", "both", "dispatch_lost"]


# ---------------------------------------------------------------- R8 的比對 helper
def judgement(data_dir: Path, output_dir: str) -> dict:
    """R8.1 的全部比對欄位（從 A5 寫出的檔案讀回）。"""
    d = Path(data_dir) / output_dir
    rep = json.loads((d / "report.json").read_text(encoding="utf-8"))
    intel = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted((d / "intel").glob("*.json")) if p.name != "index.json"}
    Report.model_validate(rep)
    for r in intel.values():                    # 情資報告的追加結果欄位（IntelMatchReport.orchestrator_results）
        for x in r["orchestrator_results"]:
            OrchestratorResult.model_validate(x)
    return {
        "findings": json.loads((d / "state" / "findings.json").read_text(encoding="utf-8")),          # 完整內容
        "impacts": {eid: [{k: v for k, v in i.items() if k != "suggestions"} for i in r["impacts"]] for eid, r in intel.items()},
        "events": [(e["id"], e["status"], RELATION.get(e["status"])) for e in rep["events"]],
        "risks": [(r["id"], r["score"], r["level"], r["matched_events"], r["breakdown"], r["status"]) for r in rep["risks"]],
        "light": (rep["light"], rep["light_reasons"]),
        "intel": {eid: (r["conclusion"], r["status"], r["complete"], (r.get("notice") or {}).get("needed"))
                  for eid, r in intel.items()},
        "completeness": rep["completeness"],
    }


def _env(monkeypatch, scenario):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    for k in ("EXECUTION_MODE", "GITHUB_OUTPUT", "TARGET_DIR", "ADVISORY_ID", "ASSETS", "TARGET_SHA", "SCANNERS_DIR",
              "DEPLOYMENTS_FILE", "GITHUB_RUN_ATTEMPT", "JOB_RESULTS"):
        monkeypatch.delenv(k, raising=False)
    if scenario == "advisory":
        for k, v in ADVISORY.items():
            monkeypatch.setenv(k, v)


@pytest.fixture()
def offline(monkeypatch):
    import claude_agent_sdk
    from tools import intel_verify
    from tools.safe_fetch import FetchResult
    monkeypatch.setattr(claude_agent_sdk, "query", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM")))

    async def no_query(self, pending, graph_query):
        raise AssertionError("不得呼叫 API")
    monkeypatch.setattr(LLMRunner, "_query", no_query)
    monkeypatch.setattr(intel_verify, "fetch", lambda url, allowlist, **kw: FetchResult(
        url=url, status=200, text=f"<p>{DAILY_QUOTE}</p>", content_type="text/html"))
    # 測試資料沒有符合條件的金鑰輪替候選與回溯紀錄：補上對象，讓驗收與回溯的追加路徑也被比對到（兩邊用同一份政策）
    real_keyrot, real_a3 = o.keyrot_candidates, o.a3_systems

    def keyrot(events, matches, risks):
        extra = [r["id"] for r in risks if r["id"] == "mail-api-key:C-THIRD-PARTY-KEY-ROTATION"]
        return list(dict.fromkeys([*real_keyrot(events, matches, risks), *extra])) if events else []

    def a3(events, matches, assets):
        out = real_a3(events, matches, assets)
        return {ev["id"]: sorted({*out.get(ev["id"], []), "admin-console"}) for ev in events}
    monkeypatch.setattr(o, "keyrot_candidates", keyrot)
    monkeypatch.setattr(o, "a3_systems", a3)


def base_ctx(monkeypatch, tmp_path, scenario):
    _env(monkeypatch, scenario)
    c = replace(build_ctx(scenario=scenario), out=tmp_path / "base" / "out", data_dir=tmp_path / "base" / "data",
                reports_dir=tmp_path / "base" / "reports", cache=LLMCache(tmp_path / "cache.json"), replay=ReplayStore(tmp_path / "replay"))
    if scenario == "daily":
        c.out.mkdir(parents=True, exist_ok=True)
        (c.out / "intel-daily.json").write_text(json.dumps({"events": [DAILY_EVENT], "impacts": []}, ensure_ascii=False),
                                                encoding="utf-8")
    for m in (router, a0_assets, a1_intel):
        m.run(c)
    return c


def dispatch_proposal(policy: o.PolicyContext) -> dict:
    """依政策上下文組一份部分核准、部分拒絕的派工提案（每種項目都有，外加會被拒絕的項目）。"""
    events = list(policy.events)
    controls = []
    for eid in events[:2]:
        mapped = set(policy.events[eid].get("controls") or [])
        controls += [{"event_id": eid, "control_id": c, "reason": "一併確認"} for c in [c for c in policy.controls if c not in mapped][:2]]
    controls.append({"event_id": "not-in-scope", "control_id": "C-NET-SEGMENT", "reason": "x"})              # 事件不在範圍
    tasks = [{"agent": "a2", "subagent": sub, "event_id": eid, "reason": "依事件解讀"} for eid, per in policy.a2.items() for sub in per]
    tasks += [{"agent": "a3", "subagent": "retro-hunter", "event_id": eid, "reason": "回溯搜查"} for eid in policy.a3]
    tasks += [{"agent": "a4", "subagent": "impact-analyst", "event_id": eid, "reason": "補充說明"} for eid in events]
    tasks.append({"agent": "a2", "subagent": "secret-analyst", "event_id": events[0] if events else "x", "reason": "x"})  # 不在選單
    prio = [{"agent": "a4", "risk_id": rid, "reason": "先說明"} for rid in policy.a4_baseline[-2:]]
    prio.append({"agent": "a4", "risk_id": "not-a-risk", "reason": "x"})                                    # 不在清單
    return {"extra_controls": controls, "extra_tasks": tasks, "priorities": prio, "skip_checks": True}       # 頂層未知欄位


def review_proposal(policy: o.PolicyContext) -> dict:
    tasks = [{"agent": "a5", "subagent": "intel-report-writer", "event_id": eid, "reason": "補寫摘要"} for eid in policy.need_check[:1]]
    tasks += [{"agent": "a5", "subagent": "key-rotation-advisor", "risk_id": rid, "reason": "補寫輪替建議"} for rid in policy.keyrot[:1]]
    tasks += [{"agent": "a5", "subagent": "brand-notice-writer", "event_id": eid, "reason": "補寫草稿"} for eid in policy.notice[:1]]
    others = [e for e in policy.events if e not in policy.need_check]
    if others:
        tasks.append({"agent": "a5", "subagent": "intel-report-writer", "event_id": others[0], "reason": "x"})   # 不是需確認
    prio = [{"agent": "a5", "risk_id": policy.a5_remediation[-1], "reason": "先寫"}] if policy.a5_remediation else []
    prio.append({"agent": "a5", "risk_id": "not-a-risk", "reason": "x"})
    return {"extra_tasks": tasks, "priorities": prio, "summary": "已核准追加任務；需確認事件與相關金鑰請工程團隊確認。"}


def run_variant(base, tmp_path, variant: str) -> tuple:
    """一個變體：複製同一份上游產物，依變體寫入計畫，跑 a2 → a5。回傳（ctx, 派工單, 驗收單）。"""
    root = tmp_path / variant
    shutil.copytree(base.out, root / "out")
    c = replace(base, out=root / "out", data_dir=root / "data", reports_dir=root / "reports", llm_plan=[])
    verified, _ = o.load_verified(c)
    dplan = rplan = None
    if variant in ("dispatch", "both", "dispatch_lost"):
        _, ref, _ = o.approve_core("dispatch", {}, verified=verified, base_inputs=o.base_inputs(c))
        dplan = o.build_plan("dispatch", dispatch_proposal(ref), ctx=c, verified=verified, source="replay")
        o.write_plan(o.plan_path(c.out, "dispatch"), dplan)
    for m in (a2_scan, a3_signals, a4_risk):
        m.run(c)
    if variant in ("review", "both", "dispatch_lost"):
        r = o.resolve_plans(c, verified=verified, want=("dispatch",))
        _, pol, _ = o.approve_core("review", {}, verified=verified, base_inputs=o.base_inputs(c), dispatch_res=r.res)
        rplan = o.build_plan("review", review_proposal(pol), ctx=c, verified=verified, source="replay", dispatch_res=r.res,
                             dispatch_plan=r.dispatch)
        o.write_plan(o.plan_path(c.out, "review"), rplan)
    if variant == "dispatch_lost":                                   # A2～A4 執行後派工單失效：驗收單也連帶停用（綁定 sha）
        o.write_plan(o.plan_path(c.out, "dispatch"), {**dplan, "run_id": "other"})
    a5_report.run(c)
    return c, dplan, rplan


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_r8_plans_never_change_any_judgement(monkeypatch, tmp_path, offline, scenario):
    base = base_ctx(monkeypatch, tmp_path, scenario)
    got = {v: run_variant(base, tmp_path, v) for v in VARIANTS}
    ref = judgement(got["none"][0].data_dir, base.output_dir)
    assert ref["risks"] and ref["findings"]
    for v in VARIANTS[1:]:
        assert judgement(got[v][0].data_dir, base.output_dir) == ref, v                    # R8.1：逐欄完全相同
    reports = {v: json.loads((got[v][0].data_dir / base.output_dir / "report.json").read_text(encoding="utf-8")) for v in VARIANTS}
    assert reports["none"]["agent_plan"] is None and reports["none"]["orchestrator_results"] == []
    # 計畫確實有效、部分核准部分拒絕，而且有被採用（不是因為停用才相同）
    _, dplan, _ = got["both"]
    assert dplan["approved"] and dplan["rejected"]
    plan = reports["both"]["agent_plan"]
    assert plan["dispatch"]["approved_count"] == len(dplan["approved"]) and plan["review"]["rejected_count"] > 0
    assert reports["dispatch"]["agent_plan"]["review"] is None and reports["review"]["agent_plan"]["dispatch"] is None
    assert reports["dispatch_lost"]["agent_plan"] is None and reports["dispatch_lost"]["orchestrator_results"] == []
    if scenario not in ("early-signal", "php2shell"):               # 有本次範圍事件的情境：追加結果與加查都有出現
        assert reports["both"]["orchestrator_results"] and dplan["events"]
        assert any(r["stage"] == "review" for r in reports["both"]["orchestrator_results"])
        intel = got["both"][0].data_dir / base.output_dir / "intel"
        assert any("8_extra_checks" in json.loads(p.read_text(encoding="utf-8"))["blocks"] for p in intel.glob("*.json")
                   if p.name != "index.json")
    else:
        assert dplan["events"] == [] and reports["both"]["orchestrator_results"] == []


def test_r8_helper_detects_judgement_changes(monkeypatch, tmp_path, offline):
    """helper 本身：改動任何一個比對欄位都會被抓到（避免比對空集合而永遠相同）。"""
    base = base_ctx(monkeypatch, tmp_path, "intel-demo")
    c, _, _ = run_variant(base, tmp_path, "none")
    ref = judgement(c.data_dir, base.output_dir)
    d = c.data_dir / base.output_dir
    rep_path, intel_path = d / "report.json", next(p for p in sorted((d / "intel").glob("demo-*.json")))
    for path, edit in [(rep_path, lambda r: r["risks"][0].update(score=r["risks"][0]["score"] + 1)),
                       (rep_path, lambda r: r["risks"][0]["breakdown"].append({"factor": "x", "points": 1, "reason": "x"})),
                       (rep_path, lambda r: r["light_reasons"].append("x")),
                       (rep_path, lambda r: r["events"][0].update(status="fixed")),
                       (rep_path, lambda r: r.update(completeness="partial")),
                       (intel_path, lambda r: r.update(conclusion="x")),
                       (intel_path, lambda r: r["impacts"][0].update(verdict="not_affected"))]:
        before = path.read_text(encoding="utf-8")
        data = json.loads(before)
        edit(data)
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        assert judgement(c.data_dir, base.output_dir) != ref
        path.write_text(before, encoding="utf-8")
    data = json.loads(intel_path.read_text(encoding="utf-8"))
    for imp in data["impacts"]:
        imp["suggestions"] = [{"text": "只改查核建議"}]                                   # impacts 的比對不含 suggestions
    intel_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    assert judgement(c.data_dir, base.output_dir) == ref


# ---------------------------------------------------------------- 快取與預算（R6.3、R7.3；兩個 AgentSpec 各自的預算）
AGENT = "orchestrator-dispatch"


def _runner(tmp_path, mode="replay", agent=AGENT, budget=None):
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
    r.replay.put(AGENT, "planner", k, "not an object", {})
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
        return {"plan": "bad"}, 0.02                                              # 格式無效 → 重試一次
    monkeypatch.setattr(LLMRunner, "_query", fake_query)
    assert r.run([PLAN_TASK])["plan"]["source"] == "template"
    assert seen == [0.05, 0.03] and r.cost["per_agent"][AGENT] == 0.04
    seen.clear()
    r.cost["per_agent"][AGENT] = 0.05
    assert r.run([PLAN_TASK])["plan"]["source"] == "template" and seen == []      # 用完就不再呼叫


def test_options_receive_remaining_budget():
    from registry import options_for
    for name in ("a1", "orchestrator-dispatch", "orchestrator-review"):           # R6.3：各 $0.05
        assert options_for(name).max_budget_usd == 0.05
        assert options_for(name, budget=0.03).max_budget_usd == 0.03
        assert options_for(name, budget=5).max_budget_usd == 0.05                # 不會超過上限


# ---------------------------------------------------------------- policy.md 與程式一致（design §3.6）
def test_reference_matches_code():
    res = subprocess.run([sys.executable, str(SENTINEL_ROOT / "scripts" / "build-agent-plan-reference.py"), "--check"],
                         capture_output=True, text=True, encoding="utf-8")
    assert res.returncode == 0, res.stderr
    ref = (SENTINEL_ROOT / ".claude" / "skills" / "orchestrator" / "references" / "policy.md").read_text(encoding="utf-8")
    assert f"每件事件最多 {MAX_CTRL_PER_EVENT} 個加查控制項，總共最多 {MAX_CTRL_TOTAL} 個" in ref
    assert f"追加任務總共最多 {MAX_DISPATCH_TASKS} 項" in ref and f"追加任務總共最多 {MAX_REVIEW_TASKS} 項" in ref
    assert f"排優先最多 {MAX_PRIORITIES} 項" in ref and f"最多 {MAX_SUMMARY} 字" in ref
    for row in ("| a2 | dependency-analyst |", "| a2 | runtime-analyst |", "| a3 | retro-hunter |", "| a4 | impact-analyst |",
                "| a5 | intel-report-writer |", "| a5 | key-rotation-advisor |", "| a5 | brand-notice-writer |"):
        assert row in ref, row
    assert all(f"| {reason} |" in ref for reason in REASON_HELP)


def test_reference_check_detects_stale_file(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_ref", SENTINEL_ROOT / "scripts" / "build-agent-plan-reference.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    stale = tmp_path / "policy.md"
    stale.write_text("old", encoding="utf-8")
    monkeypatch.setattr(mod, "OUT_PATH", stale)
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    assert mod.main(["--check"]) == 1 and stale.read_text(encoding="utf-8") == "old"   # --check 不改檔
    missing = tmp_path / "nope" / "policy.md"
    monkeypatch.setattr(mod, "OUT_PATH", missing)
    assert mod.main(["--check"]) == 1 and not missing.exists()


# ---------------------------------------------------------------- daily-intel 的舊派工建議（T4 移除 agent_plan 時改寫）
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
