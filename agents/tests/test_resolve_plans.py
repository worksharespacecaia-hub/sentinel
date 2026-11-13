"""建立與載入共用核心（specs/orchestrator R5.1、R5.1a、R5.1b；design §8 的 test_resolve_plans）。

用 intel-demo／peer-incident 情境的凍結資料與真的 evaluate；不呼叫 LLM、不連網路。
"""
import copy
import json
import os
import subprocess
import sys
from dataclasses import replace

import pytest

from context import build_ctx
from tools import orchestration as o
from tools.common import AGENTS_DIR, sha256_json, write_json
from tools.intel_verify import verify_event
from tools.pipeline import evaluate, event_sources

ENV = {"TRIGGER_SOURCE": "manual", "EVENT_NAME": "workflow_dispatch", "AS_OF": "2026-11-09T01:00:00Z", "RUN_ID": "orch-run"}

# 部分核准、部分拒絕的派工提案（intel-demo）
DISPATCH = {
    "extra_controls": [
        {"event_id": "demo-erp-rce", "control_id": "C-NET-SEGMENT", "reason": "確認資料庫網段隔離"},           # 核准
        {"event_id": "demo-erp-rce", "control_id": "C-NOPE", "reason": "x"},                                  # 不在控制項清單
        {"event_id": "demo-cache-plaintext", "control_id": "C-CACHE-TLS", "reason": "x"},                     # 已對應
    ],
    "extra_tasks": [
        {"agent": "a4", "subagent": "impact-analyst", "event_id": "demo-erp-rce", "reason": "補充相關風險"},   # 加入 control 後才有對象
        {"agent": "a4", "subagent": "impact-analyst", "event_id": "demo-firebase-public", "reason": "x"},     # 風險都在必要任務
        {"agent": "a2", "subagent": "dependency-analyst", "event_id": "demo-push-sdk-rce", "reason": "依事件解讀 SDK 漏洞"},
        {"agent": "a2", "subagent": "runtime-analyst", "event_id": "demo-push-sdk-rce", "reason": "x"},       # 沒有 eol 對象
        {"agent": "a3", "subagent": "retro-hunter", "event_id": "demo-cache-plaintext", "reason": "回溯快取存取紀錄"},
        {"agent": "a2", "subagent": "secret-analyst", "event_id": "demo-push-sdk-rce", "reason": "x"},        # 不在選單
    ],
    "priorities": [
        {"agent": "a4", "risk_id": "storefront:next:vuln", "reason": "先說明對外系統"},
        {"agent": "a4", "risk_id": "cache-redis:C-CACHE-TLS", "reason": "x"},                                # 不在前 10 個高風險
    ],
    "skip_agents": ["a2"],                                                                                   # 頂層未知欄位
}
DISPATCH_REASONS = [o.R_ONLY_ADD, o.R_CONTROL, o.R_MAPPED, o.R_NO_TARGET, o.R_NO_TARGET, o.R_TASK, o.R_PRIORITY]
REVIEW = {
    "extra_tasks": [
        {"agent": "a5", "subagent": "intel-report-writer", "event_id": "demo-cache-plaintext", "reason": "補寫需確認事件摘要"},
        {"agent": "a5", "subagent": "intel-report-writer", "event_id": "demo-push-sdk-rce", "reason": "x"},   # 不是需確認
        {"agent": "a5", "subagent": "brand-notice-writer", "event_id": "demo-push-sdk-rce", "reason": "x"},   # 程式已要求通知
        {"agent": "a5", "subagent": "key-rotation-advisor", "risk_id": "brand-app:C-SECRET-IN-GIT", "reason": "x"},  # 必要任務已涵蓋
    ],
    "priorities": [{"agent": "a5", "risk_id": "storefront:next:vuln", "reason": "先寫對外系統"},
                   {"agent": "a5", "risk_id": "cache-redis:C-CACHE-TLS", "reason": "x"}],
    "summary": "派工的追加任務已核准，需確認事件補寫摘要。",
}
REVIEW_REASONS = [o.R_NOT_NEED_CHECK, o.R_NOTICE_NEEDED, o.R_NOT_KEYROT, o.R_PRIORITY]


@pytest.fixture()
def ctx(monkeypatch, tmp_path):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    for k in ("EXECUTION_MODE", "GITHUB_OUTPUT", "TARGET_DIR", "ADVISORY_ID", "ASSETS", "TARGET_SHA", "SCANNERS_DIR",
              "DEPLOYMENTS_FILE", "GITHUB_RUN_ATTEMPT"):
        monkeypatch.delenv(k, raising=False)
    import claude_agent_sdk
    monkeypatch.setattr(claude_agent_sdk, "query", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM")))
    return replace(build_ctx(scenario="intel-demo"), out=tmp_path / "out", data_dir=tmp_path / "data",
                   reports_dir=tmp_path / "reports")


def a1_verified(c, extra=()):
    """模擬 A1：驗證情資（離線）、存成 verified.json，再用下游的 load_verified 讀回（雜湊以下游讀到的內容計算）。"""
    verified = [verify_event(raw, as_of=c.as_of, online=False) for raw in event_sources(c.eval_input())] + list(extra)
    write_json(c.out / "a1" / "verified.json", verified)
    loaded, why = o.load_verified(c)
    assert why is None
    return loaded


def checks_of(res):
    return {m["event"]["id"]: [x["control_id"] for x in m["planner_checks"]] for m in res["matches"]}


def no_checks(res):
    return all(m["planner_checks"] == [] for m in res["matches"])


def save(c, plan):
    o.write_plan(o.plan_path(c.out, plan["mode"]), plan)


def dispatch_plan(c, verified, proposal=DISPATCH, source="replay"):
    plan = o.build_plan("dispatch", proposal, ctx=c, verified=verified, source=source)
    save(c, plan)
    return plan


def review_plan(c, verified, *, bind=True, proposal=REVIEW):
    r = o.resolve_plans(c, verified=verified, want=("dispatch",))
    plan = o.build_plan("review", proposal, ctx=c, verified=verified, source="replay", dispatch_res=r.res,
                        dispatch_plan=r.dispatch if bind else None)
    save(c, plan)
    return plan


# ---------------------------------------------------------------- R5.1：核心的順序，建立與載入一致
def test_controls_change_eligibility_and_load_reproduces_partial_plan(ctx):
    verified = a1_verified(ctx)
    base = o.base_inputs(ctx)
    _, ref, _ = o.approve_core("dispatch", {}, verified=verified, base_inputs=base)          # 派工輸入的參考候選（沒有 control）
    assert "demo-erp-rce" not in ref.a4_extra
    plan = dispatch_plan(ctx, verified)
    assert plan["schema_version"] == 2 and plan["mode"] == "dispatch" and plan["status"] == "complete"
    assert plan["run_id"] == "orch-run" and plan["run_attempt"] == 1 and plan["scenario"] == "intel-demo"
    assert plan["verified_sha256"] == sha256_json(verified) and o.SHA_RE.match(plan["verified_sha256"])
    assert plan["events"] == list(ref.events) and len(plan["events"]) == 5
    assert [(a["type"], a.get("subagent")) for a in plan["approved"]] == [
        ("control", None), ("task", "impact-analyst"), ("task", "dependency-analyst"), ("task", "retro-hunter"), ("priority", None)]
    assert [r["reason"] for r in plan["rejected"]] == DISPATCH_REASONS
    assert plan["suggested"] == len(plan["approved"]) + len(plan["rejected"]) == 12
    r = o.resolve_plans(ctx, verified=verified, want=("dispatch",))
    assert r.reasons == {"dispatch": None} and r.dispatch == plan and r.review is None
    assert checks_of(r.res)["demo-erp-rce"] == ["C-NET-SEGMENT"]                           # res 含派工單 control 的結果
    final = r.policies["dispatch"]
    assert final.a4_extra["demo-erp-rce"] == ["order-db-prod:C-NET-SEGMENT"]               # 最終資格以核心第 3 步為準
    assert sha256_json(verified) == plan["verified_sha256"]                                 # 建立與載入都沒有改動 verified


def test_pick_extra_risks_list_change_is_reproduced_on_load(ctx):
    """加入 control 後 pick_extra_risks 名單變動（[r1] → [r0a, r0b, r0c]）：建立與載入結果一致。"""
    verified = a1_verified(ctx)
    base = o.base_inputs(ctx)
    _, ref, _ = o.approve_core("dispatch", {}, verified=verified, base_inputs=base)
    assert ref.a4_extra["demo-cache-plaintext"] == ["cache-redis:C-CACHE-TLS"]
    proposal = {"extra_controls": [{"event_id": "demo-cache-plaintext", "control_id": c, "reason": "一併確認"}
                                   for c in ("C-NET-SEGMENT", "C-BACKUP-ISOLATION", "C-INTERNAL-TOOL-EXPOSED")],
                "extra_tasks": [{"agent": "a4", "subagent": "impact-analyst", "event_id": "demo-cache-plaintext", "reason": "補充"}]}
    plan = dispatch_plan(ctx, verified, proposal)
    assert len(plan["approved"]) == 4 and plan["rejected"] == []
    r = o.resolve_plans(ctx, verified=verified)
    assert r.dispatch == plan
    picked = r.policies["dispatch"].a4_extra["demo-cache-plaintext"]
    assert picked == ["internal-tool:C-INTERNAL-TOOL-EXPOSED", "nas-office-01:C-BACKUP-ISOLATION", "nas-office-01:C-INTERNAL-TOOL-EXPOSED"]
    assert picked != ref.a4_extra["demo-cache-plaintext"]


def test_template_plan_ignores_proposal_and_is_valid(ctx):
    verified = a1_verified(ctx)
    plan = dispatch_plan(ctx, verified, source="template")
    assert plan["suggested"] == 0 and plan["approved"] == [] and plan["rejected"] == []
    assert o.resolve_plans(ctx, verified=verified).dispatch == plan


def test_pending_is_written_atomically_and_never_trusted(ctx):
    verified = a1_verified(ctx)
    path = o.plan_path(ctx.out, "dispatch")
    o.write_plan(path, o.pending_plan(ctx, "dispatch"))
    assert not list(path.parent.glob("*.tmp"))
    pending = json.loads(path.read_text(encoding="utf-8"))
    assert pending["status"] == "pending" and pending["note"] == o.NOTE_PENDING and pending["verified_sha256"] is None
    r = o.resolve_plans(ctx, verified=verified)
    assert r.dispatch is None and r.reasons["dispatch"] == "plan_pending"


# ---------------------------------------------------------------- 竄改與降級：只停用那一份（R5.1a）
TAMPERS = {
    "missing": "plan_missing", "garbage": "plan_unreadable", "v1": "plan_version", "wrong_mode": "plan_mode",
    "pending": "plan_pending", "other_run": "plan_other_run", "other_attempt": "plan_other_run", "sha": "plan_verified_mismatch",
    "bad_counts": "plan_invalid", "count_mismatch": "plan_counts", "bad_approved": "plan_approved_invalid",
    "reordered": "plan_approved_invalid", "extra_key": "plan_approved_invalid", "edited_reason": "plan_approved_invalid",
    "rejected_unsafe": "plan_rejected_invalid", "events": "plan_events", "verified_broken": "verified_unavailable",
}


@pytest.mark.parametrize("tamper", sorted(TAMPERS))
def test_untrusted_dispatch_plan_is_disabled(ctx, tamper, monkeypatch):
    verified = a1_verified(ctx)
    plan = dispatch_plan(ctx, verified)
    path = o.plan_path(ctx.out, "dispatch")
    bad = copy.deepcopy(plan)
    if tamper == "missing":
        path.unlink()
    elif tamper == "garbage":
        path.write_text("{not json", encoding="utf-8")
    elif tamper == "verified_broken":
        (ctx.out / "a1" / "verified.json").write_text("[{", encoding="utf-8")
        verified, why = o.load_verified(ctx)
        assert verified is None and why == "verified_unreadable"
    elif tamper == "other_attempt":
        monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")                                     # 重跑：上一次 attempt 的計畫不採用
    else:
        if tamper == "v1":
            bad["schema_version"] = 1
        elif tamper == "wrong_mode":
            bad["mode"] = "review"
        elif tamper == "pending":
            bad["status"] = "pending"
        elif tamper == "other_run":
            bad["run_id"] = "other"
        elif tamper == "sha":
            bad["verified_sha256"] = "0" * 64
        elif tamper == "bad_counts":
            bad["suggested"] = True
        elif tamper == "count_mismatch":
            bad["suggested"] += 1
        elif tamper == "bad_approved":                                                   # 不符資格的項目被寫成核准
            bad["approved"].insert(4, {"type": "task", "agent": "a4", "subagent": "impact-analyst", "event_id": "demo-firebase-public",
                                       "reason": "x"})
            bad["suggested"] += 1
        elif tamper == "reordered":
            bad["approved"] = [bad["approved"][-1], *bad["approved"][:-1]]
        elif tamper == "extra_key":
            bad["approved"][0]["score"] = 9
        elif tamper == "edited_reason":
            bad["approved"][0]["reason"] = "x" * 200                                     # 重跑後會被截斷，內容不一致
        elif tamper == "rejected_unsafe":
            bad["rejected"].append({"type": "task", "reason": o.R_TASK, "raw": "sk-ant-xxxx"})
            bad["suggested"] += 1
        elif tamper == "events":
            bad["events"] = bad["events"][:2]
        o.write_plan(path, bad)                                                          # 一律寫回派工單的位置
    r = o.resolve_plans(ctx, verified=verified, want=("dispatch", "review"))
    assert r.dispatch is None and r.reasons["dispatch"] == TAMPERS[tamper]
    assert no_checks(r.res)                                                              # 派工單無效 → res 沒有 planner_checks
    assert r.review is None


# ---------------------------------------------------------------- R5.1a 的分支
def test_valid_dispatch_and_bound_review(ctx):
    verified = a1_verified(ctx)
    dplan = dispatch_plan(ctx, verified)
    rplan = review_plan(ctx, verified)
    assert rplan["dispatch_plan_sha256"] == sha256_json(dplan) and rplan["mode"] == "review"
    assert [a["type"] for a in rplan["approved"]] == ["task", "priority", "summary"]
    assert [r["reason"] for r in rplan["rejected"]] == REVIEW_REASONS and rplan["suggested"] == 7
    assert rplan["summary"] == REVIEW["summary"]
    r = o.resolve_plans(ctx, verified=verified, want=("dispatch", "review"))
    assert r.reasons == {"dispatch": None, "review": None} and r.dispatch == dplan and r.review == rplan
    assert r.policies["review"].need_check == ["demo-cache-plaintext"]
    assert checks_of(r.res)["demo-erp-rce"] == ["C-NET-SEGMENT"]


def test_valid_dispatch_with_broken_review_keeps_dispatch(ctx):
    verified = a1_verified(ctx)
    dplan = dispatch_plan(ctx, verified)
    review_plan(ctx, verified)
    o.plan_path(ctx.out, "review").write_text("{broken", encoding="utf-8")
    r = o.resolve_plans(ctx, verified=verified, want=("dispatch", "review"))
    assert r.dispatch == dplan and r.review is None and r.reasons == {"dispatch": None, "review": "plan_unreadable"}
    assert checks_of(r.res)["demo-erp-rce"] == ["C-NET-SEGMENT"]                           # res 保留派工單的 control 結果


def test_review_bound_to_null_is_valid_when_dispatch_is_missing(ctx):
    verified = a1_verified(ctx)
    rplan = review_plan(ctx, verified)                                                    # 派工單缺失：綁定 null（R4.4）
    assert rplan["dispatch_plan_sha256"] is None
    r = o.resolve_plans(ctx, verified=verified, want=("dispatch", "review"))
    assert r.dispatch is None and r.reasons["dispatch"] == "plan_missing"
    assert r.review == rplan and r.reasons["review"] is None and no_checks(r.res)


def test_review_bound_to_null_is_disabled_when_dispatch_is_valid(ctx):
    verified = a1_verified(ctx)
    dplan = dispatch_plan(ctx, verified)
    review_plan(ctx, verified, bind=False)
    r = o.resolve_plans(ctx, verified=verified, want=("dispatch", "review"))
    assert r.dispatch == dplan and r.review is None and r.reasons["review"] == "review_dispatch_mismatch"
    assert checks_of(r.res)["demo-erp-rce"] == ["C-NET-SEGMENT"]


def test_review_bound_to_dispatch_is_disabled_when_dispatch_becomes_invalid(ctx):
    verified = a1_verified(ctx)
    dplan = dispatch_plan(ctx, verified)
    review_plan(ctx, verified)
    save(ctx, {**dplan, "run_id": "other"})                                               # 驗收之後派工單失效
    r = o.resolve_plans(ctx, verified=verified, want=("dispatch", "review"))
    assert r.dispatch is None and r.review is None
    assert r.reasons == {"dispatch": "plan_other_run", "review": "review_dispatch_mismatch"} and no_checks(r.res)


def test_tampered_review_only_disables_review(ctx):
    verified = a1_verified(ctx)
    dplan = dispatch_plan(ctx, verified)
    rplan = review_plan(ctx, verified)
    for bad in ({**rplan, "summary": "被改過的摘要"},
                {**rplan, "approved": [*rplan["approved"][:-1], {"type": "summary", "text": "C-NET-SEGMENT 需確認"}],
                 "summary": "C-NET-SEGMENT 需確認"},
                {**rplan, "dispatch_plan_sha256": "f" * 64}):
        save(ctx, bad)
        r = o.resolve_plans(ctx, verified=verified, want=("dispatch", "review"))
        assert r.dispatch == dplan and r.review is None and r.reasons["review"] is not None


def test_advisory_scope_rejects_retro_as_baseline(ctx):
    adv = replace(ctx, scenario="advisory", scope="advisory", advisory_id="adv-opsbuilder-2026-001", assets=["internal-tool"],
                  output_dir="advisories/adv-opsbuilder-2026-001/orch-run")
    verified = a1_verified(adv)
    plan = o.build_plan("dispatch", {"extra_tasks": [{"agent": "a3", "subagent": "retro-hunter", "event_id": "adv-opsbuilder-2026-001",
                                                      "reason": "回溯"}]}, ctx=adv, verified=verified, source="replay")
    assert plan["events"] == ["adv-opsbuilder-2026-001"] and [r["reason"] for r in plan["rejected"]] == [o.R_BASELINE]


# ---------------------------------------------------------------- R5.1b：evaluate 不改動輸入、跨程序雜湊一致
SUBPROC = """
import json, sys
from dataclasses import replace
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from context import build_ctx
from tools import orchestration as o
from tools.common import sha256_json
out, data, scenario, action = Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5]
ctx = replace(build_ctx(scenario=scenario), out=out, data_dir=data)
verified, why = o.load_verified(ctx)
if action == "resolve":
    r = o.resolve_plans(ctx, verified=verified, want=("dispatch", "review"))
    print(json.dumps({"sha": sha256_json(verified), "reasons": r.reasons}))
else:
    proposals = json.loads(Path(sys.argv[6]).read_text(encoding="utf-8"))
    base = o.base_inputs(ctx)
    res, dpol, dres = o.approve_core("dispatch", proposals["dispatch"], verified=verified, base_inputs=base)
    _, rpol, rres = o.approve_core("review", proposals["review"], verified=verified, base_inputs=base, dispatch_res=res)
    print(json.dumps({"dispatch": dpol.to_json(), "dispatch_result": dres, "review": rpol.to_json(), "review_result": rres},
                     sort_keys=True))
"""


def _subprocess(tmp_path, c, *args, seed="0"):
    script = tmp_path / "orch_subproc.py"
    script.write_text(SUBPROC, encoding="utf-8")
    env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run([sys.executable, str(script), str(AGENTS_DIR), str(c.out), str(c.data_dir), c.scenario, *args],
                          capture_output=True, text=True, encoding="utf-8", env=env, timeout=300)
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_update_event_hash_is_stable_across_processes(ctx, tmp_path):
    """inherit_updates 會原地改寫事件：evaluate 自己 deepcopy preverified，A1 原始 verified 的雜湊在各 Job 都相同（R5.1b）。"""
    peer = replace(ctx, scenario="peer-incident", output_dir="scenarios/peer-incident")
    base_verified = [verify_event(raw, as_of=peer.as_of, online=False) for raw in event_sources(peer.eval_input())]
    orig = next(v for v in base_verified if v["event"]["id"] == "demo-peer-mail-key")
    update = copy.deepcopy(orig)
    update["event"].update(id="demo-peer-mail-key-2", is_update_of="demo-peer-mail-key", title="示範：同業金鑰外洩新進度",
                           date="2026-11-09", controls=[], products=[], revision="2026-11-09.1")
    verified = a1_verified(peer, extra=[update])
    sha = sha256_json(verified)
    res = evaluate(replace(o.base_inputs(peer).eval_input, preverified=verified))
    upd = next(e for e in res["events"] if e["id"] == "demo-peer-mail-key-2")
    assert upd["controls"] == ["C-THIRD-PARTY-KEY-ROTATION"]                                # 評估內的拷貝已套用繼承
    assert next(v for v in verified if v["event"]["id"] == "demo-peer-mail-key-2")["event"]["controls"] == []
    assert sha256_json(verified) == sha                                                    # evaluate 不改動輸入
    proposal = {"extra_controls": [
        {"event_id": "demo-peer-mail-key-2", "control_id": "C-THIRD-PARTY-KEY-ROTATION", "reason": "x"},   # 繼承後已對應
        {"event_id": "demo-peer-mail-key-2", "control_id": "C-NET-SEGMENT", "reason": "一併確認網段"}],
        "extra_tasks": [{"agent": "a4", "subagent": "impact-analyst", "event_id": "demo-peer-mail-key-2", "reason": "補充"}]}
    dplan = dispatch_plan(peer, verified, proposal)
    assert [r["reason"] for r in dplan["rejected"]] == [o.R_MAPPED] and len(dplan["approved"]) == 2
    review_plan(peer, verified, proposal={"summary": "新進度已派工追加說明。"})
    assert sha256_json(verified) == sha == dplan["verified_sha256"]
    got = _subprocess(tmp_path, peer, "resolve")                                           # 另一個程序（另一個 Job）載入核對
    assert got == {"sha": sha, "reasons": {"dispatch": None, "review": None}}


def test_candidates_and_approvals_do_not_depend_on_hash_seed(ctx, tmp_path):
    a1_verified(ctx)
    proposals = tmp_path / "proposals.json"
    proposals.write_text(json.dumps({"dispatch": DISPATCH, "review": REVIEW}, ensure_ascii=False), encoding="utf-8")
    a = _subprocess(tmp_path, ctx, "policy", str(proposals), seed="0")
    b = _subprocess(tmp_path, ctx, "policy", str(proposals), seed="4242")
    assert a == b
    assert [r["reason"] for r in a["dispatch_result"]["rejected"]] == DISPATCH_REASONS
    assert [r["reason"] for r in a["review_result"]["rejected"]] == REVIEW_REASONS
