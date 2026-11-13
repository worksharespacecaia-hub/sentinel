"""Orchestrator 的核准政策（specs/orchestrator R3、R4.3、R6.3；design §3.2、§8 的 test_orchestration）：純函式，不呼叫 LLM。

取代 v0.11.0 的 test_agent_plan.py：新事件篩選、格式檢查、追加風險挑選沿用；approve 改為依政策上下文的兩種模式核准。
建立與載入（approve_core、resolve_plans）的整合測試在 test_resolve_plans.py。
"""
import json

import pytest

from llm import _validate
from tools.orchestration import (A2_EVENT_CATEGORY, DISPATCH_TASKS, MAX_A2_FINDINGS, MAX_EVENTS, NOTE_NO_PREV, R_BASELINE,
                                 R_CONTROL, R_DUP, R_EVENT, R_FIELDS, R_LIMIT, R_MAPPED, R_NO_TARGET, R_NOT_KEYROT,
                                 R_NOT_NEED_CHECK, R_NOTICE_NEEDED, R_ONLY_ADD, R_PRIORITY, R_REASON, R_SUMMARY, R_TASK,
                                 REASONS, REVIEW_TASKS, PolicyContext, _valid_rejected, a2_candidates, a3_systems, a4_baseline,
                                 a4_extra_candidates, a5_lists, approve, clean_summary, effective_events, event_relations,
                                 keyrot_candidates, new_peer_events, pick_extra_risks, plan_items, planner_checks, prev_daily_ids,
                                 scope_events, validate_plan_shape, validate_review_shape)

CONTROLS = {f"C-{n}": f"控制項 {n}" for n in ("A", "B", "C", "D", "E", "F", "G", "H", "I")}


def ev(eid, kind="live", date="2026-11-10", controls=(), **kw):
    return {"id": eid, "kind": kind, "date": date, "title": f"事件 {eid}", "controls": list(controls), **kw}


def reasons(res):
    return [r["reason"] for r in res["rejected"]]


# ---------------------------------------------------------------- 事件範圍（沿用 dynamic-planner R1）
def test_new_peer_events_excludes_advisory_archive_and_previous():
    events = [ev("live-a"), ev("demo-b", kind="demo"), ev("adv-c", kind="advisory"), ev("evt-d", kind="archive"), ev("live-old")]
    sel, note = new_peer_events(events, {"live-old"})
    assert [e["id"] for e in sel] == ["demo-b", "live-a"] and note is None      # 同日依 ID 升冪


def test_missing_previous_list_treats_all_as_new():
    sel, note = new_peer_events([ev("live-a"), ev("live-b")], None)
    assert len(sel) == 2 and note == NOTE_NO_PREV


def test_updates_need_their_own_new_id():
    events = [ev("live-a"), ev("live-a-2", is_update_of="live-a")]
    assert [e["id"] for e in new_peer_events(events, {"live-a", "live-a-2"})[0]] == []     # 同一個更新 ID 不重觸發
    assert [e["id"] for e in new_peer_events(events, {"live-a"})[0]] == ["live-a-2"]


def test_limit_sort_and_invalid_dates():
    events = [ev(f"live-{i}", date=f"2026-11-{i + 1:02d}") for i in range(7)] + [ev("live-x", date="bad"), ev("live-0")]
    sel, note = new_peer_events(events, set())
    assert len(sel) == MAX_EVENTS and sel[0]["id"] == "live-6" and "live-x" not in [e["id"] for e in sel]
    assert "日期無效" in note
    sel, _ = new_peer_events([ev("live-x", date="bad"), ev("live-y")], set())
    assert [e["id"] for e in sel] == ["live-y", "live-x"]                           # 無效日期排最後


@pytest.mark.parametrize("content,expected", [
    ({"events": [{"id": "live-a"}]}, {"live-a"}), ({"events": []}, set()), (None, None), ("not json", None),
    ({"events": {"id": "x"}}, None), ({"events": [{"no": 1}]}, None),
])
def test_prev_daily_ids(tmp_path, content, expected):
    p = tmp_path / "daily" / "state" / "intel.json"
    if content is not None:
        p.parent.mkdir(parents=True)
        p.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    assert prev_daily_ids(tmp_path) == expected


def test_effective_events_inherit_controls_without_touching_verified():
    verified = [{"event": ev("live-a", controls=["C-A"]), "verification": {}},
                {"event": ev("live-b", is_update_of="live-a"), "verification": {}}]
    before = json.dumps(verified, sort_keys=True)
    events = effective_events(verified)
    assert events[1]["controls"] == ["C-A"] and json.dumps(verified, sort_keys=True) == before


def test_advisory_scope_is_only_this_advisory():
    verified = [{"event": e, "verification": {}} for e in (ev("adv-a", kind="advisory"), ev("adv-b", kind="advisory"), ev("live-c"))]
    assert [e["id"] for e in scope_events(verified, scope="advisory", prev_ids=set(), advisory_id="adv-b")[0]] == ["adv-b"]
    assert scope_events(verified, scope="advisory", prev_ids=set(), advisory_id=None)[0] == []
    assert [e["id"] for e in scope_events(verified, scope="scenario", prev_ids=set())[0]] == ["live-c"]   # 公告不是同業事件


# ---------------------------------------------------------------- 整份格式（R3.1、R4.3）
@pytest.mark.parametrize("bad", [None, [], "x", {"extra_controls": None}, {"extra_controls": {}}, {"extra_tasks": ["x"]},
                                 {"priorities": "x"}, {"priorities": [1]}, {"extra_controls": [{"reason": "DEMO-FAKE-ABCD-1234"}]}])
def test_plan_shape_rejects(bad):
    with pytest.raises(ValueError):
        validate_plan_shape(bad)
    with pytest.raises(ValueError):
        _validate("plan", bad, set())


@pytest.mark.parametrize("ok", [{}, {"extra_controls": []}, {"extra_tasks": []}, {"priorities": []}, {"skip_agents": ["a2"]}])
def test_plan_shape_accepts(ok):
    assert _validate("plan", ok, set()) == ok                                         # 未知鍵留給 approve


@pytest.mark.parametrize("bad", [None, [], {"extra_tasks": {}}, {"priorities": ["x"]}, {"summary": None}, {"summary": ["x"]},
                                 {"summary": "DEMO-FAKE-ABCD-1234"}])
def test_review_shape_rejects(bad):
    with pytest.raises(ValueError):
        validate_review_shape(bad)
    with pytest.raises(ValueError):
        _validate("review", bad, set())


@pytest.mark.parametrize("ok", [{}, {"extra_tasks": []}, {"priorities": []}, {"summary": "摘要"}, {"extra_controls": []}])
def test_review_shape_accepts(ok):
    assert _validate("review", ok, set()) == ok                                       # extra_controls 是未知鍵，留給 approve


# ---------------------------------------------------------------- 派工的核准（R3）
def dctx(**kw):
    base = dict(mode="dispatch", scope="scenario", controls=dict(CONTROLS),
                events={"live-a": ev("live-a", controls=["C-A"]), "live-b": ev("live-b"), "live-c": ev("live-c")},
                a2={"live-a": {"dependency-analyst": ["f1"]}}, a3={"live-a": ["sys-1"], "live-b": ["sys-2"]},
                a4_baseline=["r-h1", "r-h2"], a4_extra={"live-a": ["r-x"], "live-b": ["r-y"]})
    base.update(kw)
    return PolicyContext(**base)


def task(agent, sub, eid="live-a", reason="理由", **kw):
    return {"agent": agent, "subagent": sub, "event_id": eid, "reason": reason, **kw}


def test_dispatch_mixed_valid_and_invalid():
    res = approve({
        "extra_controls": [
            {"event_id": "live-a", "control_id": "C-B", "reason": "值得確認"},
            {"event_id": "live-a", "control_id": "C-ZZZ", "reason": "未知"},
            {"event_id": "live-zz", "control_id": "C-B", "reason": "範圍外"},
            {"event_id": "live-a", "control_id": "C-A", "reason": "已對應"},
            {"event_id": "live-a", "control_id": "C-B", "reason": "重複"},
            {"event_id": "live-a", "control_id": "C-C", "reason": "   "},
            {"event_id": "live-a", "control_id": "C-C", "reason": "x", "score": 5},
            {"event_id": 1, "control_id": "C-C", "reason": "x"},
        ],
        "extra_tasks": [
            task("a4", "impact-analyst", "live-b", "補充說明"),
            task("a2", "secret-analyst"),                                       # 不在派工選單
            task("a4", "impact-analyst", "live-b", "重複"),
            task("a5", "intel-report-writer"),                                  # 驗收的任務，不能在派工提出
            task("a4", "impact-analyst", "live-a", risk_id="r-x"),               # 派工沒有 risk_id 欄位
        ],
        "priorities": [{"agent": "a4", "risk_id": "r-h1", "reason": "先說明"}, {"agent": "a4", "risk_id": "r-x", "reason": "x"}],
        "skip_agents": ["a2"], "disable": True, "summary": "派工沒有摘要",
    }, dctx())
    assert [a["type"] for a in res["approved"]] == ["control", "task", "priority"]
    assert reasons(res) == [R_ONLY_ADD] * 3 + [R_CONTROL, R_EVENT, R_MAPPED, R_DUP, R_REASON, R_ONLY_ADD, R_FIELDS,
                                               R_TASK, R_DUP, R_TASK, R_ONLY_ADD, R_PRIORITY]
    assert res["suggested"] == len(res["approved"]) + len(res["rejected"]) == 18       # N = M + K
    text = json.dumps(res, ensure_ascii=False)
    for banned in ("skip_agents", "score", "C-ZZZ", "live-zz", "secret-analyst", "intel-report-writer", "派工沒有摘要"):
        assert banned not in text, banned
    assert all(set(r) <= {"type", "event_id", "control_id", "agent", "subagent", "risk_id", "suggested_reason", "reason"}
               for r in res["rejected"])


@pytest.mark.parametrize("item,ctx_kw,expected", [
    (task("a2", "dependency-analyst"), {}, None),
    (task("a2", "runtime-analyst"), {}, R_NO_TARGET),                         # 這件事件沒有 eol 對象
    (task("a2", "dependency-analyst", "live-c"), {}, R_NO_TARGET),
    (task("a3", "retro-hunter"), {}, None),
    (task("a3", "retro-hunter", "live-c"), {}, R_NO_TARGET),                  # 一個系統都沒有就拒絕
    (task("a3", "retro-hunter"), {"scope": "advisory"}, R_BASELINE),            # 公告調查本來就會跑
    (task("a4", "impact-analyst"), {}, None),
    (task("a4", "impact-analyst", "live-c"), {}, R_NO_TARGET),
    (task("a4", "impact-analyst", "live-zz"), {}, R_EVENT),
    (task("a1", "planner"), {}, R_TASK),
])
def test_dispatch_task_eligibility(item, ctx_kw, expected):
    res = approve({"extra_tasks": [item]}, dctx(**ctx_kw))
    assert (reasons(res) or [None]) == [expected]
    if expected is None:
        assert res["approved"] == [{"type": "task", "agent": item["agent"], "subagent": item["subagent"], "event_id": item["event_id"],
                                    "reason": "理由"}]


def test_dispatch_limits_and_rejections_do_not_use_quota():
    events = {f"live-{i}": ev(f"live-{i}") for i in range(6)}
    ids = list(CONTROLS)
    out = {"extra_controls": [{"event_id": "live-0", "control_id": "C-ZZ", "reason": "x"}]
           + [{"event_id": "live-0", "control_id": c, "reason": "r"} for c in ids[:4]]
           + [{"event_id": f"live-{i}", "control_id": c, "reason": "r"} for i in (1, 2, 3) for c in ids[:3]],
           "extra_tasks": [task("a2", "secret-analyst")]
           + [task("a4", "impact-analyst", f"live-{i}") for i in range(6)],
           "priorities": [{"agent": "a4", "risk_id": "nope", "reason": "r"}]
           + [{"agent": "a4", "risk_id": f"r-{i}", "reason": "r"} for i in range(6)]}
    ctx = dctx(events=events, a4_extra={f"live-{i}": [f"x-{i}"] for i in range(6)}, a4_baseline=[f"r-{i}" for i in range(10)])
    res = approve(out, ctx)
    ctrls = [a for a in res["approved"] if a["type"] == "control"]
    assert len(ctrls) == 8 and sum(1 for a in ctrls if a["event_id"] == "live-0") == 3
    assert len([a for a in res["approved"] if a["type"] == "task"]) == 5               # 追加任務總共最多 5 項
    assert len([a for a in res["approved"] if a["type"] == "priority"]) == 5           # 排優先最多 5 項
    # live-0 第 4 個（每件上限）、live-2 第 3 個與 live-3 全部（總數上限）、第 6 個追加任務、第 6 個排優先
    assert reasons(res).count(R_LIMIT) == 1 + 1 + 3 + 1 + 1
    assert reasons(res).count(R_CONTROL) == 1 and reasons(res).count(R_TASK) == 1 and reasons(res).count(R_PRIORITY) == 1


def test_reason_is_trimmed_and_truncated():
    res = approve({"extra_controls": [{"event_id": " live-a ", "control_id": " C-B ", "reason": "  " + "很" * 200}]}, dctx())
    a = res["approved"][0]
    assert a["event_id"] == "live-a" and a["control_id"] == "C-B" and len(a["reason"]) <= 120


def test_priorities_only_reorder_baseline():
    ctx = dctx()
    res = approve({"priorities": [{"agent": "a4", "risk_id": "r-h2", "reason": "先講"}, {"agent": "a5", "risk_id": "r-h1", "reason": "x"},
                                  {"agent": "a4", "risk_id": "r-h2", "reason": "重複"}, {"agent": "a4", "risk_id": "r-h1", "reason": ""},
                                  {"agent": "a4", "risk_id": "r-h1", "reason": "x", "order": 1}]}, ctx)
    assert res["approved"] == [{"type": "priority", "agent": "a4", "risk_id": "r-h2", "reason": "先講"}]
    assert reasons(res) == [R_PRIORITY, R_DUP, R_REASON, R_ONLY_ADD]


def test_non_object_items_are_rejected_not_crash():
    res = approve({"extra_tasks": "x", "priorities": [1, None]}, dctx())
    assert reasons(res) == [R_FIELDS] * 3 and res["suggested"] == 3


# ---------------------------------------------------------------- 驗收的核准（R4.3）
def rctx(**kw):
    base = dict(mode="review", scope="scenario",
                events={e: ev(e) for e in ("live-a", "live-b", "live-c", "live-d")},
                need_check=["live-a"], keyrot=["k-1"], notice=["live-b"], notice_needed=["live-c"],
                a5_remediation=["r-1", "r-2"], a5_ceo=["r-1", "r-3"])
    base.update(kw)
    return PolicyContext(**base)


def rtask(sub, reason="理由", **target):
    return {"agent": "a5", "subagent": sub, "reason": reason, **target}


@pytest.mark.parametrize("item,expected", [
    (rtask("intel-report-writer", event_id="live-a"), None),
    (rtask("intel-report-writer", event_id="live-b"), R_NOT_NEED_CHECK),
    (rtask("intel-report-writer", event_id="live-zz"), R_EVENT),
    (rtask("key-rotation-advisor", risk_id="k-1"), None),
    (rtask("key-rotation-advisor", risk_id="r-1"), R_NOT_KEYROT),
    (rtask("key-rotation-advisor", event_id="live-a"), R_ONLY_ADD),                # 風險目標的任務不能帶 event_id
    (rtask("key-rotation-advisor", risk_id="k-1", event_id="live-a"), R_ONLY_ADD),
    (rtask("intel-report-writer", risk_id="k-1"), R_ONLY_ADD),
    (rtask("key-rotation-advisor"), R_FIELDS),
    (rtask("brand-notice-writer", event_id="live-b"), None),
    (rtask("brand-notice-writer", event_id="live-c"), R_NOTICE_NEEDED),
    (rtask("brand-notice-writer", event_id="live-d"), R_NO_TARGET),
    ({"agent": "a4", "subagent": "impact-analyst", "event_id": "live-a", "reason": "x"}, R_TASK),   # 派工的任務
    (rtask("remediation-advisor", event_id="live-a"), R_TASK),
])
def test_review_task_eligibility(item, expected):
    res = approve({"extra_tasks": [item]}, rctx())
    assert (reasons(res) or [None]) == [expected]


def test_review_limits_priorities_and_summary():
    res = approve({
        "extra_tasks": [rtask("intel-report-writer", event_id="live-a"), rtask("brand-notice-writer", event_id="live-b"),
                        rtask("key-rotation-advisor", risk_id="k-1"), rtask("intel-report-writer", event_id="live-a"),
                        rtask("brand-notice-writer", event_id="live-c")],
        "priorities": [{"agent": "a5", "risk_id": "r-3", "reason": "先寫"}, {"agent": "a5", "risk_id": "r-2", "reason": "再寫"},
                       {"agent": "a5", "risk_id": "k-1", "reason": "x"}, {"agent": "a4", "risk_id": "r-1", "reason": "x"}],
        "summary": "  今日派工 3 項皆完成，\n需確認事件已補摘要。 ",
        "extra_controls": [{"event_id": "live-a", "control_id": "C-A", "reason": "驗收不能加查"}],
    }, rctx())
    assert [a["type"] for a in res["approved"]] == ["task"] * 3 + ["priority"] * 2 + ["summary"]
    assert res["approved"][-1] == {"type": "summary", "text": "今日派工 3 項皆完成， 需確認事件已補摘要。"}
    assert reasons(res) == [R_ONLY_ADD, R_DUP, R_NOTICE_NEEDED, R_PRIORITY, R_PRIORITY]   # 拒絕不佔配額：第 4、5 項先被拒
    assert res["suggested"] == 11


def test_review_task_limit():
    items = [rtask("intel-report-writer", event_id="live-a"), rtask("brand-notice-writer", event_id="live-b"),
             rtask("key-rotation-advisor", risk_id="k-1"), rtask("key-rotation-advisor", risk_id="k-2")]
    res = approve({"extra_tasks": items}, rctx(keyrot=["k-1", "k-2"]))
    assert len(res["approved"]) == 3 and reasons(res) == [R_LIMIT]                       # 追加任務最多 3 項


@pytest.mark.parametrize("summary,expected", [
    ("執行摘要：派工與驗收完成。", None),
    ("聯絡 a@b.com 確認", R_SUMMARY),                        # 個資
    ("金鑰 sk-ant-abcdefghijklmnopqrstuvwxyz 已輪替", R_SUMMARY),
    ("請看 out/a1/verified.json", R_SUMMARY),                 # 檔案路徑
    ("主機 10.0.0.5 有異常", R_SUMMARY),                       # IP
    ("確認 C-NET-SEGMENT 結果", R_SUMMARY),                   # 控制項 ID
    ("連接埠 :8443 對外", R_SUMMARY),
    ("設定 session.cookie_secure 要改", R_SUMMARY),
    ("很" * 301, R_LIMIT),
    ("   ", R_FIELDS),
])
def test_summary_checks(summary, expected):
    text, why = clean_summary(summary)
    assert why == expected and (text is None) == (expected is not None)
    res = approve({"summary": summary}, rctx())
    if expected:
        assert res["approved"] == [] and res["rejected"] == [{"type": "summary", "reason": expected}]   # 不保存被拒絕的原文
    else:
        assert res["approved"] == [{"type": "summary", "text": summary}]


def test_rejected_rows_keep_only_known_ids():
    res = approve({"extra_tasks": [rtask("key-rotation-advisor", "理由", risk_id="made-up-risk"),
                                   rtask("key-rotation-advisor", "理由", risk_id="r-1")]}, rctx())
    assert res["rejected"][0] == {"type": "task", "agent": "a5", "subagent": "key-rotation-advisor", "suggested_reason": "理由",
                                  "reason": R_NOT_KEYROT}                                # 編造的 ID 不保存
    assert res["rejected"][1]["risk_id"] == "r-1"
    pol = rctx()
    assert all(_valid_rejected(r, pol) for r in res["rejected"])
    assert not _valid_rejected({"type": "task", "reason": "自己編的原因"}, pol)
    assert not _valid_rejected({"type": "task", "reason": R_TASK, "raw": "x"}, pol)
    assert not _valid_rejected({"type": "task", "reason": R_TASK, "agent": "a4", "subagent": "impact-analyst"}, pol)


def test_plan_items_round_trip():
    res = approve({"extra_tasks": [rtask("intel-report-writer", event_id="live-a")],
                   "priorities": [{"agent": "a5", "risk_id": "r-1", "reason": "r"}], "summary": "摘要"}, rctx())
    again = approve(plan_items({"approved": res["approved"]}), rctx())
    assert again["approved"] == res["approved"] and again["rejected"] == []
    assert plan_items({"approved": [{"type": "summary", "text": "a"}, {"type": "summary", "text": "b"}]}) is None
    assert plan_items({"approved": [{"type": "field"}]}) is None and plan_items({"approved": ["x"]}) is None


def test_menus_exist_in_registry_and_reasons_are_documented():
    from agents.common import CATEGORY_SUBAGENT
    from registry import AGENTS
    for agent, sub in [*DISPATCH_TASKS, *REVIEW_TASKS]:
        assert sub in AGENTS[agent].subagents, (agent, sub)
    for sub, cat in A2_EVENT_CATEGORY.items():
        assert CATEGORY_SUBAGENT[cat] == sub                                           # 沿用 CATEGORY_SUBAGENT（R3.2）
    assert {R_ONLY_ADD, R_NO_TARGET, R_BASELINE, R_PRIORITY, R_NOT_NEED_CHECK, R_NOT_KEYROT, R_NOTICE_NEEDED, R_SUMMARY} <= REASONS


# ---------------------------------------------------------------- 候選（R3.2～R3.4、R4.1）：純函式
def imp(asset, verdict="affected", risk=None, suggestions=None):
    out = {"asset_id": asset, "verdict": verdict, "risk_id": risk}
    if suggestions is not None:
        out["suggestions"] = suggestions
    return out


def match(eid, impacts, checks=()):
    return {"event": {"id": eid}, "impacts": impacts, "planner_checks": list(checks), "status": "open"}


def finding(fid, asset, cat, comp):
    return {"id": fid, "asset_id": asset, "category": cat, "component": comp}


def test_a2_candidates_normalize_category_systems_sort_and_cap():
    events = [ev("e1", products=[{"name": "Next.js"}, {"name": "PHP-FPM"}]), ev("e2", products=[{"name": "lodash"}])]
    matches = {"e1": match("e1", [imp("web-b"), imp("web-a", "need_check"), imp("*", "need_check"), imp("web-z", "not_affected")]),
               "e2": match("e2", [imp("api")])}
    findings = [finding("web-b:next:vuln", "web-b", "vuln", "nextjs"), finding("web-a:next:vuln", "web-a", "vuln", "next"),
                finding("web-a:next:vuln", "web-a", "vuln", "next"),                       # 重複的 finding ID
                finding("web-z:next:vuln", "web-z", "vuln", "next"),                       # 不受影響的系統
                finding("web-a:php:eol", "web-a", "eol", "php"), finding("web-a:php:secret", "web-a", "secret", "php"),
                finding("web-b:react:vuln", "web-b", "vuln", "react")]
    findings += [finding(f"api:lodash:{i:02d}", "api", "vuln", "lodash") for i in range(15)]
    out = a2_candidates(events, matches, findings)
    assert out["e1"] == {"dependency-analyst": ["web-a:next:vuln", "web-b:next:vuln"], "runtime-analyst": ["web-a:php:eol"]}
    assert out["e2"]["dependency-analyst"] == [f"api:lodash:{i:02d}" for i in range(MAX_A2_FINDINGS)]
    assert "runtime-analyst" not in out["e2"]
    assert a2_candidates([ev("e3")], {"e3": match("e3", [imp("web-a")])}, findings) == {}       # 事件沒有產品


def test_a3_systems_use_impacts_and_hypotheses_within_ai_assets():
    sug = [{"inferred": True, "systems": [{"asset_id": "db-1"}, {"asset_id": "secret-store"}]},
           {"inferred": False, "systems": [{"asset_id": "not-inferred"}]}]
    events = [ev("e1"), ev("e2"), ev("e3")]
    matches = {"e1": match("e1", [imp("web-b"), imp("*", "need_check", suggestions=sug), imp("web-x", "not_affected"),
                                  imp("not-inferred")]),
               "e2": match("e2", [imp(f"s-{i}") for i in range(7)]), "e3": match("e3", [imp("outside")])}
    assets = {"web-b", "db-1", "not-inferred", *{f"s-{i}" for i in range(7)}}
    out = a3_systems(events, matches, assets)
    assert out["e1"] == ["db-1", "not-inferred", "web-b"]                         # secret-store 不在 ai_assets；web-x 不受影響
    assert out["e2"] == [f"s-{i}" for i in range(5)] and "e3" not in out          # 最多 5 個；一個都沒有就沒有候選


def risk(rid, asset, level="medium", score=5, matched=(), status="open", category="config"):
    return {"id": rid, "asset_id": asset, "level": level, "score": score, "matched_events": list(matched), "status": status,
            "finding_ids": [rid], "category": category, "breakdown": []}


def test_a4_baseline_and_extra_candidates():
    risks = [risk(f"h{i}", f"a{i}", "high", 9) for i in range(12)] + [risk("m1", "x", matched=["e1"]), risk("h0b", "y", matched=["e1"])]
    risks[0]["matched_events"] = ["e1"]
    risks[1]["status"] = "fixed"
    base = a4_baseline(risks)
    assert base == ["h0", *(f"h{i}" for i in range(2, 11))]                          # 前 10 個未修復的高風險
    out = a4_extra_candidates([ev("e1"), ev("e2")], {}, risks, base)
    assert out == {"e1": ["h0b", "m1"]}                                               # 排除必要任務（h0）；依等級、分數、ID 排序


def test_pick_extra_risks():
    risks = [risk("a:C-A", "a", "low", 2), risk("a:C-B", "a", "high", 9), risk("b:x", "b", "high", 8, matched=["e"]),
             risk("c:y", "c", "medium", 4, matched=["e"]), risk("d:z", "d", matched=["e"], status="fixed"),
             risk("f:w", "f", "high", 9, matched=["e"]), risk("g:v", "g", "low", 1, matched=["e"])]
    checks = [{"control_id": "C-A", "status": "fail", "assets": [{"asset_id": "a"}]}]
    picked = pick_extra_risks("e", risks, checks, already={"f:w"})
    assert [r["id"] for r in picked] == ["b:x", "c:y", "a:C-A"]                        # 同資產不同控制項（a:C-B）不誤選
    assert pick_extra_risks("nothing", risks, [], set()) == []


def test_pick_extra_risks_list_changes_with_controls():
    """加入 control 後名單會變（[r1,r2,r3] → [r0,r1,r2]）：資格以核心第 3 步（含 control 的評估）為準。"""
    risks = [risk("r1", "a", score=5, matched=["e"]), risk("r2", "b", score=4, matched=["e"]), risk("r3", "c", score=3, matched=["e"]),
             risk("x:C-A", "x", "high", 9)]
    assert [r["id"] for r in pick_extra_risks("e", risks, [], set())] == ["r1", "r2", "r3"]
    checks = [{"control_id": "C-A", "status": "fail", "assets": [{"asset_id": "x"}]}]
    assert [r["id"] for r in pick_extra_risks("e", risks, checks, set())] == ["x:C-A", "r1", "r2"]


def test_planner_checks_maps_status_and_missing():
    approved = [{"type": "control", "event_id": "e", "control_id": "C-A", "reason": "r1"},
                {"type": "control", "event_id": "e", "control_id": "C-B", "reason": "r2"},
                {"type": "control", "event_id": "other", "control_id": "C-A", "reason": "r3"}]
    results = {"C-A": {"status": "fail", "title": "A", "reason": "不符", "assets": [{"asset_id": "x", "evidence": ["e1"]}]}}
    checks = planner_checks("e", approved, results)
    assert [(c["control_id"], c["status"]) for c in checks] == [("C-A", "fail"), ("C-B", "unknown")]
    assert checks[1]["assets"] == [] and checks[1]["check_reason"] == "本次檢查結果缺失"


def test_review_candidates():
    """R4.1：需確認事件、金鑰輪替候選、通知草稿候選、A5 兩份清單。"""
    pii = [{"factor": "資料敏感", "points": 2, "reason": ""}, {"factor": "影響範圍", "points": 1, "reason": ""}]
    risks = [risk("h-secret", "vault", "high", 9, category="secret"),                       # A5 必要任務已涵蓋
             risk("r-pii", "member-db", "high", 8, matched=["e-pii"]),
             risk("r-open", "web", "medium", 6, matched=["e-open"]),
             risk("k-match", "other", "low", 2, matched=["e-open"], category="identity"),   # 命中本次事件
             risk("k-sys", "db-2", "low", 2, category="secret"),                            # 資產在推測系統
             risk("k-far", "far", "low", 1, category="secret"),                             # 和本次事件無關
             risk("k-fixed", "web", "low", 1, status="fixed", category="secret"),
             risk("k-out", "web", "low", 1, matched=["e-out"], category="secret")]          # 命中範圍外的事件、資產也不相關
    risks[1]["breakdown"] = pii
    risks[5]["asset_id"] = "far"
    risks[7]["asset_id"] = "unrelated"
    events = [ev("e-need"), ev("e-open"), ev("e-pii"), ev("e-notice", notice_required=True), ev("e-none")]
    sug = [{"inferred": True, "systems": [{"asset_id": "db-2"}]}]
    m = {"e-need": {**match("e-need", [imp("*", "need_check", suggestions=sug)]), "status": "need_check"},
         "e-open": match("e-open", [imp("web", risk="r-open")]),
         "e-pii": match("e-pii", [imp("member-db", risk="r-pii")]),
         "e-notice": {**match("e-notice", [imp("web", risk="r-open")]), "event": ev("e-notice", notice_required=True)},
         "e-none": {**match("e-none", []), "status": "not_affected"}}
    rel = event_relations(events, m, risks)
    assert rel == {"e-need": ("need_check", False), "e-open": ("open", False), "e-pii": ("open", True),
                   "e-notice": ("open", True), "e-none": ("not_affected", False)}
    assert keyrot_candidates(events, m, risks) == ["k-match", "k-sys"]
    remediation, ceo, covered = a5_lists(risks)
    assert remediation == ["h-secret", "r-pii", "r-open"] and ceo == remediation and covered == {"h-secret"}


# ---------------------------------------------------------------- 預算與預留鍵（R6.3、design §6）
def test_two_agent_specs_have_separate_budgets_and_reservation_keys(monkeypatch, tmp_path):
    """兩個獨立的 RunCtx（兩個 Job）＋ RemoteBudget 替身：預留鍵帶各自的 Agent 名稱，互不衝突，也不跨 Job 累計。"""
    from dataclasses import replace

    from context import build_ctx
    from llm import LLMRunner, Task
    from tools import budget
    from tools.cache import LLMCache, ReplayStore
    for k in ("TARGET_DIR", "SCANNERS_DIR", "ADVISORY_ID", "ASSETS", "TARGET_SHA", "EXECUTION_MODE", "GITHUB_RUN_ATTEMPT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("RUN_ID", "run-9")
    monkeypatch.setenv("SENTINEL_BASE_URL", "https://example.invalid")
    monkeypatch.setenv("NOTIFY_TOKEN", "test-token")
    posts = []

    def fake_post(self, body):
        posts.append(body)
        return {"ok": True, "key": body.get("key")}
    monkeypatch.setattr(budget.RemoteBudget, "_post", fake_post)
    seen_budget = {}

    async def fake_query(self, pending, graph_query):
        seen_budget[self.agent] = self._call_budget
        return {t.id: ({} if t.subagent == "planner" else {"summary": "摘要"}) for t, _ in pending}, 0.01
    monkeypatch.setattr(LLMRunner, "_query", fake_query)
    for agent, sub in (("orchestrator-dispatch", "planner"), ("orchestrator-review", "reviewer")):
        c = replace(build_ctx(mode="live", scenario="peer-incident"), out=tmp_path / agent / "out",
                    cache=LLMCache(tmp_path / agent / "c.json"), replay=ReplayStore(tmp_path / agent / "r"))
        out = c.runner(agent).run([Task(id=sub, subagent=sub, payload={"ids": [sub]})])
        assert out[sub]["source"] == "live" and c.cost["per_agent"] == {agent: 0.01}       # 各 Job 只用自己的預算
    keys = [p["key"] for p in posts if p["action"] == "reserve"]
    assert keys == ["run-9-1/orchestrator-dispatch/orchestrator-dispatch/1", "run-9-1/orchestrator-review/orchestrator-review/1"]
    assert seen_budget == {"orchestrator-dispatch": 0.05, "orchestrator-review": 0.05}
