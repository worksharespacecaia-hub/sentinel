"""動態派工（specs/dynamic-planner）：新事件篩選、planner 輸入、格式檢查、逐項核准、追加風險挑選。純函式，不呼叫 LLM。"""
import json

import pytest

from llm import _validate
from tools.agent_plan import (MAX_EVENTS, NOTE_NO_PREV, R_CONTROL, R_DUP, R_EVENT, R_FIELDS, R_LIMIT, R_MAPPED, R_ONLY_ADD,
                              R_REASON, R_TASK, approve, build_payload, effective_events, new_peer_events, pick_extra_risks,
                              planner_checks, prev_daily_ids, validate_plan_shape)

CONTROLS = [{"id": f"C-{n}", "title": f"控制項 {n}"} for n in ("A", "B", "C", "D", "E", "F", "G", "H", "I")]


def ev(eid, kind="live", date="2026-11-10", controls=(), **kw):
    return {"id": eid, "kind": kind, "date": date, "title": f"事件 {eid}", "controls": list(controls), **kw}


# ---------------------------------------------------------------- R1 新事件
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
    assert [e["id"] for e in new_peer_events([ev("live-a"), ev("live-a", date="2026-01-01")], set())[0]] == ["live-a"]


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


# ---------------------------------------------------------------- R2 輸入
def test_payload_is_sanitized_and_stable():
    e = ev("live-a", controls=["C-B", "C-A", "C-A"], industry="電商 sk-ant-abcdefghijklmnop", attck=["T2", "T1", "T1"],
           attack_chain=["步驟一", "聯絡 a@b.com", *[f"s{i}" for i in range(9)]], cves=["CVE-2026-0002", "CVE-2026-0001"])
    p = build_payload([e], CONTROLS)
    row = p["events"][0]
    assert row["controls_already"] == ["C-A", "C-B"] and row["attck"] == ["T1", "T2"] and row["cves"][0] == "CVE-2026-0001"
    assert "sk-ant" not in (row["industry"] or "") and len(row["attack_chain"]) <= 5 and all("@" not in s for s in row["attack_chain"])
    text = json.dumps(p, ensure_ascii=False)
    for banned in ("as_of", "run_id", "status", "assets", "evidence", "sk-ant"):
        assert banned not in text
    assert p == build_payload([e], list(reversed(CONTROLS)))                          # 順序正規化
    assert "DEMO-FAKE" not in json.dumps(build_payload([{**e, "title": "DEMO-FAKE-SECRET-1234"}], CONTROLS))  # 先遮蔽
    assert build_payload([{**e, "title": None}], CONTROLS) is None                    # 無法安全組成 → 範本


# ---------------------------------------------------------------- R3 格式
@pytest.mark.parametrize("bad", [None, [], "x", {"extra_controls": None}, {"extra_controls": {}}, {"extra_tasks": ["x"]},
                                 {"extra_controls": [{"reason": "DEMO-FAKE-ABCD-1234"}]}])
def test_shape_rejects(bad):
    with pytest.raises(ValueError):
        validate_plan_shape(bad)
    with pytest.raises(ValueError):
        _validate("plan", bad, set()) if bad is not None else _validate("plan", None, set())


@pytest.mark.parametrize("ok", [{}, {"extra_controls": []}, {"extra_tasks": []}, {"skip_agents": ["a2"]}])
def test_shape_accepts(ok):
    assert _validate("plan", ok, set()) == ok                                         # 未知鍵留給 approve


# ---------------------------------------------------------------- R4 核准
def run_approve(output, events=None):
    return approve(output, events=events or [ev("live-a", controls=["C-A"]), ev("live-b")], controls=CONTROLS)


def reasons(res):
    return [r["reason"] for r in res["rejected"]]


def test_mixed_valid_and_invalid():
    res = run_approve({
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
            {"agent": "a4", "subagent": "impact-analyst", "event_id": "live-b", "reason": "補充說明"},
            {"agent": "a2", "subagent": "secret-analyst", "event_id": "live-b", "reason": "不在清單"},
            {"agent": "a4", "subagent": "impact-analyst", "event_id": "live-b", "reason": "重複"},
        ],
        "skip_agents": ["a2"], "disable": True,
    })
    assert [a["type"] for a in res["approved"]] == ["control", "task"]
    assert reasons(res) == [R_ONLY_ADD, R_ONLY_ADD, R_CONTROL, R_EVENT, R_MAPPED, R_DUP, R_REASON, R_ONLY_ADD, R_FIELDS,
                            R_TASK, R_DUP]
    assert res["suggested"] == len(res["approved"]) + len(res["rejected"]) == 13       # N = M + K
    text = json.dumps(res, ensure_ascii=False)
    assert "skip_agents" not in text and "score" not in text and "C-ZZZ" not in text and "live-zz" not in text


def test_limits_and_rejections_do_not_use_quota():
    events = [ev(f"live-{i}") for i in range(4)]
    out = {"extra_controls": [{"event_id": "live-0", "control_id": "C-ZZ", "reason": "x"}]
           + [{"event_id": "live-0", "control_id": c["id"], "reason": "r"} for c in CONTROLS[:4]]
           + [{"event_id": f"live-{i}", "control_id": c["id"], "reason": "r"} for i in (1, 2, 3) for c in CONTROLS[:3]],
           "extra_tasks": [{"agent": "a4", "subagent": "impact-analyst", "event_id": f"live-{i}", "reason": "r"} for i in range(4)]}
    res = approve(out, events=events, controls=CONTROLS)
    ctrls = [a for a in res["approved"] if a["type"] == "control"]
    assert len(ctrls) == 8 and sum(1 for a in ctrls if a["event_id"] == "live-0") == 3
    assert len([a for a in res["approved"] if a["type"] == "task"]) == 3
    # live-0 第 4 個（每件上限）、live-2 第 3 個與 live-3 全部（總數上限）、第 4 個追加工作
    assert reasons(res).count(R_LIMIT) == 1 + 1 + 3 + 1 and reasons(res).count(R_CONTROL) == 1


def test_reason_is_trimmed_and_truncated():
    res = run_approve({"extra_controls": [{"event_id": " live-a ", "control_id": " C-B ", "reason": "  " + "很" * 200}]})
    a = res["approved"][0]
    assert a["event_id"] == "live-a" and a["control_id"] == "C-B" and len(a["reason"]) <= 120


def test_unselected_sixth_event_cannot_be_approved():
    events = [ev(f"live-{i}", date=f"2026-11-{i + 1:02d}") for i in range(6)]
    selected, _ = new_peer_events(events, set())
    res = approve({"extra_controls": [{"event_id": "live-0", "control_id": "C-B", "reason": "r"}]}, events=selected, controls=CONTROLS)
    assert reasons(res) == [R_EVENT]


# ---------------------------------------------------------------- R5／R6 加查結果與追加風險
def test_planner_checks_maps_status_and_missing():
    approved = [{"type": "control", "event_id": "e", "control_id": "C-A", "reason": "r1"},
                {"type": "control", "event_id": "e", "control_id": "C-B", "reason": "r2"},
                {"type": "control", "event_id": "other", "control_id": "C-A", "reason": "r3"}]
    results = {"C-A": {"status": "fail", "title": "A", "reason": "不符", "assets": [{"asset_id": "x", "evidence": ["e1"]}]}}
    checks = planner_checks("e", approved, results)
    assert [(c["control_id"], c["status"]) for c in checks] == [("C-A", "fail"), ("C-B", "unknown")]
    assert checks[1]["assets"] == [] and checks[1]["check_reason"] == "本次檢查結果缺失"


def risk(rid, asset, level="medium", score=5, matched=(), status="open"):
    return {"id": rid, "asset_id": asset, "level": level, "score": score, "matched_events": list(matched), "status": status,
            "finding_ids": [rid]}


def test_pick_extra_risks():
    risks = [risk("a:C-A", "a", "low", 2), risk("a:C-B", "a", "high", 9), risk("b:x", "b", "high", 8, matched=["e"]),
             risk("c:y", "c", "medium", 4, matched=["e"]), risk("d:z", "d", matched=["e"], status="fixed"),
             risk("f:w", "f", "high", 9, matched=["e"]), risk("g:v", "g", "low", 1, matched=["e"])]
    checks = [{"control_id": "C-A", "status": "fail", "assets": [{"asset_id": "a"}]}]
    picked = pick_extra_risks("e", risks, checks, already={"f:w"})
    assert [r["id"] for r in picked] == ["b:x", "c:y", "a:C-A"]                        # 同資產不同控制項（a:C-B）不誤選
    assert pick_extra_risks("nothing", risks, [], set()) == []
