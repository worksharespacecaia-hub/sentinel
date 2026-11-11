"""daily-intel（訂閱方案 LLM）輸出的清理：只當資料，不信任其中的驗證狀態與無法驗證的宣稱。"""
import json

import pytest

from tools.daily_intel import MAX_EVENTS, load_daily_intel

SRC = {"url": "https://www.ithome.com.tw/news/1", "title": "iThome", "quote": "引用", "published": "2026-11-09"}


def event(**kw):
    return {"id": "evt-a", "title": "事件", "date": "2026-11-09", "confidence": "confirmed", "sources": [dict(SRC)], **kw}


def write(tmp_path, data):
    p = tmp_path / "intel-daily.json"
    p.write_text(data if isinstance(data, str) else json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return p


def test_missing_file_is_not_an_issue(tmp_path):
    assert load_daily_intel(tmp_path / "intel-daily.json") == ([], [])


def test_invalid_json_and_shape(tmp_path):
    assert load_daily_intel(write(tmp_path, "{not json"))[1] == ["intel-daily.json 不是合法的 JSON"]
    assert load_daily_intel(write(tmp_path, {"events": "x"}))[1] == ["intel-daily.json 缺少 events 陣列"]
    assert load_daily_intel(write(tmp_path, []))[1] == ["intel-daily.json 缺少 events 陣列"]


def test_forced_live_and_verification_claims_dropped(tmp_path):
    raw = event(kind="advisory", demo=True, demo_fixture=True, fixture_note="x",
                sources=[{**SRC, "verified": True, "fetch_status": "ok", "verification_basis": "archived",
                          "content_hash": "sha256:x"}])
    (ev,), issues = load_daily_intel(write(tmp_path, {"events": [raw]}))
    assert not issues
    assert ev["kind"] == "live" and ev["demo"] is False and ev["id"] == "live-evt-a" and ev["fixture_note"] is None
    s = ev["sources"][0]
    assert s["verified"] is False and s["fetch_status"] == "skipped" and s["verification_basis"] == "unverified"
    assert s["content_hash"] is None and s["url"] == SRC["url"] and s["quote"] == "引用"


def test_unverifiable_product_claims_dropped(tmp_path):
    raw = event(products=[{"name": "php", "ecosystem": "php", "known_exploited": True, "confirmed": True, "target": "app_sdk",
                           "conditions": [{"key": "x", "equals": True}], "cvss": 11, "impact": "remote_code_execution",
                           "affected": [{"introduced": "8.2.0", "fixed": "8.2.35"}, {"introduced": "; rm -rf"}, "junk"]},
                          {"ecosystem": "npm"}, "not-a-dict"])
    (ev,), _ = load_daily_intel(write(tmp_path, {"events": [raw]}))
    assert ev["products"] == [{"name": "php", "ecosystem": "php", "impact": "remote_code_execution",
                               "affected": [{"introduced": "8.2.0", "fixed": "8.2.35"}]}]


def test_fields_filtered(tmp_path):
    raw = event(cves=["CVE-2026-1234", "not-a-cve"], attck=["T1190", "T1"], controls=["C-SECRET-IN-GIT", "C-MADE-UP"],
                is_update_of="../etc", title="x" * 500, confidence="certain")
    (ev,), _ = load_daily_intel(write(tmp_path, {"events": [raw]}))
    assert ev["cves"] == ["CVE-2026-1234"] and ev["attck"] == ["T1190"] and ev["controls"] == ["C-SECRET-IN-GIT"]
    assert ev["is_update_of"] is None and len(ev["title"]) == 200 and ev["confidence"] == "provisional"


def test_proposed_controls_kept_as_text_only(tmp_path):
    raw = event(proposed_controls=[{"id": "C-SECRET-IN-GIT", "title": "訂單查詢需有存取控制", "reason": "r" * 500},
                                   {"reason": "沒有標題"}, "x", *[{"title": f"t{i}"} for i in range(5)]])
    (ev,), _ = load_daily_intel(write(tmp_path, {"events": [raw]}))
    assert ev["proposed_controls"] == [{"title": "訂單查詢需有存取控制", "reason": "r" * 200},
                                       {"title": "t0", "reason": ""}, {"title": "t1", "reason": ""}]
    assert ev["controls"] == []                          # 不能藉由建議項目塞進既有控制項 ID


def test_invalid_events_skipped_with_reasons(tmp_path):
    events = [event(sources=[]), event(date="昨天"), event(title=""), "x", event(), event()]
    got, issues = load_daily_intel(write(tmp_path, {"events": events}))
    assert [e["id"] for e in got] == ["live-evt-a"]
    assert issues == ["第 1 件略過：沒有來源", "第 2 件略過：日期格式不符", "第 3 件略過：沒有標題", "第 4 件略過：不是物件",
                      "第 6 件略過：ID 重複（live-evt-a）"]


def test_event_count_capped(tmp_path):
    got, issues = load_daily_intel(write(tmp_path, {"events": [event(id=f"e{i:03d}") for i in range(MAX_EVENTS + 5)]}))
    assert len(got) == MAX_EVENTS and issues == [f"事件超過 {MAX_EVENTS} 件，只處理前 {MAX_EVENTS} 件"]


def test_ids_are_slugged(tmp_path):
    got, _ = load_daily_intel(write(tmp_path, {"events": [event(id="Live-Big News!/2026"), event(id=None)]}))
    assert [e["id"] for e in got] == ["live-big-news-2026", "live-event-2"]


# ---------------------------------------------------------------- 動態派工：同一份快照與訂閱方案建議（R11）
from tools.daily_intel import load_daily_plan, load_daily_snapshot  # noqa: E402


def plan_item(eid, cid="C-SECRET-IN-GIT"):
    return {"event_id": eid, "control_id": cid, "reason": "值得一併確認"}


def test_snapshot_keeps_legacy_loader_contract(tmp_path):
    p = write(tmp_path, {"events": [event(), {"id": "bad", "title": "沒有來源", "date": "2026-11-09", "sources": []}], "impacts": []})
    snap = load_daily_snapshot(p)
    assert (snap.events, snap.issues) == load_daily_intel(p) and snap.read_issue is None
    assert snap.id_map == {"evt-a": "live-evt-a", "live-evt-a": "live-evt-a"}         # 被略過的事件不收別名


@pytest.mark.parametrize("data,why", [
    (None, "每日情資沒有輸出"), ("{not json", "每日情資無法解析"), ({"events": "x"}, "每日情資格式不符"),
    ({"events": [], "impacts": []}, "訂閱方案未提供建議"),
    ({"events": [], "agent_plan": None}, "訂閱方案建議格式不符"),
    ({"events": [], "agent_plan": {"extra_controls": {}}}, "訂閱方案建議格式不符"),
    ({"events": [], "agent_plan": {"extra_tasks": ["x"]}}, "訂閱方案建議格式不符"),
    ({"events": [], "agent_plan": {"extra_controls": [{"reason": "DEMO-FAKE-ABCD-1234"}]}}, "訂閱方案建議格式不符"),
])
def test_daily_plan_unusable_falls_back(tmp_path, data, why):
    p = tmp_path / "intel-daily.json" if data is None else write(tmp_path, data)
    assert load_daily_plan(load_daily_snapshot(p)) == (None, why)


def test_daily_plan_empty_object_is_zero_suggestions(tmp_path):
    assert load_daily_plan(load_daily_snapshot(write(tmp_path, {"events": [event()], "agent_plan": {}}))) == ({}, None)


def test_daily_plan_maps_ids_from_same_snapshot(tmp_path):
    events = [event(id="evt-a"), event(id=" Evt-B "), event(id=""), event(id="dup"), event(id="dup"),
              event(id="X-Y"), event(id="x-y"), {"id": "skipped", "title": "沒有來源", "date": "2026-11-09", "sources": []}]
    items = [plan_item(i) for i in ("evt-a", "live-evt-a", "Evt-B", "live-evt-b", "live-event-3", "", "dup", "x-y",
                                    "live-skipped", "live-whatever", " evt-a ")] + [{"event_id": 7, "control_id": "C-A", "reason": "r"}]
    p = write(tmp_path, {"events": events, "agent_plan": {"extra_controls": items, "skip": True}})
    snap = load_daily_snapshot(p)
    plan, why = load_daily_plan(snap)
    got = [i["event_id"] for i in plan["extra_controls"]]
    assert why is None and plan["skip"] is True                                         # 未知鍵留給 approve 拒絕
    assert got == ["live-evt-a", "live-evt-a", "live-evt-b", "live-evt-b", "live-event-3", "", "", "", "", "", "live-evt-a", 7]
    p.write_text("{}", encoding="utf-8")                                                # 讀快照後檔案被換掉，仍用原快照
    assert load_daily_plan(snap)[0]["extra_controls"][0]["event_id"] == "live-evt-a"


def test_ids_beyond_event_limit_still_mark_ambiguity(tmp_path):
    events = [event(id=f"e{i:03d}") for i in range(MAX_EVENTS)] + [event(id="e000")]
    snap = load_daily_snapshot(write(tmp_path, {"events": events, "agent_plan": {"extra_controls": [plan_item("e000"), plan_item("e001")]}}))
    assert [i["event_id"] for i in load_daily_plan(snap)[0]["extra_controls"]] == ["", "live-e001"]
