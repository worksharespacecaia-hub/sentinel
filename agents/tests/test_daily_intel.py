"""daily-intel（訂閱方案 LLM）輸出的清理：只當資料，不信任其中的驗證狀態與無法驗證的宣稱。"""
import json

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
