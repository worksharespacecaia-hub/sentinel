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


# ---------------------------------------------------------------- 同一份快照（A1）；v0.13.0 起不再讀派工建議（specs/orchestrator §3.6）
from tools.daily_intel import load_daily_snapshot  # noqa: E402


def test_snapshot_keeps_legacy_loader_contract(tmp_path):
    p = write(tmp_path, {"events": [event(), {"id": "bad", "title": "沒有來源", "date": "2026-11-09", "sources": []}], "impacts": []})
    snap = load_daily_snapshot(p)
    assert (snap.events, snap.issues) == load_daily_intel(p) and snap.read_issue is None
    assert [e["id"] for e in snap.events] == ["live-evt-a"]


@pytest.mark.parametrize("data,why", [
    (None, "每日情資沒有輸出"), ("{not json", "每日情資無法解析"), ({"events": "x"}, "每日情資格式不符"),
])
def test_snapshot_read_issue(tmp_path, data, why):
    p = tmp_path / "intel-daily.json" if data is None else write(tmp_path, data)
    assert load_daily_snapshot(p).read_issue == why


def test_legacy_agent_plan_is_ignored(tmp_path):
    """舊版 Skill 寫的 agent_plan 不再被讀取：事件照常清理，不產生問題，也不會成為派工建議（AI 派工只由 Orchestrator 提出）。"""
    plain = load_daily_snapshot(write(tmp_path, {"events": [event()], "impacts": []}))
    legacy = load_daily_snapshot(write(tmp_path, {"events": [event()], "impacts": [],
                                                  "agent_plan": {"extra_controls": [{"event_id": "evt-a", "control_id": "C-X"}]}}))
    assert (legacy.events, legacy.issues, legacy.read_issue) == (plain.events, plain.issues, None)
    import tools.daily_intel as di
    assert not hasattr(di, "load_daily_plan")


# ---------------------------------------------------------------- 可能的破口（specs/check-hints R4；v0.12.1 check-hints-ai R2）
from tools.common import SENTINEL_ROOT  # noqa: E402
from tools.daily_intel import ENTRY_BASIS_LIMIT, ENTRY_CHECK_LIMIT, ENTRY_TEXT_LIMIT, _entry_points  # noqa: E402

TOKEN = "ghp_" + "A1b2C3d4E5" * 3 + "F6g7H8"                       # 完整的 ghp_ + 36 字元假 token（不是真實金鑰）


def ep(text, basis, check=None, systems=()):
    """清理後的預期項目：check 沒寫時等於 text。"""
    return {"text": text, "check": check or text, "systems": list(systems), "basis": basis}


def pep_event(tmp_path, value):
    (ev,), issues = load_daily_intel(write(tmp_path, {"events": [event(possible_entry_points=value)]}))
    assert not issues                                                # 推測欄位不合格不會讓整件事件被略過
    return ev["possible_entry_points"]


@pytest.mark.parametrize("value", [None, "可能是後台", {"text": "x", "basis": "y"}, 3, True])
def test_entry_points_non_array_is_empty(tmp_path, value):
    assert pep_event(tmp_path, value) == []


def test_entry_points_absent_defaults_to_empty(tmp_path):
    (ev,), _ = load_daily_intel(write(tmp_path, {"events": [event()]}))
    assert ev["possible_entry_points"] == []


def test_entry_points_cleaning_order(tmp_path):
    raw = [
        "不是物件", 7, None, ["x"],
        {"text": "", "basis": "攻擊過程第 1 步"},
        {"text": "   ", "basis": "攻擊過程第 1 步"},
        {"text": "缺依據", "basis": ""},
        {"text": "缺依據", "basis": " \n\t "},
        {"text": "沒有依據欄位"},
        {"basis": "沒有 text 欄位"},
        {"text": 123, "basis": "text 不是字串"},
        {"text": "\x00\x01", "basis": "只有控制字元"},
        {"text": "  可能是後台\n帳號\t遭盜用  ", "check": "\x07查後台\r\n登入紀錄", "systems": ["internal-tool"],
         "basis": "攻擊過程第 1 步\r\n只說遭非法存取"},
        {"topic": "admin", "text": "舊格式 topic 被忽略", "basis": "事件摘要"},
        {"text": "check 空白改用 text", "check": " \n ", "basis": "事件摘要"},
        {"text": "第四項（超過 3 項）", "basis": "事件摘要"},
    ]
    assert pep_event(tmp_path, raw) == [
        ep("可能是後台 帳號 遭盜用", "攻擊過程第 1 步 只說遭非法存取", check="查後台 登入紀錄", systems=["internal-tool"]),
        ep("舊格式 topic 被忽略", "事件摘要"),
        ep("check 空白改用 text", "事件摘要"),
    ]


def test_entry_points_check_fallbacks(tmp_path):
    for check in (None, "", "   ", "\x00\x01", 123, ["x"]):
        assert pep_event(tmp_path, [{"text": "推測", "check": check, "basis": "依據"}]) == [ep("推測", "依據")]


def test_entry_points_truncated_to_limits(tmp_path):
    got = pep_event(tmp_path, [{"text": "長" * 150, "check": "查" * 300, "basis": "據" * 200}])
    assert got == [ep("長" * ENTRY_TEXT_LIMIT, "據" * ENTRY_BASIS_LIMIT, check="查" * ENTRY_CHECK_LIMIT)]
    assert (ENTRY_TEXT_LIMIT, ENTRY_CHECK_LIMIT, ENTRY_BASIS_LIMIT) == (80, 160, 120)


def test_entry_points_keep_first_three_valid(tmp_path):
    raw = [{"text": f"推測 {i}", "basis": f"依據 {i}"} for i in range(5)]
    assert [p["text"] for p in pep_event(tmp_path, raw)] == ["推測 0", "推測 1", "推測 2"]
    raw = [{"text": "", "basis": "x"}, *raw]                        # 不合格的項目不佔名額
    assert [p["text"] for p in pep_event(tmp_path, raw)] == ["推測 0", "推測 1", "推測 2"]


def test_entry_points_secret_across_limit_is_dropped(tmp_path):
    """先對原始未截斷的 text、check、basis 做機敏檢查：金鑰跨越字數上限時，截斷後只剩半段也要整項略過。"""
    from tools.common import SECRET_RE
    from tools.digest import has_sensitive
    text = "可" * 75 + TOKEN                                          # 前 75 字正常、後面接完整的 token
    check = "查" * 155 + TOKEN
    basis = "據" * 115 + TOKEN
    for cut, limit in ((text, ENTRY_TEXT_LIMIT), (check, ENTRY_CHECK_LIMIT), (basis, ENTRY_BASIS_LIMIT)):
        assert not has_sensitive(cut[:limit]) and not SECRET_RE.search(cut[:limit])   # 截斷後偵測不到（證明測試有意義）
    raw = [{"text": text, "basis": "攻擊過程第 1 步"}, {"text": "正常推測", "basis": basis},
           {"text": "正常推測", "check": check, "basis": "攻擊過程第 1 步"},
           {"text": "可" * 70 + "sk-ant-" + "x" * 20, "basis": "SECRET_RE 樣式"},
           {"text": "正常推測", "check": "DEMO-FAKE-KEY-0001", "basis": "SECRET_RE 樣式"},
           {"text": "可" * 60 + "someone@example.com", "basis": "個資"},
           {"text": "保留的項目", "basis": "攻擊過程第 2 步"}]
    assert pep_event(tmp_path, raw) == [ep("保留的項目", "攻擊過程第 2 步")]


def test_entry_points_systems_cleaned(tmp_path):
    """R2.3 第 4 步：只保留符合系統 ID 格式的字串，去重、最多 5 個；非陣列視為空陣列；是否存在不在這裡判斷。"""
    def systems(value):
        return pep_event(tmp_path, [{"text": "推測", "systems": value, "basis": "依據"}])[0]["systems"]
    for bad in (None, "storefront", 3, {"id": "storefront"}):
        assert systems(bad) == []
    assert systems(["storefront", "storefront", "api-gateway"]) == ["storefront", "api-gateway"]
    assert systems(["brand-app@3.1.0", "@demo-vendor/push-sdk@2.3.1", "clone:app.example", "no-such-system"]) == \
        ["brand-app@3.1.0", "@demo-vendor/push-sdk@2.3.1", "clone:app.example", "no-such-system"]   # 存在與否交給使用端
    assert systems(["有 空白", "tab\tid", "new\nline", "", "x" * 121, "中文系統", 7, None, ["a"], "a#b", "ok"]) == ["ok"]
    assert systems(["x" * 120]) == ["x" * 120]
    assert systems([f"s-{i}" for i in range(8)]) == [f"s-{i}" for i in range(5)]
    assert systems(["s-0", "s-0", "s-1", "s-2", "s-3", "s-4", "s-5"]) == [f"s-{i}" for i in range(5)]   # 先去重再取 5 個
    assert systems([TOKEN, "storefront"]) == ["storefront"]                                         # 金鑰樣式不寫入


def test_entry_points_helper_output_always_validates():
    from schemas import EntryPoint
    weird = [{"topic": "x" * 500, "text": "　" * 3 + "文" * 300, "check": "\x7f查" * 300, "basis": "\x7f據" * 200,
              "systems": [f"s{i}" for i in range(20)] + ["x" * 500]},
             {"text": "a", "basis": "b"}, {"text": "c", "basis": "d", "systems": "e", "check": 5}]
    out = _entry_points(weird)
    assert [EntryPoint.model_validate(p).model_dump() for p in out] == out and len(out) == 3
    assert all("topic" not in p for p in out)


def test_schema_entry_point_limits():
    from pydantic import ValidationError

    from schemas import EntryPoint, IntelEvent
    EntryPoint(text="x" * 80, check="c" * 160, systems=["a"] * 5, basis="y" * 120)
    assert EntryPoint(text="x", check="c", basis="y").systems == []
    for bad in ({"text": "", "check": "c", "basis": "y"}, {"text": "x", "check": "c", "basis": ""},
                {"text": "x", "check": "", "basis": "y"}, {"text": "x", "basis": "y"},
                {"text": "x" * 81, "check": "c", "basis": "y"}, {"text": "x", "check": "c" * 161, "basis": "y"},
                {"text": "x", "check": "c", "basis": "y" * 121}, {"text": "x", "check": "c", "basis": "y", "systems": ["a"] * 6},
                {"text": "x", "check": "c", "basis": "y", "topic": "admin"},              # v0.12.0 的 topic 已移除
                {"text": "x", "check": "c", "basis": "y", "extra": 1}):
        with pytest.raises(ValidationError):
            EntryPoint.model_validate(bad)
    base = {"id": "live-x", "kind": "live", "title": "t", "date": "2026-11-10", "revision": "1", "confidence": "provisional",
            "sources": []}
    assert IntelEvent.model_validate(base).possible_entry_points == []
    with pytest.raises(ValidationError):
        IntelEvent.model_validate({**base, "possible_entry_points": [{"text": "x", "check": "c", "basis": "y"}] * 4})


PEP = [{"text": "可能是後台帳號遭盜用", "check": "查後台登入紀錄與來源 IP", "systems": ["internal-tool", "phpmyadmin"],
        "basis": "攻擊過程第 1 步"}]


def test_live_entry_points_pass_verify_and_become_ai_suggestions(tmp_path):
    """daily-intel 清理後的事件能通過 verify_event；AI 推測優先，規則命中與否、規則表有效與否都一樣採用 AI。"""
    from tests.conftest import AS_OF
    from tools import check_hints as ch
    from tools.intel_verify import verify_event
    raws = [event(id="evt-miss", title="某公司遭駭", possible_entry_points=PEP),
            event(id="evt-hit", title="某公司會員中心遭駭", possible_entry_points=PEP)]
    (miss, hit), issues = load_daily_intel(write(tmp_path, {"events": raws}))
    assert not issues
    rules, _ = ch.load_rules()
    graph = {"internal-tool": {"type": "internal_tool"}}                   # phpmyadmin 不在本次圖譜 → 使用端移除
    for e in (miss, hit):
        v = verify_event(e, as_of=AS_OF, online=False)["event"]
        assert v["possible_entry_points"] == PEP                          # model_dump 後為 dict 清單
        for r in (rules, None):
            [s] = ch.suggest_for_event(v, graph=graph, controls={}, rules=r, labels={})
            assert (s["id"], s["source"], s["target"], [x["asset_id"] for x in s["systems"]]) == \
                ("ai-1", "ai", None, ["internal-tool"])
            assert s["check"] == "查後台登入紀錄與來源 IP"


# ---------------------------------------------------------------- R4.6：只有 daily-intel 入口可帶 possible_entry_points
def _event_yaml(directory, eid, kind, pep):
    import yaml
    directory.mkdir(parents=True, exist_ok=True)
    doc = {"id": eid, "kind": kind, "title": eid, "date": "2026-11-08", "revision": "1", "confidence": "provisional",
           "sources": [], "possible_entry_points": pep}
    (directory / f"{eid}.yaml").write_text(yaml.safe_dump(doc, allow_unicode=True), encoding="utf-8")
    return doc


def test_event_sources_strip_entry_points_from_other_sources(tmp_path, monkeypatch):
    import copy

    from tools import pipeline
    from tools.pipeline import EvalInput, event_sources
    pep = [{"text": "推測", "check": "查", "systems": ["internal-tool"], "basis": "依據"}]
    intel = tmp_path / "intel"
    _event_yaml(intel / "archive", "arc-1", "archive", pep)
    _event_yaml(intel / "advisories", "adv-1", "advisory", pep)
    _event_yaml(intel / "demo-events", "demo-1", "demo", pep)
    _event_yaml(tmp_path / "extra", "extra-1", "live", pep)          # 自稱 live 也一樣移除：不看事件自己填的 kind
    monkeypatch.setattr(pipeline, "INTEL_DIR", intel)
    auto = [{"id": "kev-cve-2026-0001", "kind": "advisory", "possible_entry_points": pep}]
    live = [{"id": "live-1", "kind": "live", "possible_entry_points": pep}]
    inp = EvalInput(target_root=tmp_path, as_of=None, scanners_dir=tmp_path, intel_kinds=["archive", "advisory", "demo"],
                    extra_event_dirs=[tmp_path / "extra"], auto_advisories=copy.deepcopy(auto), live_events=live)
    got = {e["id"]: e for e in event_sources(inp)}
    assert set(got) == {"arc-1", "adv-1", "demo-1", "extra-1", "kev-cve-2026-0001", "live-1"}
    assert [i for i, e in got.items() if "possible_entry_points" in e] == ["live-1"]
    assert got["live-1"]["possible_entry_points"] == pep
    assert inp.auto_advisories == auto                                 # 不修改呼叫端傳入的事件


def test_extra_event_dir_entry_points_never_used_in_pipeline(tmp_path):
    """extra_event_dirs 的事件就算帶 possible_entry_points，pipeline 也只給通用建議；同內容的 live 事件才採用 AI。"""
    from tests.conftest import AS_OF
    from tools.loaders import FIXTURE_SCANNERS, FIXTURE_TARGET
    from tools.pipeline import EvalInput, evaluate
    doc = _event_yaml(tmp_path / "extra", "extra-ai-2026-11", "live", PEP)
    live = {**doc, "id": "live-ai-2026-11", "title": "live-ai-2026-11"}
    res = evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS,
                             extra_event_dirs=[tmp_path / "extra"], live_events=[live]))
    by_id = {m["event"]["id"]: m for m in res["matches"]}

    def sugs(eid):
        return [s for i in by_id[eid]["impacts"] if i["verdict"] == "need_check" for s in i["suggestions"]]
    assert by_id["extra-ai-2026-11"]["event"]["possible_entry_points"] == []
    assert {s["source"] for s in sugs("extra-ai-2026-11")} == {"rule"} and sugs("extra-ai-2026-11")[0]["id"] == "generic-1"
    assert [(s["source"], s["target"]) for s in sugs("live-ai-2026-11")] == [("ai", None)]


# ---------------------------------------------------------------- Skill 說明（v0.12.1：不再有 check-topics 白名單）
def test_check_topics_reference_removed():
    assert not (SENTINEL_ROOT / ".claude" / "skills" / "daily-intel" / "references" / "check-topics.md").exists()
    assert not (SENTINEL_ROOT / "scripts" / "build-check-topics-reference.py").exists()


def test_daily_intel_skill_documents_entry_points():
    import re

    from tools.stack import ai_assets
    skill = (SENTINEL_ROOT / ".claude" / "skills" / "daily-intel" / "SKILL.md").read_text(encoding="utf-8")
    assert "只寫來源中出現的內容，不推測" in skill
    assert '"possible_entry_points": []' in skill and "check-topics" not in skill and "`topic`" not in skill
    assert "唯一允許合理推測的欄位" in skill and "`basis`" in skill
    for word in ("`text`", "`check`", "`systems`", "`assets`", "assets[].id", "不得自創", "不寫和事件無關的通則",
                 "新聞沒交代破口的事件", "80 字內", "160 字內", "120 字內", "0～5 個"):
        assert word in skill, word
    # 範例：新格式、清理後不變，systems 都在凍結 graph 的 ai_assets 中
    [example] = re.findall(r"```json\n\s*(\{\s+\"text\".*?\})\n\s*```", skill, re.S)
    item = json.loads(example)
    assert set(item) == {"text", "check", "systems", "basis"} and "會員訂單 API" in item["text"]
    assert _entry_points([item]) == [item]
    graph = json.loads((SENTINEL_ROOT / "agents" / "tests" / "fixtures" / "check-hints" / "graph.json").read_text(encoding="utf-8"))
    assert set(item["systems"]) <= {a["id"] for a in ai_assets(graph, None)}
