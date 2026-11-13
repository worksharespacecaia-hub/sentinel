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


# ---------------------------------------------------------------- 可能的破口（specs/check-hints R4）
from tools.common import SENTINEL_ROOT  # noqa: E402
from tools.daily_intel import ENTRY_BASIS_LIMIT, ENTRY_TEXT_LIMIT, _entry_points  # noqa: E402

TOPICS = {"admin", "vendor", "database"}
TOKEN = "ghp_" + "A1b2C3d4E5" * 3 + "F6g7H8"                       # 完整的 ghp_ + 36 字元假 token（不是真實金鑰）


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
        {"topic": "admin", "text": "  可能是後台\n帳號\t遭盜用；\x07查後台登入紀錄  ", "basis": "攻擊過程第 1 步\r\n只說遭非法存取"},
        {"topic": "no-such-topic", "text": "topic 不在白名單", "basis": "事件摘要"},
        {"topic": 3, "text": "topic 不是字串", "basis": "事件摘要"},
        {"text": "第四項（超過 3 項）", "basis": "事件摘要"},
    ]
    got = pep_event(tmp_path, raw)
    assert got == [
        {"topic": "admin", "text": "可能是後台 帳號 遭盜用； 查後台登入紀錄", "basis": "攻擊過程第 1 步 只說遭非法存取"},
        {"topic": None, "text": "topic 不在白名單", "basis": "事件摘要"},
        {"topic": None, "text": "topic 不是字串", "basis": "事件摘要"},
    ]


def test_entry_points_truncated_to_limits(tmp_path):
    got = pep_event(tmp_path, [{"topic": "vendor", "text": "長" * 150, "basis": "據" * 200}])
    assert got == [{"topic": "vendor", "text": "長" * ENTRY_TEXT_LIMIT, "basis": "據" * ENTRY_BASIS_LIMIT}]
    assert (ENTRY_TEXT_LIMIT, ENTRY_BASIS_LIMIT) == (100, 120)


def test_entry_points_keep_first_three_valid(tmp_path):
    raw = [{"text": f"推測 {i}", "basis": f"依據 {i}"} for i in range(5)]
    assert [p["text"] for p in pep_event(tmp_path, raw)] == ["推測 0", "推測 1", "推測 2"]
    raw = [{"text": "", "basis": "x"}, *raw]                        # 不合格的項目不佔名額
    assert [p["text"] for p in pep_event(tmp_path, raw)] == ["推測 0", "推測 1", "推測 2"]


def test_entry_points_secret_across_limit_is_dropped(tmp_path):
    """先對原始未截斷的文字做機敏檢查：金鑰跨越 100／120 字上限時，截斷後只剩半段也要整項略過。"""
    from tools.common import SECRET_RE
    from tools.digest import has_sensitive
    text = "可" * 95 + TOKEN                                          # 前 95 字正常、後面接完整的 token
    basis = "據" * 115 + TOKEN
    for cut, limit in ((text, ENTRY_TEXT_LIMIT), (basis, ENTRY_BASIS_LIMIT)):
        assert not has_sensitive(cut[:limit]) and not SECRET_RE.search(cut[:limit])   # 截斷後偵測不到（證明測試有意義）
    raw = [{"text": text, "basis": "攻擊過程第 1 步"}, {"text": "正常推測", "basis": basis},
           {"text": "可" * 95 + "sk-ant-" + "x" * 20, "basis": "SECRET_RE 樣式"},
           {"text": "可" * 98 + "DEMO-FAKE-KEY-0001", "basis": "SECRET_RE 樣式"},
           {"text": "可" * 90 + "someone@example.com", "basis": "個資"},
           {"text": "保留的項目", "basis": "攻擊過程第 2 步"}]
    assert pep_event(tmp_path, raw) == [{"topic": None, "text": "保留的項目", "basis": "攻擊過程第 2 步"}]


def test_entry_points_topic_whitelist_from_rules(tmp_path, monkeypatch):
    from tools.check_hints import topic_ids
    assert {"vendor", "mail", "database", "member-portal", "admin", "code-repo", "endpoint", "server"} == set(topic_ids())
    raw = [{"topic": "admin", "text": "後台帳號遭盜用", "basis": "攻擊過程第 1 步"}]
    assert pep_event(tmp_path, raw)[0]["topic"] == "admin"
    monkeypatch.setenv("SENTINEL_CHECK_HINTS_FILE", str(tmp_path / "no-such-rules.json"))   # 規則表無效 → 白名單為空
    assert pep_event(tmp_path, raw) == [{"topic": None, "text": "後台帳號遭盜用", "basis": "攻擊過程第 1 步"}]


def test_entry_points_helper_output_always_validates():
    from schemas import EntryPoint
    weird = [{"topic": "x" * 500, "text": "　" * 3 + "文" * 300, "basis": "\x7f據" * 200}, {"text": "a", "basis": "b"}]
    out = _entry_points(weird, TOPICS)
    assert [EntryPoint.model_validate(p).model_dump() for p in out] == out and len(out) == 2
    assert _entry_points(weird, set()) == out and _entry_points(weird, None) == out


def test_schema_entry_point_limits():
    from pydantic import ValidationError

    from schemas import EntryPoint, IntelEvent
    EntryPoint(text="x" * 100, basis="y" * 120)
    for bad in ({"text": "", "basis": "y"}, {"text": "x", "basis": ""}, {"text": "x" * 101, "basis": "y"},
                {"text": "x", "basis": "y" * 121}, {"text": "x", "basis": "y", "extra": 1}):
        with pytest.raises(ValidationError):
            EntryPoint.model_validate(bad)
    base = {"id": "live-x", "kind": "live", "title": "t", "date": "2026-11-10", "revision": "1", "confidence": "provisional",
            "sources": []}
    assert IntelEvent.model_validate(base).possible_entry_points == []
    with pytest.raises(ValidationError):
        IntelEvent.model_validate({**base, "possible_entry_points": [{"text": "x", "basis": "y"}] * 4})


def test_live_entry_points_pass_verify_and_become_ai_suggestions(tmp_path):
    """daily-intel 清理後的事件能通過 verify_event；規則沒命中時採用 AI，有命中時不採用。"""
    from tests.conftest import AS_OF
    from tools import check_hints as ch
    from tools.intel_verify import verify_event
    pep = [{"topic": "admin", "text": "可能是後台帳號遭盜用；查後台登入紀錄", "basis": "攻擊過程第 1 步"}]
    raws = [event(id="evt-miss", title="某公司遭駭", possible_entry_points=pep),
            event(id="evt-hit", title="某公司會員中心遭駭", possible_entry_points=pep)]
    (miss, hit), issues = load_daily_intel(write(tmp_path, {"events": raws}))
    assert not issues
    rules, _ = ch.load_rules()
    graph = {"internal-tool": {"type": "internal_tool"}}
    for e, source in ((miss, "ai"), (hit, "rule")):
        v = verify_event(e, as_of=AS_OF, online=False)["event"]
        assert v["possible_entry_points"] == pep                          # model_dump 後為 dict 清單
        out = ch.suggest_for_event(v, graph=graph, controls={}, rules=rules, labels={})
        assert {s["source"] for s in out} == {source}
    v = verify_event(miss, as_of=AS_OF, online=False)["event"]
    [s] = ch.suggest_for_event(v, graph=graph, controls={}, rules=rules, labels={})
    assert (s["id"], s["target"], [x["asset_id"] for x in s["systems"]]) == ("ai-1", "admin", ["internal-tool"])
    [s] = ch.suggest_for_event(v, graph=graph, controls={}, rules=None, labels={})        # 規則無效 → topic 移除
    assert (s["source"], s["target"], s["systems"]) == ("ai", None, [])


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
    pep = [{"topic": "admin", "text": "推測", "basis": "依據"}]
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
    pep = [{"topic": "admin", "text": "可能是後台帳號遭盜用", "basis": "攻擊過程第 1 步"}]
    doc = _event_yaml(tmp_path / "extra", "extra-ai-2026-11", "live", pep)
    live = {**doc, "id": "live-ai-2026-11", "title": "live-ai-2026-11"}
    res = evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS,
                             extra_event_dirs=[tmp_path / "extra"], live_events=[live]))
    by_id = {m["event"]["id"]: m for m in res["matches"]}

    def sugs(eid):
        return [s for i in by_id[eid]["impacts"] if i["verdict"] == "need_check" for s in i["suggestions"]]
    assert by_id["extra-ai-2026-11"]["event"]["possible_entry_points"] == []
    assert {s["source"] for s in sugs("extra-ai-2026-11")} == {"rule"} and sugs("extra-ai-2026-11")[0]["id"] == "generic-1"
    assert [(s["source"], s["target"]) for s in sugs("live-ai-2026-11")] == [("ai", "admin")]


# ---------------------------------------------------------------- reference 同步（R4.1 topic 白名單）與 Skill 說明
def test_check_topics_reference_matches_rules():
    import subprocess
    import sys

    from tools.check_hints import load_rules
    res = subprocess.run([sys.executable, str(SENTINEL_ROOT / "scripts" / "build-check-topics-reference.py"), "--check"],
                         capture_output=True, text=True, encoding="utf-8")
    assert res.returncode == 0, res.stderr
    ref = (SENTINEL_ROOT / ".claude" / "skills" / "daily-intel" / "references" / "check-topics.md").read_text(encoding="utf-8")
    rules, _ = load_rules()
    assert "請勿手改" in ref.splitlines()[0]
    for t in rules["targets"]:
        assert f"| `{t['id']}` | {t['label']} |" in ref


def test_check_topics_reference_check_detects_stale_file(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_topics", SENTINEL_ROOT / "scripts" / "build-check-topics-reference.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    stale = tmp_path / "check-topics.md"
    stale.write_text("old", encoding="utf-8")
    monkeypatch.setattr(mod, "OUT_PATH", stale)
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    assert mod.main(["--check"]) == 1 and stale.read_text(encoding="utf-8") == "old"   # --check 不改檔
    stale.unlink()
    assert mod.main(["--check"]) == 1 and not stale.exists()


def test_daily_intel_skill_documents_entry_points():
    skill = (SENTINEL_ROOT / ".claude" / "skills" / "daily-intel" / "SKILL.md").read_text(encoding="utf-8")
    assert "只寫來源中出現的內容，不推測" in skill
    assert '"possible_entry_points": []' in skill and "references/check-topics.md" in skill
    assert "唯一允許合理推測的欄位" in skill and "`basis`" in skill
