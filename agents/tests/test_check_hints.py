"""需確認項目的查核建議（specs/check-hints，T1）：規則表驗證、R2 依原因、R3 破口推測、R4 AI 推測消費端、R8.1 固定資料。"""
import copy
import json
import re
from pathlib import Path

import pytest

from tools import check_hints as ch

FIXTURES = Path(__file__).parent / "fixtures" / "check-hints"
GENERIC_1 = "人工判斷事件的攻擊手法是否適用於我們的系統"
GENERIC_2 = "把事件對應到 controls.yaml 的控制項；沒有合適的就建議新增"


@pytest.fixture(scope="module")
def rules():
    r, issue = ch.load_rules()
    assert issue is None
    return r


@pytest.fixture(scope="module")
def fx_events():
    return {e["id"]: e for e in json.loads((FIXTURES / "events.json").read_text(encoding="utf-8"))}


@pytest.fixture(scope="module")
def fx_graph():
    return json.loads((FIXTURES / "graph.json").read_text(encoding="utf-8"))


def ev(**kw):
    base = {"id": "live-test", "kind": "live", "title": "某公司事件", "attack_chain": [], "attck": [], "summary": None,
            "proposed_controls": [], "products": [], "controls": []}
    return {**base, **kw}


def write_rules(tmp_path, data, name="rules.json"):
    p = tmp_path / name
    p.write_text(data if isinstance(data, str) else json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return p


# ── 規則表 ─────────────────────────────────────────────────────

def test_shipped_rules_are_valid_and_ordered(rules):
    assert ch.topic_ids(rules) == ["vendor", "mail", "database", "member-portal", "admin", "code-repo", "endpoint", "server"]
    assert ch.topic_ids() == ch.topic_ids(rules)
    ids = [h["id"] for t in rules["targets"] for h in t["hypotheses"]]
    assert len(ids) == len(set(ids)) and all(re.fullmatch(r"[a-z0-9-]{2,40}", i) and "_" not in i for i in ids)
    assert all(2 <= len(t["hypotheses"]) <= 3 for t in rules["targets"])
    # 誤判規則（R3.1）：不用單獨的「郵件」「信件」「登入」
    kws = {t["id"]: t["keywords"] for t in rules["targets"]}
    assert not {"郵件", "信件"} & set(kws["mail"]) and "登入" not in kws["member-portal"]


def test_shipped_plain_text_is_public_safe(rules, fx_graph):
    """plain：80 字內，不含路徑、設定鍵、內部 ID、控制項 ID、網址、反引號；why 不宣稱是來源說的。"""
    node_ids = [n["id"] for n in fx_graph["nodes"]]
    bad = re.compile(r"[\\/`]|https?:|C-[A-Z0-9-]+|(?<![A-Za-z0-9_.])[a-z_][a-z0-9_]*(?:\.[a-z0-9_]+)+|:\d{2,5}|[A-Za-z]:")
    for t in rules["targets"]:
        for h in t["hypotheses"]:
            assert len(h["plain"]) <= 80 and not bad.search(h["plain"]), h["id"]
            assert not any(nid in h["plain"] for nid in node_ids), h["id"]
            assert not re.search(r"[A-Za-z]", h["plain"]), h["id"]          # 給 CEO 的白話不含英文代號
            assert "來源" not in h["why"] and "報導" not in h["why"], h["id"]


def _valid_rules():
    return {
        "schema_version": 1, "initial_access_attck": ["T1190"], "unstated_words": ["未說明"],
        "targets": [{"id": "vendor", "label": "委外", "keywords": ["委外"], "attck": [],
                     "hypotheses": [{"id": "vendor-a", "hypothesis": "h", "why": "w", "check": "c", "how": "x", "plain": "p",
                                     "attck": [], "selector": [{"types": ["vendor"]}], "related_controls": []}]}],
    }


def _broken(mutate):
    r = _valid_rules()
    mutate(r)
    return r


def _h(r):
    return r["targets"][0]["hypotheses"][0]


@pytest.mark.parametrize("case", [
    "missing", "bad_json", "underscore_id", "empty_selector", "empty_clause", "unknown_selector_key", "wrong_type_bool",
    "wrong_type_types", "unknown_control", "duplicate_id", "schema_version", "no_hypotheses", "four_hypotheses",
    "no_keywords_no_attck", "bad_attck", "has_vendor_false", "plain_too_long", "empty_check", "not_object",
])
def test_invalid_rules_fall_back_with_note(tmp_path, case):
    p = tmp_path / "missing.json"
    if case == "bad_json":
        p = write_rules(tmp_path, "{not json")
    elif case != "missing":
        mutate = {
            "underscore_id": lambda r: _h(r).update(id="vendor_a"),
            "empty_selector": lambda r: _h(r).update(selector=[]),
            "empty_clause": lambda r: _h(r).update(selector=[{}]),
            "unknown_selector_key": lambda r: _h(r).update(selector=[{"zone": "dmz"}]),
            "wrong_type_bool": lambda r: _h(r).update(selector=[{"exposed": "yes"}]),
            "wrong_type_types": lambda r: _h(r).update(selector=[{"types": "vendor"}]),
            "unknown_control": lambda r: _h(r).update(related_controls=["C-NOT-EXIST"]),
            "duplicate_id": lambda r: _h(r).update(id="vendor"),
            "schema_version": lambda r: r.update(schema_version=2),
            "no_hypotheses": lambda r: r["targets"][0].update(hypotheses=[]),
            "four_hypotheses": lambda r: r["targets"][0].update(
                hypotheses=[{**_h(r), "id": f"vendor-{i}"} for i in range(4)]),
            "no_keywords_no_attck": lambda r: r["targets"][0].update(keywords=[], attck=[]),
            "bad_attck": lambda r: r["targets"][0].update(attck=["1199"]),
            "has_vendor_false": lambda r: _h(r).update(selector=[{"has_vendor": False}]),
            "plain_too_long": lambda r: _h(r).update(plain="長" * 81),
            "empty_check": lambda r: _h(r).update(check=" "),
            "not_object": lambda r: r.update(targets=["vendor"]),
        }[case]
        p = write_rules(tmp_path, _broken(mutate))
    rules, issue = ch.load_rules(p)
    assert rules is None
    assert issue == {"source": "rules/check-hints.json", "status": "invalid", "required": False,
                     "impact": "查核建議規則無效，改用通用建議"}


def test_minimal_valid_rules_and_env_override(tmp_path, monkeypatch):
    p = write_rules(tmp_path, _valid_rules())
    assert ch.load_rules(p)[1] is None
    monkeypatch.setenv("SENTINEL_CHECK_HINTS_FILE", str(p))
    assert ch.topic_ids() == ["vendor"]
    monkeypatch.setenv("SENTINEL_CHECK_HINTS_FILE", str(tmp_path / "nope.json"))
    assert ch.load_rules() == (None, ch.INVALID_ISSUE) and ch.topic_ids() == []


# ── R2：依原因 ─────────────────────────────────────────────────

def r2(need, asset="marketing-site", controls=None, labels=None):
    imp = {"asset_id": asset, "verdict": "need_check"}
    return ch.reason_suggestions(imp, need, controls=controls or {}, labels=labels or {})


def test_r2_stack_incomplete():
    [s] = r2({"kind": "stack_incomplete", "product": "some-erp"}, asset="*")
    assert s["check"] == "確認我們是否使用 some-erp" and "補齊 runtime 快照" in s["how"]
    assert s["basis"] == "資產清單缺失或過期" and s["systems"] == []
    assert s["source"] == "rule" and s["inferred"] is False and s["target"] is None and s["hypothesis"] is None


@pytest.mark.parametrize("eco,expect", [
    ("npm", "npm ls next"), ("php", "php -v"), ("synology-dsm", "資訊中心"), ("pypi", "相依鎖定檔"),
    ("composer", "相依鎖定檔"), ("deb", "dpkg -l"), ("rpm", "rpm -q"), ("docker", "digest"), ("generic", "補 runtime 盤點"),
])
def test_r2_version_unknown_ecosystem_how(eco, expect):
    [s] = r2({"kind": "version_unknown", "product": "next", "ecosystem": eco, "version": None,
              "affected": [{"introduced": "14.0.0", "fixed": "14.2.25"}, {"introduced": "15.0.0", "fixed": None}]},
             asset="storefront", labels={"storefront": "商店網站"})
    assert expect in s["how"]
    assert s["check"].startswith("取得 storefront 上 next 的實際版本")
    assert "14.0.0 起～14.2.25 前" in s["check"] and "15.0.0 起（無修補）" in s["check"] and "修補版本 14.2.25" in s["check"]
    assert s["plain"] == "確認 next 的版本是否需要更新"
    assert s["systems"] == [{"asset_id": "storefront", "label": "商店網站"}]


def test_r2_version_unknown_npm_range_string():
    [s] = r2({"kind": "version_unknown", "product": "lodash", "ecosystem": "npm", "version": None, "affected": "<4.17.21"})
    assert "<4.17.21" in s["check"] and "修補版本 見來源" in s["check"]


def test_r2_unknown_below():
    [s] = r2({"kind": "unknown_below", "product": "php", "ecosystem": "php", "version": "7.3.1", "affected": [],
              "unknown_below": "7.4.0"})
    assert s["check"] == "php 7.3.1 是來源未涵蓋的舊分支，向原廠確認是否受影響"
    assert "受支援分支" in s["how"] and s["plain"] == "舊版本是否受影響要再向原廠確認"


def test_r2_conditions_lookup_table():
    keys = ["serves_web_requests", "session.cookie_secure", "php.allow_url_include", "hosting", "middleware_auth",
            "management_interface_internet_exposed", "login_reachable", "custom_flag"]
    out = r2({"kind": "conditions_unknown", "product": "php", "keys": keys})
    assert len(out) == 6 and out[-1]["id"] == "more"            # R2.7：8 條 → 前 5 條＋剩餘提示
    full = [ch.reason_suggestions({"asset_id": "x", "verdict": "need_check"},
                                  {"kind": "conditions_unknown", "product": "php", "keys": [k]}, controls={}, labels={})[0]
            for k in keys]
    assert full[0]["check"] == "確認 PHP 是否直接處理網頁請求"
    assert "SAPI" in full[0]["how"]
    assert full[1]["check"] == "確認 php.ini 設定 session.cookie_secure" and "session.cookie_secure" in full[1]["how"]
    assert full[2]["check"] == "確認 php.ini 設定 php.allow_url_include"
    assert full[3]["check"] == "確認是否為自行部署"
    assert "middleware" in full[4]["how"]
    assert "UPnP" in full[5]["how"] and "外部網路" in full[6]["how"]
    assert full[7]["check"] == "確認 custom_flag 的實際設定" and full[7]["how"] is None
    assert all(s["plain"] is None and s["inferred"] is False for s in full)


def test_r2_control_unknown_and_manual_check():
    res = {"C-CACHE-TLS": {"status": "unknown", "title": "快取連線需加密", "reason": "network.json 缺失"}}
    [s] = r2({"kind": "control_unknown", "control_id": "C-CACHE-TLS", "title": "快取連線需加密",
              "reason": "network.json 缺失"}, asset="*", controls=res)
    assert s["check"] == "快取連線需加密：缺少資料（network.json 缺失）"
    assert s["how"] == "補上資料後重新評估" and s["plain"] is None
    assert s["controls"] == [{"control_id": "C-CACHE-TLS", "title": "快取連線需加密", "status": "unknown",
                              "status_label": "資料不足"}]
    out = r2({"kind": "manual_check", "items": ["確認 A", "確認 B"]})
    assert [s["check"] for s in out] == ["確認 A", "確認 B"]
    assert all(s["basis"] == "事件要求人工確認" and s["source"] == "rule" and s["how"] is None for s in out)


def test_r2_cap_six_keeps_order():
    items = [f"項目 {i}" for i in range(1, 10)]
    out = r2({"kind": "manual_check", "items": items})
    assert [s["check"] for s in out[:5]] == items[:5]
    assert out[5]["id"] == "more" and out[5]["check"] == "另有 4 項待確認，見原始待確認清單"
    assert len(r2({"kind": "manual_check", "items": items[:6]})) == 6
    assert r2({"kind": "manual_check", "items": items[:6]})[5]["check"] == "項目 6"


def test_r2_does_not_read_rules():
    m = {"event": ev(), "impacts": [{"asset_id": "*", "verdict": "need_check", "to_verify": ["確認是否使用 x"],
                                     "_need": {"kind": "stack_incomplete", "product": "x"}}]}
    ch.attach(m, graph={}, controls={}, rules=None, labels={})
    assert m["impacts"][0]["suggestions"][0]["check"] == "確認我們是否使用 x"


# ── R3：被打到的地方 ──────────────────────────────────────────

def test_target_keyword_case_insensitive_and_basis_sources(rules):
    hits = ch.detect_targets(ev(title="某 saas 平台", attack_chain=["一", "後台遭存取"], summary="主要伺服器遭入侵",
                                proposed_controls=[{"title": "x", "reason": "加強 GITLAB 存取控制"}]), rules)
    got = {h["target"]["id"]: h["basis"] for h in hits}
    assert got["vendor"] == "事件標題提到「SaaS」"
    assert got["admin"] == "攻擊過程第 2 步提到「後台」"
    assert got["server"] == "事件摘要提到「伺服器」"
    assert got["code-repo"] == "建議新增的控制項提到「GitLab」"


def test_target_attck_subtechnique_and_attck_only(rules):
    hits = ch.detect_targets(ev(title="某事件", attck=["T1566.001"]), rules)
    assert [h["target"]["id"] for h in hits] == ["endpoint"] and hits[0]["basis"] == "ATT&CK T1566.001"
    assert hits[0]["key"][0] == 4
    # 關鍵字與 ATT&CK 同時命中：依據附上 ATT&CK
    [h] = ch.detect_targets(ev(title="委外商遭入侵", attck=["T1199"]), rules)
    assert h["basis"] == "事件標題提到「委外」；ATT&CK T1199"
    # 不是子技術的前綴不算（T11990 不是 T1199 的子技術）
    assert ch.detect_targets(ev(title="某事件", attck=["T11990"]), rules) == []


def test_target_order_by_earliest_source(rules):
    e = ev(title="伺服器遭入侵", attack_chain=["攻擊者進入後台", "取得郵件服務的資料"], summary="委外商通知",
           attck=["T1566"])
    order = [h["target"]["id"] for h in ch.detect_targets(e, rules)]
    assert order == ["server", "admin", "mail", "vendor", "endpoint"]
    # 同一出處層級時依規則表順序
    order = [h["target"]["id"] for h in ch.detect_targets(ev(title="伺服器與資料庫與委外商"), rules)]
    assert order == ["vendor", "database", "server"]


def test_misleading_leaked_fields_do_not_hit(rules):
    e = ev(title="某網站遭攻擊", summary="外洩電子郵件、登入密碼與信件內容", attack_chain=["異常登入"])
    assert [h["target"]["id"] for h in ch.detect_targets(e, rules)] == []


# ── R3.5／R3.6：挑選 ───────────────────────────────────────────

def ids(sugs):
    return [s["id"] for s in sugs]


def test_stated_global_priority_then_round_robin(rules, fx_graph):
    stated = ev(title="某公司伺服器漏洞遭利用，資料庫個資外洩", attck=["T1190"])
    assert ch.is_stated(stated, rules) is True
    out = ch.suggest_for_event(stated, graph=fx_graph, controls={}, rules=rules, labels={})
    assert ids(out) == ["db-exposed", "db-app-vuln", "server-unpatched", "db-cred-leak"]
    unstated = {**stated, "summary": "入侵原因仍在調查中"}
    assert ch.is_stated(unstated, rules) is False
    out = ch.suggest_for_event(unstated, graph=fx_graph, controls={}, rules=rules, labels={})
    assert ids(out) == ["db-exposed", "server-unpatched", "db-cred-leak", "server-remote-admin"]
    # attck 不是初始入侵類 → 未交代
    assert ch.is_stated({**stated, "attck": ["T1552"]}, rules) is False


def test_round_robin_cap_four_and_no_duplicates(rules, fx_graph):
    e = ev(title="委外廠商郵件服務資料庫會員中心管理後台程式碼管理員工電腦伺服器")
    out = ch.suggest_for_event(e, graph=fx_graph, controls={}, rules=rules, labels={})
    assert ids(out) == ["vendor-data-leak", "mail-key-leak", "db-exposed", "member-credential-stuffing"]
    assert len(set(ids(out))) == len(out)
    one = ch.suggest_for_event(ev(title="會員中心遭攻擊"), graph=fx_graph, controls={}, rules=rules, labels={})
    assert ids(one) == ["member-credential-stuffing", "member-idor", "member-scraping"]


def test_rule_suggestion_shape(rules, fx_graph):
    [s, *_] = ch.suggest_for_event(ev(title="委外服務商遭入侵", attck=["T1199"], summary="來源未說明手法"),
                                   graph=fx_graph, controls={}, rules=rules, labels={"mail-service": "寄信服務"})
    assert set(s) == {"id", "source", "inferred", "target", "hypothesis", "why", "check", "how", "plain", "basis",
                      "systems", "controls"}
    assert s["source"] == "rule" and s["inferred"] is True and s["target"] == "vendor"
    assert s["systems"] == [{"asset_id": "mail-service", "label": "寄信服務"},
                            {"asset_id": "saas-quicksite-builder", "label": None}]
    assert all(len(s[k] or "") <= n for k, n in ch.LIMITS.items())


# ── selector ──────────────────────────────────────────────────

GRAPH = {"nodes": [
    {"id": "b-svc", "type": "service", "exposed_to_internet": True, "data_classes": ["pii"], "env": "prod"},
    {"id": "a-svc", "type": "service", "exposed_to_internet": False, "data_classes": ["order"], "env": "test"},
    {"id": "c-svc", "type": "service", "exposed_to_internet": None, "data_classes": None},
    {"id": "dmz", "type": "zone", "exposed_to_internet": True},
    {"id": "mail-key", "type": "token", "vendor": "mail-svc"},
    {"id": "other-key", "type": "token", "vendor": None},
    {"id": "jewel", "type": "datastore", "crown_jewel": True},
    *[{"id": f"dev-{i}", "type": "device"} for i in range(7)],
]}


def sel(selector):
    return [s["asset_id"] for s in ch.select_systems(GRAPH, selector, {})]


def test_selector_or_and_bool_missing_zone_and_cap():
    assert sel([{"types": ["service"], "exposed": True}]) == ["b-svc"]                 # AND
    assert sel([{"types": ["service"], "exposed": True}, {"has_vendor": True}]) == ["b-svc", "mail-key"]   # OR
    assert sel([{"exposed": False}]) == ["a-svc"]                    # 缺值或 None 對 true 與 false 都不成立
    assert "c-svc" not in sel([{"exposed": True}]) and "dmz" not in sel([{"exposed": True}])   # zone 一律排除
    assert sel([{"data_classes_any": ["pii", "order"]}]) == ["a-svc", "b-svc"]          # 依 asset_id 排序
    assert sel([{"env": "test"}]) == ["a-svc"] and sel([{"crown_jewel": True}]) == ["jewel"]
    assert sel([{"id_contains": ["mail"]}]) == ["mail-key"]
    assert sel([{"types": ["device"]}]) == [f"dev-{i}" for i in range(5)]               # 最多 5 個


def test_selector_works_on_networkx_graph(baseline):
    got = ch.select_systems(baseline["graph"], [{"types": ["vendor"], "id_contains": ["mail"]}], {"mail-service": "寄信服務"})
    assert got == [{"asset_id": "mail-service", "label": "寄信服務"}]


def test_no_system_hypothesis_is_kept(rules):
    out = ch.suggest_for_event(ev(title="會員中心遭攻擊"), graph={"nodes": []}, controls={}, rules=rules, labels={})
    assert len(out) == 3 and all(s["systems"] == [] for s in out)


def test_control_results_missing_means_unknown(rules, fx_graph):
    controls = {"C-THIRD-PARTY-KEY-ROTATION": {"status": "fail", "title": "第三方金鑰需定期輪替"},
                "C-INTERNAL-TOOL-EXPOSED": {"status": "pass", "title": "內部工具不得對外開放"}}
    out = ch.suggest_for_event(ev(title="委外服務商遭入侵"), graph=fx_graph, controls=controls, rules=rules, labels={})
    by = {s["id"]: s for s in out}
    assert by["vendor-key-abuse"]["controls"] == [{"control_id": "C-THIRD-PARTY-KEY-ROTATION", "title": "第三方金鑰需定期輪替",
                                                   "status": "fail", "status_label": "不符合"}]
    assert by["vendor-account"]["controls"][0]["status_label"] == "符合"
    db = ch.suggest_for_event(ev(title="資料庫遭存取"), graph=fx_graph, controls={}, rules=rules, labels={})[0]
    assert [(c["status"], c["status_label"]) for c in db["controls"]] == [("unknown", "資料不足")] * 3
    assert db["controls"][0]["title"] == "內部工具不得對外開放"           # 沒有結果時標題取自 controls.yaml


# ── R4：AI 推測（消費端）與 R3.7 通用退回 ──────────────────────

def test_ai_used_only_when_rules_miss(rules, fx_graph):
    pep = [{"topic": "admin", "text": "可能是後台帳號被盜用；查後台登入紀錄", "basis": "攻擊過程第 1 步"}]
    miss = ev(title="某公司遭駭", possible_entry_points=pep)
    [s] = ch.suggest_for_event(miss, graph=fx_graph, controls={}, rules=rules, labels={})
    assert s["id"] == "ai-1" and s["source"] == "ai" and s["inferred"] is True and s["target"] == "admin"
    assert s["hypothesis"] == s["check"] == s["plain"] == pep[0]["text"]
    assert s["basis"] == "AI 依事件推測：攻擊過程第 1 步"
    assert [x["asset_id"] for x in s["systems"]] == ["internal-tool", "nas-office-01", "phpmyadmin"]   # admin 第一個假設
    assert s["controls"][0]["control_id"] == "C-INTERNAL-TOOL-EXPOSED"
    hit = {**miss, "title": "某公司會員中心遭駭"}
    assert all(x["source"] == "rule" for x in ch.suggest_for_event(hit, graph=fx_graph, controls={}, rules=rules, labels={}))


def test_ai_items_rechecked(rules, fx_graph):
    long_text = "長" * 101
    pep = [
        "不是物件",
        {"text": "", "basis": "x"},
        {"text": "缺依據", "basis": "  "},
        {"text": long_text, "basis": "x"},
        {"text": "x", "basis": "長" * 121},
        {"text": "金鑰 ghp_" + "a" * 30, "basis": "x"},
        {"text": "聯絡 someone@example.com", "basis": "x"},
        {"topic": 3, "text": "錯型別 topic", "basis": "x"},
        {"topic": "not-a-target", "text": "topic 不在白名單", "basis": "摘要"},
        {"text": "沒有 topic\n\t的推測", "basis": "標題"},
    ]
    out = ch.suggest_for_event(ev(possible_entry_points=pep), graph=fx_graph, controls={}, rules=rules, labels={})
    assert ids(out) == ["ai-1", "ai-2"]
    assert out[0]["target"] is None and out[0]["systems"] == [] and out[0]["controls"] == []
    assert out[1]["check"] == "沒有 topic 的推測"
    assert ch.suggest_for_event(ev(possible_entry_points="字串"), graph=fx_graph, controls={}, rules=rules,
                                labels={})[0]["id"] == "generic-1"
    many = [{"text": f"推測 {i}", "basis": "x"} for i in range(5)]
    assert len(ch.suggest_for_event(ev(possible_entry_points=many), graph=fx_graph, controls={}, rules=rules,
                                    labels={})) == 3


def test_invalid_rules_drop_ai_topic(fx_graph):
    pep = [{"topic": "admin", "text": "後台帳號被盜用", "basis": "攻擊過程第 1 步"}]
    [s] = ch.suggest_for_event(ev(title="某公司管理後台遭駭", possible_entry_points=pep), graph=fx_graph, controls={},
                               rules=None, labels={})
    assert s["source"] == "ai" and s["target"] is None and s["systems"] == [] and s["controls"] == []


@pytest.mark.parametrize("n", [0, 3, 5])
def test_generic_fallback_matches_to_verify(rules, n):
    pcs = [{"title": f"控制項 {i}", "reason": "r"} for i in range(1, n + 1)]
    e = ev(title="某公司遭駭", proposed_controls=pcs)
    for r in (rules, None):
        out = ch.suggest_for_event(e, graph={}, controls={}, rules=r, labels={})
        checks = [GENERIC_1, GENERIC_2, *[f"建議新增控制項：控制項 {i}" for i in range(1, n + 1)]]
        if len(checks) <= 6:
            assert [s["check"] for s in out] == checks
        else:
            assert [s["check"] for s in out] == [*checks[:5], f"另有 {len(checks) - 5} 項待確認，見原始待確認清單"]
        assert out[0]["plain"] == "依事件內容人工判斷是否適用" and all(s["plain"] is None for s in out[1:])
        assert all(s["source"] == "rule" and s["inferred"] is False for s in out)


# ── attach ────────────────────────────────────────────────────

def test_attach_strips_private_and_only_need_check(rules, fx_graph):
    m = {"event": ev(title="會員中心遭攻擊"), "impacts": [
        {"asset_id": "a", "verdict": "affected", "risk_id": "r1", "reason": "x", "to_verify": []},
        {"asset_id": "b", "verdict": "not_affected", "risk_id": None, "reason": "y"},
        {"asset_id": "*", "verdict": "need_check", "risk_id": None, "reason": "z", "to_verify": ["t"],
         "_need": {"kind": "no_criteria"}},
        {"asset_id": "c", "verdict": "need_check", "risk_id": None, "reason": "w", "to_verify": ["v"]},
    ]}
    m["impacts"][0]["_need"] = {"kind": "manual_check", "items": []}       # 私有欄位一律移除，affected 也一樣
    before = copy.deepcopy(m)
    ch.attach(m, graph=fx_graph, controls={}, rules=rules, labels={})
    assert not any("_need" in i for i in m["impacts"])
    assert "suggestions" not in m["impacts"][0] and "suggestions" not in m["impacts"][1]
    assert ids(m["impacts"][2]["suggestions"])[0] == "member-credential-stuffing"
    assert m["impacts"][3]["suggestions"] == []
    for a, b in zip(before["impacts"], m["impacts"]):
        assert {k: v for k, v in a.items() if k != "_need"} == {k: v for k, v in b.items() if k != "suggestions"}
    assert ch.strip_private([{"_need": {}, "x": 1}]) == [{"x": 1}]


def test_event_level_need_check_gets_nothing(rules):
    m = {"event": ev(), "impacts": [], "status": "need_check"}
    ch.attach(m, graph={}, controls={}, rules=rules, labels={})
    assert m["impacts"] == []


# ── R8.1：凍結的 9 件需確認事件 ────────────────────────────────

R81 = {
    "live-arara-mail-provider-breach-2026-11": ["vendor", "mail", "database"],
    "live-arara-mail-vendor-breach-2026-11": ["vendor", "mail"],
    "live-cyberbiz-ecommerce-supplier-breach-2026-11": ["vendor", "database"],
    "live-cyberbiz-shop-db-2026-11": ["vendor", "database"],
    "live-cyberbiz-vendor-breach-2026-11": ["vendor", "database"],
    "live-eztravel-member-center-breach-2026-11": ["member-portal"],
    "live-nitori-breach-2026-11": ["database", "server"],
    "live-nitori-member-breach-2026-11": ["database", "server"],
    "live-sharefull-admin-breach-2026-11": ["admin", "database"],
}


def test_fixture_is_frozen_need_check_events(fx_events, fx_graph):
    assert set(fx_events) == set(R81)
    assert all(e["summary"] and e["kind"] == "live" for e in fx_events.values())
    blob = json.dumps([fx_events, fx_graph], ensure_ascii=False)
    assert "DEMO-FAKE" not in blob and not any(r.search(blob) for r in (re.compile(r"ghp_|sk-ant-|AKIA[0-9A-Z]{16}"),))


@pytest.mark.parametrize("event_id", sorted(R81))
def test_r81_targets_and_suggestions(event_id, rules, fx_events, fx_graph):
    e = fx_events[event_id]
    assert [h["target"]["id"] for h in ch.detect_targets(e, rules)] == R81[event_id]
    out = ch.suggest_for_event(e, graph=fx_graph, controls={}, rules=rules, labels={})
    assert out and all(s["source"] == "rule" and s["inferred"] and not s["id"].startswith("generic") for s in out)
    assert len(out) <= 4 and [s["target"] for s in out][0] == R81[event_id][0]


def test_r81_arara_and_false_positive_rules(rules, fx_events, fx_graph):
    for eid in ("live-arara-mail-provider-breach-2026-11", "live-arara-mail-vendor-breach-2026-11"):
        out = ch.suggest_for_event(fx_events[eid], graph=fx_graph, controls={}, rules=rules, labels={})
        assert any("mail-service" in [x["asset_id"] for x in s["systems"]] for s in out)
    provider = ch.suggest_for_event(fx_events["live-arara-mail-provider-breach-2026-11"], graph=fx_graph, controls={},
                                    rules=rules, labels={})
    assert ids(provider) == ["vendor-data-leak", "mail-key-leak", "db-exposed", "vendor-key-abuse"]   # design §3.7 範例
    assert [x["asset_id"] for x in provider[1]["systems"]] == ["mail-api-key", "mail-service"]
    ez = {h["target"]["id"] for h in ch.detect_targets(fx_events["live-eztravel-member-center-breach-2026-11"], rules)}
    sf = {h["target"]["id"] for h in ch.detect_targets(fx_events["live-sharefull-admin-breach-2026-11"], rules)}
    assert "mail" not in ez and not {"mail", "member-portal"} & sf
