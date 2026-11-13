"""需確認項目的查核建議（specs/check-hints，T1～T3）：規則表驗證、R2 依原因、R3 破口推測、R4 AI 推測消費端、R8.1 固定資料、情資報告 markdown。

v0.12.1（specs/check-hints-ai）：採用順序改為 AI 推測 → 規則推測 → 通用建議。v0.12.0 的規則測試都是「沒有 AI 推測時」的情境
（事件不帶 possible_entry_points）；AI 優先、systems 驗證與 R7.1 的 5 件 2026-11-13 事件在檔案後段。
"""
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


@pytest.fixture(scope="module")
def fx_ai_doc():
    """R7.1：2026-11-13 daily 的 5 件需確認事件（check、systems 為測試資料補值，見檔頭 note）。"""
    return json.loads((FIXTURES / "events-2026-11-13.json").read_text(encoding="utf-8"))


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
    assert [t["id"] for t in rules["targets"]] == ["vendor", "mail", "database", "member-portal", "admin", "code-repo",
                                                   "endpoint", "server"]
    assert not hasattr(ch, "topic_ids")                                  # v0.12.1 R6：AI 不再需要 topic 白名單
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
    assert [t["id"] for t in ch.load_rules()[0]["targets"]] == ["vendor"]
    monkeypatch.setenv("SENTINEL_CHECK_HINTS_FILE", str(tmp_path / "nope.json"))
    assert ch.load_rules() == (None, ch.INVALID_ISSUE)


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


# ── R3：被打到的地方（規則推測；以下事件都不帶 possible_entry_points，即「沒有 AI 推測時」）──────

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


# ── AI 推測優先（specs/check-hints-ai R3、R4）與 R3.7 通用退回 ─────────────

def ai_item(text="會員訂單 API 可能缺少存取控制或限流", check="查訂單 API 是否驗證資料擁有者，並查存取紀錄中的異常 IP",
            systems=("api-gateway", "storefront"), basis="攻擊過程第 3 步提到異常請求涉及會員訂單相關 API", **kw):
    systems = list(systems) if isinstance(systems, (list, tuple)) else systems   # 非陣列原樣保留（測試不合格值）
    return {"text": text, "check": check, "systems": systems, "basis": basis, **kw}


RULE_HIT_TITLE = "某公司會員中心遭駭"                                     # 規則會命中 member-portal


def test_rule_hit_title_really_hits_rules(rules):
    assert [h["target"]["id"] for h in ch.detect_targets(ev(title=RULE_HIT_TITLE), rules)] == ["member-portal"]


def test_ai_first_and_not_mixed_with_rules(rules, fx_graph):
    """R3.1：有合格的 AI 推測 → 只用 AI，不再加入規則推測（規則就算命中也一樣）。"""
    labels = {"api-gateway": "API 閘道", "storefront": "商店網站"}
    out = ch.suggest_for_event(ev(title=RULE_HIT_TITLE, possible_entry_points=[ai_item()]), graph=fx_graph, controls={},
                               rules=rules, labels=labels)
    assert [s["source"] for s in out] == ["ai"]
    [s] = out
    assert s == {"id": "ai-1", "source": "ai", "inferred": True, "target": None,             # R4.1 欄位對應
                 "hypothesis": "會員訂單 API 可能缺少存取控制或限流", "why": None,
                 "check": "查訂單 API 是否驗證資料擁有者，並查存取紀錄中的異常 IP", "how": None,
                 "plain": "會員訂單 API 可能缺少存取控制或限流",
                 "basis": "AI 依事件推測：攻擊過程第 3 步提到異常請求涉及會員訂單相關 API",
                 "systems": [{"asset_id": "api-gateway", "label": "API 閘道"}, {"asset_id": "storefront", "label": "商店網站"}],
                 "controls": []}
    # 規則表無效時 AI 推測不受影響
    assert ch.suggest_for_event(ev(title=RULE_HIT_TITLE, possible_entry_points=[ai_item()]), graph=fx_graph, controls={},
                                rules=None, labels=labels) == out


def test_ai_check_missing_or_blank_uses_text(fx_graph):
    for check in (None, "", "  \n "):
        [s] = ch.ai_suggestions(ev(possible_entry_points=[ai_item(check=check)]), graph=fx_graph, labels={})
        assert s["check"] == s["plain"] == s["hypothesis"] == "會員訂單 API 可能缺少存取控制或限流"
    item = ai_item()
    item.pop("check")
    assert ch.ai_suggestions(ev(possible_entry_points=[item]), graph=fx_graph, labels={})[0]["check"] == item["text"]


def test_ai_suggestions_returns_list():
    assert ch.ai_suggestions(ev(), graph={}, labels={}) == [] and isinstance(ch.ai_suggestions(ev(), graph={}, labels={}), list)


def test_ai_systems_only_from_ai_assets(fx_graph, baseline):
    """R4.2／R7.5：systems 只保留本次 ai_assets 中的 ID；graph 有但被排除的類型（app_version、sdk、zone）也移除。"""
    picked = ["brand-app@3.1.0", "@demo-vendor/push-sdk@2.3.1", "internet", "corp-vpn", "no-such-system",
              "storefront", "storefront", "api-gateway", "Storefront", 7, None, {"id": "x"}]
    graph_ids = {n["id"] for n in fx_graph["nodes"]}
    assert {"brand-app@3.1.0", "@demo-vendor/push-sdk@2.3.1", "internet", "corp-vpn"} <= graph_ids   # 這些都在 graph 中
    [s] = ch.ai_suggestions(ev(possible_entry_points=[ai_item(systems=picked)]), graph=fx_graph, labels={})
    assert [x["asset_id"] for x in s["systems"]] == ["storefront", "api-gateway"]                    # 依 AI 給的順序、去重
    many = ["storefront", "api-gateway", "member-api", "order-db-prod", "phpmyadmin", "gitlab", "mail-service"]
    [s] = ch.ai_suggestions(ev(possible_entry_points=[ai_item(systems=many)]), graph=fx_graph, labels={})
    assert [x["asset_id"] for x in s["systems"]] == many[:5]                                         # 最多 5 個
    # graph 沒有任何節點時全部移除，推測本身保留
    [s] = ch.ai_suggestions(ev(possible_entry_points=[ai_item()]), graph={"nodes": []}, labels={})
    assert s["systems"] == [] and s["source"] == "ai"
    # networkx 圖同樣驗證
    [s] = ch.ai_suggestions(ev(possible_entry_points=[ai_item(systems=["mail-service", "brand-app@3.1.0"])]),
                            graph=baseline["graph"], labels={"mail-service": "寄信服務"})
    assert s["systems"] == [{"asset_id": "mail-service", "label": "寄信服務"}]


def test_ai_systems_drop_ids_failing_value_checks():
    """值驗證不合格的資產（ID 含 IP、連接埠、路徑）就算在 graph 中，也不能被 AI 挑到。"""
    graph = {"nodes": [{"id": "db192.0.2.1", "type": "datastore"}, {"id": "web:8080", "type": "service"},
                       {"id": "ok-svc", "type": "service"}, {"id": "odd-type", "type": "identity"}]}
    [s] = ch.ai_suggestions(ev(possible_entry_points=[ai_item(systems=["db192.0.2.1", "web:8080", "odd-type", "ok-svc"])]),
                            graph=graph, labels={})
    assert [x["asset_id"] for x in s["systems"]] == ["ok-svc"]


def test_ai_items_rechecked(rules, fx_graph):
    pep = [
        "不是物件",
        ai_item(text=""),
        ai_item(basis="  "),
        ai_item(text=None),
        ai_item(text="長" * 81),                                        # text 超過 80 字：整項丟掉
        ai_item(check="長" * 161),                                      # check 超過 160 字
        ai_item(basis="長" * 121),                                      # basis 超過 120 字
        ai_item(text="金鑰 ghp_" + "a" * 30),
        ai_item(check="聯絡 someone@example.com"),                      # 機敏內容在 check
        ai_item(basis="sk-ant-" + "x" * 30),
        ai_item(check=123),                                             # check 不是字串
        {k: v for k, v in ai_item().items() if k != "systems"},          # 缺 systems
        ai_item(systems="storefront"),                                  # systems 不是陣列
        {"topic": "admin", "text": "v0.12.0 舊格式", "basis": "攻擊過程第 1 步"},
        ai_item(text="可能是後台\n\t帳號遭盜用", systems=()),
        ai_item(text="第二項", topic="admin"),                          # 多出的 topic 不影響（R6：不再讀取）
    ]
    out = ch.suggest_for_event(ev(possible_entry_points=pep), graph=fx_graph, controls={}, rules=rules, labels={})
    assert ids(out) == ["ai-1", "ai-2"] and {s["source"] for s in out} == {"ai"}
    assert out[0]["plain"] == "可能是後台 帳號遭盜用" and out[0]["systems"] == [] and out[0]["target"] is None
    assert out[1]["plain"] == "第二項" and out[1]["target"] is None
    many = [ai_item(text=f"推測 {i}") for i in range(5)]
    assert [s["plain"] for s in ch.suggest_for_event(ev(possible_entry_points=many), graph=fx_graph, controls={},
                                                     rules=rules, labels={})] == ["推測 0", "推測 1", "推測 2"]


def test_ai_accepts_pydantic_entry_points(fx_graph):
    from schemas import IntelEvent
    e = IntelEvent.model_validate({"id": "live-x", "kind": "live", "title": "t", "date": "2026-11-13", "revision": "1",
                                   "confidence": "provisional", "sources": [], "possible_entry_points": [ai_item()]})
    [s] = ch.ai_suggestions({"possible_entry_points": e.possible_entry_points}, graph=fx_graph, labels={})
    assert s["source"] == "ai" and [x["asset_id"] for x in s["systems"]] == ["api-gateway", "storefront"]


NO_AI = {
    "absent": lambda e: e.pop("possible_entry_points", None),
    "empty": lambda e: e.update(possible_entry_points=[]),
    "all_invalid": lambda e: e.update(possible_entry_points=[ai_item(text=""), ai_item(basis=None), ai_item(systems=None),
                                                             ai_item(text="長" * 81), "x"]),
}


@pytest.mark.parametrize("case", sorted(NO_AI))
def test_no_valid_ai_falls_back_to_rules(case, rules, fx_graph):
    """R4.3／R7.6：欄位不存在、空陣列、全部項目不合格，三種都進入規則備援（source=rule、inferred=true）。"""
    e = ev(title=RULE_HIT_TITLE, possible_entry_points=[ai_item()])
    NO_AI[case](e)
    out = ch.suggest_for_event(e, graph=fx_graph, controls={}, rules=rules, labels={})
    assert out == ch.suggest_for_event(ev(title=RULE_HIT_TITLE), graph=fx_graph, controls={}, rules=rules, labels={})
    assert ids(out) == ["member-credential-stuffing", "member-idor", "member-scraping"]
    assert all(s["source"] == "rule" and s["inferred"] is True for s in out)
    # 規則也沒命中 → 通用建議
    miss = ev(title="某公司遭駭", possible_entry_points=[ai_item()])
    NO_AI[case](miss)
    assert ids(ch.suggest_for_event(miss, graph=fx_graph, controls={}, rules=rules, labels={})) == ["generic-1", "generic-2"]


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


# ── R7.1（specs/check-hints-ai）：凍結的 2026-11-13 5 件需確認事件與 AI 推測 ─────────

R71 = ["live-evt-cyberbiz-2026-11", "live-evt-mercuries-2026-11", "live-evt-nitori-2026-11",
       "live-evt-sharefull-2026-11", "live-evt-amadeus-2026-11"]


def _r71_labels():
    from tools.digest import load_asset_label_file
    return load_asset_label_file()[0]


def test_r71_fixture_frozen_from_commit(fx_ai_doc):
    from schemas import IntelEvent
    from tools.daily_intel import _entry_points
    assert fx_ai_doc["frozen_from"].startswith("662fbfd3deece733de9e194cd8a26f5a493d3e0d:")
    assert "測試資料補值" in fx_ai_doc["note"]
    assert [e["id"] for e in fx_ai_doc["events"]] == R71
    for e in fx_ai_doc["events"]:
        assert e["kind"] == "live" and e["products"] == [] and e["cves"] == [] and e["controls"] == []
        assert "測試資料補值" in e["fixture_note"] and e["possible_entry_points"]
        IntelEvent.model_validate(e)                                     # 新格式通過 EntryPoint 驗證
        assert _entry_points(e["possible_entry_points"]) == e["possible_entry_points"]   # daily_intel 清理不改內容


@pytest.mark.parametrize("event_id", R71)
def test_r71_only_ai_suggestions(event_id, rules, fx_ai_doc, fx_graph):
    e = next(x for x in fx_ai_doc["events"] if x["id"] == event_id)
    out = ch.suggest_for_event(e, graph=fx_graph, controls={}, rules=rules, labels=_r71_labels())
    assert out and all(s["source"] == "ai" and s["inferred"] is True for s in out)
    assert [s["plain"] for s in out] == [p["text"] for p in e["possible_entry_points"]]
    assert [x["asset_id"] for x in out[0]["systems"]] == e["possible_entry_points"][0]["systems"]
    assert all(x["label"] for s in out for x in s["systems"])            # 都有白話名稱


def test_r71_mercuries_ai_not_rule_boilerplate(rules, fx_ai_doc, fx_graph):
    e = next(x for x in fx_ai_doc["events"] if x["id"] == "live-evt-mercuries-2026-11")
    out = ch.suggest_for_event(e, graph=fx_graph, controls={}, rules=rules, labels=_r71_labels())
    blob = json.dumps(out, ensure_ascii=False)
    assert {s["source"] for s in out} == {"ai"}
    assert "會員訂單 API" in blob and "遠端管理帳號" not in blob
    # v0.12.0 的問題：規則因「潛在漏洞」命中伺服器類（證明這個測試有意義）
    rule_only = ch.suggest_for_event({**e, "possible_entry_points": []}, graph=fx_graph, controls={}, rules=rules, labels={})
    assert "遠端管理帳號" in json.dumps(rule_only, ensure_ascii=False)


@pytest.mark.parametrize("event_id", R71)
def test_r71_without_ai_falls_back_to_rules(event_id, rules, fx_ai_doc, fx_graph):
    e = copy.deepcopy(next(x for x in fx_ai_doc["events"] if x["id"] == event_id))
    e.pop("possible_entry_points")
    out = ch.suggest_for_event(e, graph=fx_graph, controls={}, rules=rules, labels={})
    assert out and all(s["source"] == "rule" and s["inferred"] is True for s in out)
    assert not any(s["id"].startswith(("ai-", "generic")) for s in out)


# ── R5.3：情資報告（intel_report）──────────────────────────────

def _report_match(need_suggestions=None):
    """一件受影響＋兩件需確認的比對結果；need_suggestions 為 None 時需確認項目不帶 suggestions 鍵（舊資料）。"""
    from tools.intel_report import build_report   # noqa: F401（確認可匯入）
    e = {**ev(title="某公司遭駭"), "date": "2026-11-10", "confidence": "provisional", "sources": [
        {"url": "https://example.test/1", "title": "來源一", "quote": "q"}]}
    impacts = [
        {"event_id": e["id"], "asset_id": "storefront", "basis": "version", "our_state": "next 15.0.0", "verdict": "affected",
         "risk_id": "r-x", "reason": "版本在受影響範圍", "to_verify": []},
        {"event_id": e["id"], "asset_id": "*", "basis": "control", "our_state": "沒有比對依據", "verdict": "need_check",
         "risk_id": None, "reason": "事件沒有可比對的產品", "to_verify": [GENERIC_1, GENERIC_2]},
        {"event_id": e["id"], "asset_id": "cache-redis", "basis": "version", "our_state": "redis 7.0.15",
         "verdict": "need_check", "risk_id": None, "reason": "版本範圍無法判斷", "to_verify": []},
    ]
    if need_suggestions is not None:
        impacts[1]["suggestions"], impacts[2]["suggestions"] = need_suggestions
    return {"event": e, "impacts": impacts, "status": "need_check", "notes": [], "complete": True}


def test_report_rows_only_need_check_carry_suggestions(rules, fx_graph):
    from tools.intel_report import build_report
    rule = ch.suggest_for_event(ev(title="某公司會員中心遭駭"), graph=fx_graph, controls={}, rules=rules, labels={})
    rep = build_report(_report_match((rule, [])), {}, {})
    affected = [r for r in rep["blocks"]["4_unaffected_and_check"]["need_check"] + rep["blocks"]["3_affected"]
                if r["verdict"] == "affected"]
    assert affected and all("suggestions" not in r for r in affected)
    need = rep["blocks"]["4_unaffected_and_check"]["need_check"]
    assert [r["suggestions"] for r in need] == [rule, []]
    old = build_report(_report_match(None), {}, {})                      # 舊資料：需確認項目沒有 suggestions 時為空陣列
    assert [r["suggestions"] for r in old["blocks"]["4_unaffected_and_check"]["need_check"]] == [[], []]
    assert all("suggestions" not in r for r in old["blocks"]["3_affected"])


def test_markdown_suggestion_subitems_and_inferred_mark(rules, fx_graph):
    from tools.intel_report import build_report, to_markdown
    labels = {"mail-service": "寄信服務"}
    rule = ch.suggest_for_event(ev(title="某寄信服務商遭入侵"), graph=fx_graph, controls={}, rules=rules, labels=labels)
    pep = [{"text": "可能是後台帳號遭盜用；查後台登入紀錄", "systems": [], "basis": "攻擊過程第 1 步"}]   # 沒寫 check → 用 text
    ai = ch.suggest_for_event(ev(title="某公司遭駭", possible_entry_points=pep), graph=fx_graph, controls={}, rules=rules,
                              labels=labels)
    r2 = ch.reason_suggestions({"asset_id": "cache-redis"}, {"kind": "version_unknown", "product": "redis",
                                                             "ecosystem": "generic", "affected": []},
                               controls={}, labels=labels)
    generic = ch.generic_suggestions(ev())
    md = to_markdown(build_report(_report_match((rule + ai + generic, r2)), {}, {}))
    lines = md.split("\n")
    i = lines.index(f"- 需確認：*：{GENERIC_1}；{GENERIC_2}")
    sub = lines[i + 1: i + 1 + len(rule) + len(ai) + len(generic)]
    assert all(s.startswith("  - ") for s in sub)
    # R3 規則推測：標「（推測）」；系統有白話名稱用名稱，沒有時顯示 asset_id
    first = rule[0]
    assert first["id"] == "vendor-data-leak"
    names = "、".join(x["label"] or x["asset_id"] for x in first["systems"])
    assert sub[0] == f"  - （推測）{first['hypothesis']}；查：{first['check']}；系統：{names}"
    assert "寄信服務" in names and any(x["label"] is None and x["asset_id"] in names for x in first["systems"])
    # AI 推測：標「（推測）」；hypothesis 與 check 同文不重複；沒有系統時不列系統
    assert sub[len(rule)] == f"  - （推測）{pep[0]['text']}"
    # 通用建議（R3.7）不加「（推測）」
    assert sub[len(rule) + 1:] == [f"  - 查：{GENERIC_1}", f"  - 查：{GENERIC_2}"]
    # R2 依原因：不加「（推測）」，系統顯示 asset_id（沒有白話名稱）
    j = lines.index("- 需確認：cache-redis：版本範圍無法判斷")
    assert lines[j + 1] == f"  - 查：{r2[0]['check']}；系統：cache-redis"
    assert "（推測）" not in lines[j + 1] and not lines[j + 2].startswith("  - ")
    # 沒有相關系統的破口假設仍保留，顯示「盤點中沒有對應系統」（R3.3）
    lonely = ch.suggest_for_event(ev(title="某公司會員中心遭駭"), graph={}, controls={}, rules=rules, labels={})
    md2 = to_markdown(build_report(_report_match((lonely[:1], [])), {}, {}))
    assert f"  - （推測）{lonely[0]['hypothesis']}；查：{lonely[0]['check']}；系統：盤點中沒有對應系統" in md2.split("\n")


MD_WITHOUT_SUGGESTIONS = f"""# 某公司遭駭
`真實` `暫定`

**結論：1 項受影響，最高風險為未評。storefront：next 15.0.0。**

## 事件摘要
某公司遭駭

_自動摘要未產生_

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| storefront | next 15.0.0 | version | 受影響 | — |

## 不受影響與需確認
- 需確認：*：{GENERIC_1}；{GENERIC_2}
- 需確認：cache-redis：版本範圍無法判斷

## 處理狀態
待處理

## 來源
- 來源一：https://example.test/1
"""


def test_markdown_without_suggestions_is_unchanged():
    """沒有建議的報告（舊資料沒有 suggestions 鍵，或空陣列）markdown 與改動前相同。"""
    from tools.intel_report import build_report, to_markdown
    old = to_markdown(build_report(_report_match(None), {}, {}))
    assert old == MD_WITHOUT_SUGGESTIONS                                  # 與改動前的 to_markdown 輸出逐字相同
    assert to_markdown(build_report(_report_match(([], [])), {}, {})) == old
    assert not any(line.startswith("  - ") for line in old.split("\n"))
