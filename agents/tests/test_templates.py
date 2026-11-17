"""程式範本（specs/plain-brief design §4、§5）：白話、不出現版本號與 CVE；決策帶「不決定的話」；數字對到正確的指標。"""
import json
import re

import pytest

from schemas import Solution
from tools.common import RULES_DIR
from tools.report_builder import public_labels
from tools.templates import (DECISION_SEP, FACT_WORDS, UNNAMED_SYSTEM, _COUNT_RE, ceo_summary, decision_ok, decisions, fact_key,
                             mismatched_numbers, risk_reach, solution_for, summary_facts)

TECH = re.compile(r"CVE-|CVSS|\d+\.\d+|WAF|VPN|Token|入侵路徑|納管|除役", re.I)
FORBIDDEN = re.compile(r"CVE-|WAF|VPN|Token|入侵路徑|納管|除役", re.I)
SHADOW_IF_NOT = "負責人沒確認前，更新與監控可能沒人做，出事時也可能沒人發現。"
ASK = "要正式列管（指定負責人、定期更新），還是確認沒人用後關掉？"


def _risk(**over):
    base = {"id": "r", "asset_id": "a", "title": "t", "category": "config", "level": "high", "status": "open",
            "breakdown": [], "attack_path": None, "deadline_hours": 24}
    return {**base, **over}


def _eol(**over):
    return _risk(breakdown=[{"factor": "已停止支援", "points": 2, "reason": "x"}], **over)


# ── CEO 摘要（§5.1）──────────────────────────────────────────────────
def test_baseline_summary_is_plain_language(baseline):
    nodes = dict(baseline["graph"].nodes(data=True))
    s = ceo_summary(baseline["light"], baseline["risks"], {"checked": 7, "affected": 6}, nodes, public_labels(baseline))
    assert s == [
        "今天是紅燈：有 14 個高風險、18 個中風險的問題還沒處理。",
        "最急的是 5 個問題可以被駭客串起來一路闖進去，最後可能拿到訂單資料、會員個資、核心系統（自動部署流程）；"
        "另有 1 個對外系統的軟體原廠已不再修補。",
        "今天看了 7 件外面發生的資安事件，其中 6 件的問題我們也有。",
    ]
    assert not any(TECH.search(x) for x in s), s


def test_target_without_data_classes_and_no_highs():
    nodes = {"deploy-pipeline": {"data_classes": []}}
    chained = [_risk(attack_path=["laptop", "token", "deploy-pipeline"])]
    assert ceo_summary("red", chained, {}, nodes)[1] == "最急的是 1 個問題可以被駭客串起來一路闖進去，最後可能拿到核心系統（deploy-pipeline）。"
    assert ceo_summary("red", chained, {}, nodes, {"deploy-pipeline": "自動部署流程"})[1] == \
        "最急的是 1 個問題可以被駭客串起來一路闖進去，最後可能拿到核心系統（自動部署流程）。"
    assert ceo_summary("red", [_risk(attack_path=["x", "session.cookie_secure"])], {}, {})[1] == \
        f"最急的是 1 個問題可以被駭客串起來一路闖進去，最後可能拿到核心系統（{UNNAMED_SYSTEM}）。"   # ID 不能公開
    assert ceo_summary("yellow", [_risk(level="medium")], {})[1] == "目前沒有高風險。"
    assert ceo_summary("red", [_risk()], {})[1] == "最急的是 1 個高風險要在 24 小時內處理。"
    assert ceo_summary("red", [_eol()], {})[1] == "最急的是 1 個對外系統的軟體原廠已不再修補。"
    assert ceo_summary("green", [], {"checked": 3, "affected": 0}) == [
        "今天是綠燈：有 0 個高風險、0 個中風險的問題還沒處理。", "目前沒有高風險。",
        "今天看了 3 件外面發生的資安事件，其中 0 件的問題我們也有。"]


# ── 決策（§5.1、R4.2）────────────────────────────────────────────────
def test_decisions_merge_shadow_it_after_takedown(baseline):
    labels = public_labels(baseline)
    out = decisions(baseline["risks"], labels)
    shadow = sorted({r["asset_id"] for r in baseline["risks"]
                     if r["category"] == "shadow_it" and r["level"] == "high" and r["status"] != "fixed"})
    assert out[0] == (f"是否先把行銷官網暫時關掉？{DECISION_SEP}行銷官網的軟體原廠已不再修補，漏洞會一直開著，"
                      "外人可能藉此入侵或竄改內容。")
    merged = out[1]
    assert merged.startswith(f"這 {len(shadow)} 個沒登記的系統（") and merged.endswith(f"{ASK}{DECISION_SEP}{SHADOW_IF_NOT}")
    names = merged.split("（", 1)[1].split("）", 1)[0].split("、")
    assert sorted(names) == sorted(labels[a] for a in shadow)
    assert len(out) == 2 and all(decision_ok(d) for d in out)
    assert not any(FORBIDDEN.search(d) for d in out)
    raw = decisions(baseline["risks"])                                       # 沒有名稱時：ID 通過檢查才用
    assert raw[0].startswith(f"是否先把 marketing-site 暫時關掉？{DECISION_SEP}")


def test_single_shadow_it_sentence():
    assert decisions([_risk(category="shadow_it", asset_id="nas-office-01")], {"nas-office-01": "辦公室 NAS"}) == \
        [f"辦公室 NAS 沒有登記，{ASK}{DECISION_SEP}{SHADOW_IF_NOT}"]
    assert decisions([_risk(category="shadow_it", asset_id="nas-office-01")]) == \
        [f"nas-office-01 沒有登記，{ASK}{DECISION_SEP}{SHADOW_IF_NOT}"]
    assert decisions([_risk(category="shadow_it", status="fixed")]) == []


def test_decision_ok():
    assert decision_ok(f"要不要關掉？{DECISION_SEP}會被入侵。")
    assert not decision_ok("要不要關掉？")                                  # 沒有分隔字串
    assert not decision_ok(f"要不要關掉？{DECISION_SEP}a{DECISION_SEP}b")    # 兩個分隔字串
    assert not decision_ok(f"  {DECISION_SEP}會被入侵。")                    # 問題空白
    assert not decision_ok(f"要不要關掉？{DECISION_SEP}  ")                  # 後果空白
    assert not decision_ok(None)
    assert DECISION_SEP == "——不決定的話："


# ── 數字與指標（§5.2）────────────────────────────────────────────────
def test_fact_words_file_matches_loaded_table():
    data = json.loads((RULES_DIR / "fact-words.json").read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert [(k, p.pattern) for k, p in FACT_WORDS] == [tuple(x) for x in data["words"]]


def _key(text, i):
    ms = list(_COUNT_RE.finditer(text))
    return fact_key(text, ms, i)


def test_fact_key_refines():
    """前後分別對到一般與「真實」限定的同類指標時取限定的；不同類仍是歧義。"""
    from tools.templates import FACT_REFINES
    assert FACT_REFINES == {"real_checked": "checked", "real_affected": "affected"}
    assert _key("今天檢查 13 件真實事件", 0) == "real_checked"
    assert _key("今天檢查 13 件與我們有關", 0) is None
    assert mismatched_numbers(["今天檢查 13 件真實事件。"], {"real_checked": 13, "checked": 19}) == []


def test_spaced_templates():
    """範本中英數字與中文之間補空格（品牌 App 的密碼）；數字已有空格的句子不變。"""
    from tools.templates import spaced
    assert spaced("品牌 App的密碼") == "品牌 App 的密碼"
    assert spaced("先讓QuickSite Builder只有公司內部連得到") == "先讓 QuickSite Builder 只有公司內部連得到"
    assert spaced("有 20 個高風險、22 個中風險") == "有 20 個高風險、22 個中風險"
    risk = {"id": "r", "asset_id": "brand-app", "category": "secret", "control_id": "C-SECRET-IN-GIT", "breakdown": [],
            "attack_path": None, "status": "open", "deadline_hours": 24}
    sol = solution_for(risk, {}, {"brand-app": "品牌 App"})
    assert sol["plain_title"] == "品牌 App 的密碼或金鑰保管不當"


def test_fact_key_segments():
    assert _key("有 20 個高風險、22 個中風險", 0) == "high" and _key("有 20 個高風險、22 個中風險", 1) == "medium"
    assert _key("其中 14 件與我們有關", 0) == "affected"
    assert _key("今天檢查 19 件外部資安事件", 0) == "checked"                   # 前後都是 checked
    assert _key("高風險 18 個與中風險 14 個", 0) is None                       # 前 high、後 medium：歧義
    assert _key("高風險 18 個與中風險 14 個", 1) == "medium"
    assert _key("3 個品牌回報疑似外洩", 0) is None                             # 找不到指標
    assert _key("其中 6 件真實事件與我們有關", 0) == "real_affected"           # 具體的在前


def test_summary_facts_and_mismatched_numbers(baseline):
    nodes = dict(baseline["graph"].nodes(data=True))
    intel = {"checked": 11, "affected": 7, "real_checked": 10, "real_affected": 6}
    facts = summary_facts(baseline["risks"], intel)
    assert (facts["high"], facts["medium"], facts["chained"], facts["eol"], facts["shadow_it"]) == (14, 18, 5, 1, 4)
    labels = public_labels(baseline)
    template = ceo_summary(baseline["light"], baseline["risks"], intel, nodes, labels) + decisions(baseline["risks"], labels)
    assert mismatched_numbers(template, facts) == []                     # 程式範本的數字一定對得上指標
    claude = ["今天是紅燈：14 個高風險、18 個中風險、7 個低風險。",
              "最需要處理的是：有 5 個問題可以被串成一條入侵路徑；另有 1 個對外系統已不再有官方更新。",
              "今天檢查了 11 件外部資安事件，其中 7 件與我們有關，24 小時內要處理。"]
    assert mismatched_numbers(claude, facts) == []
    assert mismatched_numbers(["今天有 15 個高風險。"], facts) == [15]          # 自行改數字 → 對不上
    assert mismatched_numbers(["今天有 18 個高風險。"], facts) == [18]          # 數值存在但指標錯置（高 14、中 18）
    assert mismatched_numbers(["高風險 18 個與中風險 14 個。"], facts) == [18, 14]
    assert mismatched_numbers(["3 個品牌回報疑似外洩"], facts) == [3]          # 找不到指標


@pytest.mark.parametrize("which", ["baseline", "demo_result"])
def test_templates_pass_a5_checks(which, request):
    """§5.3：範本本身必須通過「數字對到指標」與「決策格式」兩條。"""
    res = request.getfixturevalue(which)
    nodes = dict(res["graph"].nodes(data=True))
    labels = public_labels(res)
    for intel in ({"checked": 7, "affected": 6}, {"checked": 1, "affected": 0}, {}):
        texts = ceo_summary(res["light"], res["risks"], intel, nodes, labels)
        decs = decisions(res["risks"], labels)
        assert mismatched_numbers([*texts, *decs], summary_facts(res["risks"], intel)) == []
        assert all(decision_ok(d) for d in decs)
    small = [_eol(asset_id="marketing-site"), _risk(category="shadow_it", asset_id="nas-office-01"),
             _risk(level="medium", attack_path=["a", "b"])]
    texts = ceo_summary("red", small, {"checked": 2, "affected": 1}, {}, labels) + decisions(small, labels)
    assert mismatched_numbers(texts, summary_facts(small, {"checked": 2, "affected": 1})) == []


# ── 程式範本解法（§4）────────────────────────────────────────────────
ALL_CLASSES = ["order", "pii", "payment", "source_code", "session"]
REACH = "訂單資料、會員個資、金流資料、原始碼、登入狀態"
N = "行銷官網"

# （風險覆寫, plain_title, if_ignored, temporary）；資產節點帶全部資料類別、名稱為「行銷官網」
BRANCHES = [
    (dict(category="vuln", breakdown=[{"factor": "已停止支援"}]),
     f"{N}的軟體原廠已不再修補，有可被入侵的漏洞", f"漏洞不會再有官方修補，外人可能藉此控制{N}或竄改內容，進一步碰到{REACH}。",
     f"先限制外人連到{N}並加強監看，同時評估是否暫時關掉"),
    (dict(category="vuln", breakdown=[{"factor": "已遭實際利用"}]),
     f"{N}有已經被用來攻擊的漏洞，可能造成{REACH}外洩", f"外人可能利用這個漏洞入侵{N}，一路碰到{REACH}；這個漏洞已經有人在用。",
     f"先確認{N}有哪些地方外人連得到，能關的先關，並盡快安排更新"),
    (dict(category="vuln"),
     f"{N}有已知漏洞，可能造成{REACH}外洩", f"外人可能利用這個漏洞讓{N}停擺或被入侵，進一步碰到{REACH}。",
     f"先確認{N}有哪些地方外人連得到，並安排更新"),
    (dict(control_id="C-DEV-DEVICE-TOKEN"),
     f"{N}存著能直接改正式系統的權限", "這台電腦一旦中毒或遺失，對方就可能改動正式網站或 App。", "馬上把這個權限作廢，改用短期有效的權限"),
    (dict(control_id="C-SECRET-IN-GIT"),
     f"{N}的密碼或金鑰保管不當，可能造成{REACH}外洩",
     f"拿到這組密碼或金鑰的人，可能直接登入相關系統，讀走{REACH}；不換掉，這個破口就一直在。",
     "馬上把這組密碼或金鑰作廢換新，並檢查最近有沒有被別人用過"),
    (dict(category="identity"),
     f"{N}的密碼或金鑰保管不當，可能造成{REACH}外洩",
     f"拿到這組密碼或金鑰的人，可能直接登入相關系統，讀走{REACH}；不換掉，這個破口就一直在。",
     "馬上把這組密碼或金鑰作廢換新，並檢查最近有沒有被別人用過"),
    (dict(control_id="C-INTERNAL-TOOL-EXPOSED"),
     f"只給員工用的{N}，外人也連得到", f"任何人都能從網路找到它的登入頁，外人可能藉此進到公司內部，最後碰到{REACH}。",
     f"先讓{N}只有公司內部連得到"),
    (dict(control_id="C-NET-SEGMENT"),
     "測試或辦公室網路可以直接連到正式資料庫", "這些網路裡的電腦一旦被入侵，外人就可能直接碰到正式資料。", "先擋住測試與辦公室網路連到正式資料庫"),
    (dict(control_id="C-CLOUD-STORAGE-PUBLIC"),
     f"{N}設成任何人都能下載", "只要知道網址，任何人都能下載裡面的檔案；如果有個資外洩，可能要通報主管機關並通知受影響的人。",
     f"先把{N}改成不公開，並檢查有沒有被下載過"),
    (dict(category="backup"),
     f"{N}的備份沒有分開保存", "遇到勒索軟體時，備份可能跟著一起被加密，資料救不回來。", "先另外做一份分開保存的備份"),
    (dict(category="shadow_it"),
     f"{N}沒有登記，負責人尚未確認", "負責人沒確認前，更新與監控可能沒人做，漏洞會一直留著；出事時也可能沒人發現。",
     f"先找出{N}的負責人與用途，沒人用的話先停止對外開放"),
    (dict(category="clone_app"),
     "有人冒用品牌上架假 App", "會員可能下載到假 App，被騙走帳號或個資，品牌信譽受損。", "通知受影響品牌商並向商店檢舉下架"),
    (dict(category="mobile"),
     f"{N}的設定有安全問題", "外人可能利用 App 的設定問題取得會員資料或冒用 App。", "先在伺服器端限制舊版 App 能用的功能"),
    (dict(control_id="C-OTHER"),
     f"{N}有安全設定問題", "問題會一直存在，增加被入侵的機會。", f"先確認{N}的狀況並限制誰能使用"),
]


@pytest.mark.parametrize("over,title,ignored,temporary", BRANCHES)
def test_solution_branches(over, title, ignored, temporary):
    nodes = {"site": {"data_classes": ALL_CLASSES}}
    sol = solution_for(_risk(asset_id="site", **over), nodes, {"site": N})
    assert (sol["plain_title"], sol["if_ignored"], sol["temporary"], sol["plain_source"]) == (title, ignored, temporary, "template")
    Solution.model_validate(sol)
    assert not FORBIDDEN.search(sol["plain_title"] + sol["if_ignored"] + sol["temporary"])
    # need_check：條件語氣（R3.4）；permanent、options 與 open 相同
    nc = solution_for(_risk(asset_id="site", status="need_check", **over), nodes, {"site": N})
    assert nc["plain_title"] == "需要確認：" + title and nc["if_ignored"] == "如果確認屬實，" + ignored
    assert (nc["permanent"], nc["options"], nc["temporary"]) == (sol["permanent"], sol["options"], sol["temporary"])


def test_solution_without_reach_omits_optional_part():
    sol = solution_for(_risk(asset_id="site", category="vuln"), {}, {"site": N})
    assert sol["plain_title"] == f"{N}有已知漏洞" and sol["if_ignored"] == f"外人可能利用這個漏洞讓{N}停擺或被入侵。"
    # 攻擊路徑長度 > 1：取終點的資料類別
    nodes = {"site": {"data_classes": ["session"]}, "db": {"data_classes": ["order", "pii", "order"]}}
    assert risk_reach(_risk(asset_id="site", attack_path=["site", "db"]), nodes) == ["訂單資料", "會員個資"]
    assert risk_reach(_risk(asset_id="site", attack_path=["site"]), nodes) == ["登入狀態"]


@pytest.mark.parametrize("asset_id,labels,name", [
    ("site", {"site": "名" * 60}, "名" * 60),                                       # 60 字的白話名稱
    ("a" * 30 + "-svc-12345", None, "a" * 30 + "-svc-12345"),                        # 40 字的 ID：可用
    ("a" * 31 + "-svc-12345", None, UNNAMED_SYSTEM),                                 # 41 字：未命名
    ("x" * 161, None, UNNAMED_SYSTEM),                                               # 161 字
    ("session.cookie_secure", None, UNNAMED_SYSTEM),                                 # 設定鍵（R8）
    ("C-NET-SEGMENT", None, UNNAMED_SYSTEM),                                         # 控制項 ID（R8）
    ("@scope/package", None, UNNAMED_SYSTEM),                                        # 套件名稱（路徑）
    ("10.0.0.5", None, UNNAMED_SYSTEM),                                              # IP
])
@pytest.mark.parametrize("over", [b[0] for b in BRANCHES])
@pytest.mark.parametrize("status", ["open", "need_check"])
def test_solution_name_limits_keep_schema_valid(asset_id, labels, name, over, status):
    nodes = {asset_id: {"data_classes": ALL_CLASSES}}
    sol = solution_for(_risk(asset_id=asset_id, status=status, **over), nodes, labels)
    Solution.model_validate(sol)                                                    # plain_title 120、if_ignored 300 字內
    if over.get("control_id") != "C-NET-SEGMENT" and over.get("category") != "clone_app":
        assert name in sol["plain_title"]
    if name == UNNAMED_SYSTEM:
        assert asset_id not in sol["plain_title"] + sol["if_ignored"] + sol["temporary"]
