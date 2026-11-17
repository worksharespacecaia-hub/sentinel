"""白話欄位與事件品牌（specs/plain-brief design §3）：公開文字檢查、逐欄篩選、系統 ID 檢查、事件品牌、A5 清理不改快取。"""
import copy

import pytest

from llm import LLMRunner, Task, _validate
from tools.cache import LLMCache, ReplayStore
from tools.plain_text import clean_plain, contains_internal_id, event_brand, exact_public, report_brands, screen_fields
from tools.trace import Tracer

SECRET = "DEMO-FAKE-PASSWORD-0000"


# ── exact_public（R8.2）──────────────────────────────────────────────
@pytest.mark.parametrize("text,limit,ok", [
    ("內部營運工具有帳號被盜用的漏洞", 40, True),
    ("  前後空白會去掉  ", 40, True),
    ("聯絡 ops@example.com 處理", 200, False),           # Email：遮蔽後與原文不同
    (f"金鑰 {SECRET} 外洩", 200, False),                 # 會被遮蔽的金鑰
    ("檔案在 /etc/app/config 裡", 200, False),           # 路徑
    ("主機 10.0.0.5 對外開放", 200, False),              # IP
    ("連到 :8443 的管理頁", 200, False),                 # 連接埠
    ("設定 session.cookie_secure 沒開", 200, False),     # 設定鍵
    ("違反 C-NET-SEGMENT", 200, False),                  # 控制項 ID
    ("中間  兩個空白", 200, False),                      # 合併空白後與原文不同
    ("超過上限的文字", 3, False),                        # 截斷
    ("", 40, False),
    (None, 40, False),
    (123, 40, False),
])
def test_exact_public(text, limit, ok):
    assert exact_public(text, limit) is ok


# ── screen_fields（R2.4）──────────────────────────────────────────────
def _sol(**over):
    base = {"risk_id": "r1", "temporary": "先關掉", "permanent": "升級", "options": [], "verify": "掃描",
            "plain_title": "行銷官網有漏洞", "if_ignored": "外人可能竄改官網內容。"}
    return {**base, **over}


@pytest.mark.parametrize("field,value", [
    ("plain_title", 42),                                # 不是字串
    ("plain_title", "   "),                             # 空白
    ("plain_title", "字" * 41),                         # 超過 40 字
    ("if_ignored", "字" * 101),                         # 超過 100 字
    ("plain_title", f"官網密碼 {SECRET}"),              # 機敏值（R8）
    ("if_ignored", "請寄信到 ops@example.com 確認。"),  # Email（R8）
    ("if_ignored", "設定檔 /srv/app/.env 外洩。"),      # 路徑（R8）
    ("plain_title", "主機 192.168.1.10 有漏洞"),        # IP（R8）
    ("plain_title", "官網有 cve-2025-29927 漏洞"),      # CVE（不分大小寫）
])
def test_screen_fields_drops_only_bad_field(field, value):
    item = _sol(**{field: value})
    screen_fields(item)
    other = "if_ignored" if field == "plain_title" else "plain_title"
    assert field not in item and item[other] == _sol()[other]
    assert item["plain_dropped"] == 1
    assert {k: v for k, v in item.items() if k not in (field, "plain_dropped")} == \
        {k: v for k, v in _sol().items() if k != field}                               # 其他欄位不變


def test_screen_fields_accumulates_and_is_idempotent():
    item = _sol(plain_title="x" * 41, if_ignored="", plain_dropped=1)
    screen_fields(item)
    assert "plain_title" not in item and "if_ignored" not in item and item["plain_dropped"] == 2   # 累加，上限 2
    good = _sol(plain_title="  行銷官網有漏洞  ")
    screen_fields(good)
    assert good["plain_title"] == "行銷官網有漏洞" and "plain_dropped" not in good
    once = _sol(if_ignored="主機 10.0.0.5 對外")
    screen_fields(once)
    snapshot = copy.deepcopy(once)
    screen_fields(once)                                                                # 快取命中再驗證一次：不重複累加
    assert once == snapshot and once["plain_dropped"] == 1
    weird = _sol(plain_dropped="很多")                                                 # AI 自己寫的怪值不採用
    screen_fields(weird)
    assert "plain_dropped" not in weird


def test_validate_solutions_drops_polluted_plain_field_but_keeps_solution():
    out = _validate("solutions", [_sol(plain_title=f"官網 {SECRET}", score=0)], {"r1"})
    assert len(out) == 1 and "plain_title" not in out[0] and out[0]["if_ignored"] == "外人可能竄改官網內容。"
    assert out[0]["plain_dropped"] == 1 and out[0]["temporary"] == "先關掉" and "score" not in out[0]


def test_validate_solutions_still_rejects_secret_in_existing_field():
    with pytest.raises(ValueError, match="機敏"):
        _validate("solutions", [_sol(temporary=f"改用 {SECRET}")], {"r1"})
    with pytest.raises(ValueError, match="機敏"):
        _validate("solutions", [_sol(options=[{"name": "緩解", "action": SECRET, "cost": "", "timing": ""}])], {"r1"})


# ── contains_internal_id（R8.3）──────────────────────────────────────
IDS = {"internal-tool", "order-db-prod", "ab", "1shop"}


@pytest.mark.parametrize("text,hit", [
    ("內部internal-tool系統", True),                      # 中文字相鄰也算
    ("INTERNAL-TOOL 有漏洞", True),                       # 不分大小寫
    ("連到 internal-tool.example 的網址", True),
    ("寄到 internal-tool@example.com", True),
    ("internal-toolkit 是別的東西", False),               # 後面接英數字不算
    ("my_internal-tool 不算", False),                     # 前面接 _ 不算
    ("ab 只有兩個字", False),                             # 2 字的 ID 不檢查
    ("同業 1shop 就是這樣", False),                       # 與品牌同名的 ID 不算
    ("訂單資料庫 order-db-prod 外洩", True),
    ("完全白話的句子", False),
])
def test_contains_internal_id(text, hit):
    assert contains_internal_id(text, IDS, allow={"1SHOP".lower()}) is hit


def test_contains_internal_id_brand_not_allowed_without_allow():
    assert contains_internal_id("同業 1shop 就是這樣", IDS) is True
    assert contains_internal_id(None, IDS) is False


# ── event_brand、report_brands（R2.6）────────────────────────────────
def test_event_brand():
    title = "91APP 訂單資料庫遭入侵：未更新的內部工具成破口"
    assert event_brand("91APP", title) == "91APP"
    assert event_brand(" 91APP ", title) == "91APP"
    assert event_brand("Shopline", title) is None                        # 不是標題的子字串
    assert event_brand("訂單資料庫遭入侵：未更新的內部工具成破口", title) == "訂單資料庫遭入侵：未更新的內部工具成破口"   # 剛好 20 字
    assert event_brand("1APP 訂單資料庫遭入侵：未更新的內部工具成破口", title) is None   # 25 字：超過 20 字
    assert event_brand("a@b.co", "外洩給 a@b.co 的事件") is None            # 個資（R8）
    assert event_brand("C-NET-SEGMENT", "C-NET-SEGMENT 被繞過") is None     # 控制項 ID（R8）
    assert event_brand("", title) is None and event_brand(None, title) is None and event_brand("91APP", None) is None


def _ev(eid, kind, **over):
    return {"id": eid, "kind": kind, "title": f"{over.get('brand') or 'X'} 事件標題", "confidence": "confirmed", "demo": False,
            "is_update_of": None, **over}


def test_report_brands_only_from_confirmed_archive_and_live_updates():
    events = [
        _ev("evt-91app", "archive", brand="91APP"),
        {**_ev("evt-nextjs", "archive"), "title": "Next.js Middleware 授權繞過"},          # 漏洞公告類：沒填品牌
        _ev("evt-provisional", "archive", brand="Synology", confidence="provisional"),    # 暫定：不帶
        _ev("evt-demo-archive", "archive", brand="示範", demo=True),
        _ev("live-91app-followup", "live", is_update_of="evt-91app"),                      # 後續報導沿用
        _ev("live-own-brand", "live", brand="自稱品牌"),                                  # live 自己帶的：不採用
        _ev("live-of-provisional", "live", is_update_of="evt-provisional"),
        _ev("live-provisional", "live", is_update_of="evt-91app", confidence="provisional"),
        _ev("live-of-live", "live", is_update_of="live-91app-followup"),                  # 只沿用一層
        _ev("live-missing-parent", "live", is_update_of="evt-gone"),
        _ev("adv-1", "advisory", brand="公告"),
        _ev("demo-1", "demo", brand="示範", demo=True),
    ]
    got = report_brands(events)
    assert got == {"evt-91app": "91APP", "evt-nextjs": None, "evt-provisional": None, "evt-demo-archive": None,
                   "live-91app-followup": "91APP", "live-own-brand": None, "live-of-provisional": None,
                   "live-provisional": None, "live-of-live": None, "live-missing-parent": None, "adv-1": None, "demo-1": None}


# ── clean_plain（R2.4、R2.5）─────────────────────────────────────────
def test_clean_plain_does_not_mutate_and_counts():
    sol = _sol(if_ignored="外人可以從 internal-tool 一路碰到訂單資料。", plain_dropped=1)
    before = copy.deepcopy(sol)
    risk = {"id": "r1", "asset_id": "marketing-site", "attack_path": None}
    out, n = clean_plain(sol, risk, {"internal-tool"}, [])
    assert sol == before                                                             # 不修改傳入的物件
    assert n == 2 and "if_ignored" not in out and "plain_dropped" not in out and out["plain_title"] == "行銷官網有漏洞"
    out2, n2 = clean_plain(sol, risk, {"internal-tool"}, [])
    assert (out2, n2) == (out, n)                                                    # 同一物件呼叫兩次，結果相同
    # 風險本身的資產 ID 不在圖譜也要擋；品牌同名的 ID 不擋
    out3, n3 = clean_plain(_sol(plain_title="platform 疑似外洩"), {"asset_id": "platform"}, set(), [])
    assert n3 == 1 and "plain_title" not in out3
    out4, n4 = clean_plain(_sol(if_ignored="同業 1shop 就是這樣出事。"), {"asset_id": "x"}, {"1shop"}, ["1shop"])
    assert n4 == 0 and out4["if_ignored"] == "同業 1shop 就是這樣出事。"


def test_cache_hit_keeps_dropped_count_and_clean_plain_leaves_cache_unchanged(tmp_path):
    """快取存的是 _validate 之後的值：快取命中時 plain_dropped 還在；A5 清理（深複製）不會改到快取內容。"""
    def runner():
        return LLMRunner(agent="a5", mode="replay", scope="daily", target_sha="a" * 40, advisory_revision=None,
                         tracer=Tracer(tmp_path / "t.jsonl", "a5"), cache=cache, replay=ReplayStore(tmp_path / "replay"))
    cache = LLMCache(tmp_path / "llm.json")
    t = Task(id="remediation", subagent="remediation-advisor", payload={"ids": ["r1"], "risks": [{"id": "r1"}]})
    r = runner()
    validated = _validate("solutions", [_sol(plain_title="官網 10.0.0.5 有漏洞", if_ignored="外人可能從 internal-tool 進來。")],
                          {"r1", "remediation"})
    cache.put(r.key(t), validated, {})                                              # 與 _call_live 相同：存驗證後的值
    stored = copy.deepcopy(cache.new[r.key(t)]["output"])
    counts = []
    for _ in range(2):
        got = runner().run([t])["remediation"]
        assert got["source"] == "replay" and got["output"][0]["plain_dropped"] == 1
        cleaned, n = clean_plain(got["output"][0], {"asset_id": "marketing-site"}, {"internal-tool"}, [])
        counts.append(n)
        assert "if_ignored" not in cleaned and "plain_title" not in cleaned
    assert counts == [2, 2]
    assert cache.new[r.key(t)]["output"] == stored                                  # 快取內容沒有被 A5 清理改到
