"""CEO 摘要與決策事項的程式範本：白話、不出現版本號與 CVE；未登記系統合併成一條決策。"""
import re

from tools.templates import ceo_summary, decisions

TECH = re.compile(r"CVE-|CVSS|\d+\.\d+")


def _risk(**over):
    base = {"id": "r", "asset_id": "a", "title": "t", "category": "config", "level": "high", "status": "open",
            "breakdown": [], "attack_path": None}
    return {**base, **over}


def test_baseline_summary_is_plain_language(baseline):
    nodes = dict(baseline["graph"].nodes(data=True))
    s = ceo_summary(baseline["light"], baseline["risks"], {"checked": 7, "affected": 6}, nodes)
    assert len(s) == 3
    assert s[0].startswith("今天是紅燈")
    assert "入侵路徑" in s[1] and "訂單資料" in s[1] and "會員個資" in s[1]
    assert "已停止支援" in s[1]
    assert not TECH.search(s[1]), s[1]


def test_target_without_data_classes_and_no_highs():
    nodes = {"deploy-pipeline": {"data_classes": []}}
    s = ceo_summary("red", [_risk(attack_path=["laptop", "token", "deploy-pipeline"])], {}, nodes)
    assert s[1] == "最需要處理的是：1 個問題可被串成入侵路徑，可能一路碰到核心系統（deploy-pipeline）。"
    assert ceo_summary("yellow", [_risk(level="medium")], {})[1] == "目前沒有高風險。"
    assert ceo_summary("red", [_risk()], {})[1] == "最需要處理的是：1 個高風險要在 24 小時內處理。"


def test_decisions_merge_shadow_it_after_takedown(baseline):
    out = decisions(baseline["risks"])
    shadow = sorted({r["asset_id"] for r in baseline["risks"]
                     if r["category"] == "shadow_it" and r["level"] == "high" and r["status"] != "fixed"})
    assert out[0].startswith("是否暫時下架 marketing-site")
    merged = out[1]
    assert merged.startswith(f"{len(shadow)} 個未登記的系統要納管還是除役：")
    assert sorted(merged.split("：", 1)[1].split("、")) == shadow
    assert len(out) == 2


def test_single_shadow_it_keeps_original_sentence():
    assert decisions([_risk(category="shadow_it", asset_id="nas-office-01")]) == ["nas-office-01 要納管還是除役"]
    assert decisions([_risk(category="shadow_it", status="fixed")]) == []


def test_summary_facts_and_unsourced_numbers(baseline):
    from tools.templates import summary_facts, unsourced_numbers
    nodes = dict(baseline["graph"].nodes(data=True))
    intel = {"checked": 11, "affected": 7, "real_checked": 10, "real_affected": 6}
    facts = summary_facts(baseline["risks"], intel)
    assert (facts["high"], facts["medium"], facts["chained"], facts["eol"], facts["shadow_it"]) == (14, 18, 5, 1, 4)
    template = ceo_summary(baseline["light"], baseline["risks"], intel, nodes) + decisions(baseline["risks"])
    assert unsourced_numbers(template, facts) == []                     # 程式範本的數字一定有來源
    claude = ["今天是紅燈：14 個高風險、18 個中風險、7 個低風險。",
              "最需要處理的是：有 5 個問題可以被串成一條入侵路徑；另有 1 個對外系統已不再有官方更新。",
              "今天檢查了 11 件外部資安事件，其中 7 件與我們有關，24 小時內要處理。"]
    assert unsourced_numbers(claude, facts) == []
    assert unsourced_numbers(["今天有 15 個高風險。"], facts) == [15]   # 自行改數字 → 對不上
