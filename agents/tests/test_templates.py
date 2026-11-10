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
