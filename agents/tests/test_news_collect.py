"""每日情資的新聞抓取（news_collect）與用同一份原文確認引用（intel_verify collected）。不連任何外部網站。"""
import json
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from tools.common import INTEL_DIR
from tools.intel_verify import load_source_tiers, verify_event
from tools.news_collect import (collect, collected_texts, load_config, parse_date, parse_feed, parse_kev, score,
                                sentences)
from tools.safe_fetch import FetchRejected, FetchResult

AS_OF = datetime(2026, 11, 10, 8, 0, tzinfo=timezone.utc)
FEED = {"id": "t", "name": "測試", "url": "https://www.ithome.com.tw/rss", "tz": "+08:00"}

RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel>
<item><title>易遊網會員中心遭網路攻擊，逾69萬人訂單資料受影響</title><link>https://www.ithome.com.tw/news/1</link>
<pubDate>2026-11-09  20:00:00</pubDate><description>&lt;p&gt;旅遊電商易遊網表示會員中心遭異常存取。&lt;/p&gt;</description></item>
<item><title>新款手機發表</title><link>https://www.ithome.com.tw/news/2</link><pubDate>Mon, 09 Nov 2026 10:00:00 +0800</pubDate>
<description>規格介紹</description></item>
<item><title>舊聞：某電商資料外洩</title><link>https://www.ithome.com.tw/news/3</link><pubDate>Mon, 02 Nov 2026 10:00:00 +0800</pubDate></item>
<item><title>外站：電商個資外洩</title><link>https://evil.example/news/4</link><pubDate>Mon, 09 Nov 2026 10:00:00 +0800</pubDate></item>
</channel></rss>"""

ATOM = """<?xml version="1.0" encoding="utf-8"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Retailer data breach hits Taiwan shoppers</title><link href="https://therecord.media/retailer-breach"/>
<updated>2026-11-09T12:00:00Z</updated><summary>A ransomware gang leaked customer data. Officials confirmed the breach.</summary></entry>
</feed>"""

KEV = {"vulnerabilities": [
    {"cveID": "CVE-2026-12345", "vendorProject": "PHP Group", "product": "PHP", "vulnerabilityName": "PHP RCE",
     "dateAdded": "2026-11-09", "shortDescription": "PHP contains a remote code execution vulnerability.", "requiredAction": "Patch."},
    {"cveID": "CVE-2020-0001", "vendorProject": "Old", "product": "Old", "dateAdded": "2020-01-01", "shortDescription": "old"},
]}

ARTICLE = "<html><nav>選單 登入</nav><h1>易遊網會員中心遭網路攻擊，逾69萬人訂單資料受影響</h1><p>易遊網今天證實會員中心遭到攻擊。受影響的是歷史訂單的聯絡資料。</p></html>"


def fake_fetcher(pages):
    calls = []

    def fetcher(url, allowlist):
        calls.append(url)
        host = url.split("/")[2]
        if not any(host == d or host.endswith("." + d) for d in allowlist):
            raise FetchRejected(f"{host} 不在受信任來源清單")
        if url not in pages:
            raise RuntimeError("not found")
        body = pages[url]
        if isinstance(body, int):
            return FetchResult(url=url, status=body, text="", content_type="text/html")
        return FetchResult(url=url, status=200, text=body, content_type="text/xml")
    fetcher.calls = calls
    return fetcher


def cfg(**kw):
    base = load_config()
    base.update(feeds=[FEED, {"id": "rec", "name": "The Record", "url": "https://therecord.media/feed", "tz": "+00:00", "security": True}],
                kev={"name": "CISA KEV", "url": "https://www.cisa.gov/kev.json", "link": "https://www.cisa.gov/kev?search={cve}"})
    base.update(kw)
    return base


def test_parse_dates():
    tz8 = "+08:00"
    assert parse_date("Mon, 09 Nov 2026 10:00:00 +0800", tz8) == datetime(2026, 11, 9, 2, tzinfo=timezone.utc)
    assert parse_date("2026-11-09  20:00:00", tz8) == datetime(2026, 11, 9, 12, tzinfo=timezone.utc)   # iThome：沒有時區，用設定的時區
    assert parse_date(None, tz8, "https://www.taipeitimes.com/News/front/archives/2026/11/10/2003867459") == \
        datetime(2026, 11, 10, 4, tzinfo=timezone.utc)                                                     # Taipei Times：用網址中的日期
    assert parse_date("not a date", tz8) is None


def test_parse_rss_and_atom():
    items = parse_feed(RSS, FEED)
    assert [i["url"] for i in items][:2] == ["https://www.ithome.com.tw/news/1", "https://www.ithome.com.tw/news/2"]
    assert items[0]["summary"] == "旅遊電商易遊網表示會員中心遭異常存取。"     # 兩層 HTML 跳脫都移除
    atom = parse_feed(ATOM, {"id": "rec", "name": "The Record", "tz": "+00:00", "security": True})
    assert atom[0]["url"] == "https://therecord.media/retailer-breach" and atom[0]["security_feed"] is True


def test_xml_attacks_rejected():
    bomb = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><rss><channel><item><title>&b;</title></item></channel></rss>'
    with pytest.raises(Exception):
        parse_feed(bomb, FEED)


def test_score_requires_security_terms_for_general_feeds():
    c = load_config()
    item = {"title": "新款手機發表", "summary": "規格介紹", "security_feed": False}
    assert score(item, c, ["php"]) is None
    hit = {"title": "電商平台 PHP 漏洞遭利用，台灣商家受影響", "summary": "", "security_feed": False}
    s, matched = score(hit, c, ["php", "next"])
    assert s == 1 + 3 + 2 + 1 + 1 and "php" in matched and "電商" in matched
    nxt = {"title": "Next week: new malware report", "summary": "", "security_feed": True}
    assert "next" not in score(nxt, c, ["next"])[1]                     # next 只認 Next.js，不誤判英文單字


def test_sentences_split_and_length_limit():
    text = "第一句。第二句！Third sentence. Fourth one? " + "長" * 900
    out = sentences(text, 10)
    assert out[:4] == ["第一句。", "第二句！", "Third sentence.", "Fourth one?"]
    assert all(len(s) <= 400 for s in out) and len(sentences(text, 3)) == 3


def test_kev_window_and_link():
    items = parse_kev(KEV, {"name": "CISA KEV", "link": "https://www.cisa.gov/kev?search={cve}"}, AS_OF, timedelta(hours=72))
    assert [i["cves"] for i in items] == [["CVE-2026-12345"]]
    assert items[0]["url"] == "https://www.cisa.gov/kev?search=CVE-2026-12345"


def test_collect_end_to_end_without_network():
    pages = {"https://www.ithome.com.tw/rss": RSS, "https://therecord.media/feed": ATOM, "https://www.cisa.gov/kev.json": json.dumps(KEV),
             "https://www.ithome.com.tw/news/1": ARTICLE, "https://therecord.media/retailer-breach": 403}
    fetcher = fake_fetcher(pages)
    res = collect(as_of=AS_OF, products=["php"], cfg=cfg(), fetcher=fetcher)
    by_url = {i["url"]: i for i in res["items"]}
    assert set(by_url) == {"https://www.ithome.com.tw/news/1", "https://therecord.media/retailer-breach",
                           "https://www.cisa.gov/kev?search=CVE-2026-12345"}   # 舊聞、非資安、外站都不保留
    ithome = by_url["https://www.ithome.com.tw/news/1"]
    assert ithome["body_status"] == "ok" and ithome["sentences"][:2] == ["易遊網會員中心遭網路攻擊，逾69萬人訂單資料受影響 易遊網今天證實會員中心遭到攻擊。",
                                                                        "受影響的是歷史訂單的聯絡資料。"]
    assert "選單" not in " ".join(ithome["sentences"])                   # 從標題處開始，略過版面文字
    record = by_url["https://therecord.media/retailer-breach"]
    assert record["body_status"] == "HTTP 403" and record["sentences"][0] == "A ransomware gang leaked customer data."   # 內文抓不到時用 RSS 摘要
    assert by_url["https://www.cisa.gov/kev?search=CVE-2026-12345"]["score"] >= 4                                     # 命中技術棧產品 PHP
    assert [s["status"] for s in res["sources"]] == ["ok", "ok", "ok"]
    assert "https://evil.example/news/4" not in fetcher.calls


def test_collect_source_failure_does_not_stop_others():
    fetcher = fake_fetcher({"https://therecord.media/feed": ATOM})
    res = collect(as_of=AS_OF, products=[], cfg=cfg(), fetcher=fetcher)
    st = {s["id"]: s for s in res["sources"]}
    assert st["t"]["status"] == "failed" and st["rec"]["status"] == "ok" and st["cisa-kev"]["status"] == "failed"
    assert [i["url"] for i in res["items"]] == ["https://therecord.media/retailer-breach"]


def test_config_feeds_point_to_allowed_hosts():
    c = load_config()
    allowed = [*load_source_tiers(), *c["feed_hosts"]]
    for f in c["feeds"]:
        host = f["url"].split("/")[2]
        assert f["url"].startswith("https://") and any(host == d or host.endswith("." + d) for d in allowed), f
    assert c["window_hours"] == 72
    assert "feeds.feedburner.com" not in load_source_tiers()             # 只用來抓 RSS，不算可信來源


def _live(url, quote):
    return {"id": "live-x", "kind": "live", "title": "易遊網事件", "date": "2026-11-09", "revision": "1", "confidence": "confirmed",
            "sources": [{"url": url, "title": "t", "quote": quote, "published": None}]}


def test_verify_with_collected_text():
    news = {"items": [{"url": "https://www.ithome.com.tw/news/1", "title": "易遊網會員中心遭網路攻擊",
                       "sentences": ["受影響的是歷史訂單的聯絡資料。", "業者表示不含信用卡資料。"]}]}
    collected = collected_texts(news)
    ok = verify_event(_live("https://www.ithome.com.tw/news/1", "受影響的是歷史訂單的聯絡資料。"), as_of=AS_OF, online=True, collected=collected,
                      transport=lambda u: (_ for _ in ()).throw(AssertionError("不應再抓網頁")))
    s = ok["event"]["sources"][0]
    assert s["verified"] and s["fetch_status"] == "ok" and s["verification_basis"] == "live"
    assert ok["event"]["confidence"] == "provisional"                    # 單一媒體來源：不能自稱 confirmed
    title = verify_event(_live("https://www.ithome.com.tw/news/1", "易遊網會員中心遭網路攻擊"), as_of=AS_OF, collected=collected)
    assert title["event"]["sources"][0]["verified"]                       # 標題也可以作為引用
    bad = verify_event(_live("https://www.ithome.com.tw/news/1", "易遊網全部資料都外洩了"), as_of=AS_OF, collected=collected)
    assert bad["verification"]["status"] == "quote_mismatch" and bad["verification"]["max_level"] == "medium"


def test_collected_text_not_used_for_untrusted_or_non_live():
    collected = {"https://evil.example/x": ["引用"], "https://www.ithome.com.tw/news/1": ["引用"]}
    res = verify_event(_live("https://evil.example/x", "引用"), as_of=AS_OF, online=False, collected=collected)
    assert res["event"]["sources"][0]["verified"] is False               # 清單外網域：不採用
    archive = {**_live("https://www.ithome.com.tw/news/1", "引用"), "kind": "archive", "id": "evt-x"}
    res = verify_event(archive, as_of=AS_OF, online=False, collected=collected)
    assert res["event"]["sources"][0]["fetch_status"] == "skipped"        # 收錄事件不受今日抓取影響


def test_feed_config_is_valid_yaml_with_terms():
    data = yaml.safe_load((INTEL_DIR / "news_feeds.yaml").read_text(encoding="utf-8"))
    assert {"security_terms", "industry_terms", "region_terms", "product_terms"} <= set(data)
    assert all(isinstance(v, list) and v for v in data["product_terms"].values())


def test_collect_respects_byte_budget():
    pages = {"https://www.ithome.com.tw/rss": RSS, "https://therecord.media/feed": ATOM, "https://www.cisa.gov/kev.json": json.dumps(KEV),
             "https://www.ithome.com.tw/news/1": ARTICLE}
    full = collect(as_of=AS_OF, products=["php"], cfg=cfg(), fetcher=fake_fetcher(pages))
    size = len(json.dumps(full, ensure_ascii=False, indent=2).encode("utf-8"))
    small = collect(as_of=AS_OF, products=["php"], cfg=cfg(max_bytes=size - 1), fetcher=fake_fetcher(pages))
    assert len(small["items"]) == len(full["items"]) - 1
    assert [i["url"] for i in small["items"]] == [i["url"] for i in full["items"]][:-1]     # 捨去的是相關度最低的
