"""intel_verify：以本地假 transport 測試，不連任何第三方網站。"""
from tools.common import INTEL_DIR
from tools.intel_verify import load_events, quote_in, verify_event

TIERS = {"rapid7.com": "media", "technews.tw": "media", "cyberq.tw": "media", "github.com": "advisory"}


def fake_dns(_host):
    return ["93.184.216.34"]


def page(text, status=200):
    def transport(_url):
        return status, {"content-type": "text/html; charset=utf-8"}, f"<html><body><p>{text}</p></body></html>".encode()
    return transport


def event(sources, confidence="confirmed"):
    return {"id": "evt-test", "kind": "live", "title": "測試事件", "date": "2026-11-01", "revision": "1",
            "confidence": confidence, "sources": sources, "products": []}


SRC = {"url": "https://www.rapid7.com/blog/post/x", "title": "t", "quote": "Critical unauthenticated RCE", "published": None}


def test_quote_normalization_handles_width_and_spaces():
    assert quote_in("訂單編號：AB12  CD", "訂單編號:AB12 CD")


def test_quote_found_is_ok(as_of):
    res = verify_event(event([SRC]), as_of=as_of, online=True, transport=page("A Critical unauthenticated RCE in PHP"),
                       resolver=fake_dns, tiers=TIERS)
    assert res["event"]["sources"][0]["fetch_status"] == "ok"
    assert res["verification"]["status"] == "ok"


def test_single_media_source_becomes_provisional(as_of):
    res = verify_event(event([SRC]), as_of=as_of, online=True, transport=page("Critical unauthenticated RCE"),
                       resolver=fake_dns, tiers=TIERS)
    assert res["event"]["confidence"] == "provisional"


def test_quote_mismatch_caps_at_medium(as_of):
    res = verify_event(event([SRC]), as_of=as_of, online=True, transport=page("unrelated text"), resolver=fake_dns, tiers=TIERS)
    assert res["event"]["sources"][0]["fetch_status"] == "quote_mismatch"
    assert res["verification"]["max_level"] == "medium"


def test_fetch_failed_is_distinct_from_mismatch(as_of):
    res = verify_event(event([SRC]), as_of=as_of, online=True, transport=page("blocked", status=403), resolver=fake_dns, tiers=TIERS)
    assert res["event"]["sources"][0]["fetch_status"] == "fetch_failed"
    assert res["verification"]["status"] == "fetch_failed"
    assert res["verification"]["note"] == "來源暫時無法驗證"


def test_same_outlet_twice_is_not_independent(as_of):
    two = [SRC, {**SRC, "url": "https://www.rapid7.com/blog/post/y"}]
    res = verify_event(event(two), as_of=as_of, online=True, transport=page("Critical unauthenticated RCE"),
                       resolver=fake_dns, tiers=TIERS)
    assert res["event"]["confidence"] == "provisional"


def test_demo_events_skip_verification(as_of):
    for raw in load_events(INTEL_DIR / "demo-events"):
        res = verify_event(raw, as_of=as_of, online=True, transport=page("x"), resolver=fake_dns, tiers=TIERS)
        assert res["verification"]["status"] == "skipped"
        assert res["event"]["title"].startswith("示範：")


def test_archive_offline_uses_archived_basis(as_of):
    for raw in load_events(INTEL_DIR / "archive"):
        res = verify_event(raw, as_of=as_of, online=False)
        assert all(s["verification_basis"] == "archived" for s in res["event"]["sources"] if s.get("verified"))
        assert all(s.get("quote") for s in res["event"]["sources"])


def test_archive_has_six_real_events():
    ids = {e["id"] for e in load_events(INTEL_DIR / "archive")}
    assert ids == {"evt-91app-2026-10", "evt-1shop-2026-10", "evt-binance-2026-10", "evt-php2shell-2026-10",
                   "evt-synology-2026-10", "evt-nextjs-cve-2025-29927"}
    assert len(load_events(INTEL_DIR / "demo-events")) == 5
