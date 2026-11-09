"""safe_fetch 的 URL 限制（本地假 DNS 與 transport，不連網）。"""
import pytest

from tools.safe_fetch import FetchRejected, fetch, validate_url

ALLOW = ["rapid7.com"]


def public_dns(_host):
    return ["93.184.216.34"]


def internal_dns(_host):
    return ["10.0.0.5"]


@pytest.mark.parametrize("url", [
    "http://www.rapid7.com/a",              # 非 HTTPS
    "https://user@www.rapid7.com/a",        # userinfo
    "https://93.184.216.34/a",              # IP literal
    "https://example.org/a",                # 不在受信任清單
])
def test_rejected_urls(url):
    with pytest.raises(FetchRejected):
        validate_url(url, ALLOW, public_dns)


def test_allowed_domain_resolving_to_internal_address_is_rejected():
    with pytest.raises(FetchRejected):
        validate_url("https://www.rapid7.com/a", ALLOW, internal_dns)


def test_redirect_is_revalidated():
    def transport(url):
        if url.endswith("/a"):
            return 302, {"location": "https://example.org/b"}, b""
        return 200, {"content-type": "text/html"}, b"ok"
    with pytest.raises(FetchRejected):
        fetch("https://www.rapid7.com/a", ALLOW, transport=transport, resolver=public_dns)


def test_too_many_redirects():
    def transport(url):
        return 302, {"location": url + "x"}, b""
    with pytest.raises(FetchRejected):
        fetch("https://www.rapid7.com/a", ALLOW, transport=transport, resolver=public_dns)


def test_non_text_content_rejected():
    def transport(_url):
        return 200, {"content-type": "application/octet-stream"}, b"\x00"
    with pytest.raises(FetchRejected):
        fetch("https://www.rapid7.com/a", ALLOW, transport=transport, resolver=public_dns)


def test_ok_fetch():
    res = fetch("https://www.rapid7.com/a", ALLOW, transport=lambda u: (200, {"content-type": "text/html"}, b"<p>hi</p>"),
                resolver=public_dns)
    assert res.status == 200 and "hi" in res.text
