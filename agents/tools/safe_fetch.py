"""受限的公開來源抓取（intel_verify 與 news_collect 使用）。URL 一律視為不受信任輸入。

- 只接受 HTTPS 與受信任來源網域清單；拒絕 userinfo、IP literal、localhost、私有／link-local／保留位址
- 每次 redirect 都重新驗證 URL 與 DNS 解析結果；最多 3 次 redirect、10 秒、2 MB、只接受文字型態
- transport 可注入，測試以本地假 transport 進行，不連第三方
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin, urlsplit

MAX_REDIRECTS = 3
TIMEOUT_SECONDS = 10
MAX_BYTES = 2 * 1024 * 1024
TEXT_TYPES = ("text/html", "text/plain", "application/xhtml+xml", "application/json", "application/rss+xml", "application/xml",
              "text/xml", "application/atom+xml")


class FetchRejected(Exception):
    """URL 或回應不符合限制（不是網路錯誤）。"""


@dataclass
class FetchResult:
    url: str
    status: int
    text: str
    content_type: str


Resolver = Callable[[str], list[str]]


def default_resolver(host: str) -> list[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})


def _domain_allowed(host: str, allowlist: list[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in allowlist)


def validate_url(url: str, allowlist: list[str], resolver: Resolver = default_resolver) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise FetchRejected("只接受 HTTPS")
    if parts.username or parts.password or "@" in parts.netloc:
        raise FetchRejected("URL 不可含 userinfo")
    host = parts.hostname or ""
    if not host:
        raise FetchRejected("缺少主機名稱")
    try:
        ipaddress.ip_address(host)
        raise FetchRejected("不接受 IP literal")
    except ValueError:
        pass
    if host in ("localhost",) or host.endswith(".localhost") or host.endswith(".local") or host.endswith(".internal"):
        raise FetchRejected("不接受本機或內部網域")
    if parts.port not in (None, 443):
        raise FetchRejected("只接受 443 port")
    if not _domain_allowed(host, allowlist):
        raise FetchRejected(f"{host} 不在受信任來源清單")
    try:
        addrs = resolver(host)
    except OSError as exc:
        raise FetchRejected(f"DNS 解析失敗：{exc}") from exc
    if not addrs:
        raise FetchRejected("DNS 沒有結果")
    for a in addrs:
        ip = ipaddress.ip_address(a)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise FetchRejected(f"{host} 解析到不允許的位址")
    return url


def fetch(url: str, allowlist: list[str], *, transport=None, resolver: Resolver = default_resolver,
          max_bytes: int = MAX_BYTES, headers: dict[str, str] | None = None,
          timeout: float = TIMEOUT_SECONDS) -> FetchResult:
    """transport(url) → (status, headers: dict, body: bytes)。預設使用 httpx（不跟隨 redirect，由本函式逐次驗證）。

    max_bytes／timeout：個別官方資料集（CISA KEV 全集、回應較慢的 NVD API）可放寬；其餘限制不變。
    headers：只給預設 transport（例如 NVD apiKey）；redirect 一樣只能到 allowlist 內的網域，呼叫端應只給該 API 的網域。
    """
    request_headers = dict(headers or {})
    if transport is None:
        def transport(u: str):
            return _httpx_transport(u, max_bytes=max_bytes, headers=request_headers, timeout=timeout)
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        validate_url(current, allowlist, resolver)
        status, resp_headers, body = transport(current)
        resp_headers = {k.lower(): v for k, v in resp_headers.items()}
        if status in (301, 302, 303, 307, 308):
            location = resp_headers.get("location")
            if not location:
                raise FetchRejected("redirect 缺少 Location")
            current = urljoin(current, location)
            continue
        ctype = resp_headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype and ctype not in TEXT_TYPES:
            raise FetchRejected(f"不接受的內容型態 {ctype}")
        if len(body) > max_bytes:
            raise FetchRejected(f"回應超過 {max_bytes // (1024 * 1024)} MB")
        return FetchResult(url=current, status=status, text=body.decode("utf-8", errors="replace"), content_type=ctype)
    raise FetchRejected("redirect 超過 3 次")


def _httpx_transport(url: str, *, max_bytes: int = MAX_BYTES, headers: dict[str, str] | None = None,
                     timeout: float = TIMEOUT_SECONDS):
    import httpx

    with httpx.Client(timeout=timeout, follow_redirects=False,
                      headers={"User-Agent": "sentinel-demo-intel/0.1", **(headers or {})}) as client:
        with client.stream("GET", url) as resp:
            chunks, size = [], 0
            for chunk in resp.iter_bytes():
                size += len(chunk)
                if size > max_bytes:
                    raise FetchRejected(f"回應超過 {max_bytes // (1024 * 1024)} MB")
                chunks.append(chunk)
            return resp.status_code, dict(resp.headers), b"".join(chunks)
