"""情資驗證（第 7.2 節 A1）：所有來源都要經過。

- pydantic 驗證格式、產品名稱經 aliases 正規化（保留 SAPI 等條件）
- 來源引用：抓取頁面確認 quote 逐字出現（NFKC、空白正規化後比對）；區分 fetch_failed 與 quote_mismatch
- 預先收錄事件可沿用撰寫時的驗證結果（verification_basis=archived），只支持原來事實
- 示範事件（demo: true）與示範公告 fixture 跳過網址與引用驗證
- 可信度：官方／advisory 來源驗證通過，或兩個獨立媒體來源一致才為 confirmed；quote_mismatch 的事件最高只到中
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from schemas import IntelEvent
from tools.aliases import normalize
from tools.common import INTEL_DIR, iso
from tools.safe_fetch import FetchRejected, fetch

TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>|<[^>]+>", re.S | re.I)


def load_source_tiers(path: Path | None = None) -> dict[str, str]:
    data = yaml.safe_load((path or INTEL_DIR / "sources.yaml").read_text(encoding="utf-8")) or {}
    return {d["domain"]: d["tier"] for d in data.get("domains", [])}


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text)).strip()


def html_to_text(html: str) -> str:
    import html as _html
    return normalize_text(_html.unescape(TAG_RE.sub(" ", html)))


def quote_in(page_text: str, quote: str) -> bool:
    return normalize_text(quote) in normalize_text(page_text)


def load_events(directory: Path) -> list[dict]:
    if not directory.is_dir():
        return []
    return [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.yaml"))]


def _domain_tier(url: str | None, tiers: dict[str, str]) -> str | None:
    if not url:
        return None
    host = (urlsplit(url).hostname or "").lower()
    for domain, tier in tiers.items():
        if host == domain or host.endswith("." + domain):
            return tier
    return None


def verify_event(raw: dict, *, as_of: datetime, online: bool = False, transport=None, resolver=None,
                 tiers: dict[str, str] | None = None, collected: dict[str, list[str]] | None = None) -> dict:
    """回傳 {event, verification}。event 已通過 pydantic 驗證並正規化產品名稱。

    collected：同一次執行由 news_collect 從可信網域抓到的原文（網址 → [標題, 句子…]）。來源網址在其中時直接比對，
    不再抓一次；只接受可信網域的網址（tiers 中的網域）。
    """
    tiers = tiers if tiers is not None else load_source_tiers()
    allow = list(tiers)
    ev = IntelEvent.model_validate({k: v for k, v in raw.items() if k in IntelEvent.model_fields}).model_dump()
    extras = {k: v for k, v in raw.items() if k not in IntelEvent.model_fields}
    for p in ev["products"]:
        p["name"] = normalize(p.get("name"))
    if ev["demo"] and not ev["title"].startswith("示範："):
        raise ValueError(f"示範事件 {ev['id']} 的標題必須以「示範：」開頭")

    issues: list[str] = []
    is_fixture = ev["demo"] or ev["kind"] == "advisory" and raw.get("demo_fixture")
    if is_fixture:
        for s in ev["sources"]:
            s.update(fetch_status="skipped", verification_basis="demo")
        return {"event": {**ev, **extras}, "verification": {"status": "skipped", "issues": [], "max_level": None}}

    for s in ev["sources"]:
        if not s.get("url"):
            s.update(fetch_status="skipped", verified=False, verification_basis="unverified")
            continue
        texts = (collected or {}).get(s["url"]) if ev["kind"] == "live" else None
        if texts and _domain_tier(s["url"], tiers):
            joined = " ".join(texts)
            new_hash = "sha256:" + hashlib.sha256(joined.encode("utf-8")).hexdigest()
            if s.get("quote") and any(quote_in(t, s["quote"]) for t in [*texts, joined]):
                s.update(fetch_status="ok", verified=True, verified_at=iso(as_of), verification_basis="live", content_hash=new_hash)
            else:
                s.update(fetch_status="quote_mismatch", verified=False, verification_basis="live", content_hash=new_hash)
                issues.append(f"{s['url']}：抓取的原文中找不到引用")
            continue
        if not online:
            if ev["kind"] == "archive" and s.get("verified"):
                s["verification_basis"] = "archived"
            else:
                s.update(fetch_status="skipped", verification_basis="unverified")
            continue
        try:
            kwargs = {"transport": transport}
            if resolver is not None:
                kwargs["resolver"] = resolver
            res = fetch(s["url"], allow, **kwargs)
        except FetchRejected as exc:
            s.update(fetch_status="fetch_failed", verified=False)
            issues.append(f"{s['url']}：{exc}")
            continue
        except Exception as exc:  # 網路錯誤、逾時、403 等
            s.update(fetch_status="fetch_failed", verified=False)
            issues.append(f"{s['url']}：無法取得頁面（{type(exc).__name__}）")
            continue
        if res.status >= 400:
            s.update(fetch_status="fetch_failed", verified=False)
            issues.append(f"{s['url']}：HTTP {res.status}")
            continue
        text = html_to_text(res.text)
        new_hash = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        if s.get("quote") and quote_in(text, s["quote"]):
            s.update(fetch_status="ok", verified=True, verified_at=iso(as_of), verification_basis="live")
        else:
            s.update(fetch_status="quote_mismatch", verified=False, verification_basis="live")
            issues.append(f"{s['url']}：頁面中找不到引用")
        if ev["kind"] == "archive" and s.get("content_hash") and s["content_hash"] != new_hash:
            issues.append(f"{s['url']}：來源內容已改變，新版本範圍需重新驗證")
        s["content_hash"] = new_hash

    verified = [s for s in ev["sources"] if s.get("verified")]
    official = [s for s in verified if _domain_tier(s["url"], tiers) in ("vendor", "advisory")]
    independent = {(urlsplit(s["url"]).hostname, s.get("content_hash")) for s in verified
                   if _domain_tier(s["url"], tiers) == "media"}
    distinct_hosts = {h for h, _ in independent}
    confirmed = bool(official) or len(distinct_hosts) >= 2
    if ev["confidence"] == "confirmed" and not confirmed:
        ev["confidence"] = "provisional"
        issues.append("官方來源或兩個獨立來源未驗證通過：改為暫定")
    mismatch = any(s["fetch_status"] == "quote_mismatch" for s in ev["sources"])
    failed = all(s["fetch_status"] == "fetch_failed" for s in ev["sources"] if s.get("url")) and any(s.get("url") for s in ev["sources"])
    status = "quote_mismatch" if mismatch else "fetch_failed" if failed else "ok"
    return {"event": {**ev, **extras},
            "verification": {"status": status, "issues": issues, "max_level": "medium" if mismatch else None,
                             "note": "來源暫時無法驗證" if status == "fetch_failed" else None}}
