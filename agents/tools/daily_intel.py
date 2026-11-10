"""讀取 daily-intel Job（claude-code-action，訂閱方案）寫出的 out/intel-daily.json。

這份檔案由 LLM 依網路內容產生，只當資料，且不信任它自己宣稱的驗證狀態：
- 每個事件強制為 kind=live、demo=false，ID 加上 live- 前綴，不能冒充或覆蓋預先收錄事件、示範事件與公告
- 來源只保留網址、標題、引用與日期；驗證欄位清空，交給 intel_verify 實際抓頁面確認
- 產品只保留名稱、生態系、版本範圍、CVSS 與影響類型；「已遭利用」「已確認」與觸發條件無法由程式驗證，不採用
- 控制項只接受 controls.yaml 中已有的 ID；文字欄位限制長度
- 格式不符的事件略過並記錄原因；數量設上限，避免大量抓取
- impacts（LLM 的初步判斷）不採用：受影響與否以程式比對為準
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml
from pydantic import ValidationError

from schemas import IntelEvent
from tools.common import INTEL_DIR

MAX_EVENTS = 30
MAX_SOURCES = 5
SLUG_RE = re.compile(r"[^a-z0-9._-]+")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,80}$")
VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+_-]{0,39}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
ATTCK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ECOSYSTEMS = {"npm", "pypi", "maven", "php", "composer", "go", "nuget", "rubygems", "deb", "rpm", "docker", "synology-dsm", "generic"}
IMPACTS = {"remote_code_execution", "account_takeover", "authorization_bypass", "data_exposure", "privilege_escalation",
           "denial_of_service", "other"}


def _text(value, limit: int) -> str | None:
    return value.strip()[:limit] if isinstance(value, str) and value.strip() else None


def _strings(value, pattern: re.Pattern | None = None, limit: int = 200, max_items: int = 10) -> list[str]:
    items = value if isinstance(value, list) else []
    out = [s.strip()[:limit] for s in items if isinstance(s, str) and s.strip()]
    return [s for s in out if pattern is None or pattern.match(s)][:max_items]


def _version(value) -> str | None:
    return value if isinstance(value, str) and VERSION_RE.match(value) else None


def _known_controls() -> set[str]:
    return {c["id"] for c in yaml.safe_load((INTEL_DIR / "controls.yaml").read_text(encoding="utf-8")) or []}


def _product(raw) -> dict | None:
    if not isinstance(raw, dict) or not _text(raw.get("name"), 80):
        return None
    eco = raw.get("ecosystem") if raw.get("ecosystem") in ECOSYSTEMS else "generic"
    p = {"name": _text(raw["name"], 80), "ecosystem": eco}
    affected = raw.get("affected")
    if isinstance(affected, str) and eco == "npm" and len(affected) <= 100:
        p["affected"] = affected
    elif isinstance(affected, list):
        ranges = [{"introduced": _version(r.get("introduced")), "fixed": _version(r.get("fixed"))}
                  for r in affected[:10] if isinstance(r, dict)]
        p["affected"] = [r for r in ranges if r["introduced"] or r["fixed"]]
    if _version(raw.get("unknown_below")):
        p["unknown_below"] = raw["unknown_below"]
    cvss = raw.get("cvss")
    if isinstance(cvss, (int, float)) and not isinstance(cvss, bool) and 0 <= cvss <= 10:
        p["cvss"] = float(cvss)
    if raw.get("impact") in IMPACTS:
        p["impact"] = raw["impact"]
    return p


def _live_id(raw_id: object, index: int) -> str:
    slug = SLUG_RE.sub("-", str(raw_id or "").lower()).strip("-.")[:60]
    slug = slug.removeprefix("live-") or f"event-{index + 1}"
    return f"live-{slug}"


def sanitize_event(raw: dict, index: int, controls: set[str]) -> dict:
    """回傳可交給 intel_verify 的事件；格式不符時丟出 ValueError。"""
    if not isinstance(raw, dict):
        raise ValueError("不是物件")
    sources = raw.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("沒有來源")
    if not isinstance(raw.get("date"), str) or not DATE_RE.match(raw["date"]):
        raise ValueError("日期格式不符")
    update_of = raw.get("is_update_of")
    ev = {
        "id": _live_id(raw.get("id"), index), "kind": "live", "demo": False,
        "title": _text(raw.get("title"), 200), "date": raw["date"], "industry": _text(raw.get("industry"), 40),
        "summary": _text(raw.get("summary"), 500), "revision": _text(raw.get("revision"), 40) or "1",
        "is_update_of": update_of if isinstance(update_of, str) and ID_RE.match(update_of) else None,
        "attack_chain": _strings(raw.get("attack_chain")), "attck": _strings(raw.get("attck"), ATTCK_RE),
        "cves": _strings(raw.get("cves"), CVE_RE), "controls": [c for c in _strings(raw.get("controls")) if c in controls],
        "confidence": "confirmed" if raw.get("confidence") == "confirmed" else "provisional",   # 未驗證通過會再被降為暫定
        "products": [p for p in map(_product, (raw.get("products") or [])[:10] if isinstance(raw.get("products"), list) else []) if p],
        "sources": [{"url": _text(s.get("url"), 500), "title": _text(s.get("title"), 200) or "",
                     "quote": _text(s.get("quote"), 500), "published": _text(s.get("published"), 40)}
                    for s in sources[:MAX_SOURCES] if isinstance(s, dict)],
    }
    if not ev["title"]:
        raise ValueError("沒有標題")
    try:
        return IntelEvent.model_validate(ev).model_dump()
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})[:5]
        raise ValueError(f"欄位不符：{', '.join(fields)}") from None


def load_daily_intel(path: Path) -> tuple[list[dict], list[str]]:
    """回傳（可用事件, 問題清單）。檔案不存在時回傳空清單、無問題（daily-intel 沒執行或失敗由 A5 另外標示）。"""
    if not path.is_file():
        return [], []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError):
        return [], ["intel-daily.json 不是合法的 JSON"]
    raw_events = data.get("events") if isinstance(data, dict) else None
    if not isinstance(raw_events, list):
        return [], ["intel-daily.json 缺少 events 陣列"]
    issues = []
    if len(raw_events) > MAX_EVENTS:
        issues.append(f"事件超過 {MAX_EVENTS} 件，只處理前 {MAX_EVENTS} 件")
    controls = _known_controls()
    events, seen = [], set()
    for i, raw in enumerate(raw_events[:MAX_EVENTS]):
        try:
            ev = sanitize_event(raw, i, controls)
        except ValueError as exc:
            issues.append(f"第 {i + 1} 件略過：{exc}")
            continue
        if ev["id"] in seen:
            issues.append(f"第 {i + 1} 件略過：ID 重複（{ev['id']}）")
            continue
        seen.add(ev["id"])
        events.append(ev)
    return events, issues
