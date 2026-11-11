"""讀取 daily-intel Job（claude-code-action，訂閱方案）寫出的 out/intel-daily.json。

這份檔案由 LLM 依網路內容產生，只當資料，且不信任它自己宣稱的驗證狀態：
- 每個事件強制為 kind=live、demo=false，ID 加上 live- 前綴，不能冒充或覆蓋預先收錄事件、示範事件與公告
- 來源只保留網址、標題、引用與日期；驗證欄位清空，交給 intel_verify 實際抓頁面確認
- 產品只保留名稱、生態系、版本範圍、CVSS 與影響類型；「已遭利用」「已確認」與觸發條件無法由程式驗證，不採用
- 控制項只接受 controls.yaml 中已有的 ID；建議新增的控制項（proposed_controls）只保留標題與理由文字；文字欄位限制長度
- 沒有產品也沒有控制項的事件由 intel_match 判為「需確認」，不會因為沒東西可比就變成「不受影響」
- 格式不符的事件略過並記錄原因；數量設上限，避免大量抓取
- impacts（LLM 的初步判斷）不採用：受影響與否以程式比對為準
"""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
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


def _proposed_controls(value) -> list[dict]:
    """建議新增的控制項只當顯示文字（由人工決定是否加進 controls.yaml），不帶 ID，避免冒充既有控制項。"""
    items = value if isinstance(value, list) else []
    out = [{"title": _text(i.get("title"), 80), "reason": _text(i.get("reason"), 200) or ""}
           for i in items[:10] if isinstance(i, dict)]
    return [i for i in out if i["title"]][:3]


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
        "proposed_controls": _proposed_controls(raw.get("proposed_controls")),
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


@dataclass
class DailyIntelSnapshot:
    """同一次讀取的 intel-daily.json：A1 的事件驗證與訂閱方案建議共用，避免讀到兩份不同內容。原始 data 只留在記憶體。"""
    data: dict | None
    events: list[dict]
    issues: list[str]
    id_map: dict[str, str] = field(default_factory=dict)   # 原始字串 ID／canonical live ID → 清理後 live ID（只收唯一可定位者）
    read_issue: str | None = None                          # None 表示檔案可讀且頂層結構有效


def _id_aliases(raw_events: list) -> dict[int, list[str]]:
    """每個原始位置的別名：原始字串 ID（strip 後）與 canonical live ID。空 ID 只有 canonical（live-event-N）。"""
    out = {}
    for i, raw in enumerate(raw_events):
        rid = raw.get("id") if isinstance(raw, dict) else None
        names = [_live_id(rid, i)]
        if isinstance(rid, str) and rid.strip():
            names.append(rid.strip())
        out[i] = list(dict.fromkeys(names))
    return out


def load_daily_snapshot(path: Path) -> DailyIntelSnapshot:
    """讀取並清理 intel-daily.json（只讀一次）。缺檔、讀取或格式錯誤回傳空事件與固定原因，不輸出異常原文。"""
    if not path.is_file():
        return DailyIntelSnapshot(None, [], [], read_issue="每日情資沒有輸出")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError):
        return DailyIntelSnapshot(None, [], ["intel-daily.json 不是合法的 JSON"], read_issue="每日情資無法解析")
    except OSError:
        return DailyIntelSnapshot(None, [], ["intel-daily.json 無法讀取"], read_issue="每日情資無法讀取")
    raw_events = data.get("events") if isinstance(data, dict) else None
    if not isinstance(raw_events, list):
        return DailyIntelSnapshot(data if isinstance(data, dict) else None, [], ["intel-daily.json 缺少 events 陣列"],
                                  read_issue="每日情資格式不符")
    issues = []
    if len(raw_events) > MAX_EVENTS:
        issues.append(f"事件超過 {MAX_EVENTS} 件，只處理前 {MAX_EVENTS} 件")
    controls = _known_controls()
    # 先掃描所有原始 ID（含超額事件）找出歧義別名：同一個別名指向兩個以上位置時，相關事件的所有別名都不收
    aliases = _id_aliases(raw_events)
    owners: dict[str, set[int]] = {}
    for i, names in aliases.items():
        for n in names:
            owners.setdefault(n, set()).add(i)
    ambiguous = {i for n, idx in owners.items() if len(idx) > 1 for i in idx}
    events, seen, id_map = [], set(), {}
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
        if i not in ambiguous:
            for n in aliases[i]:
                id_map[n] = ev["id"]
    return DailyIntelSnapshot(data, events, issues, id_map)


def load_daily_intel(path: Path) -> tuple[list[dict], list[str]]:
    """回傳（可用事件, 問題清單）。檔案不存在時回傳空清單、無問題（daily-intel 沒執行或失敗由 A5 另外標示）。"""
    snap = load_daily_snapshot(path)
    return snap.events, snap.issues


def load_daily_plan(snapshot: DailyIntelSnapshot) -> tuple[dict | None, str | None]:
    """訂閱方案的 AI 建議（頂層 agent_plan）。回傳（建議, 安全原因）；None 表示要退回 A1 planner。

    格式有效時把每個字串 event_id 以同一份快照的 id_map 換成本次 live ID；無法唯一對應的改為空字串，交給 approve 拒絕。
    不信任任何計數、核准狀態或額外欄位；合法 {} 代表沒有建議，不退回 API。
    """
    from tools.agent_plan import TOP_KEYS, validate_plan_shape
    if snapshot.read_issue or not isinstance(snapshot.data, dict):
        return None, snapshot.read_issue or "每日情資格式不符"
    if "agent_plan" not in snapshot.data:
        return None, "訂閱方案未提供建議"
    try:
        plan = validate_plan_shape(copy.deepcopy(snapshot.data["agent_plan"]))
    except ValueError:
        return None, "訂閱方案建議格式不符"
    for k in TOP_KEYS:
        for item in plan.get(k) or []:
            eid = item.get("event_id")
            if isinstance(eid, str):
                item["event_id"] = snapshot.id_map.get(eid.strip(), "")
    return plan, None
