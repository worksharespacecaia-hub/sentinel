"""白話欄位與事件品牌（v0.14.0，specs/plain-brief）：公開文字檢查、AI 白話欄位的逐欄篩選、系統 ID 檢查、事件品牌。

- exact_public：公開文字過濾（orchestration.public_safe）的結果必須與原文（去掉前後空白）完全相同（R8.2）
- screen_fields：llm._validate("solutions") 在整份機敏檢查之前呼叫，只移除不合格的白話欄位並記數（R2.4）
- clean_plain：A5 對 AI 解法做本次系統 ID 檢查；先深複製，不改到快取保存的物件（R2.5）
- event_brand／report_brands：品牌只來自人工整理的 archive 事件，live 只沿用原事件的品牌（R2.6）

匯入關係（避免循環）：頂層只匯入 tools.common、tools.templates；tools.orchestration 在函式內延遲匯入
（同 orchestration.safe_text 延遲匯入 digest 的做法：digest 會匯入 llm，llm._validate 又會匯入本模組）。
"""
from __future__ import annotations

import copy
import re

PLAIN_LIMITS = {"plain_title": 40, "if_ignored": 100}     # AI 撰寫的上限（R2.1）；範本另有 schema 上限 120／300
PLAIN_FIELDS = tuple(PLAIN_LIMITS)
BRAND_LIMIT = 20
EVENT_TITLE_LIMIT = 200
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_ID_BOUNDARY = "A-Za-z0-9_-"


def exact_public(text, limit: int) -> bool:
    """字串，且 public_safe(text, limit) 與 text.strip() 完全相同（有遮蔽、截斷、合併空白或拒收都不算）。"""
    if not isinstance(text, str):
        return False
    from tools.orchestration import public_safe   # 延遲匯入（見模組說明）
    return public_safe(text, limit) == text.strip()


def _field_ok(text, limit: int) -> bool:
    if not isinstance(text, str) or not text.strip() or len(text.strip()) > limit:
        return False
    return exact_public(text, limit) and not CVE_ID_RE.search(text)


def _count(value) -> int:
    """既有的 plain_dropped：只接受 0～2 的整數（每項最多兩個白話欄位），其他值視為 0。"""
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return min(max(value, 0), len(PLAIN_FIELDS))


def screen_fields(item: dict) -> None:
    """逐欄檢查 plain_title、if_ignored（型別、非空、長度、R8、CVE 編號）；不合格只移除該欄，移除數累加到 plain_dropped。

    原地修改 item（_validate 的其他步驟也是原地修改）；本次系統 ID 的檢查需要圖譜，留給 A5 的 clean_plain。
    快取命中時會再驗證一次：已通過的欄位再檢查仍通過，plain_dropped 不會重複累加。
    """
    if not isinstance(item, dict):
        return
    dropped = _count(item.get("plain_dropped"))
    for key, limit in PLAIN_LIMITS.items():
        if key not in item:
            continue
        if _field_ok(item[key], limit):
            item[key] = item[key].strip()
        else:
            item.pop(key)
            dropped += 1
    if dropped:
        item["plain_dropped"] = min(dropped, len(PLAIN_FIELDS))
    else:
        item.pop("plain_dropped", None)


def contains_internal_id(text, ids, allow=()) -> bool:
    """文字是否含本次系統 ID（R8.3）：只比對 3 字以上、不在 allow（品牌）內的 ID；不分大小寫；
    ID 前後不是英數字、「-」、「_」才算命中（internal-tool.example、internal-tool@example.com 會命中；internal-toolkit 不會）。"""
    if not isinstance(text, str) or not text:
        return False
    allowed = {a.lower() for a in allow or () if isinstance(a, str)}
    for i in ids or ():
        if not isinstance(i, str) or len(i) < 3 or i.lower() in allowed:
            continue
        if re.search(rf"(?<![{_ID_BOUNDARY}]){re.escape(i)}(?![{_ID_BOUNDARY}])", text, re.I):
            return True
    return False


def clean_plain(sol: dict, risk: dict, internal_ids, brands) -> tuple[dict, int]:
    """A5 對一份 AI 解法做本次系統 ID 檢查（R2.4、R2.5）。回傳（清理後的副本, 移除欄位數）。

    - 不修改傳入的物件：快取（tools/cache.py）直接保存並回傳 output 的參照
    - plain_dropped（_validate 的移除數）併入計數後從副本移除（Solution 沒有這個欄位）
    - internal_ids＝本次圖譜節點；另加入該風險的資產與攻擊路徑節點（不在圖譜上的資產，例如 platform，也要擋）
    - brands：該風險相關事件的品牌；與品牌同名的 ID 不算命中
    """
    sol = copy.deepcopy(sol)
    n = _count(sol.pop("plain_dropped", 0))
    ids = set(internal_ids or ())
    if isinstance(risk, dict):
        ids |= {x for x in [risk.get("asset_id"), *(risk.get("attack_path") or [])] if isinstance(x, str)}
    allow = {b.lower() for b in brands or () if isinstance(b, str)}
    for key in PLAIN_FIELDS:
        if key in sol and contains_internal_id(sol[key], ids, allow=allow):
            sol.pop(key)
            n += 1
    return sol, n


def event_brand(value, title) -> str | None:
    """archive 事件的人工品牌（R2.6）：字串、去空白後 1～20 字、是標題的子字串、通過 R8 且過濾後與原文相同；否則 None。"""
    if not isinstance(value, str) or not isinstance(title, str):
        return None
    brand = value.strip()
    if not 1 <= len(brand) <= BRAND_LIMIT or brand not in title or not exact_public(brand, BRAND_LIMIT):
        return None
    return brand


def report_brands(raw_events: list[dict]) -> dict[str, str | None]:
    """報告 events[].brand（design §3.3）：raw_events＝result["events"]（event_sources 已移除非 archive 來源的 brand）。

    - archive：非示範、confirmed 才帶出人工品牌
    - live：非示範、confirmed，且 is_update_of 指向的原事件是帶品牌的 archive 事件時沿用（只沿用一層，不連鎖）
    - 其他（advisory、demo）一律 None
    """
    events = [e for e in raw_events or [] if isinstance(e, dict) and isinstance(e.get("id"), str)]
    by_id = {e["id"]: e for e in events}

    def own(e: dict) -> str | None:
        ok = e.get("kind") == "archive" and not e.get("demo") and e.get("confidence") == "confirmed"
        return event_brand(e.get("brand"), e.get("title")) if ok else None

    out: dict[str, str | None] = {}
    for e in events:
        if e.get("kind") == "archive":
            out[e["id"]] = own(e)
        elif e.get("kind") == "live" and not e.get("demo") and e.get("confidence") == "confirmed":
            parent = by_id.get(e.get("is_update_of")) if isinstance(e.get("is_update_of"), str) else None
            out[e["id"]] = own(parent) if parent else None
        else:
            out[e["id"]] = None
    return out


def risk_brands(risk: dict, brands: dict[str, str | None]) -> list[str]:
    """該風險相關事件（matched_events 順序）的品牌，去重保序。第一個就是風險的品牌（R2.6）。"""
    out: list[str] = []
    for eid in risk.get("matched_events") or []:
        b = brands.get(eid)
        if b and b not in out:
            out.append(b)
    return out
