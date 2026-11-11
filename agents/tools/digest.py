"""資安事件整理（0.10.0，specs/security-digest）：純程式產生，不呼叫任何 LLM。

三份公開檔案都在 dashboard/public/data/digest/（與 daily/ 同層，不會被每次 daily 發布整個覆蓋）：
- store.json：近 30 天的累積資料（收錄紀錄＋最近一次完整評估快照）
- seen.json：最小去重紀錄（只有事件 ID 的 sha256 與首次收錄日期）
- latest.json：已發布的整理（只有資料完整的 daily 才重建評估內容）

文字只取自已通過清理與驗證的欄位（A1 驗證後的來源、A5 採用的摘要），寫入前再做金鑰與個資檢查；
網址只接受 http(s)，拒絕 userinfo，移除帶金鑰／Token／個資的參數，無法安全清理時 url=None。
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from llm import SECRET_RE
from tools.common import sha256_text
from tools.findings import SECRET_VALUE_RE

WINDOW_DAYS = 30
SUMMARY_LIMIT = 300
TITLE_LIMIT = 200
LABEL_LIMIT = 60
MAX_IMPACTS = 20
UNNAMED_ASSET = "未命名系統"
PENDING_ASSET = "待確認系統"
REDACTED = "［已遮蔽］"

RELATION = {"open": "affected", "need_check": "need_check", "not_affected": "not_affected", "fixed": "fixed"}
LEVEL_ZH = {"high": "高", "medium": "中", "low": "低"}
VERDICT_ORDER = {"affected": 0, "need_check": 1, "not_affected": 2}

EVENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,120}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")

# 既有的金鑰偵測（llm.SECRET_RE：輸出驗證；findings.SECRET_VALUE_RE：掃描結果遮蔽）之外，補上常見 Token 與個資格式
EXTRA_SECRET_RE = re.compile(
    r"\bAKIA[0-9A-Z]{16}\b|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bgh[ousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|(?i:\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*)")
PII_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"          # 電子郵件
    r"|(?<!\d)09\d{2}[- ]?\d{3}[- ]?\d{3}(?!\d)"               # 台灣手機
    r"|(?<![A-Za-z0-9])[A-Z][12]\d{8}(?!\d)"                   # 身分證字號
    r"|(?<!\d)\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}(?!\d)")          # 卡號
SENSITIVE_RES = (SECRET_RE, SECRET_VALUE_RE, EXTRA_SECRET_RE, PII_RE)
SENSITIVE_PARAM_RE = re.compile(
    r"(?i)token|key|secret|pass(?:word|wd)?|pwd|auth|session|sid\b|^sig|signature|credential|^code$|otp|jwt|bearer"
    r"|e-?mail|phone|^tel$|mobile|user(?:name)?|^uid$|account|login")


def has_sensitive(text: str | None) -> bool:
    return bool(text) and any(r.search(text) for r in SENSITIVE_RES)


def redact_public(text: str) -> str:
    for r in SENSITIVE_RES:
        text = r.sub(REDACTED, text)
    return text


def public_text(value, limit: int) -> str:
    """公開文字：移除控制字元、合併空白、遮蔽金鑰與個資，再截斷到 limit 字（先遮蔽再截斷，避免留下半段金鑰）。"""
    text = re.sub(r"\s+", " ", CONTROL_RE.sub(" ", str(value or ""))).strip()
    text = redact_public(text)
    if len(text) > limit:
        text = text[:limit - 1].rstrip() + "…"
    return text


def _host(parts) -> str | None:
    try:
        host = parts.hostname
    except ValueError:
        return None
    if not host:
        return None
    try:
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return None
    return host if HOST_RE.match(host) else None


def source_domain(url) -> str | None:
    """媒體網域：只取 http(s) 網址的主機名稱（即使網址本身無法安全提供連結，仍可保留網域）。"""
    if not isinstance(url, str) or CONTROL_RE.search(url):
        return None
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https"):
        return None
    return _host(parts)


def safe_url(url) -> str | None:
    """只接受 http(s)；拒絕 userinfo；移除帶金鑰／Token／個資的參數與 fragment；仍有機敏內容時回傳 None。"""
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url or len(url) > 2048 or CONTROL_RE.search(url) or re.search(r"\s", url):
        return None
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    if "@" in parts.netloc or parts.username or parts.password:
        return None
    host = _host(parts)
    if not host:
        return None
    if has_sensitive(unquote(parts.path)):
        return None
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    kept = [(k, v) for k, v in pairs if not SENSITIVE_PARAM_RE.search(k)]
    if any(has_sensitive(k) or has_sensitive(v) for k, v in kept):
        return None
    query = parts.query if len(kept) == len(pairs) else urlencode(kept)
    if len(kept) == len(pairs) and has_sensitive(unquote(query)):
        return None
    netloc = host + (f":{port}" if port is not None else "")
    return urlunsplit((scheme, netloc, parts.path, query, ""))


def public_sources(sources: list[dict] | None) -> list[dict]:
    """只留標題、網域、網址、驗證狀態；不存原文引用。"""
    out = []
    for s in sources or []:
        domain = source_domain(s.get("url"))
        title = public_text(s.get("title"), TITLE_LIMIT) or domain or "未命名來源"
        out.append({"title": title, "domain": domain, "url": safe_url(s.get("url")), "verified": bool(s.get("verified"))})
    return out


def public_asset_labels(services: list[dict] | None = None, vendors: list[dict] | None = None,
                        graph_nodes: dict | None = None) -> dict[str, str]:
    """資產的可公開名稱：只取服務／第三方清冊的 name、圖譜節點的 display_name（不使用 people 清冊）。

    名稱與 ID 完全相同、清理後為空或含機敏內容的不採用；找不到時由 asset_label() 顯示「未命名系統」，不回退顯示 ID。
    """
    labels: dict[str, str] = {}

    def put(asset_id, name):
        if not isinstance(asset_id, str) or not isinstance(name, str) or asset_id in labels:
            return
        if has_sensitive(name):
            return
        text = public_text(name, LABEL_LIMIT)
        if text and text != asset_id:
            labels[asset_id] = text

    for s in services or []:
        put(s.get("id"), s.get("name") or s.get("display_name"))
    for v in vendors or []:
        put(v.get("id"), v.get("name"))
    for node_id, attrs in (graph_nodes or {}).items():
        put(node_id, (attrs or {}).get("display_name"))
    return labels


def asset_label(asset_id: str, labels: dict[str, str]) -> str:
    if asset_id == "*":
        return PENDING_ASSET
    return labels.get(asset_id) or UNNAMED_ASSET


def _level_queues(blocks: dict) -> dict[tuple[str, str], deque]:
    """同份報告 blocks 的等級：3_affected 與 4_unaffected_and_check.need_check，依 (asset_id, verdict) 依序對應。"""
    q: dict[tuple[str, str], deque] = defaultdict(deque)
    rows = [*(blocks.get("3_affected") or []), *((blocks.get("4_unaffected_and_check") or {}).get("need_check") or [])]
    for row in rows:
        if isinstance(row, dict) and row.get("verdict") in ("affected", "need_check"):
            q[(row.get("asset_id"), row["verdict"])].append(row.get("level"))
    return q


def public_impacts(rep: dict, labels: dict[str, str]) -> tuple[list[dict], int]:
    """最多 20 筆：受影響優先、其次需確認、再來不受影響；同級按資產 ID 穩定排序。等級不從 StackImpact 取（它沒有 level）。"""
    queues = _level_queues(rep.get("blocks") or {})
    rows = []
    for i in rep.get("impacts") or []:
        verdict, aid = i["verdict"], i["asset_id"]
        level = None
        if verdict in ("affected", "need_check"):
            q = queues.get((aid, verdict))
            level = q.popleft() if q else None
        rows.append({"asset_id": aid, "asset_label": asset_label(aid, labels), "verdict": verdict,
                     "level": level if level in LEVEL_ZH else None})
    rows.sort(key=lambda r: (VERDICT_ORDER[r["verdict"]], r["asset_id"]))
    return rows[:MAX_IMPACTS], len(rows)


# 只用 ASCII 邊界：中文字也算 \w，\b 在「高internal」之間不成立
_INTERNAL_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])[a-z0-9_][A-Za-z0-9_./-]*\.(?:json|jsonl|ya?ml|tsx?|jsx?|py|csv|php|conf|env|tf|xml|gradle|ini"
    r"|toml|sh)(?![A-Za-z0-9])"                                                                   # 檔案路徑／欄位來源
    r"|(?<![A-Za-z0-9])C-[A-Z0-9]+(?:-[A-Z0-9]+)+(?![A-Za-z0-9])"                                 # 控制項 ID
    r"|:\d{2,5}(?![0-9])"                                                                         # 連接埠
    r"|(?<![A-Za-z0-9_-])(?=[a-z0-9_-]*[a-z])[a-z0-9]+(?:[-_][a-z0-9]+)+(?![A-Za-z0-9_-])")       # 像內部 ID 的字串


def public_conclusion(rep: dict, labels: dict[str, str], relation: str) -> str:
    """結論：已知資產 ID 轉成可公開名稱；仍含內部 ID、檔案路徑或機敏內容時，改用依結構化結果產生的白話範本。"""
    text = str(rep.get("conclusion") or "")
    ids = {i["asset_id"] for i in rep.get("impacts") or [] if i.get("asset_id") and i["asset_id"] != "*"} | set(labels)
    for aid in sorted(ids, key=len, reverse=True):
        text = re.sub(rf"(?<![A-Za-z0-9_.-]){re.escape(aid)}(?![A-Za-z0-9_-])", asset_label(aid, labels), text)
    text = re.sub(r"\s+", " ", CONTROL_RE.sub(" ", text)).strip()
    if text and not has_sensitive(text) and not _INTERNAL_TOKEN_RE.search(text) and len(text) <= SUMMARY_LIMIT:
        return text
    return conclusion_template(rep, relation)


def conclusion_template(rep: dict, relation: str) -> str:
    impacts = rep.get("impacts") or []
    level = LEVEL_ZH.get(rep.get("max_level"), "未評")
    if relation == "affected":
        return f"{rep.get('affected_count', 0)} 項受影響，最高風險為{level}。"
    if relation == "fixed":
        return f"{rep.get('affected_count', 0)} 項曾受影響，目前都已修復。"
    if relation == "need_check":
        need = [i for i in impacts if i.get("verdict") == "need_check"]
        if need and all(i.get("asset_id") == "*" for i in need):
            return "無法自動判定是否受影響，需要人工確認。"
        return f"沒有確定受影響的項目，但有 {len(need)} 項需要人工確認。"
    return "不受影響：沒有符合的系統。"


def assessment_from_report(rep: dict, labels: dict[str, str], *, run_id: str, evaluated_at: str) -> dict:
    """一份完整 IntelMatchReport → 評估快照。關係、等級、受影響數、結論與明細都取自同一份報告，整組使用。"""
    relation = RELATION[rep["status"]]
    impacts, total = public_impacts(rep, labels)
    return {"evaluated_at": evaluated_at, "run_id": run_id, "relation": relation, "max_level": rep.get("max_level"),
            "affected_count": int(rep.get("affected_count") or 0), "conclusion": public_conclusion(rep, labels, relation),
            "impacts": impacts, "impacts_total": total, "impacts_truncated": total > len(impacts),
            "relation_changed_at": None}


def event_content(rep: dict) -> dict:
    """事件內容（標題、日期、可信度、來源、摘要）：取自 A1 驗證後的事件與 A5 採用的摘要。"""
    ev = rep["event"]
    date = ev.get("date")
    upd = ev.get("is_update_of")
    return {"id": ev["id"], "kind": ev["kind"], "title": public_text(ev.get("title"), TITLE_LIMIT) or "未命名事件",
            "event_date": date if isinstance(date, str) and DATE_RE.match(date) else None,
            "confidence": ev.get("confidence") if ev.get("confidence") in ("confirmed", "provisional") else "provisional",
            "is_update_of": upd if isinstance(upd, str) and EVENT_ID_RE.match(upd) else None,
            "cves": sorted({c for c in ev.get("cves") or [] if isinstance(c, str) and CVE_RE.match(c)}),
            "summary": public_text(rep.get("summary") or ev.get("summary") or "", SUMMARY_LIMIT),
            "sources": public_sources(ev.get("sources"))}


def eligible_report(rep: dict) -> bool:
    """只收 daily 的 live／archive／advisory；示範事件（kind=demo 或 demo=true）一律排除。"""
    ev = rep.get("event") or {}
    return (ev.get("kind") in ("live", "archive", "advisory") and not ev.get("demo")
            and isinstance(ev.get("id"), str) and bool(EVENT_ID_RE.match(ev["id"])))


def eligible_run(scope: str, trigger_source: str) -> bool:
    """只有 daily 範圍的 schedule／manual 來源產生新整理；web daily 留給發布端做到期清理。"""
    return scope == "daily" and trigger_source in ("schedule", "manual")


def seen_key(event_id: str) -> str:
    """最小去重鍵：sha256(UTF-8 事件 ID)。只供去重，不是加密保護。"""
    return sha256_text(event_id)
