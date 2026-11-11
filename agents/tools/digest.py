"""資安事件整理（0.10.0，specs/security-digest）：純程式產生，不呼叫任何 LLM。

三份公開檔案都在 dashboard/public/data/digest/（與 daily/ 同層，不會被每次 daily 發布整個覆蓋）：
- store.json：近 30 天的累積資料（收錄紀錄＋最近一次完整評估快照）
- seen.json：最小去重紀錄（只有事件 ID 的 sha256 與首次收錄日期）
- latest.json：已發布的整理（只有資料完整的 daily 才重建評估內容）

文字只取自已通過清理與驗證的欄位（A1 驗證後的來源、A5 採用的摘要），寫入前再做金鑰與個資檢查；
網址只接受 http(s)，拒絕 userinfo，移除帶金鑰／Token／個資的參數，無法安全清理時 url=None。
"""
from __future__ import annotations

import copy
import json
import re
from collections import defaultdict, deque
from datetime import date, datetime, timedelta
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from llm import SECRET_RE
from tools.common import TAIPEI, iso, parse_time, sha256_text
from tools.findings import SECRET_VALUE_RE

WINDOW_DAYS = 30
SUMMARY_LIMIT = 300
TITLE_LIMIT = 200
LABEL_LIMIT = 60
MAX_IMPACTS = 20
PER_DAY_LIMIT = 50                    # 每個收錄日期最多保留的完整事件內容
MAX_BYTES = 1024 * 1024               # store／latest 各最多 1 MiB（UTF-8 實際序列化位元組）
SEEN_WARN_BYTES = 1024 * 1024         # seen 不裁切，只監測大小
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


# ── T2：累積資料合併、清理、最小去重與容量限制 ────────────────────────────────

REL_RANK = {"affected": 0, "need_check": 1, "not_affected": 2, "fixed": 3, None: 4}   # None＝待評估
LEVEL_RANK = {"high": 0, "medium": 1, "low": 2, None: 3}


def serialize(value) -> bytes:
    """與 tools.common.write_json 相同的格式（indent=2、LF 結尾）；容量以這個實際位元組數計算。"""
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def taipei_date(dt: datetime) -> str:
    return dt.astimezone(TAIPEI).date().isoformat()


def window_bounds(as_of: datetime, days: int = WINDOW_DAYS) -> tuple[str, str]:
    """保留窗口：以台灣日曆日計算，包含基準當日與前 days-1 日（D-29～D），不是再往前 30 日。"""
    end = as_of.astimezone(TAIPEI).date()
    return (end - timedelta(days=days - 1)).isoformat(), end.isoformat()


def _issue(code: str, impact: str, omitted: int = 0, day: str | None = None) -> dict:
    return {"code": code, "impact": impact, "omitted": omitted, "date": day}


def _rank(ev: dict) -> tuple:
    """容量裁切順序：受影響 → 需確認 → 不受影響 → 已修復 → 待評估，等級高到低，收錄日期新到舊，ID。"""
    a = ev.get("assessment") or {}
    return (REL_RANK[a.get("relation")], LEVEL_RANK[a.get("max_level")],
            -date.fromisoformat(ev["first_seen"]).toordinal(), ev["id"])


def _obs_key(ev: dict) -> tuple:
    return (parse_time(ev["last_seen_at"]), ev["observed_run_id"])


def _eval_key(a: dict | None) -> tuple | None:
    return None if a is None else (parse_time(a["evaluated_at"]), a["run_id"])


def prune(store: dict, as_of: datetime, days: int = WINDOW_DAYS) -> dict:
    """只保留收錄日期在窗口內的事件；未來日期的 first_seen 一併移除並記錄問題。不改 updated_at 與評估時間。"""
    start, end = window_bounds(as_of, days)
    out = copy.deepcopy(store)
    future = [k for k, ev in out["events"].items() if ev["first_seen"] > end]
    out["events"] = {k: ev for k, ev in out["events"].items() if start <= ev["first_seen"] <= end}
    issues = [i for i in out.get("data_issues") or []
              if i.get("code") != "future_first_seen" and (i.get("date") is None or start <= i["date"] <= end)]
    if future:
        issues.append(_issue("future_first_seen", f"{len(future)} 件事件的收錄日期晚於今天，已排除", len(future)))
    out["data_issues"] = issues
    return out


def _event_bytes(ev: dict, depth: int) -> int:
    """單一事件在檔案中約佔的位元組（含巢狀縮排）；只用來估算，最後仍以實際序列化大小確認。"""
    body = serialize(ev)
    return len(body) + depth * 2 * body.count(b"\n") + len(ev["id"].encode("utf-8")) + 8


def trim_events(events: dict, fits, *, per_day: int = PER_DAY_LIMIT, depth: int = 2) -> tuple[dict, int]:
    """先在扁平事件集合套用每個收錄日期 50 件，再依優先順序從最後面移除，直到 fits(events) 為真。

    回傳 (保留的事件, 省略數)。只在扁平集合裁切，不會因為父事件被裁而連帶刪除子事件。
    """
    by_day: dict[str, list[dict]] = defaultdict(list)
    for ev in events.values():
        by_day[ev["first_seen"]].append(ev)
    kept: list[dict] = []
    for day_events in by_day.values():
        kept += sorted(day_events, key=_rank)[:per_day]
    kept.sort(key=_rank)
    result = {ev["id"]: ev for ev in kept}
    if not fits(result):
        excess = len(serialize(result)) - MAX_BYTES
        while kept and excess > 0:                 # 先以估算移除，再逐件確認實際大小
            excess -= _event_bytes(kept.pop(), depth)
        result = {ev["id"]: ev for ev in kept}
        while kept and not fits(result):
            kept.pop()
            result = {ev["id"]: ev for ev in kept}
    return result, len(events) - len(result)


def store_issues(store: dict, seen: dict, as_of: datetime, days: int = WINDOW_DAYS) -> list[dict]:
    """容量省略數由去重紀錄推得：窗口內每個收錄日期「曾收錄」減「實際保留」，不需保存被省略事件的任何內容。"""
    start, end = window_bounds(as_of, days)
    seen_by_day: dict[str, int] = defaultdict(int)
    for d in seen["first_seen_by_key"].values():
        if start <= d <= end:
            seen_by_day[d] += 1
    kept_by_day: dict[str, int] = defaultdict(int)
    for ev in store["events"].values():
        kept_by_day[ev["first_seen"]] += 1
    issues = [i for i in store.get("data_issues") or [] if i.get("code") in ("future_first_seen", "merge_conflict")]
    for d in sorted(seen_by_day, reverse=True):
        n = seen_by_day[d] - kept_by_day.get(d, 0)
        if n > 0:
            issues.append(_issue("capacity", f"{d} 收錄的事件超過容量上限，省略 {n} 件", n, d))
    pending = sum(1 for ev in store["events"].values() if ev.get("assessment") is None)
    if pending:
        issues.append(_issue("pending_assessment", f"{pending} 件事件尚待完整評估，暫不列入整理", pending))
    if len(serialize(seen)) > SEEN_WARN_BYTES:
        issues.append(_issue("seen_size", "去重紀錄超過 1 MiB，需要檢查（不影響首次收錄日期）"))
    return issues


def finalize_store(store: dict, seen: dict, as_of: datetime, days: int = WINDOW_DAYS) -> tuple[dict, int, int]:
    """清理窗口 → 容量限制 → 重新計算資料狀態。回傳 (store, 到期移除數, 容量省略數)。不改 updated_at。"""
    before = len(store["events"])
    store = prune(store, as_of, days)
    removed = before - len(store["events"])

    def fits(events: dict) -> bool:
        trial = {**store, "events": events}
        return len(serialize({**trial, "data_issues": store_issues(trial, seen, as_of, days)})) <= MAX_BYTES

    events, omitted = trim_events(store["events"], fits)
    store["events"] = dict(sorted(events.items()))
    store["data_issues"] = store_issues(store, seen, as_of, days)
    return store, removed, omitted


def merge_store(prev: dict | None, seen: dict | None, report: dict, intel_reports: list[dict], as_of: datetime, *,
                complete: bool, asset_labels: dict[str, str], generated_at: datetime | None = None,
                run_id: str | None = None, stats: dict | None = None) -> tuple[dict, dict]:
    """把本次 daily 的比對報告併入累積資料（純函式，不寫檔）。回傳 (store, seen)。

    - 新 ID 先查 seen：曾收錄者沿用原 first_seen；已過期 ID 不重新加入；只有從未收錄者才以 as_of 的台灣日期新增去重鍵
    - 收錄資料（last_seen／last_seen_at／observed_run_id）每次觀察都更新
    - 評估快照只在 complete=True 且該份報告 complete=True 時整組替換；事件內容與快照一起更新，避免摘要與結論來自不同 run
    - 首次只有不完整評估的事件 assessment=None（待評估，不進 latest）
    """
    run_id = run_id or report["run_id"]
    generated_at = generated_at or as_of
    stats = stats if stats is not None else {}
    for k in ("new", "assessed", "observed_only", "expired_skipped", "removed", "omitted", "pending"):
        stats.setdefault(k, 0)
    today = taipei_date(as_of)
    start, _ = window_bounds(as_of)
    store = copy.deepcopy(prev) if prev else {"schema_version": 1, "updated_at": iso(generated_at), "data_issues": [], "events": {}}
    seen_map = dict((seen or {}).get("first_seen_by_key") or {})
    events = store["events"]
    for ev in events.values():                     # 去重紀錄先於清理與容量裁切產生
        k = seen_key(ev["id"])
        seen_map[k] = min(seen_map.get(k, ev["first_seen"]), ev["first_seen"])
    obs = {"last_seen": today, "last_seen_at": iso(as_of), "observed_run_id": run_id}
    this_key = (parse_time(iso(as_of)), run_id)
    for rep in intel_reports:
        if not eligible_report(rep):
            continue
        eid = rep["event"]["id"]
        key = seen_key(eid)
        full = complete and bool(rep.get("complete"))
        old = events.get(eid)
        if old is None:
            first = seen_map.get(key)
            if first is not None and first > today:    # 去重日期晚於今天（不合理）：改用今天，仍視為同一事件
                first = today
            if first is not None and first < start:
                stats["expired_skipped"] += 1          # 已過期：不重設收錄日期、不重新收錄
                continue
            first = first or today
            seen_map[key] = first
            a = assessment_from_report(rep, asset_labels, run_id=run_id, evaluated_at=iso(as_of)) if full else None
            events[eid] = {**event_content(rep), "first_seen": first, **obs, "assessment": a}
            stats["new"] += 1
            continue
        if this_key >= _obs_key(old):
            old.update(obs)
        prev_a = old.get("assessment")
        if full and (prev_a is None or this_key >= _eval_key(prev_a)):
            a = assessment_from_report(rep, asset_labels, run_id=run_id, evaluated_at=iso(as_of))
            if prev_a is not None:
                a["relation_changed_at"] = iso(as_of) if prev_a["relation"] != a["relation"] else prev_a.get("relation_changed_at")
            old.update({**event_content(rep), "assessment": a})
            stats["assessed"] += 1
        else:
            stats["observed_only"] += 1
    store["updated_at"] = iso(generated_at)
    seen_out = {"schema_version": 1, "first_seen_by_key": dict(sorted(seen_map.items()))}
    store, removed, omitted = finalize_store(store, seen_out, as_of)
    stats["removed"] += removed
    stats["omitted"] += omitted
    stats["pending"] = sum(1 for ev in store["events"].values() if ev.get("assessment") is None)
    return store, seen_out
