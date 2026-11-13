"""A3 依事件回溯搜查的紀錄篩選（specs/orchestrator R3.3；design §3.4、§4）。純程式，不呼叫 LLM、不連網路。

- 系統：由政策上下文決定（orchestration.a3_systems：受影響或需確認＋破口推測的系統，只取 ai_assets，最多 5 個）；
  這裡只依系統篩紀錄
- 資料：auth.jsonl 中 system 屬於所選系統的紀錄；所選系統含 order-db-prod 時加上 db-audit.jsonl（沿用 signals.py 的對應：
  db-audit.jsonl 的訊號都歸在 order-db-prod）
- 期間：事件日期（Asia/Taipei 00:00）前 7 天，到 AS_OF（含）
- 特徵（程式標記）：
  - 登入失敗：只看 action=="login"，而且 result 存在、不是 success；沒有 result 的不標記
  - 重設密碼：action=="password_reset"
  - 外部 IP：ipaddress 判斷不是私有、loopback、link-local 的位址；無法解析的不標記
  - 非上班時間：沿用 signals.OFF_HOURS 與台北時區
  - 大量讀取：沿用 signals.bulk_reads 的規則。同一帳號 10 分鐘內累計 rows_read 超過該帳號基準
    （rules/baselines.json 的 accounts，沒有時用 default）的 10 倍時，該視窗內每一筆都標記
- 只輸出有特徵的紀錄（依時間排序，最多 20 筆）；欄位只有 id、time、system、account、action 或 table、flags、ip_label
- IP 一律換成穩定代號（「外部 IP #1」「內部 IP #2」），不輸出原始 IP

A3 的用法（agents/a3_signals.run_retro_tasks）：對核准的 (a3, retro-hunter, event_id)，用 resolve_plans 的評估結果 res["data"].signals、
政策上下文的 a3[event_id] 與事件日期呼叫 hunt()；result.empty 時不建立任務並記錄 result.note。
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from tools.common import TAIPEI, iso, parse_time
from tools.signals import OFF_HOURS, load_baselines

WINDOW_DAYS = 7
MAX_RECORDS = 20
DB_SYSTEM = "order-db-prod"                    # signals.bulk_reads 把 db-audit.jsonl 的訊號歸在這個資產
AUTH_FILE, DB_FILE = "auth.jsonl", "db-audit.jsonl"
BULK_WINDOW = timedelta(minutes=10)
BULK_FACTOR = 10
# 特徵代碼 → 白話（輸出順序固定）
FLAGS = {"login_failed": "登入失敗", "password_reset": "重設密碼", "external_ip": "外部 IP", "off_hours": "非上班時間",
         "bulk_read": "大量讀取"}
NOTE_NO_RECORDS = "回溯期間沒有符合特徵的紀錄"
NOTE_BAD_DATE = "事件日期無效，無法決定回溯期間"
NOTE_NO_SYSTEMS = "沒有可回溯的系統"
IP_LABELS = {"external": "外部 IP", "internal": "內部 IP", "unknown": "無法辨識的 IP"}

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
RECORD_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
WORD_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,39}$")


@dataclass
class RetroResult:
    """一件事件的回溯結果。records 最多 20 筆；flagged_total 是截斷前有特徵的紀錄數。"""
    systems: list[str]
    start: datetime | None                       # 期間開始（事件日期台北 00:00 前 7 天）；事件日期無效時為 None
    end: datetime                                # AS_OF
    scanned: int = 0                             # 期間內、所選系統的紀錄數
    flagged_total: int = 0
    records: list[dict] = field(default_factory=list)
    note: str | None = None

    @property
    def empty(self) -> bool:
        return not self.records

    def to_json(self) -> dict:
        """內部紀錄用（含期間）；交給 AI 的內容用 task_payload，不放 AS_OF。"""
        return {"systems": list(self.systems), "start": iso(self.start) if self.start else None, "end": iso(self.end),
                "scanned": self.scanned, "flagged_total": self.flagged_total, "records": [dict(r) for r in self.records],
                "note": self.note}


def retro_window(event_date, as_of: datetime) -> tuple[datetime, datetime] | None:
    """回溯期間：事件日期（Asia/Taipei 00:00）前 7 天到 AS_OF。日期無效回傳 None。"""
    if not isinstance(event_date, str) or not DATE_RE.match(event_date):
        return None
    try:
        d = date.fromisoformat(event_date)
    except ValueError:
        return None
    return datetime(d.year, d.month, d.day, tzinfo=TAIPEI) - timedelta(days=WINDOW_DAYS), as_of


# 內部位址＝RFC 1918 私有網段、IPv6 ULA、loopback、link-local（R3.3）。不用 ipaddress.is_private：
# 它把文件用網段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24）也算私有，示範資料的外部攻擊 IP 會被誤判成內部。
INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


def ip_kind(value) -> str | None:
    """external／internal；無法解析回傳 None（不標記外部 IP）。"""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if addr.is_loopback or addr.is_link_local or any(addr.version == n.version and addr in n for n in INTERNAL_NETS):
        return "internal"
    return "external"


def _time(value) -> datetime | None:
    try:
        return parse_time(value)
    except (ValueError, TypeError):
        return None


def _rows(value) -> int:
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _base_of(account, baselines: dict) -> float:
    accounts = baselines.get("accounts") if isinstance(baselines.get("accounts"), dict) else {}
    base = accounts.get(account, baselines.get("default"))
    try:
        return float(base)
    except (TypeError, ValueError):
        return float(baselines.get("default") or 100)


def _bulk_flags(db_rows: list[tuple[datetime, dict]], baselines: dict) -> set[int]:
    """沿用 signals.bulk_reads：同一帳號 10 分鐘內（(t-10m, t]）累計 rows_read 超過基準 10 倍時，該視窗內每一筆都標記。"""
    flagged: set[int] = set()
    per_account: dict = {}
    for i, (t, rec) in enumerate(db_rows):
        per_account.setdefault(rec.get("account"), []).append((t, i, _rows(rec.get("rows_read"))))
    for account, items in per_account.items():
        items.sort()
        limit = BULK_FACTOR * _base_of(account, baselines)
        for t, _, _ in items:
            window = [(x, i, n) for x, i, n in items if t - BULK_WINDOW < x <= t]
            if sum(n for _, _, n in window) > limit:
                flagged |= {i for _, i, _ in window}
    return flagged


def hunt(signals: dict | None, *, systems, event_date, as_of: datetime, baselines: dict | None = None) -> RetroResult:
    """依 R3.3 篩出有特徵的紀錄。signals 為 TargetData.signals（{"auth.jsonl": [...], "db-audit.jsonl": [...]}，已含情境覆寫）。"""
    systems = sorted({s for s in systems or [] if isinstance(s, str) and s})
    win = retro_window(event_date, as_of)
    result = RetroResult(systems=systems, start=win[0] if win else None, end=as_of)
    if not systems:
        result.note = NOTE_NO_SYSTEMS
        return result
    if win is None:
        result.note = NOTE_BAD_DATE
        return result
    start, end = win
    baselines = baselines if baselines is not None else load_baselines()
    signals = signals or {}
    picked: list[tuple[datetime, int, str, dict]] = []          # (時間, 原始順序, 來源檔, 紀錄)
    wanted = set(systems)
    for n, rec in enumerate(signals.get(AUTH_FILE) or []):
        t = _time(rec.get("event_time")) if isinstance(rec, dict) else None
        if t is not None and start <= t <= end and rec.get("system") in wanted:
            picked.append((t, n, AUTH_FILE, rec))
    if DB_SYSTEM in wanted:
        for n, rec in enumerate(signals.get(DB_FILE) or []):
            t = _time(rec.get("event_time")) if isinstance(rec, dict) else None
            if t is not None and start <= t <= end:
                picked.append((t, n, DB_FILE, rec))
    picked.sort(key=lambda x: (x[0], x[2], x[1]))
    result.scanned = len(picked)
    db_rows = [(t, rec) for t, _, src, rec in picked if src == DB_FILE]
    bulk = _bulk_flags(db_rows, baselines)
    db_index = 0
    flagged: list[tuple[datetime, str, dict, list[str]]] = []
    for t, _, src, rec in picked:
        flags = set()
        if src == AUTH_FILE:
            action = rec.get("action")
            result_value = rec.get("result")
            if action == "login" and isinstance(result_value, str) and result_value.strip() and result_value != "success":
                flags.add("login_failed")
            if action == "password_reset":
                flags.add("password_reset")
        else:
            if db_index in bulk:
                flags.add("bulk_read")
            db_index += 1
        if ip_kind(rec.get("ip")) == "external":
            flags.add("external_ip")
        if t.astimezone(TAIPEI).hour in OFF_HOURS:
            flags.add("off_hours")
        if flags:
            flagged.append((t, src, rec, [f for f in FLAGS if f in flags]))
    result.flagged_total = len(flagged)
    result.records = _project(flagged[:MAX_RECORDS])
    if not result.records:
        result.note = NOTE_NO_RECORDS
    return result


def _project(rows: list[tuple[datetime, str, dict, list[str]]]) -> list[dict]:
    """只放白名單欄位；IP 換成穩定代號（依輸出順序編號，同一個 IP 同一個代號）；不合格的 ID、帳號改用代號。"""
    ip_labels: dict[str, str] = {}
    accounts: dict[str, str] = {}
    out = []
    for n, (t, src, rec, flags) in enumerate(rows, start=1):
        rid = rec.get("id")
        row = {"id": rid if isinstance(rid, str) and RECORD_ID_RE.match(rid) else f"紀錄 #{n}", "time": iso(t),
               "system": rec.get("system") if src == AUTH_FILE else DB_SYSTEM}
        account = rec.get("account")
        key = account if isinstance(account, str) else repr(account)
        if not (isinstance(account, str) and ACCOUNT_RE.match(account) and not _sensitive(account)):
            account = accounts.setdefault(key, f"帳號 #{len(accounts) + 1}")
        row["account"] = account
        word = rec.get("action") if src == AUTH_FILE else rec.get("table")
        row["action" if src == AUTH_FILE else "table"] = word if isinstance(word, str) and WORD_RE.match(word) else None
        row["flags"] = flags
        ip = rec.get("ip")
        if isinstance(ip, str) and ip.strip():
            ip = ip.strip()
            if ip not in ip_labels:
                ip_labels[ip] = f"{IP_LABELS[ip_kind(ip) or 'unknown']} #{len(ip_labels) + 1}"
            row["ip_label"] = ip_labels[ip]
        else:
            row["ip_label"] = None
        out.append(row)
    return out


def _sensitive(text: str) -> bool:
    from tools.digest import has_sensitive   # 延遲匯入：digest 會匯入 llm
    return has_sensitive(text)


def task_payload(event_id: str, result: RetroResult) -> dict:
    """retro-hunter 任務的 payload 建議格式（A3 的 retro:<event_id> 任務使用）：只放系統、計數與白名單紀錄，不放期間與 AS_OF。"""
    return {"ids": [f"retro:{event_id}"], "event_id": event_id, "systems": list(result.systems),
            "flagged_total": result.flagged_total, "flags": dict(FLAGS), "records": [dict(r) for r in result.records]}
