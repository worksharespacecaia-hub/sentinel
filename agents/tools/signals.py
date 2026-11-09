"""A3 早期訊號規則（純程式）。時間一律以事件本身的時間戳判斷（Asia/Taipei），不用伺服器時間。"""
from __future__ import annotations

import re
from datetime import datetime, timedelta

from tools.common import RULES_DIR, TAIPEI, parse_time, read_json

ORDER_INFO_RE = re.compile(r"(訂單編號|訂單號碼|order\s*(no\.?|#)?)\s*[:：#]?\s*[A-Z0-9-]{8,}", re.I)
OFF_HOURS = range(0, 6)


def load_baselines() -> dict:
    data = read_json(RULES_DIR / "baselines.json", {"default": 100, "accounts": {}})
    if data.get("default", 0) <= 0:
        raise ValueError("baselines.json 的 default 必須 > 0")
    return data


def fraud_complaints(complaints: list[dict], as_of: datetime) -> list[dict]:
    window_start = as_of - timedelta(hours=24)
    hits = [c for c in complaints if ORDER_INFO_RE.search(c.get("text", ""))
            and (t := parse_time(c.get("received_at"))) is not None and window_start < t <= as_of]
    brands = sorted({c["brand_id"] for c in hits})
    if len(brands) >= 3:
        return [{"id": "SIG-FRAUD-MULTI-BRAND", "rule": "24 小時內 ≥3 個品牌回報含真實訂單資訊的詐騙", "level": "high",
                 "light": "red", "assets": ["platform"], "summary": f"{len(brands)} 個品牌回報疑似外洩詐騙",
                 "evidence": [f"complaints.csv: {c['id']}（{c['brand_id']}）" for c in hits], "related_event": "evt-91app-2026-10",
                 "suspected_breach": True}]
    return []


def bulk_reads(db_audit: list[dict], baselines: dict, known_ips: dict[str, set[str]] | None = None) -> list[dict]:
    out = []
    known_ips = known_ips or {}
    per_account: dict[str, list[dict]] = {}
    for e in db_audit:
        per_account.setdefault(e["account"], []).append(e)
    for account, events in per_account.items():
        base = baselines.get("accounts", {}).get(account, baselines["default"])
        events.sort(key=lambda e: e["event_time"])
        for e in events:
            t = parse_time(e["event_time"])
            window = [x for x in events if t - timedelta(minutes=10) < parse_time(x["event_time"]) <= t]
            total = sum(int(x.get("rows_read") or 0) for x in window)
            if total > 10 * base:
                out.append({"id": f"SIG-BULK-READ:{account}", "rule": "單一帳號讀取量超過平日 10 倍", "level": "high",
                            "light": None, "assets": ["order-db-prod"], "summary": f"{account} 10 分鐘讀取 {total} 列（基準 {base}）",
                            "evidence": [f"db-audit.jsonl: {x['id']}" for x in window]})
                break
    first_seen: dict[tuple[str, str], datetime] = {}
    for e in sorted(db_audit, key=lambda e: e["event_time"]):
        first_seen.setdefault((e["account"], e["ip"]), parse_time(e["event_time"]))
    for e in db_audit:
        t = parse_time(e["event_time"])
        local = t.astimezone(TAIPEI)
        is_new = e["ip"] not in known_ips.get(e["account"], set()) and first_seen[(e["account"], e["ip"])] >= t - timedelta(minutes=10)
        if e.get("table") == "orders" and local.hour in OFF_HOURS and is_new and known_ips:
            out.append({"id": f"SIG-OFFHOURS-NEWIP:{e['account']}", "rule": "非上班時間、新來源 IP 讀取訂單資料", "level": "high",
                        "light": None, "assets": ["order-db-prod"], "summary": f"{e['account']} 在 {local:%H:%M} 從新 IP 讀取訂單",
                        "evidence": [f"db-audit.jsonl: {e['id']}"]})
            break
    return out


def reset_then_new_ip(auth: list[dict]) -> list[dict]:
    out = []
    events = sorted(auth, key=lambda e: e["event_time"])
    for i, e in enumerate(events):
        if e.get("action") != "password_reset":
            continue
        seen_ips = {x["ip"] for x in events[:i] if x["account"] == e["account"]}
        for later in events[i + 1:]:
            if later["account"] == e["account"] and later.get("action") == "login" and later["ip"] not in seen_ips \
                    and parse_time(later["event_time"]) - parse_time(e["event_time"]) <= timedelta(minutes=30):
                out.append({"id": f"SIG-RESET-NEWIP:{e['account']}", "rule": "內部工具密碼重設後立即從新 IP 登入", "level": "medium",
                            "light": None, "assets": [e.get("system", "internal-tool")],
                            "summary": f"{e['account']} 重設密碼後從新 IP 登入", "evidence": [f"auth.jsonl: {e['id']}", f"auth.jsonl: {later['id']}"]})
                break
    return out


def evaluate(signals_data: dict, as_of: datetime, baselines: dict | None = None) -> list[dict]:
    baselines = baselines or load_baselines()
    complaints = signals_data.get("complaints.csv") or []
    audit = signals_data.get("db-audit.jsonl") or []
    auth = signals_data.get("auth.jsonl") or []
    # 已知 IP：觀察期間之前（as_of 前 24 小時以前）出現過的 (account, ip)
    cutoff = as_of - timedelta(hours=24)
    known: dict[str, set[str]] = {}
    for e in audit:
        if parse_time(e["event_time"]) <= cutoff:
            known.setdefault(e["account"], set()).add(e["ip"])
    recent = [e for e in audit if cutoff < parse_time(e["event_time"]) <= as_of]
    return [*fraud_complaints(complaints, as_of), *bulk_reads(recent, baselines, known), *reset_then_new_ip(auth)]
