"""A3 依事件回溯搜查的紀錄篩選（specs/orchestrator R3.3；design §8 的 test_retro）：純函式，不呼叫 LLM。"""
import json
import random
from datetime import datetime, timedelta, timezone

import pytest

from tools import retro
from tools.common import TAIPEI

AS_OF = datetime(2026, 11, 9, 1, 0, tzinfo=timezone.utc)
DATE = "2026-11-05"                                   # 回溯期間：2026-10-29 00:00（台北）到 AS_OF
START = datetime(2026, 10, 29, tzinfo=TAIPEI)
BASE = {"default": 100, "accounts": {"svc-report": 2000}}
DAY = datetime(2026, 11, 3, 2, 0, tzinfo=timezone.utc)   # 台北 10:00（上班時間）


def z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def auth(i, t, *, system="internal-tool", account="ops-admin", ip="10.30.0.23", action="login", **kw):
    return {"id": f"auth-{i:04d}", "event_time": z(t), "system": system, "account": account, "ip": ip, "action": action, **kw}


def db(i, t, *, account="svc-report", ip="10.20.1.30", table="orders", rows=10):
    return {"id": f"dba-{i:04d}", "event_time": z(t), "account": account, "ip": ip, "table": table, "rows_read": rows}


def hunt(auth_rows=(), db_rows=(), systems=("internal-tool",), date=DATE):
    return retro.hunt({"auth.jsonl": list(auth_rows), "db-audit.jsonl": list(db_rows)}, systems=list(systems), event_date=date,
                      as_of=AS_OF, baselines=BASE)


def ids(result):
    return [r["id"] for r in result.records]


# ---------------------------------------------------------------- 時間窗
def test_window_is_event_day_taipei_midnight_minus_7_days_to_as_of():
    assert retro.retro_window(DATE, AS_OF) == (START, AS_OF)
    for bad in (None, "", "2026/11/05", "2026-13-01", 20261105):
        assert retro.retro_window(bad, AS_OF) is None
    rows = [auth(1, START - timedelta(seconds=1), action="password_reset"),          # 期間開始前一秒
            auth(2, START, action="password_reset"),                                 # 開始（含）
            auth(3, AS_OF, action="password_reset"),                                 # AS_OF（含）
            auth(4, AS_OF + timedelta(seconds=1), action="password_reset"),          # AS_OF 之後
            {**auth(5, DAY, action="password_reset"), "event_time": "not-a-time"}]   # 時間無效
    res = hunt(rows)
    assert ids(res) == ["auth-0002", "auth-0003"] and res.scanned == 2 and res.start == START and res.end == AS_OF


def test_invalid_event_date_or_no_systems_is_skipped_with_note():
    rows = [auth(1, DAY, action="password_reset")]
    res = hunt(rows, date="bad")
    assert res.empty and res.note == retro.NOTE_BAD_DATE and res.start is None
    res = hunt(rows, systems=())
    assert res.empty and res.note == retro.NOTE_NO_SYSTEMS


# ---------------------------------------------------------------- 系統篩選
def test_auth_by_system_and_db_audit_only_with_order_db_prod():
    rows = [auth(1, DAY, action="password_reset"), auth(2, DAY, system="admin-console", action="password_reset")]
    dbs = [db(1, DAY, ip="8.8.8.8")]
    res = hunt(rows, dbs, systems=["internal-tool"])
    assert ids(res) == ["auth-0001"] and res.scanned == 1
    res = hunt(rows, dbs, systems=["internal-tool", "order-db-prod"])
    assert ids(res) == ["auth-0001", "dba-0001"] and res.scanned == 2
    row = res.records[1]
    assert row["system"] == retro.DB_SYSTEM and row["table"] == "orders" and "action" not in row
    res = hunt(rows, dbs, systems=["admin-console"])
    assert ids(res) == ["auth-0002"]


# ---------------------------------------------------------------- 五種特徵
def test_login_failure_needs_login_action_and_a_non_success_result():
    rows = [auth(1, DAY, result="failure"),                                           # 標記
            auth(2, DAY + timedelta(minutes=1)),                                       # 沒有 result：不算失敗
            auth(3, DAY + timedelta(minutes=2), result=None),                          # result 為 null：不算
            auth(4, DAY + timedelta(minutes=3), result=""),                            # 空字串：不算
            auth(5, DAY + timedelta(minutes=4), result="success"),
            auth(6, DAY + timedelta(minutes=5), action="logout", result="failure"),    # 非 login：不算登入失敗
            auth(7, DAY + timedelta(minutes=6), action="password_reset")]
    res = hunt(rows)
    assert {r["id"]: r["flags"] for r in res.records} == {"auth-0001": ["login_failed"], "auth-0007": ["password_reset"]}
    assert res.scanned == 7 and res.flagged_total == 2


def test_external_ip_uses_ipaddress_and_ignores_unparsable():
    rows = [auth(1, DAY, ip="8.8.8.8"), auth(2, DAY, ip="10.0.0.5"), auth(3, DAY, ip="127.0.0.1"), auth(4, DAY, ip="169.254.1.1"),
            auth(5, DAY, ip="not-an-ip"), auth(6, DAY, ip="2001:4860:4860::8888"), auth(7, DAY, ip="fe80::1")]
    res = hunt(rows)
    assert ids(res) == ["auth-0001", "auth-0006"]
    assert all(r["flags"] == ["external_ip"] for r in res.records)
    assert retro.ip_kind("192.168.1.1") == "internal" and retro.ip_kind("bad") is None and retro.ip_kind(None) is None
    # RFC 1918、loopback、link-local、ULA 是內部；文件用網段（示範資料的外部攻擊 IP）與 CGNAT 算外部
    for ip in ("10.20.1.11", "172.16.5.4", "127.0.0.1", "169.254.1.1", "::1", "fd00::1", "fe80::1"):
        assert retro.ip_kind(ip) == "internal", ip
    for ip in ("198.51.100.77", "203.0.113.5", "192.0.2.1", "100.64.0.1", "8.8.8.8", "2001:db8::5"):
        assert retro.ip_kind(ip) == "external", ip


def test_off_hours_uses_taipei_clock():
    night = datetime(2026, 11, 3, 18, 30, tzinfo=timezone.utc)                         # 台北 02:30
    rows = [auth(1, night), auth(2, DAY), auth(3, datetime(2026, 11, 3, 22, 0, tzinfo=timezone.utc))]   # 台北 06:00 不算
    res = hunt(rows)
    assert ids(res) == ["auth-0001"] and res.records[0]["flags"] == ["off_hours"]
    assert set(retro.OFF_HOURS) == set(range(0, 6))


def test_bulk_read_sums_per_account_over_10_minutes_against_baseline():
    t0 = DAY
    rows = [db(1, t0 - timedelta(minutes=20), rows=9000),                              # 自己的視窗只有 9000：不標
            db(2, t0, rows=9000), db(3, t0 + timedelta(minutes=3), rows=9000),
            db(4, t0 + timedelta(minutes=6), rows=9000),                               # (t-10m, t] 累計 27000 > 2000×10：三筆都標
            db(5, t0, account="svc-x", rows=600), db(6, t0 + timedelta(minutes=11), account="svc-x", rows=500),   # 跨窗：不標
            db(7, t0, account="svc-y", rows=600), db(8, t0 + timedelta(minutes=9), account="svc-y", rows=500),    # default 100×10
            db(9, t0, account="svc-z", rows="oops")]                                   # rows_read 無效：當 0
    res = hunt(db_rows=rows, systems=["order-db-prod"])
    assert sorted(ids(res)) == ["dba-0002", "dba-0003", "dba-0004", "dba-0007", "dba-0008"]
    assert all(r["flags"] == ["bulk_read"] for r in res.records)


def test_flags_combine_in_fixed_order():
    night = datetime(2026, 11, 3, 18, 30, tzinfo=timezone.utc)
    res = hunt([auth(1, night, ip="8.8.8.8", result="denied")])
    assert res.records[0]["flags"] == ["login_failed", "external_ip", "off_hours"]
    assert list(retro.FLAGS) == ["login_failed", "password_reset", "external_ip", "off_hours", "bulk_read"]


# ---------------------------------------------------------------- 輸出：IP 代號、欄位白名單、上限
def test_ip_labels_are_stable_codes_and_raw_ips_never_leave():
    rows = [auth(1, DAY, ip="8.8.8.8", action="password_reset"),
            auth(2, DAY + timedelta(minutes=1), ip="10.0.0.5", action="password_reset"),
            auth(3, DAY + timedelta(minutes=2), ip="8.8.8.8", action="password_reset"),
            auth(4, DAY + timedelta(minutes=3), ip="bad-ip", action="password_reset"),
            auth(5, DAY + timedelta(minutes=4), ip=None, action="password_reset")]
    res = hunt(rows)
    assert [r["ip_label"] for r in res.records] == ["外部 IP #1", "內部 IP #2", "外部 IP #1", "無法辨識的 IP #3", None]
    shuffled = rows[:]
    random.Random(7).shuffle(shuffled)
    assert hunt(shuffled).records == res.records                                       # 與輸入順序無關
    text = json.dumps([res.to_json(), retro.task_payload("evt-x", res)], ensure_ascii=False)
    assert "8.8.8.8" not in text and "10.0.0.5" not in text and "bad-ip" not in text


def test_record_fields_are_whitelisted_and_unsafe_values_are_replaced():
    rows = [auth(1, DAY, account="alice@example.com", action="password_reset", note="secret", user_agent="x"),
            {**auth(2, DAY, action="password_reset"), "id": "../../etc/passwd"},
            auth(3, DAY, account="alice@example.com", action="password_reset")]
    res = hunt(rows)
    allowed = {"id", "time", "system", "account", "action", "table", "flags", "ip_label"}
    assert all(set(r) <= allowed for r in res.records)
    assert [r["account"] for r in res.records] == ["帳號 #1", "ops-admin", "帳號 #1"]
    assert res.records[1]["id"] == "紀錄 #2" and res.records[0]["time"] == "2026-11-03T02:00:00Z"
    text = json.dumps(res.to_json(), ensure_ascii=False)
    assert "alice@example.com" not in text and "passwd" not in text and "user_agent" not in text


def test_at_most_20_records_in_time_order():
    rows = [auth(i, DAY + timedelta(minutes=i), action="password_reset") for i in range(30, 0, -1)]
    res = hunt(rows)
    assert res.flagged_total == 30 and len(res.records) == retro.MAX_RECORDS == 20
    assert ids(res) == [f"auth-{i:04d}" for i in range(1, 21)]


def test_no_flagged_records_means_skip():
    res = hunt([auth(1, DAY, result="success"), auth(2, DAY, action="logout")])
    assert res.empty and res.flagged_total == 0 and res.scanned == 2 and res.note == retro.NOTE_NO_RECORDS
    res = hunt()
    assert res.empty and res.scanned == 0 and res.note == retro.NOTE_NO_RECORDS


def test_task_payload_has_no_window_or_as_of():
    res = hunt([auth(1, DAY, action="password_reset")])
    payload = retro.task_payload("demo-cache-plaintext", res)
    assert payload["ids"] == ["retro:demo-cache-plaintext"] and payload["flagged_total"] == 1
    text = json.dumps(payload, ensure_ascii=False)
    assert "2026-11-09" not in text and "2026-10-2" not in text and "start" not in payload


def test_baselines_default_from_rules_file():
    rows = [db(1, DAY, account="svc-report", rows=19000), db(2, DAY + timedelta(minutes=1), account="svc-report", rows=2000)]
    res = retro.hunt({"db-audit.jsonl": rows}, systems=["order-db-prod"], event_date=DATE, as_of=AS_OF)   # rules/baselines.json
    assert ids(res) == ["dba-0001", "dba-0002"]                                        # 21000 > svc-report 2000×10


@pytest.mark.parametrize("signals", [None, {}, {"auth.jsonl": None, "db-audit.jsonl": [None, "x", 3]}])
def test_missing_or_malformed_signals_do_not_crash(signals):
    res = retro.hunt(signals, systems=["internal-tool", "order-db-prod"], event_date=DATE, as_of=AS_OF, baselines=BASE)
    assert res.empty and res.note == retro.NOTE_NO_RECORDS
