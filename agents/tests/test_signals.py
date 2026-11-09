from datetime import datetime, timezone

from tools.signals import evaluate

AS_OF = datetime(2026, 11, 9, 1, 0, tzinfo=timezone.utc)
BASE = {"default": 100, "accounts": {"svc-report": 2000}}


def _c(i, brand, text, t="2026-11-08T22:00:00Z"):
    return {"id": f"c-{i}", "received_at": t, "brand_id": brand, "channel": "客服信箱", "text": text}


def test_baseline_signals_are_quiet(target_data):
    assert evaluate(target_data.signals, AS_OF, BASE) == []


def test_three_brands_fraud_with_order_info_is_red():
    complaints = [_c(1, "brand-a", "收到詐騙電話，對方說出訂單編號：SO-20261108-001"),
                  _c(2, "brand-b", "簡訊提到訂單號碼:AB12345678"),
                  _c(3, "brand-c", "the caller knew my order no. ZX99887766")]
    sig = evaluate({"complaints.csv": complaints}, AS_OF, BASE)
    assert sig and sig[0]["light"] == "red" and sig[0]["suspected_breach"]


def test_two_brands_or_no_order_info_not_red():
    two = [_c(1, "brand-a", "訂單編號：SO-20261108-001"), _c(2, "brand-b", "訂單編號：SO-20261108-002")]
    assert evaluate({"complaints.csv": two}, AS_OF, BASE) == []
    plain = [_c(i, f"brand-{i}", "客服態度不好") for i in range(3)]
    assert evaluate({"complaints.csv": plain}, AS_OF, BASE) == []


def test_bulk_read_over_ten_times_baseline():
    events = [{"id": f"d{i}", "event_time": f"2026-11-08T18:0{i}:00Z", "account": "svc-x", "ip": "10.1.1.1",
               "table": "orders", "rows_read": 400} for i in range(3)]
    sig = evaluate({"db-audit.jsonl": events}, AS_OF, BASE)
    assert any(s["id"] == "SIG-BULK-READ:svc-x" for s in sig)


def test_reset_then_new_ip_login_is_medium():
    auth = [{"id": "a1", "event_time": "2026-11-08T10:00:00Z", "system": "internal-tool", "account": "ops", "ip": "10.0.0.1", "action": "login"},
            {"id": "a2", "event_time": "2026-11-08T11:00:00Z", "system": "internal-tool", "account": "ops", "ip": "10.0.0.1", "action": "password_reset"},
            {"id": "a3", "event_time": "2026-11-08T11:05:00Z", "system": "internal-tool", "account": "ops", "ip": "203.0.113.9", "action": "login"}]
    sig = evaluate({"auth.jsonl": auth}, AS_OF, BASE)
    assert sig and sig[0]["level"] == "medium"
