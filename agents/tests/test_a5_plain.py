"""A5 的白話任務內容與採用條件（specs/plain-brief design §2.1、§3.2、§5.3）。"""
from types import SimpleNamespace

from agents import a5_report
from tools import digest
from tools.report_builder import public_labels
from tools.templates import DECISION_SEP, UNNAMED_SYSTEM
from tools.trace import Tracer, read_trace

SECRET = "DEMO-FAKE-PASSWORD-0000"


def test_public_labels_drop_names_with_path_ip_email(monkeypatch):
    """系統白話名稱（§2.3）：含路徑、IP、Email、機敏值的名稱不採用，名稱沒有被遮蔽後放入。"""
    monkeypatch.setattr(digest, "load_asset_label_file", lambda path=None: ({"svc-file": "檔案裡的名稱"}, []))
    services = [{"id": "svc-path", "name": "管理頁 /admin/login"}, {"id": "svc-ip", "name": "主機 10.0.0.5"},
                {"id": "svc-mail", "name": "聯絡 ops@example.com"}, {"id": "svc-key", "name": f"金鑰 {SECRET}"},
                {"id": "svc-port", "name": "管理介面 :8443"}, {"id": "svc-ok", "name": "商店網站"}]
    result = {"data": SimpleNamespace(services=services, vendors=[]), "graph": None}
    assert public_labels(result, nodes={}) == {"svc-ok": "商店網站", "svc-file": "檔案裡的名稱"}


def _risk(**over):
    base = {"id": "r1", "title": "原始技術標題", "level": "high", "breakdown": [], "category": "vuln", "status": "need_check",
            "asset_id": "svc-a", "attack_path": ["svc-a", "db-1"], "matched_events": ["evt-ok", "evt-mail", "evt-key", "evt-ip",
                                                                                      "evt-path", "evt.yaml", "evt-other"]}
    return {**base, **over}


EVENTS = [
    {"id": "evt-ok", "kind": "archive", "title": "91APP 訂單資料庫遭入侵", "demo": False, "brand": "91APP"},
    {"id": "evt-mail", "kind": "live", "title": "駭客寄信到 ops@example.com", "demo": False, "brand": None},
    {"id": "evt-key", "kind": "live", "title": f"外洩金鑰 {SECRET}", "demo": False, "brand": None},
    {"id": "evt-ip", "kind": "live", "title": "主機 10.0.0.5 遭入侵", "demo": False, "brand": None},
    {"id": "evt-path", "kind": "advisory", "title": "設定檔 /etc/app.conf 外洩", "demo": False, "brand": None},
    {"id": "evt.yaml", "kind": "demo", "title": "示範：檔名當 ID", "demo": True, "brand": None},
    {"id": "evt-other", "kind": "demo", "title": "示範：正常事件", "demo": True, "brand": None},
    {"id": "evt-unrelated", "kind": "archive", "title": "無關事件", "demo": False, "brand": None},
]


def test_remediation_item_only_public_names_and_titles():
    nodes = {"db-1": {"data_classes": ["order", "pii"]}}
    labels = {"svc-a": "商店網站", "db-1": "正式訂單資料庫"}
    item = a5_report._remediation_item(_risk(), nodes, labels, EVENTS)
    assert {k: item[k] for k in ("id", "title", "level", "breakdown", "category")} == \
        {"id": "r1", "title": "原始技術標題", "level": "high", "breakdown": [], "category": "vuln"}   # 既有欄位不變
    assert item["status"] == "need_check" and item["asset_name"] == "商店網站"
    assert item["path_names"] == ["商店網站", "正式訂單資料庫"] and item["may_reach"] == ["訂單資料", "會員個資"]
    assert [e["id"] for e in item["events"]] == ["evt-ok", "evt-other"]          # Email、金鑰、IP、路徑、檔名 ID 的事件整筆不放
    assert item["events"][0] == {"id": "evt-ok", "title": "91APP 訂單資料庫遭入侵", "kind": "archive", "demo": False,
                                 "brand": "91APP"}
    # 沒有白話名稱：ID 通過檢查才用，否則「未命名系統」；路徑長度 1 時 path_names 為空、may_reach 取資產本身
    bare = a5_report._remediation_item(_risk(asset_id="session.cookie_secure", attack_path=None), {}, {}, [])
    assert bare["asset_name"] == UNNAMED_SYSTEM and bare["path_names"] == [] and bare["may_reach"] == [] and bare["events"] == []
    plain = a5_report._remediation_item(_risk(asset_id="order-db-prod", attack_path=["order-db-prod"]),
                                        {"order-db-prod": {"data_classes": ["payment"]}}, {}, [])
    assert plain["asset_name"] == "order-db-prod" and plain["path_names"] == [] and plain["may_reach"] == ["金流資料"]


def test_adopt_solutions_cleans_ids_and_traces_counts(tmp_path):
    tr = Tracer(tmp_path / "t.jsonl", "a5")
    res = {"graph": SimpleNamespace(nodes=["internal-tool", "1shop", "order-db-prod"])}
    risks = [{"id": "r1", "asset_id": "internal-tool", "attack_path": None, "matched_events": ["evt-1shop"]},
             {"id": "r2", "asset_id": "order-db-prod", "attack_path": None, "matched_events": []}]
    out = [{"risk_id": "r1", "temporary": "a", "permanent": "b", "options": [], "verify": "c",
            "plain_title": "內部營運工具有漏洞", "if_ignored": "同業 1shop 就是這樣出事。", "plain_dropped": 1},
           {"risk_id": "r2", "temporary": "a", "permanent": "b", "options": [], "verify": "c",
            "plain_title": "訂單資料庫外洩", "if_ignored": "外人從 internal-tool 一路進來。"}]
    sol = {"output": out, "source": "replay"}
    got = a5_report._adopt_solutions(tr, sol, risks, res, [{"id": "evt-1shop", "brand": "1shop"}])
    assert got["r1"]["if_ignored"] == "同業 1shop 就是這樣出事。" and "plain_dropped" not in got["r1"]    # 品牌同名的 ID 不擋
    assert "if_ignored" not in got["r2"] and got["r2"]["plain_title"] == "訂單資料庫外洩" and got["r2"]["source"] == "replay"
    assert "plain_dropped" in out[0] and out[1]["if_ignored"] == "外人從 internal-tool 一路進來。"       # 傳入（快取）的物件不變
    details = [e["detail"] for e in read_trace(tmp_path / "t.jsonl")]
    assert "白話欄位 2 項未通過檢查，改用程式範本" in details


def test_ceo_problem_rules():
    facts = {"high": 14, "medium": 18, "low": 7, "chained": 5, "eol": 1, "shadow_it": 4, "checked": 7, "affected": 6,
             "real_checked": 6, "real_affected": 5}
    ok = {"ceo_summary": ["今天是紅燈：有 14 個高風險、18 個中風險。", "最急的是 5 個問題可以被串起來。",
                          "今天看了 7 件外面發生的資安事件，其中 6 件的問題我們也有。"],
          "decisions": [f"是否先把行銷官網暫時關掉？{DECISION_SEP}漏洞會一直開著。"]}
    assert a5_report._ceo_problem(ok, facts) is None
    swapped = {**ok, "ceo_summary": ["今天是紅燈：高風險 18 個與中風險 14 個。", *ok["ceo_summary"][1:]]}
    assert "18" in a5_report._ceo_problem(swapped, facts)                                    # 指標錯置
    wrong_metric = {**ok, "ceo_summary": ["今天有 18 個高風險。", *ok["ceo_summary"][1:]]}
    assert a5_report._ceo_problem(wrong_metric, facts)
    no_sep = {**ok, "decisions": ["是否先把行銷官網暫時關掉？"]}
    assert "不決定的話" in a5_report._ceo_problem(no_sep, facts)                              # 缺分隔字串
    two_sep = {**ok, "decisions": [f"要不要？{DECISION_SEP}a{DECISION_SEP}b"]}
    assert a5_report._ceo_problem(two_sep, facts)
    empty_side = {**ok, "decisions": [f"要不要？{DECISION_SEP} "]}
    assert a5_report._ceo_problem(empty_side, facts)
    assert a5_report._ceo_problem({**ok, "decisions": "不是陣列"}, facts)
    assert a5_report._ceo_problem({**ok, "decisions": []}, facts) is None                     # 沒有決策：照舊採用摘要
