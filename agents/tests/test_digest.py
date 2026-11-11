"""資安事件整理（specs/security-digest）：模型、來源映射、網址與去敏、合併、清理、產生與 A5 提交。全部使用凍結時間。"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from schemas import DigestAssessment, DigestEvent, DigestLatest, DigestSeen, DigestStore, IntelMatchReport
from tools import digest as dg

RUN = "run-1"


def _impact(eid, asset, verdict, risk_id=None):
    return {"event_id": eid, "asset_id": asset, "basis": "control", "our_state": f"{asset}: network.json", "verdict": verdict,
            "risk_id": risk_id, "to_verify": [], "reason": ""}


def make_report(eid="live-ithome-2026-11-10-a", *, kind="live", status="need_check", impacts=None, levels=None,
                complete=True, title="某電商遭入侵", date="2026-11-09", summary="攻擊者利用外掛漏洞取得後台權限。",
                is_update_of=None, demo=False, conclusion=None, sources=None, max_level=None, affected_count=None):
    """組一份通過 IntelMatchReport 驗證的比對報告；levels 依 (asset_id, verdict) 放進 blocks（StackImpact 沒有 level）。"""
    impacts = impacts if impacts is not None else [_impact(eid, "storefront", "need_check")]
    levels = levels or {}
    rows = [{"asset_id": i["asset_id"], "verdict": i["verdict"], "level": levels.get((i["asset_id"], i["verdict"]))}
            for i in impacts if i["verdict"] in ("affected", "need_check")]
    affected = [i for i in impacts if i["verdict"] == "affected"]
    rep = {
        "event": {"id": eid, "kind": kind, "is_update_of": is_update_of, "title": title, "date": date, "revision": "1",
                  "confidence": "provisional", "cves": ["CVE-2026-1234", "not-a-cve"], "demo": demo,
                  "sources": sources if sources is not None else [
                      {"url": "https://www.ithome.com.tw/news/1?utm_source=rss", "title": "iThome 報導", "quote": "原文引用",
                       "published": None, "verified": True, "fetch_status": "ok", "verification_basis": "live"}]},
        "conclusion": conclusion or f"沒有確定受影響的項目，但有 {len(impacts)} 項需要人工確認。",
        "affected_count": len(affected) if affected_count is None else affected_count,
        "max_level": max_level, "impacts": impacts, "solutions": [], "notice": None, "status": status,
        "evaluated_asset_ids": sorted({i["asset_id"] for i in impacts}), "complete": complete, "summary_source": "template",
        "summary": summary,
        "blocks": {"3_affected": [r for r in rows if r["verdict"] == "affected"],
                   "4_unaffected_and_check": {"not_affected": [], "need_check": [r for r in rows if r["verdict"] == "need_check"],
                                              "notes": []}},
    }
    IntelMatchReport.model_validate(rep)
    return rep


# ── T1：資料模型、來源映射、網址與去敏 ──────────────────────────────────────────

def test_models_separate_observation_assessment_and_generation_times():
    content = dg.event_content(make_report())
    ev = {**content, "first_seen": "2026-11-10", "last_seen": "2026-11-11", "last_seen_at": "2026-11-11T00:00:00Z",
          "observed_run_id": "run-obs", "assessment": None}
    DigestEvent.model_validate(ev)                                    # 只有收錄紀錄：assessment 可為 null
    a = dg.assessment_from_report(make_report(), {}, run_id="run-eval", evaluated_at="2026-11-10T00:00:00Z")
    full = DigestEvent.model_validate({**ev, "assessment": a})
    assert full.observed_run_id == "run-obs" and full.assessment.run_id == "run-eval"
    assert full.last_seen_at != full.assessment.evaluated_at
    store = DigestStore.model_validate({"updated_at": "2026-11-11T00:20:00Z", "events": {ev["id"]: ev}})
    assert store.updated_at == "2026-11-11T00:20:00Z"
    with pytest.raises(ValidationError):                              # 時間必須是完整 UTC，不接受只有日期
        DigestEvent.model_validate({**ev, "last_seen_at": "2026-11-11"})
    with pytest.raises(ValidationError):
        DigestStore.model_validate({"updated_at": "2026-11-11T00:20:00Z", "events": {"other": ev}})
    with pytest.raises(ValidationError):                              # demo 不是可收錄的類型
        DigestEvent.model_validate({**ev, "kind": "demo"})


def test_seen_only_accepts_hash_and_date():
    DigestSeen.model_validate({"first_seen_by_key": {dg.seen_key("evt-a"): "2026-11-11"}})
    with pytest.raises(ValidationError):
        DigestSeen.model_validate({"first_seen_by_key": {"evt-a": "2026-11-11"}})       # 不能存原始 ID
    with pytest.raises(ValidationError):
        DigestSeen.model_validate({"first_seen_by_key": {dg.seen_key("evt-a"): "標題"}})
    with pytest.raises(ValidationError):
        DigestSeen.model_validate({"first_seen_by_key": {}, "titles": {}})


def test_event_content_maps_validated_fields_only():
    rep = make_report(summary="摘要" * 400, date="")
    c = dg.event_content(rep)
    assert c["event_date"] is None                                    # 缺少事件日期 → 網站顯示「未提供」
    assert len(c["summary"]) == 300 and c["summary"].endswith("…")    # 摘要截斷到 300 字
    assert c["cves"] == ["CVE-2026-1234"]
    assert c["sources"] == [{"title": "iThome 報導", "domain": "www.ithome.com.tw",
                             "url": "https://www.ithome.com.tw/news/1?utm_source=rss", "verified": True}]
    assert "quote" not in json.dumps(c, ensure_ascii=False)           # 不存原文引用


@pytest.mark.parametrize("url,expected", [
    ("https://www.ithome.com.tw/news/180209", "https://www.ithome.com.tw/news/180209"),
    ("http://example.com/a", "http://example.com/a"),
    ("HTTPS://Example.COM/a#section", "https://example.com/a"),                 # fragment 一律移除
    ("javascript:alert(1)", None),
    ("data:text/html,<script>", None),
    ("ftp://example.com/a", None),
    ("//example.com/a", None),
    ("https://user:pw@example.com/a", None),                                     # userinfo
    ("https://user@example.com/a", None),
    ("https://example.com/a?token=abc123&id=7", "https://example.com/a?id=7"),   # 移除敏感參數
    ("https://example.com/a?api_key=x&utm_source=rss", "https://example.com/a?utm_source=rss"),
    ("https://example.com/a?X-Amz-Signature=abc&email=a%40b.com", "https://example.com/a"),
    ("https://example.com/a?q=someone%40example.com", None),                     # 個資值無法安全清理
    ("https://example.com/u/someone@example.com", None),
    ("https://example.com/a?q=ghp_abcdefghijklmnopqrstuvwxyz", None),           # 金鑰值
    ("https://example.com/a b", None),
    ("https://exa mple.com/", None),
    (None, None),
    (123, None),
])
def test_safe_url(url, expected):
    assert dg.safe_url(url) == expected


def test_source_keeps_domain_when_url_unsafe():
    srcs = dg.public_sources([{"url": "https://user:pw@news.example.com/a", "title": "報導", "verified": False},
                              {"url": "javascript:alert(1)", "title": "", "verified": True},
                              {"url": None, "title": "ghp_abcdefghijklmnopqrstuvwxyz 外洩", "verified": False}])
    assert srcs[0] == {"title": "報導", "domain": "news.example.com", "url": None, "verified": False}
    assert srcs[1] == {"title": "未命名來源", "domain": None, "url": None, "verified": True}
    assert "ghp_" not in srcs[2]["title"] and dg.REDACTED in srcs[2]["title"]


@pytest.mark.parametrize("raw", [
    "DEMO-FAKE-ABCD-1234", "sk-ant-abcdefghijklmnop", "ghp_abcdefghijklmnopqrstuvwxyz", "password=hunter2hunter2",
    "-----BEGIN RSA PRIVATE KEY-----", "AKIAABCDEFGHIJKLMNOP", "xoxb-1234567890-abcdef", "Bearer abcdefghijklmnopqrstuvwxyz",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop", "someone@example.com", "0912-345-678", "A123456789",
    "4111 1111 1111 1111",
])
def test_public_text_redacts_secrets_and_pii(raw):
    out = dg.public_text(f"事件說明 {raw} 結束", 300)
    assert raw not in out and dg.REDACTED in out and out.startswith("事件說明")
    assert dg.has_sensitive(raw)


def test_public_text_keeps_cves_and_dates():
    text = "CVE-2026-109618 於 2026-11-10 公告，影響 Next.js 15。"
    assert dg.public_text(text, 300) == text and not dg.has_sensitive(text)


def test_impact_levels_come_from_blocks_not_stack_impact():
    eid = "evt-x-2026-11"
    impacts = [_impact(eid, "member-api", "need_check"), _impact(eid, "storefront", "affected", "storefront:x"),
               _impact(eid, "storefront", "affected", "storefront:y"), _impact(eid, "gitlab", "not_affected"),
               _impact(eid, "*", "need_check")]
    rep = make_report(eid, status="open", impacts=impacts, max_level="high",
                      levels={("storefront", "affected"): "high", ("member-api", "need_check"): None})
    # 同一資產同一結論有兩列時依序對應：第二列在 blocks 裡改成 medium
    rep["blocks"]["3_affected"][1]["level"] = "medium"
    assert all("level" not in i for i in rep["impacts"])
    a = dg.assessment_from_report(rep, {"storefront": "商店網站"}, run_id=RUN, evaluated_at="2026-11-10T00:00:00Z")
    assert [(i["asset_id"], i["verdict"], i["level"]) for i in a["impacts"]] == [
        ("storefront", "affected", "high"), ("storefront", "affected", "medium"),
        ("*", "need_check", None), ("member-api", "need_check", None), ("gitlab", "not_affected", None)]
    labels = [i["asset_label"] for i in a["impacts"]]
    assert labels == ["商店網站", "商店網站", "待確認系統", "未命名系統", "未命名系統"]       # 不回退顯示 ID
    assert a["relation"] == "affected" and a["max_level"] == "high" and a["affected_count"] == 2
    DigestAssessment.model_validate(a)


def test_impacts_truncated_to_20_keep_original_totals():
    eid = "evt-big-2026-11"
    impacts = [_impact(eid, f"svc-{n:02d}", "not_affected") for n in range(15)] + \
              [_impact(eid, f"app-{n:02d}", "need_check") for n in range(8)] + \
              [_impact(eid, f"db-{n:02d}", "affected", f"db-{n:02d}:r") for n in range(3)]
    rep = make_report(eid, status="open", impacts=impacts, max_level="medium", affected_count=3,
                      levels={(f"db-{n:02d}", "affected"): "medium" for n in range(3)})
    a = dg.assessment_from_report(rep, {}, run_id=RUN, evaluated_at="2026-11-10T00:00:00Z")
    assert len(a["impacts"]) == 20 and a["impacts_total"] == 26 and a["impacts_truncated"] is True
    assert [i["verdict"] for i in a["impacts"][:11]] == ["affected"] * 3 + ["need_check"] * 8   # 優先列出受影響與需確認
    assert a["affected_count"] == 3 and a["max_level"] == "medium"                             # 不由截斷結果重算
    DigestAssessment.model_validate(a)
    with pytest.raises(ValidationError):
        DigestAssessment.model_validate({**a, "impacts_truncated": False})


@pytest.mark.parametrize("status,relation", [("open", "affected"), ("need_check", "need_check"),
                                             ("not_affected", "not_affected"), ("fixed", "fixed")])
def test_relation_mapping(status, relation):
    eid = "evt-r-2026-11"
    impacts = [_impact(eid, "storefront", "affected", "r")] if status in ("open", "fixed") else \
        [_impact(eid, "storefront", status if status != "fixed" else "affected")]
    rep = make_report(eid, status=status, impacts=impacts)
    assert dg.assessment_from_report(rep, {}, run_id=RUN, evaluated_at="2026-11-10T00:00:00Z")["relation"] == relation


def test_asset_labels_only_from_public_names():
    labels = dg.public_asset_labels(
        services=[{"id": "storefront", "name": "商店網站"}, {"id": "member-api"}, {"id": "same", "name": "same"}],
        vendors=[{"id": "slack", "name": "Slack"}, {"id": "leak", "name": "寄信 someone@example.com"}],
        graph_nodes={"saas-notion": {"display_name": "Notion"}, "gitlab": {"type": "service"}})
    assert labels == {"storefront": "商店網站", "slack": "Slack", "saas-notion": "Notion"}
    assert dg.asset_label("member-api", labels) == dg.UNNAMED_ASSET
    assert dg.asset_label("*", labels) == dg.PENDING_ASSET


def _write_labels(tmp_path, value, raw=None):
    p = tmp_path / "asset-labels.json"
    p.write_text(raw if raw is not None else json.dumps(value, ensure_ascii=False), encoding="utf-8")
    return p


def test_label_file_precedence_inventory_then_graph_then_file():
    file_labels = {"storefront": "檔案名稱", "saas-x": "檔案名稱 X", "member-api": "會員服務 API"}
    labels = dg.public_asset_labels(services=[{"id": "storefront", "name": "清冊名稱"}],
                                    graph_nodes={"saas-x": {"display_name": "圖譜名稱"}}, file_labels=file_labels)
    assert labels == {"storefront": "清冊名稱", "saas-x": "圖譜名稱", "member-api": "會員服務 API"}
    assert dg.asset_label("not-listed-svc", labels) == dg.UNNAMED_ASSET            # 未列入仍顯示「未命名系統」


def test_label_file_loading_and_invalid_entries(tmp_path):
    assert dg.load_asset_label_file(tmp_path / "missing.json") == ({}, [])
    good = _write_labels(tmp_path, {"schema_version": 1, "labels": {
        "storefront": " 商店網站 ", "x-svc": "x-svc", "y-svc": "y-svc 服務", "z-svc": "長" * 61, "k-svc": "金鑰 ghp_abcdefghijklmnopqrstuvwxyz",
        "n-svc": 3, "m-svc": "", "ok-db": "訂單資料庫"}})
    labels, issues = dg.load_asset_label_file(good)
    assert labels == {"storefront": "商店網站", "ok-db": "訂單資料庫"}         # 等於／包含 ID、超過 60 字、機敏、非字串皆略過
    assert [(i["code"], i["omitted"]) for i in issues] == [("asset_labels_invalid", 6)]
    for raw in ("{not json", json.dumps({"schema_version": 2, "labels": {}}), json.dumps({"labels": {}}),
                json.dumps({"schema_version": 1, "labels": []}), json.dumps({"schema_version": 1, "labels": {}, "x": 1}), "[]"):
        labels, issues = dg.load_asset_label_file(_write_labels(tmp_path, None, raw))
        assert labels == {} and issues[0]["code"] == "asset_labels_invalid" and "未命名系統" in issues[0]["impact"]


def test_repo_label_file_is_valid_and_never_shows_ids():
    labels, issues = dg.load_asset_label_file()
    assert issues == [] and labels
    for aid, name in labels.items():
        assert aid not in name and len(name) <= 60 and not dg.has_sensitive(name)


def test_label_file_covers_every_impacted_asset_in_fixtures(baseline):
    """target-baseline 與 after-fix fixture 圖譜中，出現在比對 impacts 的每個資產都有白話名稱。"""
    from tools.loaders import FIXTURE_SCANNERS
    from tools.pipeline import EvalInput, evaluate
    from tools.common import AGENTS_DIR
    labels, _ = dg.load_asset_label_file()
    results = [evaluate(EvalInput(target_root=baseline["data"].root, as_of=day(8), scanners_dir=FIXTURE_SCANNERS,
                                  intel_kinds=("archive", "advisory", "demo")))]
    for variant in ("full", "partial"):
        root = AGENTS_DIR / "fixtures" / "after-fix" / variant
        scanners = root / "scanners" if (root / "scanners").is_dir() else FIXTURE_SCANNERS
        results.append(evaluate(EvalInput(target_root=root / "target", as_of=day(8), scanners_dir=scanners,
                                          intel_kinds=("archive", "advisory", "demo"))))
    impacted = {i["asset_id"] for r in results for m in r["matches"] for i in m["impacts"]} - {"*"}
    assert impacted and impacted <= set(labels), sorted(impacted - set(labels))
    nodes = {n for r in results for n in r["graph"].nodes}
    assert nodes <= set(labels), sorted(nodes - set(labels))                 # 圖譜所有節點也都有名稱


def test_label_issue_recorded_in_store_and_not_accumulated():
    issue = dg._issue("asset_labels_invalid", "系統名稱對照檔格式無效，已忽略")
    s, seen = dg.merge_store(None, None, daily_report(), [make_report()], day(0), complete=True, asset_labels={},
                             run_id="run-1", extra_issues=[issue])
    assert [i["code"] for i in s["data_issues"]].count("asset_labels_invalid") == 1
    s2, _ = dg.merge_store(s, seen, daily_report("run-2"), [make_report()], day(1), complete=True, asset_labels={},
                           run_id="run-2")
    assert not any(i["code"] == "asset_labels_invalid" for i in s2["data_issues"])      # 對照檔修好後不殘留
    kept, _, _ = dg.finalize_store(s, seen, day(0, 2))
    assert any(i["code"] == "asset_labels_invalid" for i in kept["data_issues"])        # 發布端清理時保留


def test_conclusion_with_graph_ids_keeps_product_names_but_not_internal_strings():
    eid = "evt-syn-2026-10"
    nodes = {"nas-office-01", "storefront", "order-db-prod", "laptop-eng-07"}
    labels = {"nas-office-01": "辦公室 NAS", "laptop-eng-07": "工程部門筆電"}
    rep = make_report(eid, status="open", impacts=[_impact(eid, "nas-office-01", "affected", "r")], max_level="medium",
                      conclusion="1 項受影響，最高風險為中。nas-office-01：synology-dsm 7.2.1-69057 Update 5，對外。")
    a = dg.assessment_from_report(rep, labels, run_id=RUN, evaluated_at="2026-11-10T00:00:00Z", internal_ids=nodes)
    assert a["conclusion"] == "1 項受影響，最高風險為中。辦公室 NAS：synology-dsm 7.2.1-69057 Update 5，對外。"
    # 沒有提供圖譜 ID 時維持保守規則
    assert dg.assessment_from_report(rep, labels, run_id=RUN, evaluated_at="2026-11-10T00:00:00Z")["conclusion"] == \
        "1 項受影響，最高風險為中。包括辦公室 NAS。"
    for text in ("1 項受影響，最高風險為中。nas-office-01 連到 order-db-prod。",           # 沒有名稱的已知 ID 殘留
                 "1 項受影響，最高風險為中。laptop-eng-07 有 ~/.config/pipeline/token。",  # 路徑
                 "1 項受影響，最高風險為中。nas-office-01：php，session.upload_progress.enabled=On。"):   # 設定鍵
        r = {**rep, "conclusion": text}
        out = dg.assessment_from_report(r, labels, run_id=RUN, evaluated_at="2026-11-10T00:00:00Z", internal_ids=nodes)
        assert out["conclusion"] == "1 項受影響，最高風險為中。包括辦公室 NAS。", text
        assert not any(n in out["conclusion"] for n in nodes)


def test_conclusion_replaces_ids_or_falls_back_to_template():
    eid = "evt-c-2026-11"
    rep = make_report(eid, status="need_check", impacts=[_impact(eid, "storefront", "need_check")],
                      conclusion="storefront 需要人工確認版本。")
    a = dg.assessment_from_report(rep, {"storefront": "商店網站"}, run_id=RUN, evaluated_at="2026-11-10T00:00:00Z")
    assert a["conclusion"] == "商店網站 需要人工確認版本。"
    rep2 = make_report(eid, status="open", impacts=[_impact(eid, "internal-tool", "affected", "r")], max_level="high",
                       conclusion="1 項受影響，最高風險為高。internal-tool：network.json: internet → internal-tool:443。")
    a2 = dg.assessment_from_report(rep2, {}, run_id=RUN, evaluated_at="2026-11-10T00:00:00Z")
    assert a2["conclusion"] == "1 項受影響，最高風險為高。"                               # 無法安全替換 → 白話範本
    assert "internal-tool" not in json.dumps(a2["conclusion"], ensure_ascii=False)
    rep3 = make_report(eid, status="need_check", impacts=[_impact(eid, "order-db-prod", "need_check")],
                       conclusion="order-db-prod 的 C-NET-SEGMENT 需確認")
    assert dg.assessment_from_report(rep3, {"order-db-prod": "訂單資料庫"}, run_id=RUN,
                                     evaluated_at="2026-11-10T00:00:00Z")["conclusion"] == "沒有確定受影響的項目，但有 1 項需要人工確認。"


def test_eligibility_excludes_demo_and_non_daily_runs():
    assert dg.eligible_report(make_report(kind="live"))
    assert dg.eligible_report(make_report("evt-a-2026-10", kind="archive"))
    assert dg.eligible_report(make_report("kev-cve-2026-1234", kind="advisory"))
    assert not dg.eligible_report(make_report("demo-x-2026", kind="demo"))
    assert not dg.eligible_report(make_report("evt-b-2026-10", kind="archive", demo=True))
    fixture = make_report("adv-fixture-2026-001", kind="advisory")
    fixture["event"]["demo_fixture"] = True                           # 原始事件的 demo_fixture（demo=false 的示範公告）
    assert not dg.eligible_report(fixture)
    demo_src = make_report("adv-fixture-2026-002", kind="advisory", sources=[
        {"url": None, "title": "虛構示範公告", "quote": None, "published": None, "verification_basis": "demo"}])
    assert not dg.eligible_report(demo_src)                           # A1 已把來源標為示範
    assert not dg.eligible_report(make_report("adv-x-2026-001", kind="advisory"), {"adv-x-2026-001"})
    assert dg.fixture_ids([{"id": "adv-a", "kind": "advisory", "demo": False, "demo_fixture": True},
                           {"id": "evt-b", "kind": "archive", "demo": False}, {"id": "demo-c", "kind": "demo"}]) == {"adv-a", "demo-c"}
    assert dg.eligible_run("daily", "schedule") and dg.eligible_run("daily", "manual")
    assert not dg.eligible_run("daily", "web")
    assert not dg.eligible_run("scenario", "manual") and not dg.eligible_run("advisory", "intel-watch")


# ── T2：累積資料合併、清理、最小去重與容量 ────────────────────────────────────

D0 = datetime(2026, 11, 1, 0, 0, tzinfo=timezone.utc)     # 台灣 2026-11-01 08:00（每日排程時間）


def day(n, hours=0):
    return D0 + timedelta(days=n, hours=hours)


def daily_report(run_id="run-1", completeness="complete", status="ok"):
    return {"run_id": run_id, "completeness": completeness, "daily_intel_status": status}


def merge(prev, seen, reps, as_of, *, run_id="run-1", complete=True, labels=None, stats=None):
    store, seen = dg.merge_store(prev, seen, daily_report(run_id, "complete" if complete else "partial"), reps, as_of,
                                 complete=complete, asset_labels=labels or {}, generated_at=as_of + timedelta(minutes=20),
                                 run_id=run_id, stats=stats)
    DigestStore.model_validate(store)
    DigestSeen.model_validate(seen)
    return store, seen


def test_new_event_recorded_with_taipei_first_seen_and_full_assessment():
    stats = {}
    rep = make_report("live-a-2026-11", status="open", impacts=[_impact("live-a-2026-11", "storefront", "affected", "r")],
                      levels={("storefront", "affected"): "high"}, max_level="high")
    store, seen = merge(None, None, [rep], day(0), labels={"storefront": "商店網站"}, stats=stats)
    ev = store["events"]["live-a-2026-11"]
    assert ev["first_seen"] == ev["last_seen"] == "2026-11-01" and ev["last_seen_at"] == "2026-11-01T00:00:00Z"
    assert ev["observed_run_id"] == "run-1" and store["updated_at"] == "2026-11-01T00:20:00Z"
    a = ev["assessment"]                                           # 關係、數量、等級、明細皆來自同一份報告
    assert (a["relation"], a["affected_count"], a["max_level"], a["run_id"], a["evaluated_at"]) == \
        ("affected", 1, "high", "run-1", "2026-11-01T00:00:00Z")
    assert a["impacts"] == [{"asset_id": "storefront", "asset_label": "商店網站", "verdict": "affected", "level": "high"}]
    assert a["relation_changed_at"] is None and stats["new"] == 1
    assert seen["first_seen_by_key"] == {dg.seen_key("live-a-2026-11"): "2026-11-01"}


def test_relation_change_records_time_and_keeps_first_seen():
    eid = "live-b-2026-11"
    need = make_report(eid, status="need_check")
    hit = make_report(eid, status="open", impacts=[_impact(eid, "storefront", "affected", "r")], max_level="medium",
                      levels={("storefront", "affected"): "medium"})
    s, seen = merge(None, None, [need], day(0))
    s, seen = merge(s, seen, [hit], day(1), run_id="run-2")
    ev = s["events"][eid]
    assert ev["first_seen"] == "2026-11-01" and ev["last_seen"] == "2026-11-02"
    assert ev["assessment"]["relation"] == "affected" and ev["assessment"]["relation_changed_at"] == "2026-11-02T00:00:00Z"
    s, seen = merge(s, seen, [hit], day(2), run_id="run-3")
    assert s["events"][eid]["assessment"]["relation_changed_at"] == "2026-11-02T00:00:00Z"   # 未改變則沿用
    assert s["events"][eid]["assessment"]["evaluated_at"] == "2026-11-03T00:00:00Z"


def test_archive_seen_32_days_never_resets_first_seen():
    eid = "evt-archive-2026-10"
    rep = make_report(eid, kind="archive", status="not_affected", impacts=[_impact(eid, "storefront", "not_affected")])
    store = seen = None
    for n in range(32):
        stats = {}
        store, seen = merge(store, seen, [rep], day(n), run_id=f"run-{n}", stats=stats)
        if n <= 29:                                                # 2026-11-01～2026-11-30：仍在窗口內
            assert store["events"][eid]["first_seen"] == "2026-11-01"
        else:                                                      # 第 31、32 天：過期移除，不重新收錄
            assert eid not in store["events"] and stats["new"] == 0
            assert stats["expired_skipped"] == (0 if n == 30 else 1) and stats["removed"] == (1 if n == 30 else 0)
        assert seen["first_seen_by_key"][dg.seen_key(eid)] == "2026-11-01"   # seen 不裁成 30 天
    assert not any(i["code"] == "capacity" for i in store["data_issues"])    # 過期不是容量省略


def test_window_is_taipei_calendar_d_minus_29_to_d():
    base = datetime(2026, 11, 29, 16, 0, tzinfo=timezone.utc)        # 台灣 2026-11-30 00:00
    assert dg.window_bounds(base) == ("2026-11-01", "2026-11-30")
    assert dg.window_bounds(base - timedelta(seconds=1)) == ("2026-10-31", "2026-11-29")   # 跨台灣午夜前一秒

    def ev(i, d):
        return {**dg.event_content(make_report(i)), "first_seen": d, "last_seen": d,
                "last_seen_at": "2026-11-01T00:00:00Z", "observed_run_id": "r", "assessment": None}
    store = {"schema_version": 1, "updated_at": "2026-11-29T00:20:00Z", "data_issues": [],
             "events": {"evt-old-1": ev("evt-old-1", "2026-10-31"), "evt-in-1": ev("evt-in-1", "2026-11-01"),
                        "evt-now-1": ev("evt-now-1", "2026-11-30"), "evt-fut-1": ev("evt-fut-1", "2026-12-01")}}
    out = dg.prune(store, base)
    assert sorted(out["events"]) == ["evt-in-1", "evt-now-1"]
    assert [i["code"] for i in out["data_issues"]] == ["future_first_seen"]      # 未來日期拒絕並記錄
    assert out["updated_at"] == store["updated_at"]                              # 清理不刷新時間


def test_utc_crossing_taipei_midnight_sets_first_seen_by_taipei_date():
    before = datetime(2026, 11, 10, 15, 59, 59, tzinfo=timezone.utc)   # 台灣 11/10 23:59:59
    after = datetime(2026, 11, 10, 16, 0, 0, tzinfo=timezone.utc)      # 台灣 11/11 00:00:00
    s1, _ = merge(None, None, [make_report("live-m1-2026")], before)
    s2, _ = merge(None, None, [make_report("live-m2-2026")], after)
    assert s1["events"]["live-m1-2026"]["first_seen"] == "2026-11-10"
    assert s2["events"]["live-m2-2026"]["first_seen"] == "2026-11-11"


def test_incomplete_run_only_updates_observation():
    eid = "live-c-2026-11"
    full = make_report(eid, status="open", impacts=[_impact(eid, "storefront", "affected", "r")], max_level="high",
                       levels={("storefront", "affected"): "high"}, title="原標題", summary="原摘要")
    s, seen = merge(None, None, [full], day(0))
    before = json.loads(json.dumps(s["events"][eid]))
    changed = make_report(eid, status="not_affected", impacts=[_impact(eid, "storefront", "not_affected")],
                          title="新標題", summary="新摘要")
    newcomer = make_report("live-d-2026-11", status="not_affected", impacts=[_impact("live-d-2026-11", "x", "not_affected")])
    stats = {}
    s2, seen2 = merge(s, seen, [changed, newcomer], day(1, 2), run_id="run-partial", complete=False, stats=stats)
    ev = s2["events"][eid]
    assert ev["assessment"] == before["assessment"]                       # 任何結論欄位都不被覆寫
    assert (ev["title"], ev["summary"]) == ("原標題", "原摘要")            # 內容跟著評估快照，不混用
    assert (ev["last_seen"], ev["last_seen_at"], ev["observed_run_id"]) == ("2026-11-02", "2026-11-02T02:00:00Z", "run-partial")
    assert s2["events"]["live-d-2026-11"]["assessment"] is None            # 首次不完整：只記收錄資料，待評估
    assert stats["pending"] == 1 and stats["observed_only"] == 1
    pending = next(i for i in s2["data_issues"] if i["code"] == "pending_assessment")
    assert pending["omitted"] == 1
    # 整體 complete 但該份 IntelMatchReport 不完整：同樣不更新評估
    s3, _ = merge(s2, seen2, [make_report(eid, status="not_affected", complete=False,
                                          impacts=[_impact(eid, "storefront", "not_affected")])], day(2), run_id="run-x")
    assert s3["events"][eid]["assessment"] == before["assessment"]
    # 之後取得完整評估才補上
    s4, _ = merge(s3, seen2, [make_report("live-d-2026-11", status="need_check")], day(3), run_id="run-4")
    assert s4["events"]["live-d-2026-11"]["assessment"]["run_id"] == "run-4"
    assert s4["events"]["live-d-2026-11"]["first_seen"] == "2026-11-02"


def test_older_run_does_not_overwrite_newer_assessment_or_observation():
    eid = "live-e-2026-11"
    s, seen = merge(None, None, [make_report(eid, status="need_check")], day(1, 5), run_id="run-new")
    s2, _ = merge(s, seen, [make_report(eid, status="open", impacts=[_impact(eid, "a", "affected", "r")])], day(1),
                  run_id="run-old")
    ev = s2["events"][eid]
    assert ev["assessment"]["run_id"] == "run-new" and ev["observed_run_id"] == "run-new"


def test_same_day_rerun_takes_later_complete_snapshot():
    eid = "live-f-2026-11"
    s, seen = merge(None, None, [make_report(eid, status="need_check")], day(0), run_id="run-a")
    s, seen = merge(s, seen, [make_report(eid, status="not_affected", impacts=[_impact(eid, "s", "not_affected")])],
                    day(0, 3), run_id="run-b")
    a = s["events"][eid]["assessment"]
    assert (a["run_id"], a["relation"], a["evaluated_at"]) == ("run-b", "not_affected", "2026-11-01T03:00:00Z")
    assert s["events"][eid]["first_seen"] == "2026-11-01"


def test_demo_events_never_recorded():
    s, seen = merge(None, None, [make_report("demo-x-2026", kind="demo"),
                                 make_report("evt-d-2026-10", kind="archive", demo=True)], day(0))
    assert s["events"] == {} and seen["first_seen_by_key"] == {}


def test_demo_fixture_never_enters_store_seen_or_latest():
    fixture = make_report("adv-opsbuilder-2026-001", kind="advisory", status="open",
                          impacts=[_impact("adv-opsbuilder-2026-001", "internal-tool", "affected", "r")])
    real = make_report("evt-real-2026-10", kind="archive")
    stats = {}
    s, seen = dg.merge_store(None, None, daily_report(), [fixture, real], day(0), complete=True, asset_labels={},
                             run_id="run-1", stats=stats, exclude_ids={"adv-opsbuilder-2026-001"})
    assert list(s["events"]) == ["evt-real-2026-10"] and stats["new"] == 1
    assert dg.seen_key("adv-opsbuilder-2026-001") not in seen["first_seen_by_key"]
    latest = dg.build_latest(s, daily_report(), day(0), day(0, 1), "run-1")
    assert "adv-opsbuilder-2026-001" not in json.dumps(latest)
    # 前版（功能修正前）已收錄的 fixture：下一次合併時一併移除
    prev = {**s, "events": {**s["events"], "adv-opsbuilder-2026-001": {
        **dg.event_content(fixture), "first_seen": "2026-11-01", "last_seen": "2026-11-01",
        "last_seen_at": "2026-11-01T00:00:00Z", "observed_run_id": "run-0", "assessment": None}}}
    prev_seen = {"schema_version": 1, "first_seen_by_key": {**seen["first_seen_by_key"],
                                                            dg.seen_key("adv-opsbuilder-2026-001"): "2026-11-01"}}
    s2, seen2 = dg.merge_store(prev, prev_seen, daily_report("run-2"), [fixture, real], day(1), complete=True,
                               asset_labels={}, run_id="run-2", exclude_ids={"adv-opsbuilder-2026-001"})
    assert list(s2["events"]) == ["evt-real-2026-10"]
    assert dg.seen_key("adv-opsbuilder-2026-001") not in seen2["first_seen_by_key"]


def test_seen_contains_only_hash_and_date():
    rep = make_report("live-secret-title-2026", title="很長的標題", summary="摘要")
    _, seen = merge(None, None, [rep], day(0))
    text = json.dumps(seen, ensure_ascii=False)
    assert "live-secret-title-2026" not in text and "很長的標題" not in text and "摘要" not in text
    assert list(seen) == ["schema_version", "first_seen_by_key"]


def _many(prefix, n, status="not_affected"):
    out = []
    for i in range(n):
        eid = f"{prefix}-{i:03d}"
        if status == "open":
            out.append(make_report(eid, status="open", impacts=[_impact(eid, "s", "affected", "r")], max_level="low",
                                   levels={("s", "affected"): "low"}))
        else:
            out.append(make_report(eid, status=status, impacts=[_impact(eid, "s", status)]))
    return out


def test_per_day_capacity_50_keeps_priority_and_never_resets_first_seen():
    reps = _many("live-na", 52) + _many("live-hit", 3, "open")
    stats = {}
    s, seen = merge(None, None, reps, day(0), stats=stats)
    assert len(s["events"]) == 50 and stats["omitted"] == 5
    assert all(f"live-hit-{i:03d}" in s["events"] for i in range(3))        # 受影響優先保留
    assert "live-na-051" not in s["events"] and "live-na-050" not in s["events"]   # 同級依 ID 穩定裁切
    issue = next(i for i in s["data_issues"] if i["code"] == "capacity")
    assert (issue["date"], issue["omitted"]) == ("2026-11-01", 5) and "5" in issue["impact"]
    assert len(seen["first_seen_by_key"]) == 55                              # 去重紀錄先於容量裁切產生
    # 隔天同樣的事件再出現：不能被當成新事件、不能出現在 11/02
    s2, seen2 = merge(s, seen, reps, day(1), run_id="run-2")
    assert {ev["first_seen"] for ev in s2["events"].values()} == {"2026-11-01"}
    assert seen2["first_seen_by_key"][dg.seen_key("live-na-051")] == "2026-11-01"
    assert next(i for i in s2["data_issues"] if i["code"] == "capacity")["omitted"] == 5


def test_size_limit_trims_lowest_priority_and_records_omissions(monkeypatch):
    monkeypatch.setattr(dg, "MAX_BYTES", 40_000)
    reps = []
    for n in range(40):
        eid = f"live-big-{n:03d}"
        reps.append(make_report(eid, status="need_check" if n < 5 else "not_affected", summary="長" * 290,
                                impacts=[_impact(eid, "s", "need_check" if n < 5 else "not_affected")],
                                sources=[{"url": f"https://news.example.com/{eid}/{k}", "title": "來源" * 30, "quote": None,
                                          "published": None, "verified": True} for k in range(3)]))
    stats = {}
    s, _ = merge(None, None, reps, day(0), stats=stats)
    assert len(dg.serialize(s)) <= 40_000 and stats["omitted"] > 0
    assert all(f"live-big-{n:03d}" in s["events"] for n in range(5))       # 需確認優先保留
    issue = next(i for i in s["data_issues"] if i["code"] == "capacity")
    assert issue["omitted"] == stats["omitted"] == 40 - len(s["events"])


def test_real_limits_are_1mib_and_50_per_day():
    assert dg.MAX_BYTES == 1024 * 1024 and dg.PER_DAY_LIMIT == 50 and dg.WINDOW_DAYS == 30


# ── T3：整理產生（latest） ─────────────────────────────────────────────────────

def build(store, as_of, *, run_id="run-1", generated_at=None, status="ok"):
    latest = dg.build_latest(store, daily_report(run_id, status=status), as_of, generated_at or as_of + timedelta(minutes=20),
                             run_id)
    DigestLatest.model_validate(latest)
    return latest


@pytest.mark.parametrize("generated,expected", [
    ("2026-11-10T23:59:59Z", "2026-11-11T00:00:00Z"),     # 台灣 08:00 前一秒
    ("2026-11-11T00:00:00Z", "2026-11-12T00:00:00Z"),     # 剛好台灣 08:00：取隔日
    ("2026-11-11T00:20:00Z", "2026-11-12T00:00:00Z"),     # 08:20 產生
    ("2026-11-30T15:59:00Z", "2026-12-01T00:00:00Z"),     # 跨月
    ("2026-12-31T23:30:00Z", "2027-01-01T00:00:00Z"),     # 跨年
])
def test_next_update_at_boundaries(generated, expected):
    from tools.common import parse_time
    assert dg.iso(dg.next_update_at(parse_time(generated))) == expected


def test_next_update_uses_actual_generation_time_when_run_crosses_day():
    s, _ = merge(None, None, [make_report("live-late-2026")], day(9))   # 評估 as_of 11/10 00:00Z
    latest = build(s, day(9), generated_at=day(10, 1))                 # 實際完成於 11/11 01:00Z
    assert latest["as_of"] == "2026-11-10T00:00:00Z" and latest["updated_at"] == "2026-11-11T01:00:00Z"
    assert latest["next_update_at"] == "2026-11-12T00:00:00Z"         # 嚴格晚於實際產生時間


def test_first_build_groups_archives_under_today_and_sorts_by_relation_and_level():
    eids = [f"evt-arch{n}-2026-10" for n in range(6)]
    reps = [
        make_report(eids[0], kind="archive", status="not_affected", impacts=[_impact(eids[0], "s", "not_affected")]),
        make_report(eids[1], kind="archive", status="open", impacts=[_impact(eids[1], "s", "affected", "r")],
                    max_level="medium", levels={("s", "affected"): "medium"}),
        make_report(eids[2], kind="archive", status="need_check"),
        make_report(eids[3], kind="archive", status="open", impacts=[_impact(eids[3], "s", "affected", "r")],
                    max_level="high", levels={("s", "affected"): "high"}),
        make_report(eids[4], kind="archive", status="fixed", impacts=[_impact(eids[4], "s", "affected", "r")]),
        make_report(eids[5], kind="advisory", status="need_check"),
    ]
    s, _ = merge(None, None, reps, day(10))
    latest = build(s, day(10))
    assert [d["date"] for d in latest["days"]] == ["2026-11-11"] and latest["days"][0]["count"] == 6
    assert [ev["id"] for ev in latest["days"][0]["events"]] == [eids[3], eids[1], eids[2], eids[5], eids[0], eids[4]]
    assert latest["counts"] == {"total": 6, "affected": 2, "need_check": 2, "not_affected": 1, "fixed": 1}
    assert latest["window_days"] == 30 and latest["daily_intel_status"] == "ok" and latest["run_id"] == "run-1"


def test_days_newest_first_and_history_keeps_its_evaluation_time():
    s, seen = merge(None, None, [make_report("live-old-2026")], day(0), run_id="run-0")
    s, seen = merge(s, seen, [make_report("live-new-2026")], day(2), run_id="run-2")   # 舊事件本次未出現
    latest = build(s, day(2), run_id="run-2")
    assert [d["date"] for d in latest["days"]] == ["2026-11-03", "2026-11-01"]
    old = latest["days"][1]["events"][0]
    assert old["assessment"]["evaluated_at"] == "2026-11-01T00:00:00Z" and old["assessment"]["run_id"] == "run-0"
    assert latest["as_of"] == "2026-11-03T00:00:00Z"


def test_only_assessed_events_are_published():
    s, seen = merge(None, None, [make_report("live-full-2026")], day(0))
    s, seen = merge(s, seen, [make_report("live-pending-2026")], day(1), complete=False, run_id="run-p")
    latest = build(s, day(1))
    ids = [ev["id"] for d in latest["days"] for ev in d["events"]]
    assert ids == ["live-full-2026"] and latest["counts"]["total"] == 1
    assert any(i["code"] == "pending_assessment" and i["omitted"] == 1 for i in latest["data_issues"])


def test_updates_nested_promoted_and_invalid_links_kept():
    parent = make_report("evt-parent-2026", kind="archive", status="not_affected", title="原事件標題",
                         impacts=[_impact("evt-parent-2026", "s", "not_affected")])
    child = make_report("live-child-2026", is_update_of="evt-parent-2026", status="open",
                        impacts=[_impact("live-child-2026", "s", "affected", "r")], max_level="high",
                        levels={("s", "affected"): "high"})
    grandchild = make_report("live-grand-2026", is_update_of="live-child-2026")
    selfref = make_report("live-self-2026", is_update_of="live-self-2026")
    cyc_a = make_report("live-cyc-a-2026", is_update_of="live-cyc-b-2026")
    cyc_b = make_report("live-cyc-b-2026", is_update_of="live-cyc-a-2026")
    other = make_report("live-other-2026", status="need_check")
    s, seen = merge(None, None, [parent, other], day(0))
    s, seen = merge(s, seen, [child, grandchild, selfref, cyc_a, cyc_b], day(1), run_id="run-2")
    latest = build(s, day(1))
    d1, d0 = latest["days"]
    assert d1["date"] == "2026-11-02" and d0["date"] == "2026-11-01"
    # 新進度掛在原事件底下（原事件所在日期），鏈結攤平到原事件；受影響子事件讓整組排到需確認之前
    assert [(ev["id"], [u["id"] for u in ev["updates"]]) for ev in d0["events"]] == [
        ("evt-parent-2026", ["live-child-2026", "live-grand-2026"]), ("live-other-2026", [])]
    assert d0["count"] == 4
    # 自我參照、循環降為獨立卡片並記錄問題，事件不消失
    assert sorted(ev["id"] for ev in d1["events"]) == ["live-cyc-a-2026", "live-cyc-b-2026", "live-self-2026"]
    assert {ev["standalone_reason"] for ev in d1["events"]} == {"link_invalid"}
    assert next(i for i in latest["data_issues"] if i["code"] == "invalid_update_link")["omitted"] == 3
    assert latest["counts"]["total"] == 7 == sum(d["count"] for d in latest["days"])       # 唯一 ID 計數（含 updates）
    # 原事件到期：子事件提升為獨立卡片（較早事件的新進度），不保留原事件標題
    pruned = dg.prune_latest(latest, day(30))                       # 窗口 11/02～12/01：11/01 的原事件到期
    DigestLatest.model_validate(pruned)
    heads = {ev["id"]: ev for d in pruned["days"] for ev in d["events"]}
    assert "evt-parent-2026" not in heads and "live-other-2026" not in heads
    assert heads["live-child-2026"]["standalone_reason"] == "parent_missing"
    assert [u["id"] for u in heads["live-child-2026"]["updates"]] == ["live-grand-2026"]
    assert "原事件標題" in json.dumps(latest, ensure_ascii=False)
    assert "原事件標題" not in json.dumps(pruned, ensure_ascii=False)
    assert pruned["counts"]["total"] == 5
    for k in ("updated_at", "as_of", "run_id", "next_update_at", "daily_intel_status"):
        assert pruned[k] == latest[k]                               # 清理不刷新任何時間


def test_filter_like_regroup_keeps_affected_child_of_unaffected_parent():
    """父事件不受影響、子事件受影響：整組依最優先的成員排序，不會排到需確認之後。"""
    parent = make_report("evt-p2-2026", kind="archive", status="not_affected", impacts=[_impact("evt-p2-2026", "s", "not_affected")])
    child = make_report("live-c2-2026", is_update_of="evt-p2-2026", status="open",
                        impacts=[_impact("live-c2-2026", "s", "affected", "r")], max_level="low", levels={("s", "affected"): "low"})
    need = make_report("live-n2-2026", status="need_check")
    s, _ = merge(None, None, [parent, child, need], day(0))
    latest = build(s, day(0))
    assert [ev["id"] for ev in latest["days"][0]["events"]] == ["evt-p2-2026", "live-n2-2026"]
    assert latest["counts"]["affected"] == 1 and latest["counts"]["not_affected"] == 1


def test_prune_latest_only_removes_expired_and_keeps_times():
    s, seen = merge(None, None, [make_report("live-p1-2026")], day(0))
    s, seen = merge(s, seen, [make_report("live-p2-2026")], day(5), run_id="run-5")
    latest = build(s, day(5), run_id="run-5")
    assert dg.prune_latest(latest, day(5)) == latest
    later = dg.prune_latest(latest, day(30))
    assert [d["date"] for d in later["days"]] == ["2026-11-06"] and later["counts"]["total"] == 1
    assert later["updated_at"] == latest["updated_at"] and later["next_update_at"] == latest["next_update_at"]
    assert later["days"][0]["events"][0]["assessment"] == latest["days"][0]["events"][0]["assessment"]


def test_latest_size_limit_trims_flat_set_before_grouping(monkeypatch):
    parent = make_report("evt-cap-parent", kind="archive", status="fixed",
                         impacts=[_impact("evt-cap-parent", "s", "affected", "r")], summary="長" * 290)
    child = make_report("live-cap-child", is_update_of="evt-cap-parent", status="open",
                        impacts=[_impact("live-cap-child", "s", "affected", "r")], max_level="high",
                        levels={("s", "affected"): "high"})
    fillers = [make_report(f"live-fill-{n:02d}", status="need_check", summary="填" * 290) for n in range(12)]
    s, _ = merge(None, None, [parent, child, *fillers], day(0))
    monkeypatch.setattr(dg, "MAX_BYTES", 20_000)
    latest = build(s, day(0))
    assert len(dg.serialize(latest)) <= 20_000
    heads = {ev["id"]: ev for d in latest["days"] for ev in d["events"]}
    assert "evt-cap-parent" not in heads                            # 已修復、優先順序最低的原事件被裁切
    assert heads["live-cap-child"]["standalone_reason"] == "parent_missing"   # 子事件未超限，不被連帶刪除
    cap = sum(i["omitted"] for i in latest["data_issues"] if i["code"] == "capacity")
    assert cap == 14 - latest["counts"]["total"] and cap > 0


def test_empty_digest_has_no_days():
    latest = build({"schema_version": 1, "updated_at": "2026-11-01T00:20:00Z", "data_issues": [], "events": {}}, day(0))
    assert latest["days"] == [] and latest["counts"]["total"] == 0


# ── T4：暫存 bundle 與整組提交 ─────────────────────────────────────────────────

def _bundle(tmp_path, reps, as_of, *, completeness="complete", run_id="run-1"):
    stats = {}
    files = dg.prepare_bundle(tmp_path / "digest", {**daily_report(run_id, completeness)}, reps, as_of=as_of,
                              generated_at=as_of + timedelta(minutes=20), run_id=run_id, asset_labels={}, stats=stats)
    return files, stats


def test_first_commit_failure_leaves_no_files(tmp_path, monkeypatch):
    files, _ = _bundle(tmp_path, [make_report()], day(0))
    calls = {"n": 0}
    real = dg._replace

    def flaky(src, dst):
        calls["n"] += 1
        if calls["n"] == 3:
            raise OSError("disk full")
        real(src, dst)
    monkeypatch.setattr(dg, "_replace", flaky)
    with pytest.raises(OSError):
        dg.commit_bundle(tmp_path / "digest", files, tmp_path / "staging")
    assert not (tmp_path / "digest").exists()                          # 首次失敗：三檔皆不存在
    assert not any((tmp_path / "staging").iterdir())


def test_incomplete_bundle_without_previous_latest_has_no_latest(tmp_path):
    files, stats = _bundle(tmp_path, [make_report()], day(0), completeness="partial")
    assert set(files) == {"seen.json", "store.json"} and stats["latest"] == "absent"
    dg.commit_bundle(tmp_path / "digest", files, tmp_path / "staging")
    store = json.loads((tmp_path / "digest" / "store.json").read_text(encoding="utf-8"))
    assert next(iter(store["events"].values()))["assessment"] is None


def test_invalid_previous_file_is_not_overwritten(tmp_path):
    (tmp_path / "digest").mkdir()
    (tmp_path / "digest" / "store.json").write_text("{\"events\": 1}", encoding="utf-8")
    with pytest.raises(dg.DigestError) as exc:
        _bundle(tmp_path, [make_report()], day(0))
    assert exc.value.code == "invalid_previous_store"


def test_bundle_rejects_secret_left_in_content(tmp_path, monkeypatch):
    monkeypatch.setattr(dg, "public_text", lambda value, limit: str(value or "")[:limit])   # 模擬去敏被繞過
    with pytest.raises(dg.DigestError) as exc:
        _bundle(tmp_path, [make_report(summary="外洩 ghp_abcdefghijklmnopqrstuvwxyz")], day(0))
    assert exc.value.code.startswith("sensitive_")
    assert dg.safe_error_code(RuntimeError("ghp_secret")) == "RuntimeError"
