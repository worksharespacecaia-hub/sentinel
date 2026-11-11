"""資安事件整理（specs/security-digest）：模型、來源映射、網址與去敏、合併、清理、產生與 A5 提交。全部使用凍結時間。"""
from __future__ import annotations

import json

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
    assert dg.eligible_run("daily", "schedule") and dg.eligible_run("daily", "manual")
    assert not dg.eligible_run("daily", "web")
    assert not dg.eligible_run("scenario", "manual") and not dg.eligible_run("advisory", "intel-watch")
