"""給 AI 的輸入投影（specs/orchestrator R2.2、R2.3、R4.2；design §4、§8 的 test_orchestrator_input）。

用 intel-demo 的凍結資料與真的 evaluate，再注入污染資料：風險標題含路徑、金鑰、IP；事件文字含設定鍵；非 ai_assets 的系統。
這些內容都不得出現在 out/orchestrator-<m>/<m>-input.json；內部政策上下文只寫在 internal/。不呼叫 LLM、不連網路。
"""
import copy
import json
from dataclasses import replace

import pytest

from agents import orchestrator_agent as oa
from context import build_ctx
from tools import orchestration as o
from tools.common import sha256_json, write_json
from tools.intel_verify import verify_event
from tools.pipeline import event_sources

ENV = {"TRIGGER_SOURCE": "manual", "EVENT_NAME": "workflow_dispatch", "AS_OF": "2026-11-09T01:00:00Z", "RUN_ID": "orch-input-run"}
POISON_EVENT = "demo-poison-evt"
POISON_TITLE = "金鑰存放在 config/prod.env，值 DEMO-FAKE-ABCD-1234，來源 198.51.100.77"
HIDDEN = "vault-hidden-99"                            # 不在 ai_assets（不在圖譜）的系統
CLEAN_STEP = "攻擊者以釣魚信取得帳號"
CLEAN_HYPOTHESIS = "確認快取連線是否加密"
FORBIDDEN = ["session.cookie_secure", "/var/log", "203.0.113.9", "8443", "config/secrets.yml", "config/prod.env", "DEMO-FAKE",
             "198.51.100.77", "services/brand-app", "10.20.1.11", HIDDEN, "/etc/nginx", "2026-11-09T01", "orch-input-run",
             "ghp_", "evidence", "quote"]

TOP = {"dispatch": {"schema_version", "mode", "available", "scope", "note", "events", "risks", "controls", "candidates", "menu",
                    "limits"},
       "review": {"schema_version", "mode", "available", "scope", "note", "dispatch_plan", "jobs", "dispatch_outcomes", "events",
                  "risks", "candidates", "menu", "limits"}}
EVENT_KEYS = {"id", "title", "date", "industry", "attck", "cves", "attack_chain", "relation", "systems", "hypotheses"}
RISK_KEYS = {"id", "level", "category", "asset_id", "label"}


@pytest.fixture()
def ctx(monkeypatch, tmp_path):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    for k in ("EXECUTION_MODE", "GITHUB_OUTPUT", "TARGET_DIR", "ADVISORY_ID", "ASSETS", "TARGET_SHA", "SCANNERS_DIR",
              "DEPLOYMENTS_FILE", "GITHUB_RUN_ATTEMPT", "JOB_RESULTS"):
        monkeypatch.delenv(k, raising=False)
    import claude_agent_sdk
    monkeypatch.setattr(claude_agent_sdk, "query", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM")))
    return replace(build_ctx(scenario="intel-demo"), out=tmp_path / "out", data_dir=tmp_path / "data",
                   reports_dir=tmp_path / "reports")


def a1_verified(c, *, poison=False):
    verified = [verify_event(raw, as_of=c.as_of, online=False) for raw in event_sources(c.eval_input())]
    if poison:
        bad = copy.deepcopy(next(v for v in verified if v["event"]["id"] == "demo-cache-plaintext"))
        bad["event"].update(id=POISON_EVENT, date="2026-11-06", title="設定 session.cookie_secure=On 後仍遭入侵",
                            industry="電商 /var/log/app.log",
                            attack_chain=["從 203.0.113.9:8443 連入", "讀取 config/secrets.yml", CLEAN_STEP],
                            revision="2026-11-06.1")
        verified.append(bad)
    write_json(c.out / "a1" / "verified.json", verified)
    loaded, why = o.load_verified(c)
    assert why is None
    return loaded


@pytest.fixture()
def poisoned(monkeypatch):
    """評估快照注入污染：高風險標題含路徑、金鑰、IP；非 ai_assets 系統的風險、影響與推測；含路徑的推測。"""
    real = o.evaluate_snapshot

    def wrapped(base, verified, agent_plan):
        res = real(base, verified, agent_plan)
        res["risks"].insert(0, {"id": "r-poison-1", "finding_ids": [], "asset_id": HIDDEN, "title": POISON_TITLE, "category": "secret",
                                "level": "high", "score": 9, "status": "open", "matched_events": [POISON_EVENT], "breakdown": []})
        for r in res["risks"]:
            if r["id"] == "brand-app:C-SECRET-IN-GIT":
                r["title"] = "存放於 services/brand-app/src/config.ts 的 DEMO-FAKE-WXYZ-9876（10.20.1.11）"
        m = next((m for m in res["matches"] if m["event"]["id"] == POISON_EVENT), None)
        if m is not None:
            m["impacts"].append({"event_id": POISON_EVENT, "asset_id": HIDDEN, "verdict": "need_check", "risk_id": None, "suggestions": [
                {"inferred": True, "plain": "檢查 /etc/nginx 設定", "systems": [{"asset_id": HIDDEN}], "source": "ai"},
                {"inferred": True, "plain": CLEAN_HYPOTHESIS, "systems": [{"asset_id": "cache-redis"}, {"asset_id": HIDDEN}],
                 "source": "ai"}]})
        return res
    monkeypatch.setattr(o, "evaluate_snapshot", wrapped)


def read(path):
    return path.read_text(encoding="utf-8"), json.loads(path.read_text(encoding="utf-8"))


def assert_clean(text):
    for bad in FORBIDDEN:
        assert bad not in text, bad


def assert_shape(data, mode, assets):
    assert set(data) == TOP[mode]
    for ev in data["events"]:
        assert set(ev) == EVENT_KEYS | ({"mapped_controls"} if mode == "dispatch" else set())
        assert set(ev["systems"]) <= assets and len(ev["attack_chain"]) <= o.MAX_CHAIN
    for r in data["risks"]:
        assert set(r) in ({"id", "level", "category"}, RISK_KEYS)                      # 不放風險標題
        assert "asset_id" not in r or r["asset_id"] in assets


def ai_assets(c, verified):
    res, _, _ = o.approve_core("dispatch", {}, verified=verified, base_inputs=o.base_inputs(c))
    return o.ai_asset_ids(res)


# ---------------------------------------------------------------- 派工輸入
def test_dispatch_input_is_whitelisted_and_internal_context_is_separate(ctx):
    verified = a1_verified(ctx)
    got = oa.build_input(ctx, "dispatch")
    assert got["available"] is True and got["events"] == 5
    path, internal = oa.input_path(ctx, "dispatch"), oa.internal_path(ctx, "dispatch")
    assert path == ctx.out / "orchestrator-dispatch" / "dispatch-input.json"
    assert internal == ctx.out / "orchestrator-dispatch" / "internal" / "context.json"
    text, data = read(path)
    assets = ai_assets(ctx, verified)
    assert_shape(data, "dispatch", assets)
    assert_clean(text)
    assert data["mode"] == "dispatch" and data["scope"] == "scenario" and [e["id"] for e in data["events"]] == [
        "demo-push-sdk-rce", "demo-erp-rce", "demo-firebase-public", "demo-clone-app-fraud", "demo-cache-plaintext"]
    by_id = {e["id"]: e for e in data["events"]}
    assert by_id["demo-push-sdk-rce"]["title"] is None                                 # 標題含 /（套件路徑）整段丟掉
    assert by_id["demo-erp-rce"]["title"] == "示範：某 ERP 系統重大漏洞"
    assert by_id["demo-cache-plaintext"]["relation"] == "need_check" and by_id["demo-cache-plaintext"]["mapped_controls"] == ["C-CACHE-TLS"]
    risks = {r["id"]: r for r in data["risks"]}
    assert risks["brand-app:C-SECRET-IN-GIT"]["label"] == "金鑰外洩：品牌 App"
    assert risks["clone:app.bloomrewards.example"] == {"id": "clone:app.bloomrewards.example", "level": "medium",
                                                       "category": "clone_app"}            # 資產不在 ai_assets：只放三個欄位
    c = data["candidates"]
    assert c["a2"] == [{"event_id": "demo-push-sdk-rce", "subagent": "dependency-analyst", "count": 1,
                        "components": [{"name": "@demo-vendor/push-sdk", "version": None}]}]
    assert {x["event_id"]: x["systems"] for x in c["a3"]} == {"demo-push-sdk-rce": ["brand-app"],
                                                              "demo-firebase-public": ["firebase-brand-app-storage", "order-exports-bucket"],
                                                              "demo-cache-plaintext": ["cache-redis"]}
    assert all(x["flagged_count"] == 0 and set(x) == {"event_id", "systems", "flagged_count"} for x in c["a3"])
    assert len(c["a4_baseline"]) == 10 and set(c["a4_baseline"]) <= set(risks)
    assert c["a4_extra"] == [{"event_id": "demo-clone-app-fraud", "risk_ids": ["clone:app.bloomrewards.example"]},
                             {"event_id": "demo-cache-plaintext", "risk_ids": ["cache-redis:C-CACHE-TLS"]}]
    assert {(m["agent"], m["subagent"]) for m in data["menu"]} == set(o.DISPATCH_TASKS)
    assert data["limits"]["extra_tasks"] == o.MAX_DISPATCH_TASKS and {x["id"] for x in data["controls"]} == set(o.control_titles())
    # 內部政策上下文：PolicyContext 全部欄位（含完整事件），只在 internal/
    _, ctx_json = read(internal)
    assert set(ctx_json) == set(o.PolicyContext(mode="dispatch").to_json())
    assert ctx_json["mode"] == "dispatch" and list(ctx_json["events"]) == [e["id"] for e in data["events"]]
    assert "sources" in ctx_json["events"]["demo-erp-rce"]                              # 內部保留完整事件，公開輸入沒有
    assert sorted(p.name for p in (ctx.out / "orchestrator-dispatch").iterdir()) == ["dispatch-input.json", "internal", "trace.jsonl"]
    assert not list((ctx.out / "orchestrator-dispatch").rglob("*.tmp"))


def test_dispatch_input_pollution_never_reaches_the_ai(ctx, poisoned):
    verified = a1_verified(ctx, poison=True)
    oa.build_input(ctx, "dispatch")
    text, data = read(oa.input_path(ctx, "dispatch"))
    assert_clean(text)
    assert_shape(data, "dispatch", ai_assets(ctx, verified))
    ev = next(e for e in data["events"] if e["id"] == POISON_EVENT)
    assert ev["title"] is None and ev["industry"] is None                              # 設定鍵、路徑：整段丟掉
    assert ev["attack_chain"] == [CLEAN_STEP]                                           # 含 IP、連接埠、路徑的步驟丟掉
    assert ev["systems"] == ["cache-redis"]                                             # 非 ai_assets 的系統不放
    assert ev["hypotheses"] == [f"{CLEAN_HYPOTHESIS}；先查：網站快取"]                     # 含路徑的推測丟掉；系統只用白話名稱
    poison_risk = next(r for r in data["risks"] if r["id"] == "r-poison-1")
    assert poison_risk == {"id": "r-poison-1", "level": "high", "category": "secret"}
    assert next(r for r in data["risks"] if r["id"] == "brand-app:C-SECRET-IN-GIT")["label"] == "金鑰外洩：品牌 App"
    assert "r-poison-1" in data["candidates"]["a4_baseline"]
    assert {x["event_id"]: x["systems"] for x in data["candidates"]["a3"]}[POISON_EVENT] == ["cache-redis"]
    # 內部檔保留原始資料（證明污染確實存在，只是沒有進公開輸入）
    internal_text, _ = read(oa.internal_path(ctx, "dispatch"))
    assert "session.cookie_secure" in internal_text and "/var/log" in internal_text


def test_unsafe_ids_are_dropped_whole(ctx, monkeypatch):
    """ID 含路徑、空白、IP、檔名的事件與風險整筆不交給 AI（只能使用輸入中出現的 ID）。"""
    real = o.evaluate_snapshot

    def wrapped(base, verified, agent_plan):
        res = real(base, verified, agent_plan)
        res["risks"].insert(0, {"id": "secret:config/db.yml#abcd1234", "finding_ids": [], "asset_id": "gitlab", "title": "x",
                                "category": "secret", "level": "high", "score": 9, "status": "open", "matched_events": []})
        res["risks"].insert(0, {"id": "api-gateway:GET /internal/v1/export:shadow_api", "finding_ids": [], "asset_id": "api-gateway",
                                "title": "x", "category": "shadow_api", "level": "high", "score": 9, "status": "open",
                                "matched_events": []})
        return res
    monkeypatch.setattr(o, "evaluate_snapshot", wrapped)
    a1_verified(ctx)
    oa.build_input(ctx, "dispatch")
    text, data = read(oa.input_path(ctx, "dispatch"))
    assert "config/db.yml" not in text and "/internal/v1" not in text
    assert len(data["candidates"]["a4_baseline"]) == 8                                   # 前 10 個高風險中兩筆 ID 不安全


@pytest.mark.parametrize("value,ok", [
    ("brand-app:C-SECRET-IN-GIT", True), ("brand-app:@demo-vendor/push-sdk:vuln", True), ("live-evt-php2shell-2026-10", True),
    ("secret:config/db.yml#abcd1234", False), ("api-gateway:GET /internal/v1/members/export:shadow_api", False),
    ("host:10.0.0.1", False), ("x:8080", False), ("a@b.example.com", False), ("x:DEMO-FAKE-ABCD-1234", False), ("", False),
    (None, False), ("../etc/passwd", False), ("a" * 200, False)])
def test_safe_id(value, ok):
    assert o.safe_id(value) is ok


def test_daily_without_new_events_has_empty_candidates(ctx):
    daily = replace(ctx, scenario="daily", scope="daily", output_dir="daily")
    a1_verified(daily)
    oa.build_input(daily, "dispatch")
    _, data = read(oa.input_path(daily, "dispatch"))
    assert data["events"] == [] and data["candidates"]["a2"] == [] and data["candidates"]["a3"] == []
    assert data["note"] == o.NOTE_NO_PREV and len(data["candidates"]["a4_baseline"]) == 10


def test_unavailable_verified_writes_marked_input(ctx):
    got = oa.build_input(ctx, "dispatch")                                               # 沒有 A1 verified
    assert got == {"mode": "dispatch", "available": False, "reason": "verified_missing"}
    _, data = read(oa.input_path(ctx, "dispatch"))
    assert data["available"] is False and data["reason"] == "verified_missing" and "events" not in data
    _, internal = read(oa.internal_path(ctx, "dispatch"))
    assert internal == {"mode": "dispatch", "unavailable": "verified_missing"}


# ---------------------------------------------------------------- 驗收輸入
DISPATCH = {
    "extra_controls": [{"event_id": "demo-erp-rce", "control_id": "C-NET-SEGMENT", "reason": "確認資料庫網段隔離"}],
    "extra_tasks": [
        {"agent": "a4", "subagent": "impact-analyst", "event_id": "demo-erp-rce", "reason": "補充相關風險"},
        {"agent": "a2", "subagent": "dependency-analyst", "event_id": "demo-push-sdk-rce", "reason": "依事件解讀 SDK 漏洞"},
        {"agent": "a3", "subagent": "retro-hunter", "event_id": "demo-cache-plaintext", "reason": "回溯快取存取紀錄"}],
    "priorities": [{"agent": "a4", "risk_id": "storefront:next:vuln", "reason": "先說明對外系統"}],
}


def save_dispatch(c, verified, proposal=DISPATCH):
    plan = o.build_plan("dispatch", proposal, ctx=c, verified=verified, source="replay")
    o.write_plan(o.plan_path(c.out, "dispatch"), plan)
    return plan


def test_review_input_pollution_and_job_results_only_result(ctx, poisoned, monkeypatch):
    verified = a1_verified(ctx, poison=True)
    save_dispatch(ctx, verified, {})
    monkeypatch.setenv("JOB_RESULTS", json.dumps({
        "router": {"result": "success", "outputs": {"plan": "{\"a2\":true}"}},
        "a2-scan": {"result": "failure", "outputs": {"token": "ghp_abcdefghijklmnopqrstuvwxyz123456"}},
        "a3-signals": {"result": "weird"}, "a4-risk": "success", "BAD KEY": {"result": "success"},
        "orchestrator-dispatch": {"result": "skipped"}}))
    oa.build_input(ctx, "review")
    text, data = read(oa.input_path(ctx, "review"))
    assert_clean(text)
    assert_shape(data, "review", ai_assets(ctx, verified))
    assert data["jobs"] == {"a2-scan": "failure", "orchestrator-dispatch": "skipped", "router": "success"}
    assert data["dispatch_plan"] == {"available": True, "reason": None, "note": None}
    c = data["candidates"]
    assert set(c) == {"need_check", "key_rotation", "notice", "a5_remediation", "a5_ceo"}
    assert c["need_check"] == [POISON_EVENT]                                            # 第 6 件事件擠掉最舊的 demo-cache-plaintext
    assert c["a5_remediation"][0] == "r-poison-1" and c["a5_ceo"] == c["a5_remediation"][:5]
    assert next(r for r in data["risks"] if r["id"] == "r-poison-1") == {"id": "r-poison-1", "level": "high", "category": "secret"}
    assert {(m["agent"], m["subagent"]) for m in data["menu"]} == set(o.REVIEW_TASKS)
    _, ctx_json = read(oa.internal_path(ctx, "review"))
    assert ctx_json["mode"] == "review" and "r-poison-1" in ctx_json["a5_remediation"]


def test_review_input_without_dispatch_plan_says_unavailable(ctx):
    a1_verified(ctx)
    oa.build_input(ctx, "review")
    _, data = read(oa.input_path(ctx, "review"))
    assert data["dispatch_plan"] == {"available": False, "reason": "plan_missing", "note": oa.NOTE_DISPATCH_UNAVAILABLE}
    assert data["dispatch_outcomes"] == [] and data["jobs"] == {}                        # 本機沒有 JOB_RESULTS


def test_review_input_dispatch_outcomes(ctx):
    verified = a1_verified(ctx)
    plan = save_dispatch(ctx, verified)
    assert [a["type"] for a in plan["approved"]] == ["control", "task", "task", "task", "priority"]
    a2_task = next(a for a in plan["approved"] if a.get("agent") == "a2")
    rows = [o.outcome_row(a2_task, "completed", "done"),
            {**o.outcome_row(a2_task, "template", "llm_template"), "status": "exploded"}]   # 格式不符的列略過
    o.write_outcomes(ctx.out, "a2", plan, rows)
    o.write_outcomes(ctx.out, "a4", {**plan, "run_id": "other"}, [])                   # 綁定別的派工單
    with pytest.raises(ValueError):
        o.outcome_row(a2_task, "completed", "free text")
    oa.build_input(ctx, "review")
    _, data = read(oa.input_path(ctx, "review"))
    got = [(r["item"]["type"], r["item"].get("agent"), r["status"], r["reason"]) for r in data["dispatch_outcomes"]]
    assert got == [("control", None, "completed", "check_fail"),                         # 加查結果由評估快照得知
                   ("task", "a4", "unknown", "outcome_mismatch"),
                   ("task", "a2", "completed", "done"),
                   ("task", "a3", "unknown", "outcome_missing"),                          # T3 之前讀不到：unknown，不失敗
                   ("priority", "a4", "unknown", "outcome_mismatch")]
    assert all("reason" not in r["item"] for r in data["dispatch_outcomes"])            # 不轉交 AI 寫的理由
    assert data["dispatch_outcomes"][0]["item"] == {"type": "control", "event_id": "demo-erp-rce", "control_id": "C-NET-SEGMENT"}
    found, why = o.read_outcomes(ctx.out, "a2", plan)
    assert why is None and found == {o.outcome_key(a2_task): ("completed", "done")}
    assert json.loads((ctx.out / "a2" / o.OUTCOME_FILE).read_text(encoding="utf-8"))["dispatch_plan_sha256"] == sha256_json(plan)


@pytest.mark.parametrize("content,why", [("{bad", "outcome_invalid"), ("[]", "outcome_invalid"),
                                          (json.dumps({"agent": "a3", "items": [], "dispatch_plan_sha256": None}), "outcome_invalid")])
def test_read_outcomes_rejects_malformed_files(ctx, content, why):
    (ctx.out / "a2").mkdir(parents=True)
    (ctx.out / "a2" / o.OUTCOME_FILE).write_text(content, encoding="utf-8")
    assert o.read_outcomes(ctx.out, "a2", {"x": 1}) == (None, why)


@pytest.mark.parametrize("raw,expected", [
    (None, {}), ("", {}), ("not json", {}), ("[1]", {}),
    (json.dumps({"a1-intel": {"result": "cancelled", "outputs": {"x": "y"}}}), {"a1-intel": "cancelled"})])
def test_job_results_only_take_result(raw, expected):
    assert oa.job_results(raw) == expected
