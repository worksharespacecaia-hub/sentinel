import copy
import shutil

from schemas import Report
from tests.conftest import AS_OF, risk
from tools.intel_match import match_event
from tools.intel_report import build_report
from tools.lights import compute_light
from tools.loaders import FIXTURE_SCANNERS, FIXTURE_TARGET
from tools.pipeline import EvalInput, evaluate
from tools.report_builder import assemble, write_outputs

# 第 7.4 節的列，以實際 daily 資料計算（非凍結因子）
EXPECTED_DAILY = {
    "marketing-site:php:vuln": (9, "high"),
    "phpmyadmin:php:vuln": (4, "medium"),
    "internal-tool:opsbuilder:vuln": (11, "high"),
    "gitlab:C-SECRET-IN-GIT": (8, "high"),
    "mail-api-key:C-THIRD-PARTY-KEY-ROTATION": (6, "medium"),
    "laptop-eng-07:C-DEV-DEVICE-TOKEN": (7, "high"),
    "storefront:next:vuln": (8, "high"),
    "firebase-brand-app-storage:C-CLOUD-STORAGE-PUBLIC": (7, "high"),
}


def test_daily_scores_and_light(baseline):
    for rid, (score, level) in EXPECTED_DAILY.items():
        r = risk(baseline, rid)
        assert (r["score"], r["level"]) == (score, level), rid
        assert r["breakdown"]
    assert baseline["light"] == "red"
    assert sum(1 for r in baseline["risks"] if r["level"] == "high") >= 3


def test_provisional_nas_vuln_capped_but_shadow_it_high(baseline):
    nas = risk(baseline, "nas-office-01:synology-dsm:vuln")
    assert nas["score_level"] == "high" and nas["level"] == "medium" and "暫定" in nas["level_reason"]
    assert risk(baseline, "nas-office-01:shadow_it")["level"] == "high"


def test_report_without_llm_validates(baseline):
    built = assemble(baseline, run_id="t1", scenario="daily", trigger_source="manual", scope="daily", generated_at=AS_OF)
    Report.model_validate(built["report"])
    assert built["report"]["execution_mode"] == "template"
    assert all(r["solution"]["source"] == "template" for r in built["report"]["risks"] if r["solution"])


def test_eleven_intel_reports_without_llm(baseline, demo_result):
    reps = []
    for res in (baseline, demo_result):
        built = assemble(res, run_id="t", scenario="x", trigger_source="manual", scope="scenario", generated_at=AS_OF)
        reps += [r for r in built["intel_reports"] if r["event"]["kind"] in ("archive", "demo")]
    assert len(reps) == 11
    for r in reps:
        b = r["blocks"]
        assert {"1_summary", "2_conclusion", "4_unaffected_and_check", "7_status"} <= set(b)
        if r["affected_count"]:
            assert "3_affected" in b and b["5_solutions"]
    by = {r["event"]["id"]: r for r in reps}
    assert by["demo-erp-rce"]["status"] == "not_affected" and by["demo-cache-plaintext"]["status"] == "need_check"
    assert by["demo-clone-app-fraud"]["notice"]["needed"] is True
    assert [by[i]["max_level"] for i in ("demo-push-sdk-rce", "demo-firebase-public", "demo-clone-app-fraud")] == ["high", "high", "medium"]


def test_write_outputs_has_no_secret_values(baseline, tmp_path):
    built = assemble(baseline, run_id="t2", scenario="daily", trigger_source="manual", scope="daily", generated_at=AS_OF)
    manifest = write_outputs(tmp_path / "daily", built, baseline, reports_md_dir=tmp_path / "md", run_id="t2")
    assert manifest["status"] == "ok" and "report.json" in manifest["files"]
    for p in (tmp_path).rglob("*"):
        if p.is_file():
            assert "DEMO-FAKE" not in p.read_text(encoding="utf-8")


def test_missing_data_never_green_or_not_affected(tmp_path):
    root = tmp_path / "target"
    shutil.copytree(FIXTURE_TARGET, root)
    (root / "ops" / "snapshots" / "runtime.json").unlink()
    res = evaluate(EvalInput(target_root=root, as_of=AS_OF, scanners_dir=tmp_path / "no-scanners"))
    assert res["light"] != "green" and res["complete"] is False
    erp = {"id": "demo-erp-rce"}
    demo = evaluate(EvalInput(target_root=root, as_of=AS_OF, scanners_dir=tmp_path / "no-scanners", intel_kinds=("demo",)))
    m = next(m for m in demo["matches"] if m["event"]["id"] == erp["id"])
    assert m["status"] != "not_affected"            # 清單不完整時不能判定不受影響


def test_event_with_nothing_to_compare_is_not_not_affected(baseline):
    """沒有產品、CVE、控制項的新聞事件：程式沒比對任何資產，清單再完整也不能判定不受影響。"""
    ev = {"id": "live-shop-member-breach", "kind": "live", "title": "某電商會員中心遭攻擊", "date": "2026-11-09",
          "revision": "1", "confidence": "confirmed", "sources": [], "products": [], "cves": [], "controls": [],
          "proposed_controls": [{"title": "訂單查詢需有存取控制", "reason": "x"}]}
    kw = dict(data=baseline["data"], g=baseline["graph"], control_results=baseline["controls"],
              findings=baseline["findings"], coverage=baseline["recon"]["coverage"])
    assert baseline["stack_complete"] is True
    m = match_event(ev, **kw)
    assert m["status"] == "need_check"
    rep = build_report(m, {}, {})
    assert rep["status"] == "need_check" and rep["conclusion"].startswith("無法自動判定") and "不受影響" not in rep["conclusion"]
    assert "建議新增控制項：訂單查詢需有存取控制" in rep["blocks"]["4_unaffected_and_check"]["need_check"][0]["to_verify"]
    # 控制項 ID 沒有檢查結果，同樣沒比對任何東西
    assert match_event({**ev, "controls": ["C-NOT-CHECKED"]}, **kw)["status"] == "need_check"
    # 對照：有產品、且完整清單確認沒有 → 才是不受影響
    assert match_event({**ev, "products": [{"name": "some-erp", "ecosystem": "generic"}]}, **kw)["status"] == "not_affected"


def test_previous_high_kept_until_complete_evidence(tmp_path, baseline):
    prev = {r["id"]: r for r in baseline["risks"]}
    root = tmp_path / "target"
    shutil.copytree(FIXTURE_TARGET, root)
    # 修補 internal-tool，但掃描結果缺失 → 不完整：被移除的風險保留為 need_check
    import json
    rt = root / "ops" / "snapshots" / "runtime.json"
    data = json.loads(rt.read_text(encoding="utf-8"))
    for r in data:
        if r["service_id"] == "internal-tool":
            r["components"][0]["version"] = "1.90"
    rt.write_text(json.dumps(data), encoding="utf-8")
    partial = evaluate(EvalInput(target_root=root, as_of=AS_OF, scanners_dir=tmp_path / "none", prev_risks=prev))
    assert risk(partial, "internal-tool:opsbuilder:vuln")["status"] == "need_check"
    full = evaluate(EvalInput(target_root=root, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS, prev_risks=prev))
    assert risk(full, "internal-tool:opsbuilder:vuln")["status"] == "fixed"


def test_light_rules():
    cov_ok = {"unregistered_exposed": 0, "owner_ratio": 1, "version_known_ratio": 1, "eol_exposed": 0}
    med = [{"level": "medium", "status": "open"}]
    assert compute_light(risks=[], signals=[], open_alerts=[], coverage=cov_ok, data_issues=[])[0] == "green"
    assert compute_light(risks=med, signals=[], open_alerts=[], coverage=cov_ok, data_issues=[])[0] == "yellow"
    assert compute_light(risks=[], signals=[], open_alerts=[], coverage={**cov_ok, "owner_ratio": 0.5}, data_issues=[])[0] == "yellow"
    assert compute_light(risks=[], signals=[], open_alerts=[], coverage=cov_ok,
                         data_issues=[{"source": "snapshots/runtime.json", "status": "stale"}])[0] == "yellow"
    alert = {"level": "high", "status": "open", "simulated": False}
    assert compute_light(risks=[], signals=[], open_alerts=[alert], coverage=cov_ok, data_issues=[])[0] == "red"
    assert compute_light(risks=[], signals=[], open_alerts=[{**alert, "simulated": True}], coverage=cov_ok, data_issues=[])[0] == "green"


def test_multiple_events_add_peer_once(baseline):
    nas = risk(baseline, "nas-office-01:synology-dsm:vuln")
    assert len(nas["matched_events"]) >= 2
    assert sum(1 for b in nas["breakdown"] if b["factor"] == "同業事件命中") == 1


# ── 查核建議（specs/check-hints）：_need 私有欄位與 R8.2 前後一致 ──────────────

HINT_NOTE = {"source": "rules/check-hints.json", "status": "invalid", "required": False,
             "impact": "查核建議規則無效，改用通用建議"}


def _kw(baseline, **over):
    kw = dict(data=baseline["data"], g=baseline["graph"], control_results=baseline["controls"],
              findings=baseline["findings"], coverage=baseline["recon"]["coverage"])
    return {**kw, **over}


def _ev(**kw):
    base = {"id": "live-need-test", "kind": "live", "title": "測試事件", "date": "2026-11-09", "revision": "1",
            "confidence": "confirmed", "sources": [], "products": [], "cves": [], "controls": []}
    return {**base, **kw}


def _needs(m):
    return [(i["asset_id"], (i.get("_need") or {}).get("kind")) for i in m["impacts"] if i["verdict"] == "need_check"]


def test_match_event_writes_need_on_each_branch(baseline):
    from tools.check_hints import attach
    kw = _kw(baseline)
    m = match_event(_ev(), **kw)
    assert _needs(m) == [("*", "no_criteria")]
    m = match_event(_ev(products=[{"name": "some-erp", "ecosystem": "generic"}]),
                    **_kw(baseline, coverage={"version_known_ratio": 0}))
    assert _needs(m) == [("*", "stack_incomplete")] and m["impacts"][0]["_need"]["product"] == "some-erp"
    m = match_event(_ev(products=[{"name": "redis", "ecosystem": "generic", "affected": []}]), **kw)
    assert _needs(m) == [("cache-redis", "version_unknown")]
    assert m["impacts"][0]["_need"] == {"kind": "version_unknown", "product": "redis", "ecosystem": "generic",
                                        "affected": [], "version": "7.0.15"}
    m = match_event(_ev(products=[{"name": "php", "ecosystem": "php", "affected": [{"introduced": "8.5.0", "fixed": "8.5.12"}],
                                   "unknown_below": "8.2.0"}]), **kw)
    below = [i for i in m["impacts"] if i["verdict"] == "need_check"]
    assert [(i["asset_id"], i["_need"]["kind"], i["_need"]["unknown_below"]) for i in below] == \
        [("marketing-site", "unknown_below", "8.2.0")]
    assert all("_need" not in i for i in m["impacts"] if i["verdict"] != "need_check")
    m = match_event(_ev(products=[{"name": "php", "ecosystem": "php", "affected": [{"introduced": "8.0.0", "fixed": "8.9.0"}],
                                   "conditions": [{"key": "custom_flag", "equals": True}]}]), **kw)
    assert m["impacts"] and {k for _, k in _needs(m)} == {"conditions_unknown"}
    assert all(i["_need"]["keys"] == ["custom_flag"] for i in m["impacts"])
    unknown = {"C-X": {"status": "unknown", "title": "測試控制項", "reason": "network.json 缺失", "assets": []}}
    m = match_event(_ev(controls=["C-X"]), **_kw(baseline, control_results={**baseline["controls"], **unknown}))
    assert m["impacts"][0]["_need"] == {"kind": "control_unknown", "control_id": "C-X", "title": "測試控制項",
                                        "reason": "network.json 缺失"}
    m = match_event(_ev(controls=["C-SECRET-IN-GIT"], requires_manual_check=["確認 A"]), **kw)
    assert m["impacts"] and {k for _, k in _needs(m)} == {"manual_check"}
    assert all(i["to_verify"] == ["確認 A"] for i in m["impacts"])
    # 事件層級的 need_check（沒有 impacts、沒有 notes、盤點不完整）：沒有 impact 可附，不產生建議（R1.5）
    m = match_event(_ev(match_finding_categories=["no-such-category"]), **_kw(baseline, coverage={"version_known_ratio": 0}))
    assert m["status"] == "need_check" and m["impacts"] == []
    # attach 之後私有欄位全部移除，既有 to_verify 等欄位不變
    m = match_event(_ev(controls=["C-SECRET-IN-GIT"], requires_manual_check=["確認 A"]), **kw)
    before = [dict(i) for i in m["impacts"]]
    attach(m, graph=baseline["graph"], controls=baseline["controls"], rules=None, labels={})
    assert not any("_need" in i for i in m["impacts"])
    assert [{k: v for k, v in i.items() if k != "suggestions"} for i in m["impacts"]] == \
        [{k: v for k, v in i.items() if k != "_need"} for i in before]
    assert all(i["suggestions"][0]["check"] == "確認 A" for i in m["impacts"])


def _frozen_events():
    import json
    from pathlib import Path
    p = Path(__file__).parent / "fixtures" / "check-hints" / "events.json"
    return json.loads(p.read_text(encoding="utf-8"))


def _frozen_ai_events():
    """specs/check-hints-ai R7.1：2026-11-13 的 5 件需確認事件（帶新格式 possible_entry_points，check／systems 為測試資料補值）。"""
    import json
    from pathlib import Path
    p = Path(__file__).parent / "fixtures" / "check-hints" / "events-2026-11-13.json"
    return json.loads(p.read_text(encoding="utf-8"))["events"]


AI_ONLY_EVENT = {
    "id": "live-ai-only-test-2026-11", "kind": "live", "title": "某公司遭駭，影響範圍仍在確認", "date": "2026-11-11",
    "revision": "1", "confidence": "provisional", "sources": [], "products": [], "cves": [], "controls": [],
    "attack_chain": ["攻擊者取得存取權"], "summary": "公司公告遭駭。", "proposed_controls": [],
    "possible_entry_points": [{"text": "可能是後台帳號遭盜用", "check": "查後台登入紀錄",
                               "systems": ["internal-tool", "brand-app@3.1.0"], "basis": "攻擊過程第 1 步"}],
}


def _r82(res):
    """R8.2 比對欄位：impacts 去掉 suggestions 後的判定欄位、事件 status、complete、風險、燈號與原因、報告結論與完整性。"""
    built = assemble(res, run_id="r82", scenario="daily", trigger_source="manual", scope="daily", generated_at=AS_OF)
    return {
        "impacts": [[{k: v for k, v in i.items() if k != "suggestions"} for i in m["impacts"]] for m in res["matches"]],
        "status": [m["status"] for m in res["matches"]], "complete": res["complete"],
        "risks": [(r["id"], r["score"], r["level"], r["matched_events"], r["status"]) for r in res["risks"]],
        "light": res["light"], "light_reasons": res["light_reasons"],
        "data_issues": [i for i in res["data_issues"] if i != HINT_NOTE],
        "reports": [(r["event"]["id"], r["conclusion"], r["status"], r["complete"]) for r in built["intel_reports"]],
        "completeness": built["report"]["completeness"],
    }, built


def _with_and_without_rules(monkeypatch, tmp_path, make_result):
    """同一份輸入：正常規則 vs SENTINEL_CHECK_HINTS_FILE 指向不存在的路徑（規則無效），R8.2 欄位逐欄相同。"""
    monkeypatch.delenv("SENTINEL_CHECK_HINTS_FILE", raising=False)
    ok_res = make_result()
    ok, ok_built = _r82(ok_res)
    monkeypatch.setenv("SENTINEL_CHECK_HINTS_FILE", str(tmp_path / "no-such-check-hints.json"))
    bad_res = make_result()
    bad, bad_built = _r82(bad_res)
    monkeypatch.delenv("SENTINEL_CHECK_HINTS_FILE", raising=False)
    assert HINT_NOTE in bad_res["data_issues"] and HINT_NOTE not in ok_res["data_issues"]
    assert HINT_NOTE in bad_built["report"]["data_issues"]
    for res in (ok_res, bad_res):
        assert not any("_need" in i for m in res["matches"] for i in m["impacts"])
    assert ok == bad
    return ok_res, bad_res, ok_built


def _validate_impacts(built):
    from schemas import StackImpact
    for rep in built["intel_reports"]:
        for i in rep["impacts"]:
            StackImpact.model_validate(i)


def test_r82_daily_same_with_and_without_rules(monkeypatch, tmp_path):
    def run():
        return evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS))
    ok_res, _, built = _with_and_without_rules(monkeypatch, tmp_path, run)
    assert ok_res["light"] == "red"
    _validate_impacts(built)


def test_r82_frozen_and_ai_events_same_with_and_without_rules(monkeypatch, tmp_path):
    live = [*_frozen_events(), *_frozen_ai_events(), AI_ONLY_EVENT]

    def run():
        return evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS,
                                  live_events=copy.deepcopy(live)))
    ok_res, bad_res, built = _with_and_without_rules(monkeypatch, tmp_path, run)
    _validate_impacts(built)

    def sugs(res, eid):
        m = next(m for m in res["matches"] if m["event"]["id"] == eid)
        assert m["status"] == "need_check"
        return [i.get("suggestions") for i in m["impacts"] if i["verdict"] == "need_check"][0]

    for e in _frozen_events():
        assert all(s["source"] == "rule" and s["inferred"] for s in sugs(ok_res, e["id"]))
        assert [s["id"] for s in sugs(bad_res, e["id"])][:2] == ["generic-1", "generic-2"]   # 規則無效 → 通用建議
    ai_ok, ai_bad = sugs(ok_res, AI_ONLY_EVENT["id"]), sugs(bad_res, AI_ONLY_EVENT["id"])
    assert [(s["source"], s["target"]) for s in ai_ok] == [("ai", None)]
    assert [x["asset_id"] for x in ai_ok[0]["systems"]] == ["internal-tool"]       # app_version 不在 ai_assets → 移除
    assert ai_bad == ai_ok                                                          # AI 推測不依賴規則表
    for e in _frozen_ai_events():                                                   # R7.1：5 件都只有 AI 推測
        assert {s["source"] for s in sugs(ok_res, e["id"])} == {"ai"} == {s["source"] for s in sugs(bad_res, e["id"])}


def test_r82_same_with_and_without_ai_entry_points(monkeypatch):
    """specs/check-hints-ai R7.2：有沒有 AI 推測，判定、分數、燈號、結論、完整性都不變；拿掉 AI 後退回規則推測。"""
    monkeypatch.delenv("SENTINEL_CHECK_HINTS_FILE", raising=False)
    with_ai = [*_frozen_ai_events(), AI_ONLY_EVENT]
    without_ai = [{k: v for k, v in e.items() if k != "possible_entry_points"} for e in copy.deepcopy(with_ai)]

    def run(live):
        return evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS,
                                  live_events=copy.deepcopy(live)))
    a_res, b_res = run(with_ai), run(without_ai)
    (a, a_built), (b, _) = _r82(a_res), _r82(b_res)
    assert a == b
    _validate_impacts(a_built)

    def sources(res, eid):
        m = next(m for m in res["matches"] if m["event"]["id"] == eid)
        return {s["source"] for i in m["impacts"] if i["verdict"] == "need_check" for s in i["suggestions"]}
    for e in _frozen_ai_events():
        assert sources(a_res, e["id"]) == {"ai"} and sources(b_res, e["id"]) == {"rule"}


def test_r82_scenarios_same_with_and_without_rules(monkeypatch, tmp_path):
    from datetime import datetime, timezone

    from context import build_ctx
    from tools.overlay import materialize
    for k in ("TARGET_DIR", "SCANNERS_DIR", "ADVISORY_ID", "ASSETS", "TARGET_SHA", "EXECUTION_MODE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AS_OF", AS_OF.isoformat())
    for name in ("peer-incident", "early-signal", "php2shell", "intel-demo"):
        _with_and_without_rules(monkeypatch, tmp_path / name, lambda: evaluate(build_ctx(scenario=name).eval_input()))
    prev = {r["id"]: r for r in evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF,
                                                   scanners_dir=FIXTURE_SCANNERS))["risks"]}
    fix_as_of = datetime(2026, 11, 10, 6, 0, tzinfo=timezone.utc)      # 與 test_scenarios 的修復後情境相同
    lights = {}
    for name in ("partial", "full"):
        target, scanners = materialize(name, tmp_path / "fix" / name)
        ok_res, _, _ = _with_and_without_rules(
            monkeypatch, tmp_path / name,
            lambda: evaluate(EvalInput(target_root=target, as_of=fix_as_of, scanners_dir=scanners, prev_risks=prev)))
        lights[name] = ok_res["light"]
    assert lights["full"] == "yellow"


def test_green_light_unaffected_by_invalid_rules_note():
    """現有情境沒有綠燈：以 compute_light 的綠燈輸入比較 data_issues 不含／含規則無效註記。"""
    cov_ok = {"unregistered_exposed": 0, "owner_ratio": 1, "version_known_ratio": 1, "eol_exposed": 0}
    a = compute_light(risks=[], signals=[], open_alerts=[], coverage=cov_ok, data_issues=[])
    b = compute_light(risks=[], signals=[], open_alerts=[], coverage=cov_ok, data_issues=[HINT_NOTE])
    assert a == b and a[0] == "green"
