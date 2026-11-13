"""Phase 7 情境驗收（第 8 節）：每個情境以確定性流程產出預期結果；「修復後」以 after-fix fixture 驗證。"""
import json
from datetime import datetime, timezone

import pytest

from context import build_ctx
from tests.conftest import AS_OF, risk
from tools.loaders import FIXTURE_SCANNERS, FIXTURE_TARGET
from tools.overlay import AFTER_FIX_DIR, load_fix, materialize
from tools.pipeline import EvalInput, evaluate
from tools.reconcile import visibility_ok
from tools.report_builder import assemble

FIX_AS_OF = datetime(2026, 11, 10, 6, 0, tzinfo=timezone.utc)    # 修正 PR 合併、重產快照後的下一次 daily


def scenario_result(monkeypatch, name):
    for k in ("TARGET_DIR", "SCANNERS_DIR", "ADVISORY_ID", "ASSETS", "TARGET_SHA", "EXECUTION_MODE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AS_OF", AS_OF.isoformat())
    ctx = build_ctx(scenario=name)
    res = evaluate(ctx.eval_input())
    built = assemble(res, run_id="t", scenario=name, trigger_source="manual", scope=ctx.scope, generated_at=AS_OF)
    return res, built


def intel_report(built, event_id):
    return next(r for r in built["intel_reports"] if r["event"]["id"] == event_id)


# ── P1 情境 ──────────────────────────────────────────────

def test_peer_incident_checks_third_party_key(monkeypatch):
    res, built = scenario_result(monkeypatch, "peer-incident")
    mail = risk(res, "mail-api-key:C-THIRD-PARTY-KEY-ROTATION")
    assert "demo-peer-mail-key" in mail["matched_events"]
    assert any("天未輪替" in e and int(e.split("：")[1].split(" 天")[0]) > 365 for e in mail["evidence"])   # 超過一年
    rep = intel_report(built, "demo-peer-mail-key")
    assert rep["affected_count"] >= 1 and rep["status"] == "open"            # 受影響、待處理
    assert any("輪替" in json.dumps(s, ensure_ascii=False) for s in rep["solutions"])
    assert rep["notice"]["needed"] is True and rep["notice"]["draft"]
    assert rep["event"]["kind"] == "demo"          # 示範事件，不得計入同業事件加分
    assert not any(b["factor"] == "同業事件命中" and "demo-peer-mail-key" in b["reason"] for b in mail["breakdown"])


def test_early_signal_is_red_and_links_both_signals(monkeypatch):
    res, built = scenario_result(monkeypatch, "early-signal")
    assert res["light"] == "red"
    assert any("疑似已發生外洩" in r for r in res["light_reasons"])
    breach = [s for s in res["signals"] if s.get("suspected_breach")]
    assert breach and breach[0].get("related_event") == "evt-91app-2026-10"
    kinds = {s["id"] for s in res["signals"]}
    assert any("BULK" in k or "READ" in k for k in kinds), kinds        # 凌晨大量讀取也被評估
    top = res["risks"][0]
    assert top["category"] == "signal" and top["title"].startswith("疑似已發生外洩")


def test_php2shell_matches_marketing_high_and_phpmyadmin_medium(monkeypatch):
    res, built = scenario_result(monkeypatch, "php2shell")
    mk, pma = risk(res, "marketing-site:php:vuln"), risk(res, "phpmyadmin:php:vuln")
    assert (mk["score"], mk["level"]) == (9, "high") and (pma["score"], pma["level"]) == (4, "medium")
    assert "adv-php-2026-10-21" in mk["matched_events"] and "adv-php-2026-10-21" in pma["matched_events"]
    rep = intel_report(built, "adv-php-2026-10-21")
    assert {i["asset_id"] for i in rep["impacts"] if i["verdict"] == "affected"} >= {"marketing-site", "phpmyadmin"}
    assert rep["solutions"]


def test_intel_demo_five_reports_do_not_touch_official(monkeypatch):
    res, built = scenario_result(monkeypatch, "intel-demo")
    demo = [r for r in built["intel_reports"] if r["event"]["kind"] == "demo"]
    assert len(demo) == 5
    levels = sorted(r["max_level"] or r["status"] for r in demo)
    assert levels.count("high") == 2 and levels.count("medium") == 1
    assert {r["status"] for r in demo} >= {"not_affected", "need_check"}
    assert not any(r["event"]["kind"] in ("archive", "live") for r in built["intel_reports"])
    assert build_ctx(scenario="intel-demo").output_dir == "scenarios/intel-demo"


# ── 「修復後」情境 ───────────────────────────────────────

@pytest.fixture(scope="module")
def baseline_prev():
    base = evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS))
    return {r["id"]: r for r in base["risks"]}


def after_fix(name, tmp_path, prev, *, edit=None, open_alerts=()):
    target, scanners = materialize(name, tmp_path / name)
    if edit:
        edit(target)
    return evaluate(EvalInput(target_root=target, as_of=FIX_AS_OF, scanners_dir=scanners, prev_risks=prev,
                              open_alerts=list(open_alerts)))


def test_fixture_layout_is_overlay_only():
    for name in ("partial", "full"):
        fix = load_fix(name)
        assert fix["expect"]["light"] in ("red", "yellow", "green")
        assert not (AFTER_FIX_DIR / name / "target" / ".fixture.json").exists()    # 沿用 baseline 的 target_sha 紀錄
        for p in (AFTER_FIX_DIR / name).rglob("*"):
            if p.is_file():
                assert "DEMO-FAKE" not in p.read_text(encoding="utf-8")


def test_partial_fix_only_clears_matching_risks(tmp_path, baseline_prev):
    fix = load_fix("partial")["expect"]
    res = after_fix("partial", tmp_path, baseline_prev)
    assert res["complete"] is True and res["light"] == fix["light"]
    for rid in fix["fixed"]:
        r = risk(res, rid)
        assert r["status"] == "fixed" and r["verification_evidence"], rid
    for rid in fix["still_high"]:
        r = risk(res, rid)
        assert (r["status"], r["level"]) == ("open", "high"), rid
    for node in fix["no_path_through"]:
        assert not any(node in p["nodes"] for p in res["paths"]["paths"])
    assert any(p["nodes"][-1] == "member-db-prod" for p in res["paths"]["paths"])   # 其他攻擊鏈仍在
    fixed = {r["id"] for r in res["risks"] if r["status"] == "fixed"}
    assert fixed == set(fix["fixed"])                                                # 只解除對應風險


def test_revocation_needs_evidence_when_history_keeps_old_secret(tmp_path, baseline_prev):
    def drop_evidence(target):
        p = target / "ops" / "snapshots" / "secrets.json"
        secrets = json.loads(p.read_text(encoding="utf-8"))
        for s in secrets:
            if s["id"] == "order-db-prod-cred":
                s.pop("revocation_evidence")          # 只在清冊寫 revoked、HEAD 移除舊值，沒有撤銷證據
        p.write_text(json.dumps(secrets, ensure_ascii=False), encoding="utf-8")

    res = after_fix("partial", tmp_path, baseline_prev, edit=drop_evidence)
    sec = risk(res, "gitlab:C-SECRET-IN-GIT")
    assert sec["status"] == "open"            # 入口已關閉所以不在攻擊鏈上（分數下降），但金鑰仍有效，不能標 fixed
    assert any(i["source"] == "secrets.json:order-db-prod-cred" and i["status"] == "unverified" for i in res["data_issues"])
    assert res["graph"].nodes["order-db-prod-cred"]["status"] == "active"
    # 有撤銷證據的同一份 fixture 才解除
    ok = after_fix("partial", tmp_path / "ok", baseline_prev)
    assert risk(ok, "gitlab:C-SECRET-IN-GIT")["status"] == "fixed"


def test_full_fix_drops_to_yellow_only_after_alerts_closed(tmp_path, baseline_prev):
    fix = load_fix("full")["expect"]
    res = after_fix("full", tmp_path, baseline_prev)
    assert res["complete"] is True and res["light"] == fix["light"] == "yellow"
    base_high = [rid for rid, r in baseline_prev.items() if r["level"] == "high"]
    assert base_high and all(risk(res, rid)["status"] == "fixed" for rid in base_high)
    assert not [r for r in res["risks"] if r["level"] == "high" and r["status"] in ("open", "need_check")]
    assert res["paths"]["paths"] == []
    assert visibility_ok(res["recon"]["coverage"])[0] is True
    assert res["light_reasons"] and all("中風險" in r for r in res["light_reasons"])

    real = {"level": "high", "status": "open", "simulated": False}
    for still_open in (real, {**real, "status": "contained"}):
        blocked = after_fix("full", tmp_path / still_open["status"], baseline_prev, open_alerts=[still_open])
        assert blocked["light"] == "red" and any("即時高風險告警" in r for r in blocked["light_reasons"])
    closed = after_fix("full", tmp_path / "closed", baseline_prev,
                       open_alerts=[{**real, "status": "closed"}, {**real, "simulated": True}])
    assert closed["light"] == "yellow"


def test_full_fix_without_previous_state_is_not_reported_fixed(tmp_path):
    """沒有前次狀態（例如情境頁單獨執行）時，只會沒有命中，不會無中生有地標成 fixed。"""
    res = after_fix("full", tmp_path, {})
    assert not [r for r in res["risks"] if r["status"] == "fixed"]


def test_registered_saas_clears_previous_shadow_it(tmp_path, baseline_prev):
    res = after_fix("full", tmp_path, baseline_prev)
    assert "saas-quicksite-builder" in res["recon"]["saas_registered"]
    assert risk(res, "saas-quicksite-builder:shadow_it")["status"] == "fixed"


# ── P2 情境：未提供輸入時明確拒絕 ─────────────────────────

@pytest.mark.parametrize("name", ["nas", "insider-path", "mobile-sdk"])
def test_p2_scenarios_are_explicitly_disabled(monkeypatch, capsys, name):
    import run_agent
    from context import ScenarioDisabled
    monkeypatch.delenv("TARGET_DIR", raising=False)
    with pytest.raises(ScenarioDisabled):
        build_ctx(scenario=name)
    assert run_agent.main(["router", "--scenario", name]) == 2
    assert "P2" in capsys.readouterr().err
