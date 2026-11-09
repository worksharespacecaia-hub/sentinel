import copy
import shutil

from schemas import Report
from tests.conftest import AS_OF, risk
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
