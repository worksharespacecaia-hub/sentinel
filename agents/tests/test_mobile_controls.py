import copy

import pytest

from tools.controls import CHECKS, ControlContext, load_controls, run_controls
from tools.findings import triage_secrets
from tools.mobile_rules import affected_installations, check_gradle, check_manifest


def test_manifest_rules(target_data):
    rules = {i["rule"] for i in check_manifest(target_data.files["services/brand-app/android/app/src/main/AndroidManifest.xml"])}
    assert rules == {"android-debuggable", "android-cleartext", "android-exported-component"}
    exported = next(i for i in check_manifest(target_data.files["services/brand-app/android/app/src/main/AndroidManifest.xml"])
                    if i["rule"] == "android-exported-component")
    assert "MainActivity" not in exported["evidence"]          # 啟動畫面本來就要 exported
    assert check_gradle(target_data.files["services/brand-app/android/app/build.gradle"])[0]["rule"] == "target-sdk-outdated"


def _row(brand, platform, version, n, sdk="2.3.1", observed="2026-11-09"):
    return {"brand_id": brand, "platform": platform, "app_version": version, "active_installations": n,
            "observed_at": observed, "sdks": {"@demo-vendor/push-sdk": sdk}}


def test_installations_summed_per_brand_not_multiplied():
    rows = [_row("A", "ios", "3.4.0", 100), _row("B", "android", "3.4.0", 40)]
    res = affected_installations(rows, lambda r: True)
    assert res["affected_installations"] == 140 and res["affected_brands"] == 2
    assert "不代表不重複使用者" in res["note"]


def test_installations_multi_platform_zero_and_duplicates():
    rows = [_row("A", "ios", "3.4.0", 100), _row("A", "android", "3.4.0", 60), _row("A", "ios", "3.4.0", 100),
            _row("B", "ios", "3.2.0", 0), _row("C", "ios", "2.9.1", 50, sdk="1.9.2")]
    res = affected_installations(rows, lambda r: r["sdks"]["@demo-vendor/push-sdk"].startswith("2."))
    assert res["affected_installations"] == 160          # 重複列只計一次
    assert res["affected_brands"] == 1                   # 零安裝的品牌不計入
    assert res["total_installations"] == 210


def test_every_control_has_check_function():
    controls = load_controls()
    assert {c["check"] for c in controls} <= set(CHECKS)
    assert len(controls) == 10 and all(isinstance(c["base_points"], int) for c in controls)


@pytest.fixture()
def ctx(graph_and_recon):
    g, recon, data = graph_and_recon
    return ControlContext(data=data, graph=g, recon=recon, secret_findings=triage_secrets(data), as_of=data.as_of)


EXPECTED_FAIL = {
    "C-SECRET-IN-GIT": {"gitlab", "brand-app"},
    "C-INTERNAL-TOOL-EXPOSED": {"internal-tool", "nas-office-01"},
    "C-NET-SEGMENT": {"order-db-prod"},
    "C-THIRD-PARTY-KEY-ROTATION": {"mail-api-key"},
    "C-NON-CI-DEPLOY": {"ai-code-assistant"},
    "C-DEV-DEVICE-TOKEN": {"laptop-eng-07"},
    "C-BACKUP-ISOLATION": {"nas-office-01"},
    "C-CLOUD-STORAGE-PUBLIC": {"firebase-brand-app-storage", "order-exports-bucket"},
    "C-CACHE-TLS": {"cache-redis"},
}


def test_baseline_control_results(ctx):
    res = run_controls(ctx)
    for cid, assets in EXPECTED_FAIL.items():
        assert res[cid]["status"] == "fail", cid
        assert {a["asset_id"] for a in res[cid]["assets"]} == assets, cid
    assert res["C-APP-SDK"]["status"] == "pass"            # daily 沒有 SDK 漏洞公告


def test_controls_unknown_when_data_missing(ctx):
    c = copy.copy(ctx)
    c.secret_findings = None
    assert CHECKS["secret_in_git"](c)["status"] == "unknown"
    c2 = copy.copy(ctx)
    c2.data = copy.deepcopy(ctx.data)
    for name in ("network.json", "secrets.json", "backups.json", "mdm.json", "app-versions.json"):
        c2.data.snapshots.pop(name)
    for check in ("internal_tool_exposed", "net_segment", "third_party_key_rotation", "dev_device_token", "backup_isolation", "app_sdk"):
        assert CHECKS[check](c2)["status"] == "unknown", check


def test_controls_pass_cases(ctx):
    c = copy.copy(ctx)
    c.data = copy.deepcopy(ctx.data)
    for s in c.data.snapshots["secrets.json"]:
        if s.get("vendor"):
            s.update(last_rotated="2026-10-01", ip_allowlist=True)
    for b in c.data.snapshots["backups.json"]:
        b.update(isolated=True, last_restore_test="2026-10-01")
    for d in c.data.snapshots["mdm.json"]["devices"]:
        d["sensitive_files"] = []
    assert CHECKS["third_party_key_rotation"](c)["status"] == "pass"
    assert CHECKS["backup_isolation"](c)["status"] == "pass"
    assert CHECKS["dev_device_token"](c)["status"] == "pass"


def test_secret_triage_keeps_fixture_and_env(target_data):
    s = {x["credential_id"]: x for x in triage_secrets(target_data)}
    assert s["order-db-prod-cred"]["env"] == "prod" and s["order-db-prod-cred"]["fixture"] is True
    assert s["order-db-test-cred"]["env"] == "test"
    assert s["app-api-key"]["asset_id"] == "brand-app"
    assert all("DEMO-FAKE" not in x["location"] for x in s.values())
