import copy

from tools.graph_builder import stored_in_node
from tools.reconcile import identify_device, reconcile, visibility_ok


def test_reconcile_finds_unregistered_assets_and_shadow_api(graph_and_recon):
    _, recon, _ = graph_and_recon
    shadow = {r["asset_id"] for r in recon["records"] if r["conclusion"] == "shadow_it"}
    assert shadow == {"internal-tool", "marketing-site", "nas-office-01", "saas-quicksite-builder"}
    assert all(r["level_floor"] == "high" for r in recon["records"] if r["conclusion"] == "shadow_it")
    assert [a["path"] for a in recon["shadow_apis"]] == ["/internal/v1/members/export"]


def test_ci_deploy_reconcile_only_for_ci_services(graph_and_recon):
    _, recon, _ = graph_and_recon
    by = {r["asset_id"]: r for r in recon["records"]}
    assert by["storefront"]["conclusion"] == "normal" and by["storefront"]["deployed_via_ci"] is True
    assert by["laptop-eng-07"]["ci_applicable"] is False      # 設備不做部署對帳
    assert by["order-db-prod"]["deployed_via_ci"] is None


def test_non_ci_prod_and_missing_runtime(target_data):
    data = copy.deepcopy(target_data)
    data.deployments = [d for d in data.deployments if d["service_id"] != "report-svc"]
    by = {r["asset_id"]: r for r in reconcile(data)["records"]}
    assert by["report-svc"]["conclusion"] == "non_ci_prod" and by["report-svc"]["level_floor"] == "high"
    data2 = copy.deepcopy(target_data)
    data2.snapshots.pop("runtime.json")
    rec2 = {r["asset_id"]: r for r in reconcile(data2)["records"]}
    assert rec2["gitlab"]["conclusion"] in ("data_missing", "normal")


def test_device_fingerprint():
    ident = identify_device({"mac_vendor": "Synology Incorporated", "http_title": "Synology DiskStation",
                             "banner": "DS920+ DSM 7.2.1-69057 Update 5"})
    assert ident["product"] == "synology-dsm" and ident["version"] == "7.2.1-69057 Update 5"
    assert identify_device({"mac_vendor": "Dell"}) is None


def test_stored_in_mapping():
    assert stored_in_node("git:config/db.yml") == "gitlab"
    assert stored_in_node("device:laptop-eng-07") == "laptop-eng-07"
    assert stored_in_node("app:brand-app/src/config.ts") == "brand-app"
    assert stored_in_node("secrets-manager") is None


def test_visibility_thresholds():
    ok = {"unregistered_exposed": 0, "owner_ratio": 0.95, "version_known_ratio": 0.9, "eol_exposed": 0}
    assert visibility_ok(ok)[0]
    assert not visibility_ok({**ok, "owner_ratio": 0.89})[0]
    assert not visibility_ok({**ok, "unregistered_exposed": 1})[0]
    assert not visibility_ok({**ok, "version_known_ratio": None})[0]   # 無法計算分母 → 未達標
    assert not visibility_ok({**ok, "eol_exposed": 1})[0]


def test_baseline_coverage_fails_visibility(graph_and_recon):
    _, recon, _ = graph_and_recon
    cov = recon["coverage"]
    assert cov["unregistered_exposed"] == 3 and cov["eol_exposed"] == 1
    assert not visibility_ok(cov)[0]
