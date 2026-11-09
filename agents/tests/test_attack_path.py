import copy

from tools.attack_path import find_paths
from tools.findings import build_findings
from tools.graph_builder import build_graph
from tools.intel_match import match_event, merge_findings
from tools.intel_verify import load_events
from tools.common import INTEL_DIR
from tools.reconcile import reconcile


def _nodes(result):
    return {" → ".join(p["nodes"]) for p in result["paths"]["paths"]}


def test_expected_paths(baseline):
    paths = _nodes(baseline)
    assert "internet → internal-tool → gitlab-read-token-internal-tool → gitlab → order-db-prod-cred → order-db-prod" in paths
    assert "laptop-eng-07 → deploy-token-eng07 → deploy-pipeline" in paths
    assert "internet → brand-app → app-api-key → api-gateway → member-db-prod" in paths
    assert not any("phpmyadmin" in p for p in paths)


def test_device_start_is_labelled_assumption(baseline):
    p = next(p for p in baseline["paths"]["paths"] if p["start"] == "laptop-eng-07")
    assert "假設" in p["assumption"]


def test_chain_findings_are_necessary_steps_only(baseline):
    chain = set(baseline["paths"]["chain_finding_ids"])
    assert {"internal-tool:opsbuilder:vuln", "gitlab:C-SECRET-IN-GIT", "laptop-eng-07:C-DEV-DEVICE-TOKEN",
            "brand-app:C-SECRET-IN-GIT"} <= chain
    assert "storefront:next:vuln" not in chain           # 授權繞過不取得主機控制
    assert "marketing-site:php:vuln" not in chain        # 可控制但沒有通往核心資料的前提
    assert "brand-app:android-debuggable" not in chain   # 同資產上的無關問題不加分


def _rebuild(target_data, mutate):
    data = copy.deepcopy(target_data)
    mutate(data)
    recon = reconcile(data)
    g = build_graph(data, recon)
    a2 = build_findings(data, g, recon, kev=set())
    findings = a2["findings"]
    for raw in load_events(INTEL_DIR / "advisories"):
        m = match_event(raw, data=data, g=g, control_results=a2["controls"], findings=findings, coverage=recon["coverage"])
        findings = merge_findings(findings, m["findings"])
    return find_paths(g, findings)


def test_revoking_key_breaks_path(target_data):
    def revoke(data):
        for s in data.snapshots["secrets.json"]:
            if s["id"] == "order-db-prod-cred":
                s["status"] = "revoked"
    res = _rebuild(target_data, revoke)
    assert not any(p["target"] == "order-db-prod" for p in res["paths"])


def test_network_reachable_without_exploit_is_not_a_chain(target_data):
    def patch(data):   # internal-tool 升級到修補版：仍可從 internet 連到，但沒有利用前提
        for r in data.snapshots["runtime.json"]:
            if r["service_id"] == "internal-tool":
                r["components"][0]["version"] = "1.90"
    res = _rebuild(target_data, patch)
    assert not any("internal-tool" in p["nodes"] for p in res["paths"])


def test_unknown_conditions_are_pending_not_chain(target_data):
    def unknown(data):
        data.snapshots["network.json"]["edges"] = [e for e in data.snapshots["network.json"]["edges"]
                                                   if not (e["from"] == "internet" and e["to"] == "internal-tool")]
    res = _rebuild(target_data, unknown)
    assert not any("internal-tool" in p["nodes"] for p in res["paths"])
