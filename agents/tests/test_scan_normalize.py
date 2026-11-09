import json

from tools.scan_normalize import main


def test_gitleaks_redacted_even_if_raw_has_values(tmp_path):
    raw, out = tmp_path / "raw", tmp_path / "out"
    raw.mkdir()
    secret = "DEMO-FAKE-" + "PASSWORD-0000"
    (raw / "gitleaks.json").write_text(json.dumps([{"RuleID": "demo-fake-secret", "File": "config/db.yml", "StartLine": 4,
                                                    "Secret": secret, "Match": f"url: {secret}", "Fingerprint": "x"}]),
                                       encoding="utf-8")
    assert main(["gitleaks", str(raw), str(out), "--target-sha", "a" * 40, "--run-id", "1"]) == 0
    text = (out / "gitleaks.json").read_text(encoding="utf-8")
    assert secret not in text and "REDACTED" in text
    m = json.loads((out / "gitleaks.manifest.json").read_text(encoding="utf-8"))
    assert m["status"] == "ok" and m["target_sha"] == "a" * 40 and "gitleaks.json" in m["files"]


def test_missing_raw_output_is_failed_not_empty(tmp_path):
    raw, out = tmp_path / "raw", tmp_path / "out"
    raw.mkdir()
    assert main(["trivy", str(raw), str(out), "--target-sha", "a" * 40, "--run-id", "1"]) == 1
    m = json.loads((out / "trivy.manifest.json").read_text(encoding="utf-8"))
    assert m["status"] == "failed" and not (out / "trivy.json").exists()


def test_trivy_normalized_per_service(tmp_path):
    raw, out = tmp_path / "raw", tmp_path / "out"
    raw.mkdir()
    (raw / "trivy-storefront.json").write_text(json.dumps({"Results": [{"Target": "package-lock.json", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2025-29927", "PkgName": "next", "InstalledVersion": "14.1.0", "FixedVersion": "14.2.25",
         "Severity": "CRITICAL", "CVSS": {"nvd": {"V3Score": 9.1}}}]}]}), encoding="utf-8")
    (raw / "trivy-version.json").write_text(json.dumps({"Version": "0.57.1", "VulnerabilityDB": {"UpdatedAt": "2026-11-09"}}),
                                            encoding="utf-8")
    assert main(["trivy", str(raw), str(out), "--target-sha", "a" * 40, "--run-id", "1"]) == 0
    data = json.loads((out / "trivy.json").read_text(encoding="utf-8"))
    assert data["results"][0]["target"] == "services/storefront"
    assert data["results"][0]["vulnerabilities"][0]["CVSSv3"] == 9.1
