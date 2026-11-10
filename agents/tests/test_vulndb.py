"""程式查漏洞資料庫（CISA KEV、NVD）：本地重新比對版本、平台條件、涵蓋不足的註記，以及結果流進風險評分。"""
import json
import shutil
import types

import pytest

import tools.vulndb as vulndb
from tests.conftest import AS_OF, risk
from tools.loaders import FIXTURE_SCANNERS, FIXTURE_TARGET, load_scanners
from tools.pipeline import EvalInput, evaluate
from tools.version_match import AFFECTED, NOT_AFFECTED, UNKNOWN, fixed_available, match
from tools.vulndb import (advisory_from_cve, assess, cpe_name, criteria_matches, fixed_version, normalize_kev,
                          nvd_components, scan_components, trim_cve)

PHP = "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"
PHP_TPL = ["cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*"]
DSM = "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*"
DSM_TPL = ["cpe:2.3:o:synology:diskstation_manager:{version}:*:*:*:*:*:*:*"]
WIN = "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"


def nvd_cve(cid, *matches, platforms=(), cvss=9.8, last="2026-11-01T00:00:00.000", kev=None):
    """NVD 2.0 格式的 CVE。matches：(criteria, {versionStartIncluding: …})。有 platforms 時為 AND 設定。"""
    nodes = [{"operator": "OR", "negate": False,
              "cpeMatch": [{"vulnerable": True, "criteria": c, **rng} for c, rng in matches]}]
    if platforms:
        nodes.append({"operator": "OR", "negate": False, "cpeMatch": [{"vulnerable": False, "criteria": p} for p in platforms]})
    return {"id": cid, "published": "2026-10-01T00:00:00.000", "lastModified": last, "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": f"{cid} description"}],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": cvss}}]},
            "configurations": [{"operator": "AND" if platforms else None, "nodes": nodes}],
            **({"cisaExploitAdd": kev} if kev else {})}


class FakeFetch:
    """依網址片段回應；值為 Exception 時丟出。記錄每次呼叫（不連第三方）。"""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, url, allow, **kw):
        self.calls.append((url, allow, kw))
        for key, val in self.routes.items():
            if key in url:
                if isinstance(val, Exception):
                    raise val
                val = val(url) if callable(val) else val
                return types.SimpleNamespace(status=200, text=json.dumps(val))
        return types.SimpleNamespace(status=404, text="{}")


# ---------------------------------------------------------------- KEV、CPE

def test_normalize_kev_keeps_valid_cves_only():
    raw = {"catalogVersion": "2026.11.09", "dateReleased": "2026-11-09T19:54:37Z", "vulnerabilities": [
        {"cveID": "CVE-2024-4577", "vendorProject": "PHP", "product": "PHP", "dateAdded": "2024-06-12",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "not-a-cve"}, "junk"]}
    kev = normalize_kev(raw)
    assert set(kev["cves"]) == {"CVE-2024-4577"} and kev["cves"]["CVE-2024-4577"]["ransomware"] is True
    assert kev["tool_version"] == "2026.11.09" and kev["count"] == 1
    with pytest.raises(ValueError):
        normalize_kev({"vulnerabilities": []})


def test_criteria_matching_respects_vendor_and_edition():
    tpl = "cpe:2.3:a:gitlab:gitlab:{version}:*:*:*:community:*:*:*"
    assert criteria_matches("cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", tpl)
    assert criteria_matches("cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", tpl)
    assert not criteria_matches("cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*", tpl)   # EE 專屬漏洞不算 CE
    assert not criteria_matches("cpe:2.3:a:hardened-php_project:hardened-php:*:*:*:*:*:*:*:*", PHP_TPL[0])


def test_cpe_name_conversion():
    assert cpe_name(PHP_TPL[0], "8.1.27", "php") == "cpe:2.3:a:php:php:8.1.27:*:*:*:*:*:*:*"
    assert cpe_name(DSM_TPL[0], "7.2.1-69057 Update 5", "synology-dsm") == \
        "cpe:2.3:o:synology:diskstation_manager:7.2.1-69057:*:*:*:*:*:*:*"   # Update 由本地重新比對
    assert cpe_name(PHP_TPL[0], "8.1.27:*:evil", "php") is None and cpe_name(PHP_TPL[0], None, "php") is None


# ---------------------------------------------------------------- 版本比對（NVD 區間）

def test_nvd_interval_semantics():
    rng = [{"start_including": "8.1.0", "end_excluding": "8.1.29"}]
    assert match("8.1.27", rng, "php") == AFFECTED and match("8.1.29", rng, "php") == NOT_AFFECTED
    assert match("8.1.29", [{"start_including": "8.1.0", "end_including": "8.1.29"}], "php") == AFFECTED
    assert match("8.1.27", [{"start_excluding": "8.1.27"}], "php") == NOT_AFFECTED
    assert match("8.4.27", [{"start_including": "7.3.0"}], "php") == AFFECTED        # 沒有上界：之後所有版本
    assert match("5.2.1", [{"exact": "5.2.1"}], "generic") == AFFECTED
    assert match("5.2.2", [{"exact": "5.2.1"}], "generic") == NOT_AFFECTED
    assert match("8.1.27", [{"start_including": "8.1.x"}], "php") == UNKNOWN
    # DSM：Update 編號要比對（NVD 伺服器端會忽略）
    dsm = "7.2.1-69057 Update 5"
    assert match(dsm, [{"start_including": "7.2.1-69057", "end_excluding": "7.2.1-69057-2"}], "synology-dsm") == NOT_AFFECTED
    assert match(dsm, [{"start_including": "7.2.1-69057", "end_excluding": "7.2.1-69057-6"}], "synology-dsm") == AFFECTED
    # 原有 OSV 區間語意不變：fixed 為 null 只涵蓋同一分支
    assert match("8.2.0", [{"introduced": "8.1.0", "fixed": None}], "php") == NOT_AFFECTED
    assert fixed_available("8.1.27", rng, "php") is True
    assert fixed_available("8.1.27", [{"start_including": "8.1.0", "end_including": "8.1.29"}], "php") is None
    assert match("1.2.3", [{"end_excluding": "2.0.0"}], "npm") == UNKNOWN            # NVD 區間不用在 npm


def test_assess_platform_condition_unbounded_and_out_of_range():
    win = trim_cve(nvd_cve("CVE-2024-4577", (PHP, {"versionStartIncluding": "8.1.0", "versionEndExcluding": "8.1.29"}),
                           platforms=[WIN]), PHP_TPL)
    a = assess(win, PHP_TPL, "8.1.27", "php")
    assert a["verdict"] == AFFECTED and a["conditional"] is True and a["platforms"] == ["microsoft windows"]
    allv = trim_cve(nvd_cve("CVE-2007-3205", (PHP, {})), PHP_TPL)
    assert assess(allv, PHP_TPL, "8.1.27", "php")["verdict"] == UNKNOWN              # 「所有版本」不能當成確定
    old = trim_cve(nvd_cve("CVE-2024-0001", (PHP, {"versionStartIncluding": "8.1.0", "versionEndExcluding": "8.1.20"})), PHP_TPL)
    assert assess(old, PHP_TPL, "8.1.27", "php") is None
    other = nvd_cve("CVE-2024-0002", ("cpe:2.3:a:hardened-php_project:hardened-php:*:*:*:*:*:*:*:*", {}))
    assert trim_cve(other, PHP_TPL) is None


def test_fixed_version_is_highest_upper_bound_or_unknown():
    ivs = [{"end_excluding": "8.1.29"}, {"end_excluding": "8.2.35"}, {"end_excluding": "8.1.34"}]
    assert fixed_version(ivs, "php") == "8.2.35"
    assert fixed_version([*ivs, {"start_including": "7.3.0"}], "php") is None      # 有漏洞沒有修補版本


# ---------------------------------------------------------------- NVD 查詢

def test_nvd_components_skip_npm_and_list_uncovered(baseline):
    targets, uncovered = nvd_components(baseline["graph"])
    names = {(t["name"], t["version"]) for t in targets}
    assert {("php", "8.1.27"), ("php", "8.4.27"), ("synology-dsm", "7.2.1-69057 Update 5")} <= names
    pg = next(t for t in targets if t["name"] == "postgresql")
    assert pg["asset_ids"] == ["member-db-prod", "order-db-prod", "order-db-test"]      # 同版本只查一次
    assert not any(t["name"] in ("next", "lodash", "express") for t in targets)         # npm 由 Trivy 涵蓋
    assert "opsbuilder" in {u["name"] for u in uncovered}


def test_scan_components_paginates_paces_and_records_failures(monkeypatch):
    monkeypatch.setattr(vulndb, "NVD_PAGE", 1)
    page = {0: nvd_cve("CVE-2026-0001", (PHP, {"versionStartIncluding": "8.1.0", "versionEndExcluding": "8.1.40"})),
            1: nvd_cve("CVE-2026-0002", (PHP, {"versionStartIncluding": "8.1.0", "versionEndExcluding": "8.1.30"}))}

    def php_pages(url):
        i = int(url.rsplit("startIndex=", 1)[1])
        return {"totalResults": 2, "vulnerabilities": [{"cve": page[i]}]}
    fake = FakeFetch({"cpe:2.3:a:php:php:8.1.27": php_pages, "cpe:2.3:a:redis:redis": TimeoutError("slow")})
    paced = []
    targets = [{"name": "php", "version": "8.1.27", "ecosystem": "php", "templates": PHP_TPL, "asset_ids": ["marketing-site"]},
               {"name": "redis", "version": "7.0.15", "ecosystem": "generic",
                "templates": ["cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*"], "asset_ids": ["cache-redis"]}]
    res = scan_components(targets, fetcher=fake, pace=lambda: paced.append(1))
    php, redis = res
    assert php["status"] == "ok" and [c["id"] for c in php["cves"]] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert redis["status"] == "failed" and "TimeoutError" in redis["queries"][0]["reason"]
    assert len(paced) == 3                                   # 每次請求前都經過速率限制
    url, allow, kw = fake.calls[0]
    assert allow == ["services.nvd.nist.gov"] and "isVulnerable" in url and kw["max_bytes"] > 2 * 1024 * 1024


def test_advisory_from_cve_maps_products_and_flags_platform_condition():
    entry = {"added": "2026-11-08", "vendor": "PHP", "product": "PHP", "name": "PHP-CGI Argument Injection"}
    adv = advisory_from_cve(nvd_cve("CVE-2024-4577", (PHP, {"versionStartIncluding": "8.1.0", "versionEndExcluding": "8.1.29"}),
                                    platforms=[WIN]), entry, as_of=AS_OF)
    assert adv["id"] == "kev-cve-2024-4577" and adv["generated_by"] == "kev-nvd" and adv["confidence"] == "confirmed"
    p = adv["products"][0]
    assert p["name"] == "php" and p["known_exploited"] is True
    assert p["affected"] == [{"start_including": "8.1.0", "end_excluding": "8.1.29"}]
    assert adv["requires_manual_check"]                       # 只在 Windows：命中後仍需人工確認
    zyxel = nvd_cve("CVE-2020-29583", ("cpe:2.3:o:zyxel:usg_flex_100_firmware:*:*:*:*:*:*:*:*", {}))
    assert advisory_from_cve(zyxel, entry, as_of=AS_OF) is None   # 不涉及我們的產品


# ---------------------------------------------------------------- 結果流進 A2／A4

def _scanners_with(tmp_path, *, kev=None, nvd=None):
    d = tmp_path / "scanners"
    shutil.copytree(FIXTURE_SCANNERS, d)
    if kev is not None:
        (d / "kev.json").write_text(json.dumps(kev), encoding="utf-8")
    if nvd is not None:
        (d / "nvd.json").write_text(json.dumps(nvd), encoding="utf-8")
    return d


def _nvd_result(name, version, eco, templates, assets, cves):
    return {"name": name, "version": version, "ecosystem": eco, "templates": templates, "asset_ids": assets,
            "status": "ok", "queries": [{"cpe": "x", "status": "ok", "truncated": False}],
            "cves": [trim_cve(c, templates) for c in cves]}


def test_kev_and_nvd_results_flow_into_findings_and_risks(tmp_path):
    kev = {"tool": "kev", "cves": {"CVE-2024-45590": {"added": "2026-11-01"}, "CVE-2026-90001": {"added": "2026-11-08"}}}
    nvd = {"tool": "nvd", "results": [
        _nvd_result("php", "8.1.27", "php", PHP_TPL, ["marketing-site"], [
            nvd_cve("CVE-2026-90001", (PHP, {"versionStartIncluding": "8.1.0", "versionEndExcluding": "8.1.40"}), cvss=9.1),
            nvd_cve("CVE-2024-4577", (PHP, {"versionStartIncluding": "8.1.0", "versionEndExcluding": "8.1.29"}), platforms=[WIN])]),
        _nvd_result("php", "8.4.27", "php", PHP_TPL, ["report-svc"], [
            nvd_cve("CVE-2026-90002", (PHP, {"versionStartIncluding": "8.4.0", "versionEndExcluding": "8.4.30"}), platforms=[WIN])]),
        _nvd_result("synology-dsm", "7.2.1-69057 Update 5", "synology-dsm", DSM_TPL, ["nas-office-01"], [
            nvd_cve("CVE-2024-0854", (DSM, {"versionEndExcluding": "7.2.1-69057-2"}))]),
    ], "uncovered": [{"name": "opsbuilder", "version": "1.88", "asset_ids": ["internal-tool"], "reason": "沒有 CPE 對照"}]}
    res = evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF, scanners_dir=_scanners_with(tmp_path, kev=kev, nvd=nvd)))
    by = {f["id"]: f for f in res["findings"]}
    assert by["member-api:body-parser:vuln"]["known_exploited"] is True               # Trivy 的 CVE 列入 KEV
    mk = by["marketing-site:php:vuln"]                                                # 與 PHP2Shell 事件的發現合併為一筆
    assert {"CVE-2026-90001", "CVE-2024-4577", "evt-php2shell-2026-10"} <= set(mk["advisory_ids"])
    assert mk["known_exploited"] is True and any("需在 microsoft windows 上執行" in e for e in mk["evidence"])
    rs = by["report-svc:php:vuln"]                                                    # 只有平台條件：暫定、待確認
    assert rs["status"] == "provisional" and rs["exploit_conditions"] == "unknown"
    r = risk(res, "report-svc:php:vuln")
    assert r["status"] == "need_check" and r["level"] != "high"
    assert "nas-office-01:synology-dsm:vuln" in by and "CVE-2024-0854" not in by["nas-office-01:synology-dsm:vuln"]["advisory_ids"]
    issues = {(i["source"], i["status"]) for i in res["data_issues"]}
    assert ("scanner/kev", "missing") not in issues and ("scanner/nvd", "uncovered") in issues
    assert all(i.get("required") is False for i in res["data_issues"] if i["source"].startswith("scanner/nvd"))
    assert res["complete"] is True                                                    # 涵蓋不足只是註記


def test_missing_kev_and_nvd_are_noted_but_not_blocking(baseline):
    notes = [i for i in baseline["data_issues"] if i["source"] in ("scanner/kev", "scanner/nvd")]
    assert {i["source"] for i in notes} == {"scanner/kev", "scanner/nvd"}
    assert all(i["required"] is False for i in notes) and baseline["complete"] is True


def test_failed_or_stale_manifest_not_loaded(tmp_path):
    d = tmp_path / "s"
    d.mkdir()
    (d / "kev.json").write_text("{}", encoding="utf-8")                              # 前一次留下的結果
    (d / "kev.manifest.json").write_text(json.dumps({"status": "failed", "reason": "HTTP 503"}), encoding="utf-8")
    (d / "nvd.json").write_text("{}", encoding="utf-8")
    (d / "nvd.manifest.json").write_text(json.dumps({"status": "ok", "valid_until": "2026-11-08T00:00:00Z"}), encoding="utf-8")
    s = load_scanners(d, AS_OF)
    assert s["kev"]["status"] == "failed" and s["nvd"]["status"] == "stale" and s["trivy"]["status"] == "missing"


def test_reusable_scanners_ignore_optional_tool_failures(tmp_path, monkeypatch):
    import context
    state = tmp_path / "daily" / "state" / "scanners"
    state.mkdir(parents=True)
    sha = "a" * 40
    for tool, status in (("trivy", "ok"), ("gitleaks", "ok"), ("checkov", "ok"), ("kev", "failed"), ("nvd", "failed")):
        (state / f"{tool}.manifest.json").write_text(json.dumps(
            {"job": f"scanners-{tool}", "status": status, "target_sha": sha, "valid_until": "2026-11-10T00:00:00Z"}),
            encoding="utf-8")
    monkeypatch.setattr(context, "DATA_DIR", tmp_path)
    assert context.reusable_scanners(sha, AS_OF) == state
    (state / "trivy.manifest.json").write_text(json.dumps({"job": "scanners-trivy", "status": "failed"}), encoding="utf-8")
    assert context.reusable_scanners(sha, AS_OF) is None


def test_scan_normalize_nvd_total_failure_is_tool_failure(tmp_path):
    from tools.scan_normalize import main
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "nvd.json").write_text(json.dumps({"tool": "nvd", "results": [
        {"name": "php", "version": "8.1.27", "status": "failed", "queries": [], "cves": []}]}), encoding="utf-8")
    assert main(["nvd", str(raw), str(tmp_path / "out"), "--target-sha", "a" * 40, "--run-id", "1"]) == 1
    m = json.loads((tmp_path / "out" / "nvd.manifest.json").read_text(encoding="utf-8"))
    assert m["status"] == "failed" and not (tmp_path / "out" / "nvd.json").exists()
    (raw / "kev.json").write_text(json.dumps({"catalogVersion": "v", "vulnerabilities": [{"cveID": "CVE-2024-4577"}]}),
                                  encoding="utf-8")
    assert main(["kev", str(raw), str(tmp_path / "out"), "--target-sha", "a" * 40, "--run-id", "1"]) == 0
    assert "CVE-2024-4577" in json.loads((tmp_path / "out" / "kev.json").read_text(encoding="utf-8"))["cves"]


def test_nvd_without_any_component_is_not_zero_findings(tmp_path):
    """資產清單缺失時圖譜是空的：不能把「沒有元件」當成「查過、沒有漏洞」。"""
    from tools.scan_normalize import main
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "nvd.json").write_text(json.dumps({"tool": "nvd", "results": [], "uncovered": []}), encoding="utf-8")
    assert main(["nvd", str(raw), str(tmp_path / "out"), "--target-sha", "a" * 40, "--run-id", "1"]) == 1
    with pytest.raises(SystemExit):
        vulndb.main(["nvd", str(raw), "--target", str(tmp_path / "no-such-target")])
