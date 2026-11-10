"""A2 弱點掃描的確定性部分：解析已遮蔽的掃描結果，加上規則檢查，產出 Finding。

Subagents（dependency-analyst、secret-analyst…）只補充說明；版本、環境判定與基礎分都以這裡的程式結果為準。
掃描結果在進入 artifact、LLM、快取或 public/data 之前一律不含金鑰值。
"""
from __future__ import annotations

import re

import networkx as nx

from tools.aliases import normalize
from tools.common import iso, stable_id
from tools.controls import CATEGORY, ControlContext, run_controls
from tools.eol import eol_status
from tools.loaders import TargetData
from tools.mobile_rules import check_gradle, check_manifest, detect_clone_apps
from tools.vulndb import assess, fixed_version, kev_ids

SECRET_VALUE_RE = re.compile(r"DEMO-FAKE-[A-Z0-9-]{4,}|(?i:(password|secret|token|key)\s*[:=]\s*\S{8,})")


def redact(text: str) -> str:
    return SECRET_VALUE_RE.sub("REDACTED", text)


def _yaml_env_at(text: str | None, line: int) -> str | None:
    if not text:
        return None
    lines = text.splitlines()
    for i in range(min(line, len(lines)) - 1, -1, -1):
        m = re.match(r"^([A-Za-z_][\w-]*):\s*$", lines[i])
        if m:
            key = m.group(1).lower()
            return {"production": "prod", "prod": "prod", "test": "test", "staging": "test"}.get(key, "unknown")
    return None


def triage_secrets(data: TargetData) -> list[dict] | None:
    """secret-triage 的確定性版本。DEMO-FAKE 只代表 fixture，不代表可忽略；modeled_env 依模擬環境判斷。"""
    gl = data.scanners.get("gitleaks") or {}
    if gl.get("status") != "ok":
        return None
    secrets = data.snap("secrets.json", []) or []
    out = []
    for f in (gl.get("data") or {}).get("findings", []):
        path, line = f.get("File", ""), int(f.get("StartLine") or 0)
        file_text = data.files.get(path)
        env = _yaml_env_at(file_text, line) if path.endswith((".yml", ".yaml")) else None
        cred = None
        for s in secrets:
            loc = s.get("stored_in", "")
            if loc == f"git:{path}" and (env is None or s.get("env") == env):
                cred = s
                break
            if loc.startswith("app:") and path.endswith(loc[4:]):
                cred = s
                break
        holder = "brand-app" if cred and cred["stored_in"].startswith("app:") else "gitlab"
        line_text = (file_text or "").splitlines()[line - 1] if file_text and 0 < line <= len(file_text.splitlines()) else ""
        secret_type = "postgres-connection-string" if "postgres://" in line_text else "api-key"
        modeled_env = (cred or {}).get("env") or env or "unknown"
        out.append({
            "id": stable_id("secret", (cred or {}).get("id") or f"{path}#{f.get('Fingerprint', '')[-8:]}"),
            "location": f"{path}:{line}", "secret_type": secret_type, "env": modeled_env,
            "grants": (cred or {}).get("grants", []), "is_test_value": False, "fixture": True,
            "modeled_env": modeled_env, "credential_id": (cred or {}).get("id"),
            "credential_status": (cred or {}).get("status", "unknown"), "confidence": "high" if cred else "low",
            "asset_id": holder, "rule": f.get("RuleID"), "commit": (f.get("Commit") or "")[:12],
        })
    return out


def _finding(data: TargetData, **kw) -> dict:
    base = {"control_id": None, "status": "confirmed", "cvss": None, "base_points": None, "credential_id": None,
            "level_floor": None, "observed_at": iso(data.as_of), "source_sha": data.target_sha, "vuln_id": None,
            "component": None, "known_exploited": None, "eol_no_fix": False, "impact": None, "advisory_ids": []}
    base.update(kw)
    return base


def trivy_findings(data: TargetData, kev: set[str]) -> list[dict]:
    tv = data.scanners.get("trivy") or {}
    if tv.get("status") != "ok":
        return []
    grouped: dict[tuple[str, str, str], list[dict]] = {}
    for res in (tv.get("data") or {}).get("results", []):
        asset = res["target"].split("/")[-1]
        for v in res.get("vulnerabilities", []):
            grouped.setdefault((asset, v["PkgName"], v["InstalledVersion"]), []).append(v)
    out = []
    for (asset, pkg, ver), vulns in sorted(grouped.items()):
        vulns.sort(key=lambda v: (-(v.get("CVSSv3") or 0), v["VulnerabilityID"]))
        primary = vulns[0]
        ids = [v["VulnerabilityID"] for v in vulns]
        exploited = any(i in kev for i in ids)
        out.append(_finding(
            data, id=stable_id(asset, pkg, "vuln"), asset_id=asset, category="vuln",
            title=f"{pkg} {ver} 有 {len(vulns)} 個已知漏洞（最高 CVSS {primary.get('CVSSv3')}，{primary['VulnerabilityID']}）",
            evidence=[f"trivy: services/{asset} {pkg}@{ver}", f"修補版本：{primary.get('FixedVersion') or '無'}"],
            source="trivy", cvss=primary.get("CVSSv3"), vuln_id=primary["VulnerabilityID"], component=pkg,
            known_exploited=exploited, advisory_ids=ids, version=ver, fixed_version=primary.get("FixedVersion")))
    return out


def kev_catalog(data: TargetData) -> set[str]:
    """CISA KEV 全集（scanners 的 kev 工具）。沒有取得時為空集合，報告另外註明涵蓋不足。"""
    kv = data.scanners.get("kev") or {}
    return kev_ids(kv.get("data")) if kv.get("status") == "ok" else set()


def nvd_findings(data: TargetData, graph: nx.MultiDiGraph, kev: set[str]) -> list[dict]:
    """NVD 候選 CVE 在本地重新比對版本後的發現。確定受影響 → confirmed；只有平台條件或版本無法判斷 → 暫定且待確認。"""
    nv = data.scanners.get("nvd") or {}
    if nv.get("status") != "ok":
        return []
    out = []
    for res in (nv.get("data") or {}).get("results", []):
        if res.get("status") != "ok":
            continue
        name, ver, eco, templates = res["name"], res["version"], res["ecosystem"], res.get("templates") or []
        rows = []
        for c in res.get("cves") or []:
            a = assess(c, templates, ver, eco)
            if a:
                rows.append({**c, **a})
        if not rows:
            continue
        rows.sort(key=lambda r: (-(r.get("cvss") or 0), r["id"]))
        sure = [r for r in rows if r["verdict"] == "affected" and not r["conditional"]]
        maybe = [r for r in rows if r not in sure]
        exploited = [r["id"] for r in sure if r["id"] in kev or r.get("kev_added")]
        primary = (sure or maybe)[0]
        fix = fixed_version([r["interval"] for r in sure], eco) if sure else None
        if sure:
            title = f"{name} {ver} 有 {len(sure)} 個已知漏洞（NVD，最高 CVSS {primary.get('cvss')}，{primary['id']}）"
        else:
            title = f"{name} {ver} 有 {len(maybe)} 個漏洞需確認執行環境或版本（NVD）"
        evidence = [f"nvd: {name}@{ver} 依 CPE 取得候選後，本地重新比對版本（{len(sure)} 確定、{len(maybe)} 需確認）",
                    f"修補版本：{fix or '無法確定（部分漏洞沒有修補版本或範圍不明）'}"]
        if exploited:
            evidence.append(f"已遭實際利用（CISA KEV）：{'、'.join(exploited[:5])}")
        for r in maybe[:5]:
            why = f"需在 {'、'.join(r['platforms'])} 上執行" if r["conditional"] else "NVD 版本範圍無法判斷"
            evidence.append(f"需確認：{r['id']}（{why}{'；已列入 KEV' if r['id'] in kev or r.get('kev_added') else ''}）")
        for asset in res.get("asset_ids") or []:
            node = graph.nodes[asset] if asset in graph else None
            if not node or not any(normalize(c.get("name")) == name and c.get("version") == ver for c in node.get("components", [])):
                continue                               # 圖譜已不是這個版本（例如掃描後又更新），不沿用
            out.append(_finding(
                data, id=stable_id(asset, name, "vuln"), asset_id=asset, category="vuln", title=title, evidence=evidence,
                source="nvd", cvss=primary.get("cvss"), vuln_id=primary["id"], component=name,
                known_exploited=bool(exploited), advisory_ids=[r["id"] for r in rows], version=ver, fixed_version=fix,
                status="confirmed" if sure else "provisional", exploit_conditions=None if sure else "unknown"))
    return out


def coverage_issues(data: TargetData) -> list[dict]:
    """KEV／NVD 涵蓋不足：列在報告的資料問題中，但不影響完整性與燈號（required=False）。"""
    issues = []
    kv = data.scanners.get("kev") or {}
    if kv.get("status") != "ok":
        issues.append({"source": "scanner/kev", "status": kv.get("status", "missing"), "required": False,
                       "impact": "「已遭實際利用」只依已收錄的事件與公告標記，CISA KEV 新列入的漏洞不會加分"})
    nv = data.scanners.get("nvd") or {}
    if nv.get("status") != "ok":
        issues.append({"source": "scanner/nvd", "status": nv.get("status", "missing"), "required": False,
                       "impact": "執行環境與設備（PHP、NAS、資料庫等）的 CVE 只能靠情資事件比對"})
        return issues
    d = nv.get("data") or {}
    failed = [f"{r['name']} {r['version']}" for r in d.get("results", []) if r.get("status") != "ok"]
    if failed:
        issues.append({"source": "scanner/nvd", "status": "failed", "required": False,
                       "impact": f"NVD 查詢失敗：{'、'.join(failed[:8])}；這些元件的 CVE 只能靠情資事件比對"})
    truncated = [f"{r['name']} {r['version']}" for r in d.get("results", [])
                 if any(q.get("truncated") for q in r.get("queries") or [])]
    if truncated:
        issues.append({"source": "scanner/nvd", "status": "partial", "required": False,
                       "impact": f"NVD 結果過多被截斷：{'、'.join(truncated[:8])}"})
    uncovered = [f"{u['name']} {u.get('version') or '版本未知'}" for u in d.get("uncovered", [])]
    if uncovered:
        issues.append({"source": "scanner/nvd", "status": "uncovered", "required": False,
                       "impact": f"NVD 未涵蓋（沒有 CPE 對照或版本未知）：{'、'.join(uncovered[:10])}；只能靠情資事件比對"})
    return issues


def eol_findings(data: TargetData, graph: nx.MultiDiGraph) -> list[dict]:
    out = []
    for nid, node in graph.nodes(data=True):
        for c in node.get("components", []):
            st = eol_status(c.get("name"), c.get("version"), data.as_of)
            if not st["eol"]:
                continue
            exposed = bool(node.get("exposed_to_internet"))
            out.append(_finding(
                data, id=stable_id(nid, c["name"], "eol"), asset_id=nid, category="eol",
                title=f"{c['name']} {c['version']} 已停止支援（{st['eol_date']}）",
                evidence=[f"runtime.json: {nid} {c['name']} {c['version']}", f"eol.json: {st['cycle']} 支援至 {st['eol_date']}"],
                source="eol", component=c["name"], rule_key="eol:exposed" if exposed else "eol:internal"))
    return out


def mobile_findings(data: TargetData) -> list[dict]:
    out = []
    issues = check_manifest(data.files.get("services/brand-app/android/app/src/main/AndroidManifest.xml"))
    issues += check_gradle(data.files.get("services/brand-app/android/app/build.gradle"))
    for i in issues:
        out.append(_finding(data, id=stable_id("brand-app", i["rule"]), asset_id="brand-app", category="mobile",
                            title=i["title"], evidence=[i["evidence"]], source="mobile_rules", rule_key=f"mobile:{i['rule']}"))
    for k in data.snap("mobile-keys.json", []) or []:
        if k.get("type") == "push_key" and str(k.get("stored_in", "")).startswith("share:") or "all-office-staff" in k.get("accessible_by", []):
            out.append(_finding(data, id=stable_id(k["id"], "shared-storage"), asset_id=k["id"], category="identity",
                                title=f"{k['id']} 存放在共用磁碟，所有辦公室人員可取用",
                                evidence=[f"mobile-keys.json: {k['id']} stored_in {k['stored_in']}；accessible_by {', '.join(k.get('accessible_by', []))}"],
                                source="identity_rules", credential_id=k["id"], rule_key="mobile:signing-or-push-key-shared"))
    apps = (data.snap("apps.json", {}) or {}).get("apps", [])
    brands = {a["brand_id"]: a["brand_name"] for a in apps}
    developer = apps[0]["developer"] if apps else ""
    for c in detect_clone_apps(data.snap("app-store-scan.json"), developer, brands):
        out.append(_finding(data, id=stable_id("clone", c["package"]), asset_id=f"clone:{c['package']}", category="clone_app",
                            title=f"商店上有冒用「{brands[c['brand_id']]}」的山寨 App：{c['app_name']}",
                            evidence=[f"app-store-scan.json: {c['store']} {c['package']}（開發者 {c['developer']}，圖示相似度 {c['icon_similarity']}）"],
                            source="app_store_rules", brand_id=c["brand_id"]))
    return out


def reconcile_findings(data: TargetData, recon: dict) -> list[dict]:
    out = []
    for r in recon["records"]:
        if r["conclusion"] == "shadow_it":
            name = r.get("display_name") or r["asset_id"]
            out.append(_finding(data, id=stable_id(r["asset_id"], "shadow_it"), asset_id=r["asset_id"], category="shadow_it",
                                title=f"未登記的資產：{name}", evidence=[f"對帳：{r['reason']}"], source="reconcile",
                                level_floor="high", floor_reason="對帳：影子 IT"))
        elif r["conclusion"] in ("no_owner", "unobserved", "stale_inventory", "non_ci_prod"):
            out.append(_finding(data, id=stable_id(r["asset_id"], r["conclusion"]), asset_id=r["asset_id"], category="config",
                                title=f"對帳異常：{r['label']}", evidence=[f"對帳：{r['reason']}"], source="reconcile",
                                level_floor=r["level_floor"], floor_reason=f"對帳：{r['label']}", rule_key=f"reconcile:{r['conclusion']}"))
    for api in recon["shadow_apis"]:
        out.append(_finding(data, id=stable_id("api-gateway", f"{api['method']} {api['path']}", "shadow_api"),
                            asset_id="api-gateway", category="shadow_api",
                            title=f"影子 API：{api['method']} {api['path']}（7 天 {api['calls_7d']} 次）",
                            evidence=[f"api-inventory.json: {api['reason']}"], source="reconcile", data_store=api.get("data_store")))
    return out


def control_findings(data: TargetData, results: dict[str, dict]) -> list[dict]:
    out = []
    for cid, res in results.items():
        if res["status"] != "fail":
            continue
        for a in res["assets"]:
            out.append(_finding(data, id=stable_id(a["asset_id"], cid), asset_id=a["asset_id"], category=CATEGORY[cid],
                                control_id=cid, title=f"{res['title']}：{a['asset_id']}", evidence=a["evidence"],
                                source=f"controls:{cid}", base_points=res["base_points"], credential_id=a.get("credential_id")))
    return out


def build_findings(data: TargetData, graph: nx.MultiDiGraph, recon: dict, *, kev: set[str],
                   sdk_advisories: list[dict] | None = None) -> dict:
    secrets = triage_secrets(data)
    ctx = ControlContext(data=data, graph=graph, recon=recon, secret_findings=secrets, as_of=data.as_of,
                         sdk_advisories=sdk_advisories or [])
    controls = run_controls(ctx)
    kev = set(kev) | kev_catalog(data)
    findings = [*trivy_findings(data, kev), *nvd_findings(data, graph, kev), *eol_findings(data, graph), *mobile_findings(data),
                *reconcile_findings(data, recon), *control_findings(data, controls)]
    for s in secrets or []:
        if s["env"] == "test":
            findings.append(_finding(data, id=stable_id(s["credential_id"] or s["id"], "test-secret-in-git"), asset_id="gitlab",
                                     category="secret", title=f"Git 中有測試環境金鑰（{s['location']}）", evidence=[s["location"]],
                                     source="secret-triage", credential_id=s["credential_id"], rule_key="secret:test_env"))
    data_issues = []
    for tool in ("gitleaks", "trivy"):
        if (data.scanners.get(tool) or {}).get("status") != "ok":
            data_issues.append({"source": f"scanner/{tool}", "status": "missing", "impact": "相關控制項為待確認，不視為零發現"})
    return {"findings": findings, "secret_findings": secrets, "controls": controls, "data_issues": data_issues,
            "coverage_issues": coverage_issues(data), "kev": kev}
