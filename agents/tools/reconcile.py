"""多來源對帳與可見度指標（A0）。

對帳表的等級是規則下限（level_floor），由 scoring 套用；缺來源與來源確認「不存在」是不同狀態。
部署對帳只套用在應走 CI/CD 的正式服務；NAS、員工設備、商店上架紀錄使用各自的觀察來源。
"""
from __future__ import annotations

import re
from tools.common import days_between
from tools.eol import eol_status
from tools.loaders import TargetData

RULES = {
    (True, True, True): ("normal", "正常", None),
    (False, False, True): ("shadow_it", "影子 IT", "high"),
    (True, False, True): ("non_ci_prod", "非 CI/CD 正式上線", "high"),
    (False, True, True): ("no_owner", "無負責人", "medium"),
    (True, True, False): ("unobserved", "待確認", "medium"),
    (True, False, False): ("stale_inventory", "清冊過時", "low"),
}

# 設備特徵規則（device-fingerprint Skill 的確定性版本；對不上時才交給 device-identifier）
FINGERPRINTS = [
    {"product": "synology-dsm", "match": {"mac_vendor": r"synology", "http_title": r"synology diskstation"},
     "version_re": r"DSM\s+(\d+\.\d+(?:\.\d+)?-\d+(?:\s+Update\s+\d+)?)"},
    {"product": "phpmyadmin", "match": {"http_title": r"phpmyadmin"}, "version_re": None},
]


def identify_device(host: dict) -> dict | None:
    for fp in FINGERPRINTS:
        if all(re.search(p, str(host.get(k) or ""), flags=re.I) for k, p in fp["match"].items()):
            version = None
            if fp["version_re"]:
                m = re.search(fp["version_re"], str(host.get("banner") or ""), flags=re.I)
                version = m.group(1) if m else None
            return {"product": fp["product"], "version": version, "confidence": "high" if version else "low",
                    "source": "fingerprint-rule"}
    return None


def _observed_sources(data: TargetData) -> dict[str, set[str]]:
    seen: dict[str, set[str]] = {}

    def add(asset: str | None, src: str):
        if asset:
            seen.setdefault(asset, set()).add(src)

    for r in data.snap("runtime.json", []):
        add(r.get("service_id"), "runtime")
    for h in (data.snap("lan-scan.json", {}) or {}).get("hosts", []):
        add(h.get("hostname"), "lan-scan")
    for r in (data.snap("external-scan.json", {}) or {}).get("results", []):
        add(r.get("asset_hint"), "external-scan")
    for d in (data.snap("mdm.json", {}) or {}).get("devices", []):
        add(d.get("id"), "mdm")
    for a in (data.snap("apps.json", {}) or {}).get("apps", []):
        add(a.get("codebase"), "store-console")
    return seen


def reconcile(data: TargetData) -> dict:
    services = {s["id"]: s for s in data.services}
    mdm_devices = {d["id"]: d for d in (data.snap("mdm.json", {}) or {}).get("devices", [])}
    observed = _observed_sources(data)
    runtime_missing = "runtime.json" not in data.snapshots
    deployed = {d["service_id"] for d in data.deployments if d.get("environment") == "production" and d.get("state") == "success"}

    records = []
    for asset_id in sorted(set(services) | set(observed)):
        svc = services.get(asset_id)
        registered = svc is not None or asset_id in mdm_devices
        srcs = sorted(observed.get(asset_id, set()))
        is_obs = bool(srcs)
        kind = (svc or {}).get("type") or ("device" if asset_id in mdm_devices or "lan-scan" in srcs and "runtime" not in srcs else "service")
        ci_applicable = (svc or {}).get("deploy") == "ci" or (svc is None and "runtime" in srcs)
        rec = {"asset_id": asset_id, "type": kind, "registered": registered, "observed": is_obs,
               "observed_sources": srcs, "ci_applicable": ci_applicable,
               "owner": (svc or {}).get("owner") or (mdm_devices.get(asset_id) or {}).get("owner")}
        if not is_obs and runtime_missing:
            rec.update(conclusion="data_missing", label="資料不足", level_floor=None,
                       reason="runtime.json 缺失，無法確認是否實際執行")
        elif ci_applicable:
            has_deploy = asset_id in deployed
            rec["deployed_via_ci"] = has_deploy
            code, label, floor = RULES[(registered, has_deploy, is_obs)]
            rec.update(conclusion=code, label=label, level_floor=floor,
                       reason=f"清冊{'有' if registered else '無'}、部署紀錄{'有' if has_deploy else '無'}、"
                              f"實際觀察{'有' if is_obs else '無'}（{', '.join(srcs) or '—'}）")
        else:
            rec["deployed_via_ci"] = None
            if registered and is_obs:
                rec.update(conclusion="normal", label="正常", level_floor=None, reason="清冊與實際觀察一致（不適用 CI/CD 部署對帳）")
            elif not registered and is_obs:
                rec.update(conclusion="shadow_it", label="影子 IT", level_floor="high",
                           reason=f"未出現在任何清冊，但在 {', '.join(srcs)} 被觀察到")
            else:
                rec.update(conclusion="unobserved", label="待確認", level_floor="medium", reason="清冊有登記，但沒有任何實際觀察")
        records.append(rec)

    # SaaS：付款紀錄、SSO 與第三方清冊對帳
    billing = {v.get("billing_name", "").lower(): v["id"] for v in data.vendors}
    saas_seen: dict[str, set[str]] = {}
    for p in data.snap("payments.csv", []) or []:
        saas_seen.setdefault(p["vendor"], set()).add("payments")
    vendor_ids = {v["id"] for v in data.vendors}
    for a in (data.snap("sso-apps.json", {}) or {}).get("apps", []):
        if a.get("asset_id") or a.get("vendor_id") in vendor_ids:
            continue
        saas_seen.setdefault(a["name"], set()).add("sso")
    for name, srcs in sorted(saas_seen.items()):
        if name.lower() in billing:
            continue
        asset_id = "saas-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        records.append({"asset_id": asset_id, "type": "saas", "registered": False, "observed": True,
                        "observed_sources": sorted(srcs), "ci_applicable": False, "deployed_via_ci": None,
                        "owner": None, "display_name": name, "conclusion": "shadow_it", "label": "影子 IT",
                        "level_floor": "high", "reason": f"{name} 出現在 {', '.join(sorted(srcs))}，但不在第三方清冊"})

    shadow_apis = find_shadow_apis(data)
    devices = identify_unmatched_devices(data, services, mdm_devices)
    return {"records": records, "shadow_apis": shadow_apis, "devices": devices,
            "coverage": coverage(data, records)}


def find_shadow_apis(data: TargetData) -> list[dict]:
    inv = data.snap("api-inventory.json") or {}
    spec = {(e["method"], e["path"]) for e in inv.get("openapi", [])}
    return [{"method": e["method"], "path": e["path"], "calls_7d": e.get("calls_7d"), "data_store": e.get("data_store"),
             "reason": "Gateway 實際流量中有，但未列在 OpenAPI 規格"}
            for e in inv.get("gateway_observed", []) if (e["method"], e["path"]) not in spec]


def identify_unmatched_devices(data: TargetData, services: dict, mdm: dict) -> list[dict]:
    out = []
    for host in (data.snap("lan-scan.json", {}) or {}).get("hosts", []):
        name = host.get("hostname")
        if name in services or name in mdm:
            continue
        ident = identify_device(host)
        out.append({"asset_id": name or host.get("ip"), "ip": host.get("ip"),
                    "identified": ident, "needs_llm": ident is None or ident["confidence"] == "low"})
    return out


def coverage(data: TargetData, records: list[dict]) -> dict:
    as_of = data.as_of
    services = {s["id"]: s for s in data.services}
    edges = (data.snap("network.json", {}) or {}).get("edges", [])
    exposed_ids = {e["to"] for e in edges if e.get("from") == "internet"}
    assets = [r for r in records if r["type"] not in ("zone",)]
    total = len(assets)
    unregistered_exposed = sorted(r["asset_id"] for r in records if not r["registered"] and r["asset_id"] in exposed_ids)
    owned = sum(1 for r in assets if r.get("owner"))
    runtime = {r["service_id"]: r for r in data.snap("runtime.json", []) or []}
    versioned_scope = [r for r in assets if r["type"] not in ("saas", "device") or r["asset_id"] in runtime]
    version_known = 0
    eol_exposed = []
    for r in versioned_scope:
        comps = (runtime.get(r["asset_id"]) or {}).get("components") or []
        if r["asset_id"] in runtime and (not comps or all(c.get("version") for c in comps)):
            version_known += 1
        for c in comps:
            st = eol_status(c.get("name"), c.get("version"), as_of)
            if st["eol"] and r["asset_id"] in exposed_ids:
                eol_exposed.append({"asset_id": r["asset_id"], "component": c["name"], "version": c["version"],
                                    "eol_date": st["eol_date"]})
    ci_scope = [r for r in records if r.get("ci_applicable")]
    ci_ok = sum(1 for r in ci_scope if r.get("deployed_via_ci"))
    backups = data.snap("backups.json", []) or []
    verified = 0
    for b in backups:
        age = days_between(b.get("last_restore_test"), as_of)
        if b.get("isolated") and age is not None and age <= 90:
            verified += 1
    crown = [n["id"] for n in (data.snap("network.json", {}) or {}).get("nodes", []) if n.get("crown_jewel")]
    backup_scope = {b["asset_id"] for b in backups} | {c for c in crown if services.get(c, {}).get("type") == "datastore"}

    def ratio(n, d):
        return None if d == 0 else round(n / d, 3)

    return {
        "assets_total": total,
        "unregistered_exposed": len(unregistered_exposed),
        "unregistered_exposed_ids": unregistered_exposed,
        "owner_ratio": ratio(owned, total),
        "version_known_ratio": ratio(version_known, len(versioned_scope)),
        "ci_ratio": ratio(ci_ok, len(ci_scope)),
        "eol_exposed": len(eol_exposed),
        "eol_exposed_items": eol_exposed,
        "backup_verified_ratio": ratio(verified, len(backup_scope)),
        "shadow_it": sorted(r["asset_id"] for r in records if r["conclusion"] == "shadow_it"),
    }


def visibility_ok(cov: dict) -> tuple[bool, list[str]]:
    """可見度門檻（第 7.5 節）。無法計算分母時視為未達標。"""
    reasons = []
    if cov.get("unregistered_exposed") != 0:
        reasons.append(f"未登記的對外資產 {cov.get('unregistered_exposed')} 個（門檻 0）")
    for key, label in (("owner_ratio", "有負責人比例"), ("version_known_ratio", "版本已知比例")):
        v = cov.get(key)
        if v is None:
            reasons.append(f"{label}無法計算")
        elif v < 0.9:
            reasons.append(f"{label} {v:.0%}（門檻 90%）")
    if cov.get("eol_exposed") != 0:
        reasons.append(f"對外且已停止支援的元件 {cov.get('eol_exposed')} 個（門檻 0）")
    return (not reasons), reasons

