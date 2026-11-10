"""情資比對（A1 的確定性部分）：事件／公告 × 圖譜 → StackImpact 與漏洞 Finding。

- 有產品與版本範圍：version_match 判斷，利用條件三態（成立／不成立／未知）
- 沒有 CVE：controls.py 的檢查結果決定受影響資產
- 版本未知、條件缺值、必要來源缺失 → need_check；產品確實不在完整且新鮮的資產清單才 not_affected
- LLM 的 verdict 只是初步判斷，最後以這裡的程式結果為準
"""
from __future__ import annotations

import networkx as nx

from tools.aliases import normalize
from tools.common import iso, stable_id
from tools.eol import eol_status
from tools.loaders import TargetData
from tools.mobile_rules import affected_installations, app_package_sdks
from tools.version_match import AFFECTED, NOT_AFFECTED, compare, fixed_available, match

WEB_SAPIS = {"apache2handler", "fpm-fcgi", "cgi-fcgi", "litespeed", "frankenphp"}
FOOTHOLD_IMPACTS = {"remote_code_execution", "account_takeover"}


def _php_cfg(data: TargetData, asset_id: str) -> dict | None:
    return next((c for c in data.snap("php-config.json", []) or [] if c["asset_id"] == asset_id), None)


def resolve_condition(key: str, asset_id: str, data: TargetData, g: nx.MultiDiGraph):
    """回傳條件的實際值；None 表示未知（→ need_check）。"""
    node = g.nodes[asset_id] if asset_id in g else {}
    cfg = _php_cfg(data, asset_id)
    if key == "serves_web_requests":
        sapi = (cfg or {}).get("sapi") or next((c.get("sapi") for c in node.get("components", []) if c.get("sapi")), None)
        return None if sapi is None else sapi in WEB_SAPIS
    if key.startswith("session.") or key.startswith("php."):
        return None if cfg is None else (cfg.get("settings") or {}).get(key)
    if key == "hosting":
        return node.get("hosting")
    if key == "middleware_auth":
        if asset_id != "storefront":
            return None
        text = data.files.get("services/storefront/middleware.ts")
        return None if text is None else ("redirect" in text and "cookies" in text)
    if key in ("management_interface_internet_exposed",):
        return bool(node.get("management_interface")) and bool(node.get("exposed_to_internet"))
    if key == "login_reachable":
        return node.get("exposed_to_internet")
    return None


def _conditions_state(conds: list[dict], asset_id: str, data: TargetData, g) -> tuple[str, list[str], list[str]]:
    met, unknown = [], []
    for c in conds or []:
        actual = resolve_condition(c["key"], asset_id, data, g)
        if actual is None:
            unknown.append(c["key"])
        elif actual != c.get("equals"):
            return "not_met", met, [f"{c['key']}={actual}（需要 {c.get('equals')}）"]
        else:
            met.append(f"{c['key']}={actual}")
    return ("unknown" if unknown else "met"), met, unknown


def stack_complete(data: TargetData, coverage: dict) -> bool:
    """資產清單完整且新鮮：runtime 存在且未過期、版本已知比例 ≥ 90%。"""
    bad = any(i["source"] == "snapshots/runtime.json" and i["status"] in ("missing", "stale") for i in data.data_issues)
    return not bad and (coverage.get("version_known_ratio") or 0) >= 0.9


def match_event(ev: dict, *, data: TargetData, g: nx.MultiDiGraph, control_results: dict, findings: list[dict],
                coverage: dict) -> dict:
    impacts: list[dict] = []
    new_findings: list[dict] = []
    notes: list[str] = []
    real = ev["kind"] in ("archive", "live")
    complete = stack_complete(data, coverage)
    scope_types = set((ev.get("match_scope") or {}).get("asset_types") or [])

    for p in ev.get("products", []):
        name = normalize(p["name"])
        eco = p.get("ecosystem", "generic")
        if p.get("target") == "app_sdk":
            impacts_sdk, f = _match_app_sdk(ev, p, name, data, g)
            impacts += impacts_sdk
            new_findings += f
            continue
        candidates = [(nid, c) for nid, node in g.nodes(data=True) for c in node.get("components", [])
                      if normalize(c.get("name")) == name]
        if not candidates:
            if complete:
                notes.append(f"技術棧中沒有 {p['name']}（資產清單完整且新鮮）")
            else:
                impacts.append({"event_id": ev["id"], "asset_id": "*", "basis": "version", "our_state": "資產清單不完整或過期",
                                "verdict": "need_check", "risk_id": None, "to_verify": [f"確認是否使用 {p['name']}"],
                                "reason": "資產清單不完整，不能判定不受影響"})
            continue
        for nid, comp in candidates:
            ver = comp.get("version")
            v = match(ver, p.get("affected"), eco)
            if v == NOT_AFFECTED and p.get("unknown_below") and ver and (compare(ver, p["unknown_below"], eco) or 0) < 0:
                v = "unknown"   # 來源未涵蓋的舊分支：不能判定不受影響
            state = f"{comp['name']} {ver or '版本未知'}"
            if comp.get("sapi"):
                state += f"（{comp['sapi']}）"
            if v == NOT_AFFECTED:
                impacts.append({"event_id": ev["id"], "asset_id": nid, "basis": "version", "our_state": state,
                                "verdict": "not_affected", "risk_id": None, "reason": f"{ver} 不在受影響範圍（已是修補版本或不同分支）"})
                continue
            if v != AFFECTED:
                impacts.append({"event_id": ev["id"], "asset_id": nid, "basis": "version", "our_state": state,
                                "verdict": "need_check", "risk_id": None, "to_verify": ["版本未知或範圍無法判斷"],
                                "reason": "版本未知或範圍無法判斷，不視為安全"})
                continue
            cstate, met, detail = _conditions_state(p.get("conditions", []), nid, data, g)
            agg = [f"{c['key']}={resolve_condition(c['key'], nid, data, g)}" for c in p.get("aggravating_conditions", [])
                   if resolve_condition(c["key"], nid, data, g) == c.get("equals")]
            if cstate == "not_met":
                impacts.append({"event_id": ev["id"], "asset_id": nid, "basis": "condition", "our_state": state,
                                "verdict": "not_affected", "risk_id": None, "reason": "版本受影響但利用條件不成立：" + "；".join(detail)})
                continue
            fid = stable_id(nid, name, "vuln")
            exposed = bool(g.nodes[nid].get("exposed_to_internet"))
            if exposed:
                state += "，對外"
            if agg:
                state += "，" + "、".join(agg)
            eol = eol_status(name, ver, data.as_of)
            no_fix = fixed_available(ver, p.get("affected") or [], eco) is False if isinstance(p.get("affected"), list) else False
            verdict = "affected" if cstate == "met" else "need_check"
            impacts.append({"event_id": ev["id"], "asset_id": nid, "basis": "condition" if p.get("conditions") else "version",
                            "our_state": state, "verdict": verdict, "risk_id": fid,
                            "to_verify": [f"確認 {k}" for k in detail] if cstate == "unknown" else [],
                            "reason": "版本落在受影響範圍" + ("，利用條件成立：" + "、".join(met) if met else "")
                                      + ("；停止支援且無修補" if eol["eol"] and no_fix else "")})
            new_findings.append({
                "id": fid, "asset_id": nid, "category": "vuln", "control_id": None,
                "title": f"{comp['name']} {ver}：{_short_title(ev)}",
                "evidence": [f"{ev['id']}：{p.get('affected')}", f"我們的狀況：{state}"],
                "status": "confirmed" if p.get("confirmed", True) and ev["confidence"] == "confirmed" else "provisional",
                "source": f"intel:{ev['id']}", "cvss": p.get("cvss"), "base_points": None, "credential_id": None,
                "level_floor": None, "observed_at": iso(data.as_of), "source_sha": data.target_sha,
                "vuln_id": (ev.get("cves") or [ev["id"]])[0], "component": name,
                "known_exploited": bool(p.get("known_exploited")), "eol_no_fix": bool(eol["eol"] and no_fix),
                "impact": p.get("impact"), "advisory_ids": [ev["id"], *ev.get("cves", [])],
                "exploit_conditions": cstate, "grants_foothold": p.get("impact") in FOOTHOLD_IMPACTS and cstate == "met",
                "demo_fixture": bool(ev.get("demo_fixture") or ev.get("demo")),
            })

    for cid in ev.get("controls", []):
        res = control_results.get(cid)
        if res is None:
            continue
        if res["status"] == "unknown":
            impacts.append({"event_id": ev["id"], "asset_id": "*", "basis": "control", "our_state": res["reason"],
                            "verdict": "need_check", "risk_id": None, "to_verify": [f"{cid}：{res['reason']}"],
                            "reason": "控制項資料不足"})
        elif res["status"] == "pass":
            notes.append(f"{cid}（{res['title']}）符合")
        else:
            for a in res["assets"]:
                if scope_types and (g.nodes[a["asset_id"]]["type"] if a["asset_id"] in g else None) not in scope_types:
                    continue
                impacts.append({"event_id": ev["id"], "asset_id": a["asset_id"], "basis": "control",
                                "our_state": "；".join(a["evidence"]), "verdict": "affected",
                                "risk_id": stable_id(a["asset_id"], cid), "reason": f"不符合 {cid}（{res['title']}）"})

    for cat in ev.get("match_finding_categories", []):
        for f in findings:
            if f["category"] == cat:
                impacts.append({"event_id": ev["id"], "asset_id": f["asset_id"], "basis": "control", "our_state": f["title"],
                                "verdict": "affected", "risk_id": f["id"], "reason": f["evidence"][0] if f["evidence"] else ""})

    if ev.get("requires_manual_check"):
        for imp in impacts:
            if imp["verdict"] == "affected":
                imp["verdict"] = "need_check"
                imp["to_verify"] = list(ev["requires_manual_check"])

    # 沒有產品、也沒有任何有檢查結果的控制項：程式其實沒比對任何資產，不能當成「不受影響」
    has_criteria = (bool(ev.get("products")) or bool(ev.get("match_finding_categories"))
                    or any(cid in control_results for cid in ev.get("controls", [])))
    if not has_criteria:
        proposed = [pc.get("title") or pc.get("id") for pc in ev.get("proposed_controls", []) if isinstance(pc, dict)]
        impacts.append({"event_id": ev["id"], "asset_id": "*", "basis": "control",
                        "our_state": "事件沒有可比對的產品、版本或控制項", "verdict": "need_check", "risk_id": None,
                        "to_verify": ["人工判斷事件的攻擊手法是否適用於我們的系統",
                                      "把事件對應到 controls.yaml 的控制項；沒有合適的就建議新增",
                                      *[f"建議新增控制項：{t}" for t in proposed if t]],
                        "reason": "事件沒有可比對的產品、CVE 或控制項，程式沒有比對任何資產"})

    affected = [i for i in impacts if i["verdict"] == "affected"]
    need = [i for i in impacts if i["verdict"] == "need_check"]
    if affected:
        status = "open"
    elif need:
        status = "need_check"
    elif not impacts and not notes and not complete:
        status = "need_check"
    else:
        status = "not_affected"
    return {"event": ev, "impacts": impacts, "findings": new_findings, "notes": notes, "status": status,
            "real": real, "complete": complete}


def _match_app_sdk(ev, p, name, data: TargetData, g):
    rows = (data.snap("app-versions.json") or {}).get("rows", [])
    current = app_package_sdks(_package_json(data)).get(name)

    def is_aff(row):
        ver = (row.get("sdks") or {}).get(name)
        return ver is not None and match(ver, p["affected"], "npm") == AFFECTED

    inst = affected_installations(rows, is_aff)
    if inst["affected_installations"] == 0 and (current is None or match(current, p["affected"], "npm") != AFFECTED):
        return [{"event_id": ev["id"], "asset_id": "brand-app", "basis": "version",
                 "our_state": f"{name} {current or '未使用'}", "verdict": "not_affected", "risk_id": None,
                 "reason": "各 App 版本打包的 SDK 都不在受影響範圍"}], []
    fid = stable_id("brand-app", name, "vuln")
    state = (f"目前程式碼 {name} {current}；受影響 {inst['affected_brands']} 個品牌、"
             f"{inst['affected_installations']:,} 個安裝（共 {inst['total_installations']:,}）；"
             f"非最新版安裝占 {inst['old_version_share']:.0%}")
    impact = {"event_id": ev["id"], "asset_id": "brand-app", "basis": "version", "our_state": state, "verdict": "affected",
              "risk_id": fid, "reason": "App 版本內實際打包的 SDK 落在受影響範圍", "app_impact": inst}
    finding = {"id": fid, "asset_id": "brand-app", "category": "vuln", "control_id": None,
               "title": f"App 內的 {name} 受影響（{inst['affected_brands']} 個品牌、{inst['affected_installations']:,} 個安裝）",
               "evidence": [f"services/brand-app/package.json: {name} {current}", "app-versions.json：逐品牌逐版本加總"],
               "status": "confirmed" if ev["confidence"] == "confirmed" else "provisional", "source": f"intel:{ev['id']}",
               "cvss": p.get("cvss"), "base_points": None, "credential_id": None, "level_floor": None,
               "observed_at": iso(data.as_of), "source_sha": data.target_sha, "vuln_id": (ev.get("cves") or [ev["id"]])[0],
               "component": name, "known_exploited": bool(p.get("known_exploited")), "eol_no_fix": False,
               "impact": p.get("impact"), "advisory_ids": [ev["id"], *ev.get("cves", [])], "exploit_conditions": "met",
               "grants_foothold": False, "app_impact": inst, "demo_fixture": bool(ev.get("demo"))}
    return [impact], [finding]


def _short_title(ev: dict) -> str:
    title = ev.get("short_title") or ev["title"]
    head, _, tail = title.partition("：")
    return tail if head.startswith("示範") and tail else head


def _package_json(data: TargetData) -> dict:
    import json
    text = data.files.get("services/brand-app/package.json")
    return json.loads(text) if text else {}


def merge_findings(base: list[dict], extra: list[dict]) -> list[dict]:
    """同一 ID 只保留一筆：合併情資來源、CVSS 取大、已利用取 OR。"""
    by_id = {f["id"]: dict(f) for f in base}
    for f in extra:
        if f["id"] not in by_id:
            by_id[f["id"]] = dict(f)
            continue
        cur = by_id[f["id"]]
        cur["advisory_ids"] = sorted(set(cur.get("advisory_ids", [])) | set(f.get("advisory_ids", [])))
        if (f.get("cvss") or 0) > (cur.get("cvss") or 0) and cur.get("source") != "trivy":
            cur["cvss"] = f["cvss"]
        cur["known_exploited"] = bool(cur.get("known_exploited")) or bool(f.get("known_exploited"))
        cur["eol_no_fix"] = cur.get("eol_no_fix") or f.get("eol_no_fix")
        for k in ("impact", "exploit_conditions", "grants_foothold", "app_impact"):
            if f.get(k) is not None and cur.get(k) is None:
                cur[k] = f[k]
        cur["evidence"] = [*cur.get("evidence", []), *[e for e in f.get("evidence", []) if e not in cur.get("evidence", [])]]
    return list(by_id.values())
