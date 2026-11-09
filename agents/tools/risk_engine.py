"""A4：由 Finding、圖譜、攻擊路徑與情資命中計算評分因子，產出 Risk。LLM 不能新增分數或變更判定。"""
from __future__ import annotations

import networkx as nx

from tools.common import iso
from tools.scoring import Factors, score

SENSITIVE = {"pii", "order", "payment", "session"}
OTHER_CATEGORIES = {"clone_app", "shadow_api", "shadow_it"}


def _subject_nodes(f: dict, g: nx.MultiDiGraph) -> list[str]:
    nodes = [f["asset_id"]] if f["asset_id"] in g else []
    cred = f.get("credential_id")
    if cred and cred in g:
        nodes.append(cred)
        nodes += [v for _, v, d in g.out_edges(cred, data=True) if d["kind"] == "authorizes"]
    if f.get("data_store") and f["data_store"] in g:
        nodes.append(f["data_store"])
    if f.get("control_id") == "C-NET-SEGMENT":
        nodes = [f["asset_id"]]
    return nodes


def _exposed(f: dict, g: nx.MultiDiGraph) -> tuple[bool, str]:
    if f["category"] == "clone_app":
        return True, "商店上架，任何人可下載"
    node = g.nodes.get(f["asset_id"], {})
    if node.get("exposed_to_internet"):
        kinds = {d["kind"] for u, v, d in g.in_edges(f["asset_id"], data=True) if u == "internet"}
        return True, "商店上架的 App" if kinds == {"download"} else "可從 internet 連到"
    cred = g.nodes.get(f.get("credential_id") or "", {})
    if cred.get("vendor") and cred.get("ip_allowlist") is False:
        return True, "第三方金鑰無 IP 白名單，外部任何來源都可使用"
    return False, ""


def _compensating(f: dict, g: nx.MultiDiGraph) -> tuple[bool, str]:
    """補償措施需有本次證據證明涵蓋此攻擊手法：vpn-only 只在沒有任何 internet 入站時有效。"""
    if f["category"] != "vuln":
        return False, ""
    node = g.nodes.get(f["asset_id"], {})
    if "vpn-only" not in node.get("compensating", []):
        return False, ""
    inbound = {u for u, _, d in g.in_edges(f["asset_id"], data=True) if d["kind"] in ("network", "download")}
    if "internet" in inbound:
        return False, "宣稱 vpn-only，但 network.json 有 internet 入站連線（無效）"
    if inbound and inbound <= {"corp-vpn"}:
        return True, "network.json 顯示只允許 corp-vpn 連入（本次快照證據）"
    return False, "缺少 VPN 入站證據"


def build_risks(findings: list[dict], g: nx.MultiDiGraph, *, chain_ids: set[str], event_links: dict[str, set[str]],
                real_events: set[str], provisional_events: set[str], as_of, prev: dict[str, dict] | None = None) -> list[dict]:
    prev = prev or {}
    risks = []
    for f in findings:
        subj = _subject_nodes(f, g)
        classes = set()
        platform = False
        for n in subj:
            node = g.nodes.get(n, {})
            classes |= set(node.get("data_classes", []))
            platform = platform or bool(node.get("platform_layer"))
        exposed, exposed_note = _exposed(f, g)
        comp, comp_note = _compensating(f, g)
        matched = sorted(event_links.get(f["id"], set()))
        peer = [e for e in matched if e in real_events]
        if f["category"] == "vuln":
            base_kind = "vuln"
        elif f.get("control_id"):
            base_kind = "control"
        elif f["category"] in OTHER_CATEGORIES:
            base_kind = "other"
        else:
            base_kind = "rule"
        provisional = f.get("status") == "provisional"
        factors = Factors(
            base_kind=base_kind, cvss=f.get("cvss"), base_points=f.get("base_points"), category=f["category"],
            rule_key=f.get("rule_key"), known_exploited=bool(f.get("known_exploited")), exposed=exposed,
            data_sensitive=bool(classes & SENSITIVE), platform=platform, peer_event=bool(peer),
            on_attack_chain=f["id"] in chain_ids, eol_no_fix=bool(f.get("eol_no_fix")), compensating_effective=comp,
            provisional=provisional, level_floor=f.get("level_floor"), floor_reason=f.get("floor_reason"),
            notes={"exposed": exposed_note, "compensating": comp_note,
                   "data": "、".join(sorted(classes & SENSITIVE)) or "",
                   "peer": "、".join(peer)})
        r = score(factors)
        status = "need_check" if r.need_check or f.get("exploit_conditions") == "unknown" else "open"
        old = prev.get(f["id"]) or {}
        risks.append({
            "id": f["id"], "finding_ids": [f["id"]], "asset_id": f["asset_id"], "title": f["title"],
            "category": f["category"], "level": r.level, "score": r.score, "raw_score": r.raw_score,
            "score_level": r.score_level, "level_reason": r.level_reason, "breakdown": r.breakdown,
            "attack_path": None, "matched_events": matched, "deadline_hours": r.deadline_hours, "solution": None,
            "status": status, "first_seen": old.get("first_seen") or iso(as_of), "last_evaluated": iso(as_of),
            "verification_evidence": [], "control_id": f.get("control_id"), "credential_id": f.get("credential_id"),
            "evidence": f.get("evidence", []), "demo_fixture": bool(f.get("demo_fixture")),
            "provisional_basis": provisional,
        })
    return sorted(risks, key=lambda x: (-{"high": 2, "medium": 1, "low": 0}[x["level"]], -x["score"], x["id"]))


def link_events(matches: list[dict], findings: list[dict]) -> dict[str, set[str]]:
    """事件 → 風險的關聯：直接命中（risk_id），以及控制項命中資產上的根因漏洞（只關聯，不重複製造風險）。"""
    links: dict[str, set[str]] = {}
    vuln_by_asset: dict[str, list[str]] = {}
    for f in findings:
        if f["category"] == "vuln":
            vuln_by_asset.setdefault(f["asset_id"], []).append(f["id"])
    for m in matches:
        eid = m["event"]["id"]
        for imp in m["impacts"]:
            if imp["verdict"] not in ("affected", "need_check"):
                continue
            if imp.get("risk_id"):
                links.setdefault(imp["risk_id"], set()).add(eid)
            if imp["basis"] == "control" and m["real"]:
                for fid in vuln_by_asset.get(imp["asset_id"], []):
                    links.setdefault(fid, set()).add(eid)
    return links


def attach_paths(risks: list[dict], paths: list[dict]) -> None:
    for r in risks:
        for p in paths:
            if any(r["id"] in s["finding_ids"] for s in p["steps"]):
                r["attack_path"] = p["nodes"]
                break


def mark_fixed(risks: list[dict], prev: dict[str, dict], *, complete: bool, evaluated_assets: set[str], as_of) -> list[dict]:
    """前次 open 的風險本次未命中：只有資料完整、新鮮且涵蓋該資產時才標 fixed；否則保留為 need_check。"""
    current = {r["id"] for r in risks}
    out = []
    for rid, old in prev.items():
        if rid in current or old.get("status") == "fixed":
            continue
        carried = dict(old)
        carried["last_evaluated"] = iso(as_of)
        if complete and old.get("asset_id") in evaluated_assets:
            carried["status"] = "fixed"
            carried["verification_evidence"] = ["本次完整且新鮮的重新評估未再命中"]
        else:
            carried["status"] = "need_check"
            carried["level_reason"] = "本次資料不完整或不在評估範圍，保留前次結果待確認"
        out.append(carried)
    return out
