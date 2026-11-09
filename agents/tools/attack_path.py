"""攻擊路徑分析（A4）：找出「串起來才是高風險」的弱點組合，作為修補優先順序的依據。

區分「網路可達」與「具前提的路徑」：
- network 邊只代表可達；必須有本次已確認可利用的弱點（版本＋條件成立）才取得該資產的控制
- stores 邊需取得存放位置的控制（或 App 安裝檔）且金鑰仍有效
- authorizes 邊需持有金鑰，且目前位置可連到目的服務
- api_data_access 邊需金鑰具備對應 API 範圍
未知條件不建立轉移，只記錄為待確認；搜尋以 (位置, 能力) 去重並限制深度與路徑數。
員工設備起點是「假設已遭入侵」的情境分析，不代表員工已遭入侵。
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import networkx as nx

MAX_DEPTH = 8
MAX_PATHS = 20


@dataclass
class Step:
    src: str
    dst: str
    kind: str
    finding_ids: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


def assumed_start_devices(g: nx.MultiDiGraph) -> list[str]:
    """辦公室設備若存放正式環境金鑰，納入「假設已遭入侵」的起點。"""
    out = []
    for nid, node in g.nodes(data=True):
        if node["type"] != "device" or node.get("env") != "office":
            continue
        for _, cid, d in g.out_edges(nid, data=True):
            if d["kind"] == "stores" and g.nodes[cid].get("env") == "prod" and g.nodes[cid].get("status") != "revoked":
                out.append(nid)
                break
    return sorted(set(out))


def find_paths(g: nx.MultiDiGraph, findings: list[dict], *, starts: list[str] | None = None) -> dict:
    crown = {n for n, d in g.nodes(data=True) if d.get("crown_jewel")}
    exploit_by_asset: dict[str, list[dict]] = {}
    pending: list[dict] = []
    for f in findings:
        if f["category"] != "vuln":
            continue
        if f.get("grants_foothold"):
            exploit_by_asset.setdefault(f["asset_id"], []).append(f)
        elif f.get("exploit_conditions") == "unknown" and f.get("impact") in ("remote_code_execution", "account_takeover"):
            pending.append({"asset_id": f["asset_id"], "finding_id": f["id"], "reason": "利用條件未知，未納入完整攻擊鏈"})
    exposure = {f["asset_id"]: f["id"] for f in findings if f.get("control_id") == "C-INTERNAL-TOOL-EXPOSED"}
    cred_findings: dict[str, list[str]] = {}
    for f in findings:
        if f.get("credential_id"):
            cred_findings.setdefault(f["credential_id"], []).append(f["id"])

    starts = starts if starts is not None else ["internet", *assumed_start_devices(g)]
    paths: list[dict] = []
    seen_states: set = set()
    queue: deque = deque()
    for s in starts:
        if s in g:
            caps = frozenset({f"at:{s}"})
            queue.append((s, caps, [], s != "internet"))

    def can_reach(pos: str, target: str) -> bool:
        return any(d["kind"] == "network" for _, v, d in g.out_edges(pos, data=True) if v == target)

    while queue and len(paths) < MAX_PATHS:
        pos, caps, steps, assumed = queue.popleft()
        key = (pos, caps)
        if key in seen_states or len(steps) > MAX_DEPTH:
            continue
        seen_states.add(key)
        reached = [c.split(":", 1)[1] for c in caps if c.startswith(("access:", "at:"))]
        hit = [c for c in reached if c in crown]
        if hit and steps:
            paths.append(_path(steps, hit[0], assumed, starts))
            continue

        nexts = []
        for _, q, d in g.out_edges(pos, data=True):
            if d["kind"] == "download":
                nexts.append((pos, caps | {f"binary:{q}"}, Step(pos, q, "download", [], d["evidence"])))
            elif d["kind"] == "network":
                for f in exploit_by_asset.get(q, []):
                    fids = [f["id"], *([exposure[q]] if pos == "internet" and q in exposure else [])]
                    nexts.append((q, caps | {f"at:{q}"}, Step(pos, q, "exploit", fids, [*d["evidence"], *f["evidence"][:1]])))
        holders = {c.split(":", 1)[1] for c in caps if c.startswith(("at:", "repo:"))}
        binaries = {c.split(":", 1)[1] for c in caps if c.startswith("binary:")}
        for h in holders | binaries:
            if h not in g:
                continue
            for _, cid, d in g.out_edges(h, data=True):
                if d["kind"] != "stores" or g.nodes[cid].get("status") == "revoked":
                    continue
                need_binary = "app_binary" in d["requires"]
                if need_binary and h not in binaries or not need_binary and h not in holders:
                    continue
                if f"cred:{cid}" in caps:
                    continue
                nexts.append((pos, caps | {f"cred:{cid}"}, Step(h, cid, "read_secret", cred_findings.get(cid, []), d["evidence"])))
        for c in [c.split(":", 1)[1] for c in caps if c.startswith("cred:")]:
            for _, t, d in g.out_edges(c, data=True):
                if d["kind"] != "authorizes" or f"access:{t}" in caps:
                    continue
                if not can_reach(pos, t):
                    continue
                new = {f"access:{t}"} | {f"scope:{t}:{s}" for s in d.get("scopes", [])}
                if d.get("repo_read"):
                    new.add(f"repo:{t}")
                nexts.append((pos, caps | new, Step(c, t, "authorize", cred_findings.get(c, []), d["evidence"])))
        for a in [c.split(":", 1)[1] for c in caps if c.startswith("access:")]:
            for _, ds, d in g.out_edges(a, data=True):
                if d["kind"] != "api_data_access" or f"access:{ds}" in caps:
                    continue
                need = d.get("scope")
                if need and f"scope:{a}:{need}" not in caps:
                    continue
                nexts.append((pos, caps | {f"access:{ds}"}, Step(a, ds, "api_data_access", [], d["evidence"])))
        for npos, ncaps, step in nexts:
            queue.append((npos, frozenset(ncaps), [*steps, step], assumed))

    paths = _dedupe(paths)
    chain_findings = sorted({fid for p in paths for s in p["steps"] for fid in s["finding_ids"]})
    return {"paths": paths, "chain_finding_ids": chain_findings, "pending": pending, "starts": starts}


def _path(steps: list[Step], target: str, assumed: bool, starts: list[str]) -> dict:
    nodes = [steps[0].src]
    for s in steps:
        if s.kind == "download":
            nodes.append(s.dst)
        elif s.dst not in nodes:
            nodes.append(s.dst)
    start = steps[0].src
    return {"id": "path:" + "→".join(nodes), "start": start, "target": target, "nodes": nodes,
            "assumption": f"假設 {start} 已遭入侵（情境分析）" if assumed else None,
            "steps": [{"from": s.src, "to": s.dst, "kind": s.kind, "finding_ids": s.finding_ids, "evidence": s.evidence}
                      for s in steps]}


def _dedupe(paths: list[dict]) -> list[dict]:
    """同一起點與目標只保留最短的路徑。"""
    best: dict[tuple[str, str], dict] = {}
    for p in paths:
        k = (p["start"], p["target"])
        if k not in best or len(p["steps"]) < len(best[k]["steps"]):
            best[k] = p
    return sorted(best.values(), key=lambda p: (p["start"], p["target"]))
