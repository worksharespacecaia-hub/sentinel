"""與上次 daily 圖譜比較。只用來決定 LLM 說明能否重用；確定性評估每次都重算，不因圖譜沒變就跳過。"""
from __future__ import annotations

IGNORED = {"sources", "last_evaluated"}


def _node_key(n: dict) -> dict:
    return {k: v for k, v in n.items() if k not in IGNORED}


def diff(prev: dict | None, cur: dict) -> dict:
    if not prev:
        return {"first_run": True, "added_nodes": [n["id"] for n in cur["nodes"]], "removed_nodes": [], "changed_nodes": [],
                "added_edges": len(cur["edges"]), "removed_edges": 0, "changed": True}
    pn = {n["id"]: _node_key(n) for n in prev.get("nodes", [])}
    cn = {n["id"]: _node_key(n) for n in cur.get("nodes", [])}

    def ekey(e):
        return (e["from"], e["to"], e["kind"], str(e.get("port")), str(e.get("scopes")))

    pe = {ekey(e) for e in prev.get("edges", [])}
    ce = {ekey(e) for e in cur.get("edges", [])}
    changed = sorted(i for i in set(pn) & set(cn) if pn[i] != cn[i])
    out = {"first_run": False, "added_nodes": sorted(set(cn) - set(pn)), "removed_nodes": sorted(set(pn) - set(cn)),
           "changed_nodes": changed, "added_edges": len(ce - pe), "removed_edges": len(pe - ce)}
    out["changed"] = bool(out["added_nodes"] or out["removed_nodes"] or changed or out["added_edges"] or out["removed_edges"])
    return out
