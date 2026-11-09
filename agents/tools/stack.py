"""從圖譜產出 stack.json（技術棧摘要，給每日情資使用）與 seen.json（近 14 天已知事件）。不含任何機敏值。"""
from __future__ import annotations

from datetime import datetime, timedelta

import networkx as nx

from tools.common import iso, parse_time


def build_stack(g: nx.MultiDiGraph, *, as_of: datetime) -> dict:
    products: dict[tuple[str, str], dict] = {}
    for nid, node in g.nodes(data=True):
        for c in node.get("components", []):
            key = (c.get("name") or "?", c.get("version") or "unknown")
            entry = products.setdefault(key, {"product": key[0], "version": key[1], "assets": [], "exposed": False,
                                              "owners": set(), "qualifiers": {}})
            entry["assets"].append(nid)
            entry["exposed"] = entry["exposed"] or bool(node.get("exposed_to_internet"))
            if node.get("owner"):
                entry["owners"].add(node["owner"])
            for q in ("sapi", "ecosystem"):
                if c.get(q):
                    entry["qualifiers"][q] = c[q]
    items = []
    for e in sorted(products.values(), key=lambda x: (x["product"], x["version"])):
        e["owners"] = sorted(e["owners"])
        e["assets"] = sorted(set(e["assets"]))
        items.append(e)
    return {"generated_at": iso(as_of), "note": "技術棧摘要（Demo 假設環境）。只含產品、版本、部署位置、是否對外、負責團隊。",
            "products": items}


def build_seen(previous: dict | None, events: list[dict], *, as_of: datetime, days: int = 14) -> dict:
    cutoff = as_of - timedelta(days=days)
    seen = {e["id"]: e for e in (previous or {}).get("events", []) if (parse_time(e.get("first_seen")) or as_of) >= cutoff}
    for ev in events:
        if ev["kind"] not in ("live", "archive"):
            continue
        seen.setdefault(ev["id"], {"id": ev["id"], "urls": [s["url"] for s in ev.get("sources", []) if s.get("url")],
                                   "first_seen": iso(as_of)})
    return {"updated_at": iso(as_of), "events": sorted(seen.values(), key=lambda e: e["id"])}
