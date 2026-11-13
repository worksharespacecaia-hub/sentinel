"""從圖譜產出 stack.json（技術棧摘要，給每日情資使用）與 seen.json（近 14 天已知事件）。不含任何機敏值。

stack.json 的 assets（specs/check-hints-ai R1）是給 daily-intel 挑「先查哪些系統」的系統清單：鍵與值都採白名單，
不含金鑰值、帳密、存放位置、指紋、IP、連接埠、檔案路徑與人員資料。check_hints 驗證 AI 挑的系統時也用同一個 ai_assets。
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta

import networkx as nx

from tools.common import iso, parse_time

ALLOWED_TYPES = {"service", "api", "datastore", "internal_tool", "vendor", "saas", "token", "device", "ai_tool", "app"}
ALLOWED_ENV = {"prod", "test", "staging", "office"}
ALLOWED_DATA_CLASSES = {"pii", "order", "payment", "source_code", "credential", "session"}
ASSET_ID_RE = re.compile(r"^[a-z0-9][a-z0-9@._-]{0,80}$")
UNSAFE_VALUE_RE = re.compile(r"::|:\d{2,5}|[/\\]|(?<![A-Za-z])[A-Za-z]:[\\/]")
IP_CANDIDATE_RE = re.compile(r"[0-9A-Fa-f:.]*[:.][0-9A-Fa-f:.]*")    # IPv6（與一般片段）
IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")        # 獨立掃描：前綴字母或連接埠不會吞掉位址


def nodes_of(graph) -> list[tuple]:
    """(節點 ID, 屬性)：支援 networkx 圖、graph_to_json 的 {"nodes": [...]}，以及 {asset_id: 屬性}。"""
    if graph is None:
        return []
    if hasattr(graph, "nodes") and callable(getattr(graph, "nodes")):
        return [(nid, attrs) for nid, attrs in graph.nodes(data=True)]
    if isinstance(graph, dict) and isinstance(graph.get("nodes"), list):
        return [(n.get("id"), n) for n in graph["nodes"] if isinstance(n, dict) and n.get("id")]
    if isinstance(graph, dict):
        return [(k, v) for k, v in graph.items() if isinstance(v, dict)]
    return []


def _is_ip(cand: str) -> bool:
    for c in (cand, cand.strip(".:")):          # 先驗原候選（保留 ::1），再驗去掉外圍標點的版本
        try:
            ipaddress.ip_address(c)
            return True
        except ValueError:
            continue
    return False


def _has_ip(s: str) -> bool:
    return any(_is_ip(c) for c in IPV4_RE.findall(s)) or any(_is_ip(c) for c in IP_CANDIDATE_RE.findall(s))


def _safe(s: str) -> bool:
    from tools.digest import has_sensitive   # 延遲匯入：digest 會匯入 llm

    return not (has_sensitive(s) or UNSAFE_VALUE_RE.search(s) or _has_ip(s))


def ai_assets(graph, labels: dict[str, str] | None) -> list[dict]:
    """可以給 AI 的系統清單（R1）：stack.json 匯出與 check_hints 驗證共用。結果依 id 排序。

    labels 為 None 時 label 全部為 null。
    """
    out = []
    for nid, node in nodes_of(graph):
        ntype = node.get("type")
        if (not isinstance(nid, str) or not isinstance(ntype, str) or ntype not in ALLOWED_TYPES
                or not ASSET_ID_RE.fullmatch(nid) or not _safe(nid)):
            continue
        label = (labels or {}).get(nid)
        env = node.get("env")
        classes = node.get("data_classes")
        out.append({
            "id": nid,
            "label": label if isinstance(label, str) and label and _safe(label) and nid not in label else None,
            "type": ntype,
            "data_classes": sorted({c for c in (classes if isinstance(classes, (list, tuple)) else [])
                                    if isinstance(c, str) and c in ALLOWED_DATA_CLASSES}),
            "exposed": node.get("exposed_to_internet") is True,
            "management_interface": node.get("management_interface") is True,
            "crown_jewel": node.get("crown_jewel") is True,
            "env": env if isinstance(env, str) and env in ALLOWED_ENV else None})
    return sorted(out, key=lambda a: a["id"])


def build_stack(g: nx.MultiDiGraph, *, as_of: datetime, labels: dict[str, str] | None = None) -> dict:
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
    return {"generated_at": iso(as_of),
            "note": "技術棧摘要（Demo 假設環境）。只含產品、版本、部署位置、是否對外、負責團隊；"
                    "assets 為系統清單（不含金鑰與設定值）。",
            "products": items, "assets": ai_assets(g, labels)}


def build_seen(previous: dict | None, events: list[dict], *, as_of: datetime, days: int = 14) -> dict:
    cutoff = as_of - timedelta(days=days)
    seen = {e["id"]: e for e in (previous or {}).get("events", []) if (parse_time(e.get("first_seen")) or as_of) >= cutoff}
    for ev in events:
        if ev["kind"] not in ("live", "archive"):
            continue
        seen.setdefault(ev["id"], {"id": ev["id"], "urls": [s["url"] for s in ev.get("sources", []) if s.get("url")],
                                   "first_seen": iso(as_of)})
    return {"updated_at": iso(as_of), "events": sorted(seen.values(), key=lambda e: e["id"])}
