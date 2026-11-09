"""建立資安知識圖譜（A0）。

邊一律帶 kind／evidence／requires／grants：
- network：只表示可達（reach），不代表取得權限
- download：可下載商店上架的 App 安裝檔
- stores：金鑰存放位置（第 5.3 節 stored_in 對應規則）
- authorizes：金鑰可授權的目標與範圍
- api_data_access：API 範圍可存取的資料庫
- contains／installed：App → 版本 → SDK 的關聯，不自動成為攻擊路徑
"""
from __future__ import annotations

import networkx as nx

from tools.aliases import component_key
from tools.loaders import TargetData

STORED_IN_PREFIXES = ("git:", "device:", "app:", "service:", "share:")


def stored_in_node(stored_in: str) -> str | None:
    """`git:<path>` → gitlab；`device:<id>` → 設備；`app:<id>/<path>` → App；`service:<id>` → 服務；
    `share:<host>/<path>` → 檔案伺服器；`secrets-manager` 等不建立存放邊。"""
    if stored_in.startswith("git:"):
        return "gitlab"
    for prefix in ("device:", "service:"):
        if stored_in.startswith(prefix):
            return stored_in[len(prefix):]
    if stored_in.startswith("app:"):
        return stored_in[4:].split("/", 1)[0]
    if stored_in.startswith("share:"):
        return stored_in[6:].split("/", 1)[0]
    return None


def build_graph(data: TargetData, recon: dict) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    services = {s["id"]: s for s in data.services}
    recon_by_id = {r["asset_id"]: r for r in recon["records"]}
    runtime = {r["service_id"]: r for r in data.snap("runtime.json", []) or []}
    net = data.snap("network.json", {}) or {"nodes": [], "edges": []}
    exposed = {e["to"] for e in net.get("edges", []) if e.get("from") == "internet"}

    def ensure(node_id: str, **attrs):
        node_type = attrs.pop("type", None)
        if node_id not in g:
            g.add_node(node_id, id=node_id, type=node_type or "service", env=None, owner=None, sources=[],
                       registered=False, deployed_via_ci=None, components=[], exposed_to_internet=None,
                       crown_jewel=False, management_interface=False, compensating=[], platform_layer=False,
                       data_classes=[])
        g.nodes[node_id].update({k: v for k, v in attrs.items() if v is not None})

    for n in net.get("nodes", []):
        ensure(n["id"], type=n.get("type", "service"), env=n.get("env"), crown_jewel=n.get("crown_jewel", False),
               management_interface=n.get("management_interface", False), compensating=n.get("compensating", []),
               tls=n.get("tls"))
        g.nodes[n["id"]]["sources"] = sorted(set(g.nodes[n["id"]]["sources"]) | {"network"})

    data_map = {"email": "pii", "order_summary": "order", "device_token": "pii", "user_uploads": "pii"}
    for v in data.vendors:
        if v["id"] in g or v["id"] in {n["id"] for n in net.get("nodes", [])}:
            ensure(v["id"], type="vendor", owner=v.get("owner"),
                   data_classes=sorted({data_map.get(x, x) for x in v.get("data_shared", [])}), registered=True)
    for sid, s in services.items():
        ensure(sid, type=s.get("type", "service"), env=s.get("env"), owner=s.get("owner"),
               platform_layer=s.get("platform_layer", False), data_classes=s.get("data_classes", []))
    for rid, rec in recon_by_id.items():
        ensure(rid, type=rec["type"] if rec["type"] != "saas" else "saas")
        node = g.nodes[rid]
        node.update(registered=rec["registered"], deployed_via_ci=rec.get("deployed_via_ci"),
                    reconcile=rec["conclusion"], level_floor=rec.get("level_floor"),
                    sources=sorted(set(node["sources"]) | set(rec["observed_sources"]) | ({"inventory"} if rec["registered"] else set())))
        if rec.get("display_name"):
            node["display_name"] = rec["display_name"]
    for rid, r in runtime.items():
        ensure(rid, env=r.get("env"))
        g.nodes[rid]["components"] = [component_key(c) for c in r.get("components", [])]
        if r.get("tls") is not None:
            g.nodes[rid]["tls"] = r["tls"]
        if r.get("hosting"):
            g.nodes[rid]["hosting"] = r["hosting"]
        g.nodes[rid]["started_by"] = r.get("started_by")
    for dev in recon.get("devices", []):
        ident = dev.get("identified")
        if ident and dev["asset_id"] in g:
            g.nodes[dev["asset_id"]]["components"] = [{"name": ident["product"], "version": ident["version"]}]
            g.nodes[dev["asset_id"]]["fingerprint"] = ident

    for nid in g.nodes:
        if g.nodes[nid]["type"] != "zone":
            g.nodes[nid]["exposed_to_internet"] = nid in exposed

    for e in net.get("edges", []):
        kind = "download" if e.get("kind") == "store-download" else "network"
        g.add_edge(e["from"], e["to"], kind=kind, port=e.get("port"), evidence=["network.json"],
                   requires=[], grants=["binary"] if kind == "download" else ["reach"])

    for s in data.snap("secrets.json", []) or []:
        cid = s["id"]
        ensure(cid, type="token", env=s.get("env"))
        g.nodes[cid].update(credential=True, status=s.get("status", "unknown"), stored_in=s.get("stored_in"),
                            scope=s.get("scope"), last_rotated=s.get("last_rotated"),
                            ip_allowlist=s.get("ip_allowlist"), vendor=s.get("vendor"),
                            api_scopes=s.get("api_scopes", []), repo_read=s.get("repo_read", False))
        holder = stored_in_node(s.get("stored_in", ""))
        if holder:
            ensure(holder)
            via = "app_binary" if s["stored_in"].startswith("app:") else "foothold"
            g.add_edge(holder, cid, kind="stores", evidence=[f"secrets.json:{cid}.stored_in"],
                       requires=[via], grants=[f"cred:{cid}"], location=s["stored_in"])
        for target in s.get("grants", []):
            ensure(target)
            g.add_edge(cid, target, kind="authorizes", evidence=[f"secrets.json:{cid}.grants"],
                       requires=[f"cred:{cid}", "reach"], grants=[f"access:{target}"],
                       scopes=s.get("api_scopes", []), repo_read=s.get("repo_read", False))

    for k in data.snap("mobile-keys.json", []) or []:
        ensure(k["id"], type="token", env="prod")
        g.nodes[k["id"]].update(credential=True, status="active", stored_in=k.get("stored_in"), scope=k.get("scope"),
                                key_type=k.get("type"), expires=k.get("expires"), accessible_by=k.get("accessible_by", []))
        holder = stored_in_node(k.get("stored_in", ""))
        if holder:
            ensure(holder)
            g.add_edge(holder, k["id"], kind="stores", evidence=[f"mobile-keys.json:{k['id']}"],
                       requires=["foothold"], grants=[f"cred:{k['id']}"], location=k["stored_in"])
        for target in k.get("grants", []):
            ensure(target, type="service", env="prod")
            g.add_edge(k["id"], target, kind="authorizes", evidence=[f"mobile-keys.json:{k['id']}"],
                       requires=[f"cred:{k['id']}", "reach"], grants=[f"access:{target}"], scopes=[], repo_read=False)

    api = data.snap("api-inventory.json", {}) or {}
    for ep in api.get("openapi", []):
        if ep.get("data_store"):
            ensure(ep["data_store"])
            g.add_edge("api-gateway", ep["data_store"], kind="api_data_access", evidence=[f"api-inventory.json:{ep['path']}"],
                       requires=[f"scope:{ep.get('scope')}"], grants=[f"access:{ep['data_store']}"], path=ep["path"],
                       scope=ep.get("scope"), data_fields=ep.get("data_fields", []))

    for row in (data.snap("app-versions.json", {}) or {}).get("rows", []):
        vid = f"brand-app@{row['app_version']}"
        ensure(vid, type="app_version", env="prod")
        node = g.nodes[vid]
        node.setdefault("installations", [])
        node["installations"].append({k: row[k] for k in ("brand_id", "platform", "active_installations", "observed_at")})
        if not g.has_edge("brand-app", vid):
            g.add_edge("brand-app", vid, kind="contains", evidence=["app-versions.json"], requires=[], grants=[])
        for sdk, ver in (row.get("sdks") or {}).items():
            sid = f"{sdk}@{ver}"
            ensure(sid, type="sdk", env="prod", components=[{"name": sdk, "version": ver, "ecosystem": "npm"}])
            if not g.has_edge(vid, sid):
                g.add_edge(vid, sid, kind="contains", evidence=["app-versions.json"], requires=[], grants=[])

    for p in data.people:
        for dev in p.get("devices", []):
            ensure(dev, type="device", env="office")
            g.nodes[dev]["owner"] = g.nodes[dev].get("owner") or p["id"]
    return g


def graph_to_json(g: nx.MultiDiGraph) -> dict:
    nodes = [dict(g.nodes[n]) for n in sorted(g.nodes)]
    edges = sorted(({"from": u, "to": v, **{k: val for k, val in d.items()}} for u, v, d in g.edges(data=True)),
                   key=lambda e: (e["from"], e["to"], e["kind"]))
    return {"schema_version": 1, "nodes": nodes, "edges": edges}
