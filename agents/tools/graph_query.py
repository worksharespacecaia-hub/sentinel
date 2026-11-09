"""提供給 Subagent 的圖查詢函式（Phase 3 以 SDK 自訂工具包裝，mcp server key 為 graph）。

每次查詢只允許本次資產範圍，結果大小有上限；不回傳金鑰值（圖譜本來就不含）。
"""
from __future__ import annotations

import json

MAX_RESULT_CHARS = 6000


class ScopeError(ValueError):
    pass


class GraphQuery:
    def __init__(self, graph_json: dict, attack_paths: dict | None = None, *, scope: set[str] | None = None):
        self.nodes = {n["id"]: n for n in graph_json.get("nodes", [])}
        self.edges = graph_json.get("edges", [])
        self.paths = (attack_paths or {}).get("paths", [])
        self.scope = scope

    def _check(self, asset_id: str) -> None:
        if asset_id not in self.nodes:
            raise ScopeError(f"未知資產：{asset_id}")
        if self.scope is not None and asset_id not in self.scope:
            raise ScopeError(f"{asset_id} 不在本次資產範圍")

    @staticmethod
    def _limit(obj) -> str:
        text = json.dumps(obj, ensure_ascii=False)
        return text if len(text) <= MAX_RESULT_CHARS else text[:MAX_RESULT_CHARS] + "…（已截斷）"

    def get_asset_context(self, asset_id: str) -> str:
        self._check(asset_id)
        node = {k: v for k, v in self.nodes[asset_id].items() if k not in ("installations",)}
        neighbors = [{"to": e["to"], "kind": e["kind"], "port": e.get("port")} for e in self.edges if e["from"] == asset_id][:30]
        inbound = [{"from": e["from"], "kind": e["kind"], "port": e.get("port")} for e in self.edges if e["to"] == asset_id][:30]
        return self._limit({"asset": node, "outbound": neighbors, "inbound": inbound})

    def find_assets_by_component(self, name: str) -> str:
        hits = [{"asset_id": nid, "version": c.get("version")} for nid, n in self.nodes.items()
                for c in n.get("components", []) if (c.get("name") or "").lower() == name.lower()
                and (self.scope is None or nid in self.scope)]
        return self._limit({"component": name, "assets": hits[:50]})

    def get_attack_paths(self, asset_id: str) -> str:
        self._check(asset_id)
        paths = [{"nodes": p["nodes"], "assumption": p.get("assumption")} for p in self.paths if asset_id in p["nodes"]]
        return self._limit({"asset_id": asset_id, "paths": paths[:10]})
