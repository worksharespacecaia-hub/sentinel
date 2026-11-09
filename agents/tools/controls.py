"""控制項檢查（第 7.2 節 A1）。LLM 判斷「事件和哪些控制項有關」，程式判斷「我們有沒有做到」。

`check` 只能是 CHECKS 白名單的函式名稱；不使用 eval、動態匯入或執行 YAML 內容。
每個函式回傳 {status: pass|fail|unknown, assets: [{asset_id, credential_id?, evidence}], reason}；缺資料為 unknown。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import networkx as nx
import yaml

from tools.common import INTEL_DIR, days_between
from tools.loaders import TargetData
from tools.version_match import AFFECTED, match

SECRETS_TOOL_OK = "ok"


@dataclass
class ControlContext:
    data: TargetData
    graph: nx.MultiDiGraph
    recon: dict
    secret_findings: list[dict] | None      # None = 掃描未完成
    as_of: datetime
    sdk_advisories: list[dict] = field(default_factory=list)


def _result(status: str, assets: list[dict], reason: str) -> dict:
    return {"status": status, "assets": assets, "reason": reason}


def _net_edges(ctx: ControlContext):
    return [(u, v, d) for u, v, d in ctx.graph.edges(data=True) if d["kind"] == "network"]


def secret_in_git(ctx: ControlContext) -> dict:
    if ctx.secret_findings is None:
        return _result("unknown", [], "金鑰掃描結果缺失，無法判斷")
    hits = [s for s in ctx.secret_findings if s["env"] == "prod" and s["credential_id"] and s["credential_status"] != "revoked"]
    assets = [{"asset_id": s["asset_id"], "credential_id": s["credential_id"], "evidence": [s["location"]]} for s in hits]
    return _result("fail" if assets else "pass", assets, f"Git 中有 {len(assets)} 個有效的正式環境金鑰" if assets else "未發現")


def internal_tool_exposed(ctx: ControlContext) -> dict:
    if "network.json" not in ctx.data.snapshots:
        return _result("unknown", [], "network.json 缺失")
    assets = []
    for u, v, d in _net_edges(ctx):
        node = ctx.graph.nodes[v]
        if u == "internet" and (node["type"] == "internal_tool" or node.get("management_interface")):
            assets.append({"asset_id": v, "evidence": [f"network.json: internet → {v}:{d.get('port')}"]})
    return _result("fail" if assets else "pass", assets, "內部工具或管理介面可從 internet 連到" if assets else "未發現")


def net_segment(ctx: ControlContext) -> dict:
    if "network.json" not in ctx.data.snapshots:
        return _result("unknown", [], "network.json 缺失")
    assets: dict[str, dict] = {}
    for u, v, d in _net_edges(ctx):
        src, dst = ctx.graph.nodes[u], ctx.graph.nodes[v]
        if src.get("env") in ("test", "office") and dst["type"] == "datastore" and dst.get("env") == "prod":
            entry = assets.setdefault(v, {"asset_id": v, "evidence": []})
            entry["evidence"].append(f"network.json: {u}（{src['env']}）→ {v}:{d.get('port')}")
    return _result("fail" if assets else "pass", list(assets.values()), "非正式環境可直連正式資料庫" if assets else "未發現")


def third_party_key_rotation(ctx: ControlContext) -> dict:
    secrets = ctx.data.snap("secrets.json")
    if secrets is None:
        return _result("unknown", [], "secrets.json 缺失")
    assets = []
    for s in secrets:
        if not s.get("vendor"):
            continue
        age = days_between(s.get("last_rotated"), ctx.as_of)
        problems = []
        if age is None:
            problems.append("輪替時間未知")
        elif age > 90:
            problems.append(f"{age} 天未輪替")
        if s.get("ip_allowlist") is not True:
            problems.append("無 IP 白名單")
        if problems:
            assets.append({"asset_id": s["id"], "credential_id": s["id"], "evidence": [f"secrets.json: {s['id']}：" + "、".join(problems)]})
    return _result("fail" if assets else "pass", assets, "第三方金鑰未依規定輪替或無白名單" if assets else "未發現")


def non_ci_deploy(ctx: ControlContext) -> dict:
    assets = []
    for r in ctx.recon["records"]:
        if r.get("ci_applicable") and r["registered"] and r.get("deployed_via_ci") is False and r["observed"]:
            assets.append({"asset_id": r["asset_id"], "evidence": [f"對帳：{r['reason']}"]})
    for u, v, d in ctx.graph.edges(data=True):
        if d["kind"] != "authorizes" or v != "deploy-pipeline":
            continue
        for holder, _, sd in ctx.graph.in_edges(u, data=True):
            if sd["kind"] == "stores" and ctx.graph.nodes[holder]["type"] in ("ai_tool", "service", "internal_tool"):
                assets.append({"asset_id": holder, "credential_id": u,
                               "evidence": [f"secrets.json: {u} 存放於 {holder}，可直接觸發 deploy-pipeline（繞過 Pipeline 審核）"]})
    return _result("fail" if assets else "pass", assets, "有不經 Pipeline 的正式部署途徑" if assets else "未發現")


def dev_device_token(ctx: ControlContext) -> dict:
    mdm = ctx.data.snap("mdm.json")
    secrets = ctx.data.snap("secrets.json")
    if mdm is None or secrets is None:
        return _result("unknown", [], "mdm.json 或 secrets.json 缺失")
    by_id = {s["id"]: s for s in secrets}
    assets = []
    for dev in mdm.get("devices", []):
        for f in dev.get("sensitive_files", []):
            cred = by_id.get(f.get("credential_id"))
            if f.get("type") == "deploy-token" and cred and cred.get("env") == "prod" and cred.get("status") != "revoked":
                assets.append({"asset_id": dev["id"], "credential_id": cred["id"],
                               "evidence": [f"mdm.json: {dev['id']} 有 {f['path']}", f"secrets.json: {cred['id']} → {', '.join(cred['grants'])}"]})
    return _result("fail" if assets else "pass", assets, "員工電腦持有正式部署權杖" if assets else "未發現")


def backup_isolation(ctx: ControlContext) -> dict:
    backups = ctx.data.snap("backups.json")
    if backups is None:
        return _result("unknown", [], "backups.json 缺失")
    assets = []
    for b in backups:
        problems = []
        if not b.get("isolated"):
            problems.append(f"備份與來源未隔離（{b.get('target')}）")
        age = days_between(b.get("last_restore_test"), ctx.as_of)
        if age is None:
            problems.append("從未做過還原測試")
        elif age > 90:
            problems.append(f"{age} 天未做還原測試")
        if problems:
            assets.append({"asset_id": b["asset_id"], "evidence": [f"backups.json: {b['asset_id']}：" + "、".join(problems)]})
    return _result("fail" if assets else "pass", assets, "備份未隔離或未驗證還原" if assets else "未發現")


def app_sdk(ctx: ControlContext) -> dict:
    rows = (ctx.data.snap("app-versions.json") or {}).get("rows")
    if rows is None:
        return _result("unknown", [], "app-versions.json 缺失")
    if not ctx.sdk_advisories:
        return _result("pass", [], "目前沒有命中的行動 SDK 漏洞公告")
    hit_versions = []
    for adv in ctx.sdk_advisories:
        for row in rows:
            for sdk, ver in (row.get("sdks") or {}).items():
                if sdk == adv["name"] and match(ver, adv["affected"], adv.get("ecosystem", "npm")) == AFFECTED:
                    hit_versions.append((row["app_version"], sdk, ver))
    if not hit_versions:
        return _result("pass", [], "各 App 版本打包的 SDK 不在受影響範圍")
    versions = sorted({v for v, _, _ in hit_versions})
    return _result("fail", [{"asset_id": "brand-app", "evidence": [f"app-versions.json: 受影響版本 {', '.join(versions)}"]}],
                   "App 版本內打包的 SDK 有已知漏洞")


def cloud_storage_public(ctx: ControlContext) -> dict:
    fb = ctx.data.snap("firebase-config.json")
    ext = ctx.data.snap("external-scan.json")
    if fb is None and ext is None:
        return _result("unknown", [], "firebase-config.json 與 external-scan.json 皆缺失")
    assets: dict[str, dict] = {}
    for s in (fb or {}).get("storage", []):
        if s.get("public_read"):
            rules = "；".join(f"{r['match']} read {r['read']}" for r in s.get("rules", []))
            assets.setdefault(s["asset_id"], {"asset_id": s["asset_id"], "evidence": []})["evidence"].append(f"firebase-config.json: {rules}")
    for r in (ext or {}).get("results", []):
        if r.get("anonymous_list") and r.get("asset_hint"):
            assets.setdefault(r["asset_hint"], {"asset_id": r["asset_hint"], "evidence": []})["evidence"].append(
                f"external-scan.json: {r['target']} 可匿名列出內容")
    tf = ctx.data.files.get("infra/terraform/main.tf") or ""
    for bucket in re.findall(r'acl\s*=\s*"public-read"', tf):
        if "order-exports-bucket" in assets:
            assets["order-exports-bucket"]["evidence"].append('infra/terraform/main.tf: aws_s3_bucket_acl acl = "public-read"')
            break
    return _result("fail" if assets else "pass", list(assets.values()), "雲端儲存空間可公開讀取" if assets else "未發現")


def cache_tls(ctx: ControlContext) -> dict:
    found, unknown = [], []
    for nid, node in ctx.graph.nodes(data=True):
        if not any(c.get("name") == "redis" for c in node.get("components", [])):
            continue
        if node.get("tls") is False:
            found.append({"asset_id": nid, "evidence": [f"runtime.json: {nid} tls=false"]})
        elif node.get("tls") is None:
            unknown.append(nid)
    if found:
        return _result("fail", found, "快取服務未啟用 TLS")
    if unknown:
        return _result("unknown", [], f"無法確認 TLS 設定：{', '.join(unknown)}")
    return _result("pass", [], "未發現")


CHECKS = {
    "secret_in_git": secret_in_git,
    "internal_tool_exposed": internal_tool_exposed,
    "net_segment": net_segment,
    "third_party_key_rotation": third_party_key_rotation,
    "non_ci_deploy": non_ci_deploy,
    "dev_device_token": dev_device_token,
    "backup_isolation": backup_isolation,
    "app_sdk": app_sdk,
    "cloud_storage_public": cloud_storage_public,
    "cache_tls": cache_tls,
}

CATEGORY = {
    "C-SECRET-IN-GIT": "secret", "C-INTERNAL-TOOL-EXPOSED": "config", "C-NET-SEGMENT": "config",
    "C-THIRD-PARTY-KEY-ROTATION": "secret", "C-NON-CI-DEPLOY": "config", "C-DEV-DEVICE-TOKEN": "identity",
    "C-BACKUP-ISOLATION": "backup", "C-APP-SDK": "mobile", "C-CLOUD-STORAGE-PUBLIC": "config", "C-CACHE-TLS": "config",
}


def load_controls(path: Path | None = None) -> list[dict]:
    controls = yaml.safe_load((path or INTEL_DIR / "controls.yaml").read_text(encoding="utf-8")) or []
    for c in controls:
        if c.get("check") not in CHECKS:
            raise ValueError(f"控制項 {c.get('id')} 的 check `{c.get('check')}` 不在白名單")
        if not isinstance(c.get("base_points"), int):
            raise ValueError(f"控制項 {c.get('id')} 缺少 base_points")
    return controls


def run_controls(ctx: ControlContext, controls: list[dict] | None = None) -> dict[str, dict]:
    controls = controls or load_controls()
    out = {}
    for c in controls:
        res = CHECKS[c["check"]](ctx)
        out[c["id"]] = {**res, "control_id": c["id"], "title": c["title"], "base_points": c["base_points"]}
    return out
