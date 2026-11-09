"""讀取 Repo ① 的清冊、快照、訊號、SBOM、GitHub Deployments 與掃描結果。

所有外部內容都只當資料處理。缺檔記錄為 data_issues（missing），過期記錄為 stale，不靜默當成空資料。
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from tools.common import AGENTS_DIR, parse_time, read_json

SNAPSHOT_FILES = [
    "runtime.json", "network.json", "secrets.json", "lan-scan.json", "external-scan.json", "mdm.json",
    "sso-apps.json", "payments.csv", "backups.json", "php-config.json", "apps.json", "app-versions.json",
    "mobile-keys.json", "firebase-config.json", "app-store-scan.json", "api-inventory.json", "deployments.json",
]
REQUIRED = {"runtime.json", "network.json", "secrets.json"}
DEFAULT_MAX_AGE_DAYS = 30
FIXTURE_TARGET = AGENTS_DIR / "fixtures" / "target-baseline"
FIXTURE_SCANNERS = AGENTS_DIR / "fixtures" / "scanners" / "baseline"
FIXTURE_GITHUB = AGENTS_DIR / "fixtures" / "github"


@dataclass
class TargetData:
    root: Path
    target_sha: str
    as_of: datetime
    services: list[dict] = field(default_factory=list)
    vendors: list[dict] = field(default_factory=list)
    people: list[dict] = field(default_factory=list)
    snapshots: dict = field(default_factory=dict)
    snapshot_meta: dict = field(default_factory=dict)
    signals: dict = field(default_factory=dict)
    files: dict = field(default_factory=dict)          # 原始檔文字（Manifest、gradle、terraform、package.json）
    deployments: list[dict] = field(default_factory=list)
    scanners: dict = field(default_factory=dict)
    data_issues: list[dict] = field(default_factory=list)

    def snap(self, name: str, default=None):
        value = self.snapshots.get(name)
        return default if value is None else value

    def service(self, asset_id: str) -> dict | None:
        return next((s for s in self.services if s["id"] == asset_id), None)


def _read_text(path: Path) -> str | None:
    return path.read_text(encoding="utf-8") if path.is_file() else None


def _yaml(path: Path):
    text = _read_text(path)
    return None if text is None else (yaml.safe_load(text) or [])


def _csv(text: str) -> list[dict]:
    return list(csv.DictReader(io.StringIO(text)))


def _jsonl(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def load_target(root: Path, *, as_of: datetime, target_sha: str | None = None,
                deployments: list[dict] | None = None, scanners_dir: Path | None = None,
                max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> TargetData:
    root = Path(root)
    fixture_info = read_json(root / ".fixture.json", {}) or {}
    data = TargetData(root=root, target_sha=target_sha or fixture_info.get("target_sha") or "unknown", as_of=as_of)

    for name, attr in (("services.yaml", "services"), ("vendors.yaml", "vendors"), ("people.yaml", "people")):
        value = _yaml(root / "ops" / "inventory" / name)
        if value is None:
            data.data_issues.append({"source": f"inventory/{name}", "status": "missing", "impact": "清冊對帳"})
            value = []
        setattr(data, attr, value)

    meta = read_json(root / "ops" / "snapshots" / "_meta.json", {}) or {}
    data.snapshot_meta = meta.get("snapshots", {})
    for name in SNAPSHOT_FILES:
        path = root / "ops" / "snapshots" / name
        text = _read_text(path)
        if text is None:
            data.data_issues.append({"source": f"snapshots/{name}", "status": "missing",
                                     "required": name in REQUIRED, "impact": "依賴此快照的評估改為待確認"})
            continue
        data.snapshots[name] = _csv(text) if name.endswith(".csv") else json.loads(text)
        observed = parse_time((data.snapshot_meta.get(name) or {}).get("observed_at"))
        if observed is None:
            data.data_issues.append({"source": f"snapshots/{name}", "status": "unknown_age", "impact": "觀察時間未知"})
        elif as_of - observed > timedelta(days=max_age_days):
            data.data_issues.append({"source": f"snapshots/{name}", "status": "stale",
                                     "observed_at": observed.isoformat(), "required": name in REQUIRED,
                                     "impact": f"超過 {max_age_days} 天未重新觀察"})

    for name in ("complaints.csv", "db-audit.jsonl", "auth.jsonl"):
        text = _read_text(root / "ops" / "signals" / name)
        if text is None:
            data.data_issues.append({"source": f"signals/{name}", "status": "missing", "impact": "早期訊號不完整"})
            continue
        data.signals[name] = _csv(text) if name.endswith(".csv") else _jsonl(text)

    for rel in ("services/brand-app/package.json", "services/brand-app/android/app/src/main/AndroidManifest.xml",
                "services/brand-app/android/app/build.gradle", "services/brand-app/src/config.ts",
                "infra/terraform/main.tf", "config/db.yml", "services/marketing-site/Dockerfile",
                "services/storefront/middleware.ts"):
        text = _read_text(root / rel)
        if text is not None:
            data.files[rel] = text

    snap_deploys = (data.snapshots.get("deployments.json") or {}).get("deployments", [])
    if deployments is None:
        gh = read_json(FIXTURE_GITHUB / "deployments.json", {"deployments": []})
        deployments = gh.get("deployments", [])
        data.data_issues.append({"source": "github/deployments", "status": "reused",
                                 "impact": "使用離線部署紀錄 fixture（未連 GitHub API）"})
    data.deployments = [*expand_github_deployments(deployments), *snap_deploys]

    data.scanners = load_scanners(scanners_dir) if scanners_dir else {}
    return data


def expand_github_deployments(deployments: list[dict]) -> list[dict]:
    """GitHub Deployment → 每個 service_id 一筆；只採用 production + success 且 payload 明確列出的服務。"""
    out = []
    for d in deployments:
        payload = d.get("payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                payload = {}
        if d.get("environment") != "production" or d.get("state") != "success":
            continue
        for sid in payload.get("service_ids") or []:
            out.append({"service_id": sid, "environment": "production", "state": "success",
                        "source_sha": payload.get("source_sha"), "created_at": d.get("created_at"),
                        "creator": d.get("creator"), "source_repo": "shopsaas-demo-platform"})
    return out


def load_scanners(directory: Path) -> dict:
    """讀取已遮蔽的掃描結果；缺檔記錄 missing，不轉成零發現。"""
    result = {}
    for tool in ("gitleaks", "trivy", "checkov"):
        path = Path(directory) / f"{tool}.json"
        result[tool] = {"status": "ok", "data": read_json(path)} if path.is_file() else {"status": "missing", "data": None}
    return result
