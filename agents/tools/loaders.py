"""讀取 Repo ① 的清冊、快照、訊號、SBOM、GitHub Deployments 與掃描結果。

所有外部內容都只當資料處理。缺檔記錄為 data_issues（missing），過期記錄為 stale，不靜默當成空資料。
"""
from __future__ import annotations

import csv
import io
import json
import re
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
                deployments_file: Path | None = None, max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> TargetData:
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

    _require_revocation_evidence(data)

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
        deployments, issue = github_deployments(deployments_file)
        if issue:
            data.data_issues.append(issue)
    data.deployments = [*expand_github_deployments(deployments), *snap_deploys]

    data.scanners = load_scanners(scanners_dir, as_of) if scanners_dir else {}
    return data


def _require_revocation_evidence(data: TargetData) -> None:
    """金鑰只有附撤銷證據（revocation_evidence）才算 revoked（第 10 節：有正式撤銷證據才 fixed）。

    Git 歷史仍保留舊值時，只改 HEAD 或只在清冊寫 revoked 都不能解除授權；沒有證據就當作仍然有效。
    """
    for s in data.snapshots.get("secrets.json") or []:
        if s.get("status") == "revoked" and not str(s.get("revocation_evidence") or "").strip():
            s["status"] = "active"
            s["revocation_claimed"] = True
            data.data_issues.append({"source": f"secrets.json:{s.get('id')}", "status": "unverified", "required": False,
                                     "impact": "宣稱已撤銷但沒有撤銷證據，仍視為有效金鑰"})


def github_deployments(path: Path | None) -> tuple[list[dict], dict | None]:
    """A0 Job 由 GitHub API 抓到的部署紀錄（scripts/fetch-deployments.py）；沒有或失敗時改用離線 fixture 並記錄原因。"""
    fetched = read_json(path) if path else None
    if isinstance(fetched, dict) and fetched.get("status") == "ok" and isinstance(fetched.get("deployments"), list):
        return fetched["deployments"], None
    fixture = (read_json(FIXTURE_GITHUB / "deployments.json", {"deployments": []}) or {}).get("deployments", [])
    if isinstance(fetched, dict) and fetched.get("status") == "failed":
        reason = str(fetched.get("error") or "未知錯誤")[:80]
        return fixture, {"source": "github/deployments", "status": "reused",
                         "impact": f"GitHub Deployments API 讀取失敗（{reason}），改用離線部署紀錄 fixture"}
    return fixture, {"source": "github/deployments", "status": "reused",
                     "impact": "使用離線部署紀錄 fixture（未連 GitHub API）"}


SERVICE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,80}$")


def expand_github_deployments(deployments: list[dict]) -> list[dict]:
    """GitHub Deployment → 每個 service_id 一筆；只採用 production + success 且 payload 明確列出的服務。

    payload 由受評估的 Repo 寫入，只當資料：service_id 必須是合法 ID，其他欄位不採用。
    """
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
        sids = payload.get("service_ids") if isinstance(payload, dict) else None
        for sid in sids if isinstance(sids, list) else []:
            if not isinstance(sid, str) or not SERVICE_ID_RE.match(sid):
                continue
            out.append({"service_id": sid, "environment": "production", "state": "success",
                        "source_sha": payload.get("source_sha"), "created_at": d.get("created_at"),
                        "creator": d.get("creator"), "source_repo": "shopsaas-demo-platform"})
    return out


def load_scanners(directory: Path, as_of: datetime | None = None) -> dict:
    """讀取已遮蔽的掃描結果；缺檔記錄 missing，不轉成零發現。

    有 manifest 時一併檢查：工具失敗（沿用目錄中可能留著前一次的結果檔）記為 failed；超過 valid_until 記為 stale。
    """
    result = {}
    for tool in ("gitleaks", "trivy", "checkov", "kev", "nvd"):
        path = Path(directory) / f"{tool}.json"
        manifest = read_json(Path(directory) / f"{tool}.manifest.json")
        if manifest and manifest.get("status") != "ok":
            result[tool] = {"status": "failed", "data": None, "reason": manifest.get("reason")}
            continue
        until = parse_time((manifest or {}).get("valid_until"))
        if manifest and as_of is not None and until is not None and until < as_of:
            result[tool] = {"status": "stale", "data": None}
            continue
        result[tool] = {"status": "ok", "data": read_json(path)} if path.is_file() else {"status": "missing", "data": None}
    return result
