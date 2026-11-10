#!/usr/bin/env python3
"""A0 Job：用 TARGET_READ_TOKEN 讀取 Repo ① 的 production Deployments 與最新狀態，寫成 JSON 給 A0～A5 共用。

用法：GH_READ_TOKEN=... TARGET_REPO=owner/repo python scripts/fetch-deployments.py gh/deployments.json

- 只呼叫 GitHub REST API 的讀取端點（GET），不寫入 Repo ①
- 失敗時不讓 Job 失敗：寫出 {"status": "failed", "error": ...}，後續改用離線 fixture 並在報告標示
- Token 只放在 Authorization 標頭，不寫入輸出或 log；錯誤訊息只含 HTTP 狀態碼與例外類型
- payload 由 Repo ① 的 CI 寫入，只當資料（service_id 由 loaders 驗證格式）
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API = "https://api.github.com"
REPO_RE = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
MAX_DEPLOYMENTS = 20


def _get(url: str, token: str, opener=urllib.request.urlopen):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "sentinel-fetch-deployments",
    })
    with opener(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch(repo: str, token: str, *, opener=urllib.request.urlopen) -> list[dict]:
    items = _get(f"{API}/repos/{repo}/deployments?environment=production&per_page={MAX_DEPLOYMENTS}", token, opener)
    out = []
    for d in items[:MAX_DEPLOYMENTS]:
        statuses = _get(f"{API}/repos/{repo}/deployments/{int(d['id'])}/statuses?per_page=1", token, opener)
        out.append({
            "id": d["id"], "environment": d.get("environment"), "sha": d.get("sha"),
            "state": statuses[0].get("state") if statuses else None,     # 最新狀態在第一筆
            "created_at": d.get("created_at"), "creator": (d.get("creator") or {}).get("login"),
            "payload": d.get("payload") or {},
        })
    return out


def main(argv: list[str], env=os.environ, opener=urllib.request.urlopen) -> int:
    if len(argv) != 2:
        print("用法：fetch-deployments.py <輸出檔>", file=sys.stderr)
        return 2
    dest = Path(argv[1])
    repo, token = env.get("TARGET_REPO", ""), env.get("GH_READ_TOKEN", "")
    result = {"repo": repo, "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if not REPO_RE.match(repo):
        result.update(status="failed", error="TARGET_REPO 格式錯誤")
    elif not token:
        result.update(status="failed", error="未設定 TARGET_READ_TOKEN")
    else:
        try:
            result.update(status="ok", deployments=fetch(repo, token, opener=opener))
        except urllib.error.HTTPError as exc:
            result.update(status="failed", error=f"HTTP {exc.code}")
        except Exception as exc:   # 網路錯誤、逾時、回應格式不符
            result.update(status="failed", error=type(exc).__name__)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if result["status"] == "ok":
        print(f"讀到 {len(result['deployments'])} 筆 production Deployment")
    else:
        print(f"::warning::GitHub Deployments 讀取失敗（{result['error']}），本次改用離線 fixture")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
