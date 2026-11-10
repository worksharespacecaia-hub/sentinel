"""GitHub Deployments：A0 Job 以唯讀 Token 讀取（scripts/fetch-deployments.py），各 Agent 由 loaders 讀取同一份檔案。"""
import importlib.util
import io
import json
import urllib.error

import pytest

from tools.common import SENTINEL_ROOT
from tools.loaders import FIXTURE_SCANNERS, FIXTURE_TARGET, expand_github_deployments, github_deployments, load_target

spec = importlib.util.spec_from_file_location("fetch_deployments", SENTINEL_ROOT / "scripts" / "fetch-deployments.py")
fd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fd)

TOKEN = "ghp_test-token-value"
DEPLOY = {"id": 7, "environment": "production", "sha": "a" * 40, "created_at": "2026-11-10T03:34:49Z",
          "creator": {"login": "github-actions[bot]"},
          "payload": {"service_ids": ["storefront"], "source_sha": "a" * 40, "workflow_run_id": 1}}


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def opener_for(routes, calls):
    def opener(req, timeout):
        calls.append((req.full_url, req.get_header("Authorization"), req.get_method(), timeout))
        for prefix, body in routes.items():
            if req.full_url.startswith(prefix):
                if isinstance(body, Exception):
                    raise body
                return Resp(json.dumps(body).encode())
        raise AssertionError(req.full_url)
    return opener


def run_main(tmp_path, env, routes=None):
    calls = []
    dest = tmp_path / "gh" / "deployments.json"
    assert fd.main(["x", str(dest)], env=env, opener=opener_for(routes or {}, calls)) == 0
    return json.loads(dest.read_text(encoding="utf-8")), dest.read_text(encoding="utf-8"), calls


ENV = {"TARGET_REPO": "owner/shopsaas-demo-platform", "GH_READ_TOKEN": TOKEN}
API = "https://api.github.com/repos/owner/shopsaas-demo-platform/deployments"


def test_fetch_ok_uses_latest_status_and_read_only_requests(tmp_path):
    routes = {f"{API}/7/statuses": [{"state": "success"}, {"state": "in_progress"}], API: [DEPLOY]}
    data, text, calls = run_main(tmp_path, ENV, routes)
    assert data["status"] == "ok" and data["repo"] == "owner/shopsaas-demo-platform"
    assert data["deployments"] == [{"id": 7, "environment": "production", "sha": "a" * 40, "state": "success",
                                    "created_at": "2026-11-10T03:34:49Z", "creator": "github-actions[bot]",
                                    "payload": DEPLOY["payload"]}]
    assert calls[0][0] == f"{API}?environment=production&per_page=20"
    assert all(m == "GET" and auth == f"Bearer {TOKEN}" and t == 15 for _, auth, m, t in calls)
    assert TOKEN not in text


@pytest.mark.parametrize("env,error", [
    ({**ENV, "GH_READ_TOKEN": ""}, "未設定 TARGET_READ_TOKEN"),
    ({**ENV, "TARGET_REPO": "owner/x/../y"}, "TARGET_REPO 格式錯誤"),
])
def test_fetch_config_errors_do_not_call_api(tmp_path, env, error):
    data, _, calls = run_main(tmp_path, env)
    assert data["status"] == "failed" and data["error"] == error and calls == []


def test_fetch_http_error_is_recorded_without_token(tmp_path):
    err = urllib.error.HTTPError(API, 403, "Forbidden", {}, io.BytesIO(TOKEN.encode()))
    data, text, _ = run_main(tmp_path, ENV, {API: err})
    assert data == {"repo": ENV["TARGET_REPO"], "fetched_at": data["fetched_at"], "status": "failed", "error": "HTTP 403"}
    assert TOKEN not in text


def test_fetch_bad_shape_is_recorded(tmp_path):
    data, _, _ = run_main(tmp_path, ENV, {API: {"message": "unexpected"}})
    assert data["status"] == "failed" and data["error"] in ("KeyError", "TypeError")


def test_loader_uses_fetched_deployments(tmp_path, as_of):
    p = tmp_path / "deployments.json"
    p.write_text(json.dumps({"status": "ok", "deployments": [{**DEPLOY, "state": "success", "creator": "bot"}]}), encoding="utf-8")
    deployments, issue = github_deployments(p)
    assert issue is None and deployments[0]["id"] == 7
    data = load_target(FIXTURE_TARGET, as_of=as_of, scanners_dir=FIXTURE_SCANNERS, deployments_file=p)
    assert not any(i["source"] == "github/deployments" for i in data.data_issues)
    gh = [d for d in data.deployments if d.get("source_repo") == "shopsaas-demo-platform"]
    assert [d["service_id"] for d in gh] == ["storefront"]


def test_loader_falls_back_to_fixture_with_reason(tmp_path):
    p = tmp_path / "deployments.json"
    p.write_text(json.dumps({"status": "failed", "error": "HTTP 403"}), encoding="utf-8")
    deployments, issue = github_deployments(p)
    assert deployments and issue["status"] == "reused" and "HTTP 403" in issue["impact"]
    deployments, issue = github_deployments(tmp_path / "missing.json")
    assert deployments and issue["impact"] == "使用離線部署紀錄 fixture（未連 GitHub API）"
    assert github_deployments(None)[1]["impact"] == "使用離線部署紀錄 fixture（未連 GitHub API）"


def test_payload_service_ids_are_validated():
    rows = expand_github_deployments([
        {"environment": "production", "state": "success", "payload": {"service_ids": ["storefront", "../x", 3, "A B"]}},
        {"environment": "production", "state": "success", "payload": {"service_ids": "storefront"}},
        {"environment": "production", "state": "success", "payload": "[1, 2]"},
        {"environment": "production", "state": "failure", "payload": {"service_ids": ["member-api"]}},
    ])
    assert [r["service_id"] for r in rows] == ["storefront"]
