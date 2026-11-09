"""incident.yml 的圍堵建議流程（第 7.6、14.5 節）：以假的 HTTP 回應測試，不連任何外部服務、不呼叫 LLM。"""
import json
import os
import subprocess
import sys
from dataclasses import replace

import pytest
import yaml

from agents import incident
from context import build_ctx
from llm import scrubbed_environ
from tools.common import SENTINEL_ROOT

ALERT = "al-rt-001-0123456789abcdef"
REPO = "demo-owner/sentinel"
BASE = "https://sentinel.example.com"
ENV = {"ALERT_ID": ALERT, "ASSET_ID": "deploy-pipeline", "GITHUB_REPOSITORY": REPO, "SENTINEL_BASE_URL": BASE,
       "NOTIFY_TOKEN": "notify-test-token", "GH_TOKEN": "gh-test-token"}


def context_body(**over):
    body = {"alert_id": ALERT, "rule_id": "RT-001", "rule_title": "非 Pipeline 發起的正式部署", "level": "high",
            "asset_id": "deploy-pipeline", "account": None, "summary": "alice-dev 直接建立 production 部署（ref main），未經 Pipeline",
            "repo": REPO, "issue_number": 7, "simulated": False, "simulation_id": None, "status": "open",
            "maps_to_event": "evt-binance-2026-10", "source_event_ids": ["gh-deployment-99"], "created_at": "2026-11-09T03:00:00Z",
            "advice": None}
    body.update(over)
    return body


class FakeHttp:
    def __init__(self, context=None, comments=None, advice_status=200):
        self.calls = []
        self.context = context or context_body()
        self.comments = comments if comments is not None else []
        self.advice_status = advice_status

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        if url.startswith(f"{BASE}/api/alerts/context"):
            assert headers["authorization"] == "Bearer notify-test-token"
            return 200, self.context
        if url.startswith(f"https://api.github.com/repos/{REPO}/issues/7/comments") and method == "GET":
            assert headers["authorization"] == "Bearer gh-test-token"
            return 200, self.comments
        if url == f"https://api.github.com/repos/{REPO}/issues/7/comments" and method == "POST":
            self.comments.append({"body": body["body"], "html_url": f"https://github.com/{REPO}/issues/7#issuecomment-555"})
            return 201, {"html_url": f"https://github.com/{REPO}/issues/7#issuecomment-555"}
        if url == f"{BASE}/api/alerts/advice":
            return self.advice_status, {"ok": True}
        raise AssertionError(f"未預期的呼叫 {method} {url}")


@pytest.fixture()
def ctx(monkeypatch, tmp_path):
    for k in ("EXECUTION_MODE", "SCENARIO", "TARGET_DIR", "ADVISORY_ID", "ASSETS", "TARGET_SHA", "AS_OF"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("RUN_ID", "incident-test")
    import claude_agent_sdk
    monkeypatch.setattr(claude_agent_sdk, "query", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM")))
    return replace(build_ctx(), out=tmp_path / "out")


def posted(http):
    return [c for c in http.calls if c[0] == "POST" and c[1].endswith("/comments")]


def test_replay_flow_comments_template_and_reports_advice(ctx):
    http = FakeHttp()
    res = incident.run(ctx, http=http, env=ENV)
    assert res["source"] == "template" and not res["reused"]
    [(_, _, _, body)] = posted(http)
    text = body["body"]
    assert incident.advice_marker(ALERT) in text
    assert "只建議、不執行" in text
    assert "deploy-token-eng07" in text, "從圖譜找出可授權 deploy-pipeline 的權杖"
    assert "laptop-eng-07 → deploy-token-eng07 → **deploy-pipeline**" in text, "列出經過告警資產的攻擊鏈"
    assert "DEMO-FAKE" not in text
    advice = [c for c in http.calls if c[1] == f"{BASE}/api/alerts/advice"]
    assert advice[0][3] == {"alert_id": ALERT, "comment_url": f"https://github.com/{REPO}/issues/7#issuecomment-555",
                            "source": "template", "run_id": "incident-test"}
    trace = (ctx.out / "incident" / "trace.jsonl").read_text(encoding="utf-8")
    assert "containment-advisor 未錄製，改用程式範本" in trace


def test_rerun_reuses_marker_comment_without_regenerating(ctx, monkeypatch):
    http = FakeHttp()
    incident.run(ctx, http=http, env=ENV)
    # 第二次執行：Issue 已有 marker → 不呼叫 Subagent、不再留言，只補回報
    monkeypatch.setattr(incident.Task, "__init__", lambda *a, **k: (_ for _ in ()).throw(AssertionError("不應重新產生")))
    http2 = FakeHttp(comments=http.comments)
    res = incident.run(ctx, http=http2, env=ENV)
    assert res["reused"] is True
    assert posted(http2) == []
    assert any(c[1] == f"{BASE}/api/alerts/advice" for c in http2.calls)


@pytest.mark.parametrize("override,match", [
    ({"repo": "attacker/other"}, "不屬於本 Repo"),
    ({"alert_id": "al-rt-001-ffffffffffffffff"}, "alert_id 不符"),
    ({"asset_id": "member-db-prod"}, "資產不在即時規則範圍"),
    ({"issue_number": None}, "Issue number"),
    ({"issue_number": "7; rm -rf /"}, "Issue number"),
])
def test_forged_context_is_rejected(ctx, override, match):
    http = FakeHttp(context=context_body(**override))
    with pytest.raises(incident.IncidentError, match=match):
        incident.run(ctx, http=http, env=ENV)
    assert posted(http) == []


@pytest.mark.parametrize("env_over,match", [
    ({"ALERT_ID": "../../etc"}, "ALERT_ID"),
    ({"ALERT_ID": "al-rt-001-0123456789abcdef; echo"}, "ALERT_ID"),
    ({"SENTINEL_BASE_URL": "http://sentinel.example.com"}, "HTTPS"),
    ({"NOTIFY_TOKEN": ""}, "缺少"),
])
def test_invalid_inputs_are_rejected(ctx, env_over, match):
    with pytest.raises(incident.IncidentError, match=match):
        incident.run(ctx, http=FakeHttp(), env={**ENV, **env_over})


def test_payload_asset_hint_is_not_trusted(ctx):
    http = FakeHttp()
    res = incident.run(ctx, http=http, env={**ENV, "ASSET_ID": "member-db-prod"})
    assert res["source"] == "template"
    text = posted(http)[0][3]["body"]
    assert "`deploy-pipeline`" in text and "member-db-prod" not in text


def test_advice_callback_failure_is_reported(ctx):
    with pytest.raises(incident.IncidentError, match="回報"):
        incident.run(ctx, http=FakeHttp(advice_status=503), env=ENV)


def test_simulated_alert_is_labelled(ctx):
    http = FakeHttp(context=context_body(simulated=True, simulation_id="sim-202611090300-abcdef", rule_id="RT-002",
                                         asset_id="order-db-prod", account="dba-alice", summary="凌晨大量讀取"))
    incident.run(ctx, http=http, env=ENV)
    text = posted(http)[0][3]["body"]
    assert "模擬告警（sim-202611090300-abcdef）" in text
    assert "dba-alice" in text and "order-db-prod-cred" in text


def test_tokens_are_not_passed_to_llm_subprocess(monkeypatch):
    monkeypatch.setenv("NOTIFY_TOKEN", "x")
    monkeypatch.setenv("GH_TOKEN", "y")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "z")
    with scrubbed_environ():
        assert "NOTIFY_TOKEN" not in os.environ and "GH_TOKEN" not in os.environ
        assert os.environ.get("ANTHROPIC_API_KEY") == "z"
    assert os.environ["NOTIFY_TOKEN"] == "x"


# ------------------------------------------------------------------ workflow 與規則打包

def load_wf(name):
    text = (SENTINEL_ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    data["on"] = data.pop(True, data.get("on"))
    return text, data


def test_incident_workflow_structure():
    text, d = load_wf("incident.yml")
    assert d["on"] == {"repository_dispatch": {"types": ["incident"]}}
    assert d["concurrency"] == {"group": "incident-${{ github.event.client_payload.alert_id }}", "cancel-in-progress": False}
    assert d["permissions"] == {"contents": "read", "issues": "write"}
    job = d["jobs"]["contain"]
    assert job["timeout-minutes"] == 10
    for step in job["steps"]:
        assert "client_payload" not in step.get("run", ""), "payload 只能經 env 傳入"
        if "uses" in step and step["uses"].startswith("actions/checkout"):
            assert step["with"]["persist-credentials"] is False
    env = job["steps"][-1]["env"]
    assert "== 'live'" in env["ANTHROPIC_API_KEY"]
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in text
    assert "git push" not in text and "contents: write" not in text


def test_realtime_rules_json_is_in_sync():
    proc = subprocess.run([sys.executable, str(SENTINEL_ROOT / "scripts" / "build-rules.py"), "--check"], capture_output=True)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    data = json.loads((SENTINEL_ROOT / "dashboard" / "lib" / "realtime-rules.json").read_text(encoding="utf-8"))
    assert [r["id"] for r in data["rules"]] == ["RT-001", "RT-002", "RT-003"]
    assert incident.rule_assets() == {"deploy-pipeline", "order-db-prod", "platform"}
