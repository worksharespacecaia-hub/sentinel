"""Workflow 結構規則（第 14.3、14.4 節）。actionlint 另由 scripts/lint-workflows.sh 檢查語法。"""
import re

import pytest
import yaml

from tools.common import SENTINEL_ROOT

WF = SENTINEL_ROOT / ".github" / "workflows"


def load(name):
    text = (WF / name).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    data["on"] = data.pop(True, data.get("on"))      # PyYAML 把 on 解析成 True
    return text, data


@pytest.fixture(scope="module")
def sentinel():
    return load("sentinel.yml")


def test_concurrency_queues_and_no_cancel(sentinel):
    _, d = sentinel
    assert d["concurrency"] == {"group": "sentinel", "cancel-in-progress": False, "queue": "max"}
    _, w = load("intel-watch.yml")
    assert w["concurrency"]["queue"] == "max"


def test_jobs_reading_orchestrator_list_it_directly(sentinel):
    _, d = sentinel
    for name, job in d["jobs"].items():
        body = yaml.safe_dump(job, allow_unicode=True)
        if "needs.orchestrator" in body and name != "orchestrator":
            assert "orchestrator" in job["needs"], name


def test_downstream_conditions_use_not_cancelled(sentinel):
    _, d = sentinel
    for name, job in d["jobs"].items():
        if name == "orchestrator":
            continue
        assert job["if"].startswith("${{ !cancelled()"), name
        assert "always()" not in job["if"], name
    a5 = d["jobs"]["a5-report"]
    assert a5["if"] == "${{ !cancelled() }}"
    assert set(a5["needs"]) == {"orchestrator", "a0-assets", "scanners", "daily-intel", "a1-intel", "a2-scan", "a3-signals", "a4-risk"}


def test_only_a5_can_write_contents(sentinel):
    _, d = sentinel
    assert d["permissions"] == {"contents": "read"}
    for name, job in d["jobs"].items():
        perms = job.get("permissions") or {}
        if name == "a5-report":
            assert perms == {"contents": "write"}
        else:
            assert perms.get("contents", "read") == "read", name


def test_subscription_token_only_in_daily_intel(sentinel):
    _, d = sentinel
    for name, job in d["jobs"].items():
        body = yaml.safe_dump(job, allow_unicode=True)
        if name == "daily-intel":
            assert "CLAUDE_CODE_OAUTH_TOKEN" in body and "ANTHROPIC_API_KEY" not in body
            cond = job["if"]
            for clause in ("daily_intel == 'true'", "execution_mode == 'live'", "github.event_name == 'schedule'",
                           "inputs.scenario == 'daily'", "inputs.trigger_source == 'manual'"):
                assert clause in cond
            assert job["steps"][0]["with"]["persist-credentials"] is False
            assert job["continue-on-error"] is True
        else:
            assert "CLAUDE_CODE_OAUTH_TOKEN" not in body, name


def test_api_key_only_passed_in_live(sentinel):
    _, d = sentinel
    for name, job in d["jobs"].items():
        for step in job.get("steps", []):
            env = step.get("env") or {}
            if "ANTHROPIC_API_KEY" in env:
                assert "execution_mode == 'live'" in env["ANTHROPIC_API_KEY"], name


def test_artifact_names_are_unique_per_run(sentinel):
    _, d = sentinel
    names = []
    for job in d["jobs"].values():
        for step in job.get("steps", []):
            if str(step.get("uses", "")).startswith("actions/upload-artifact"):
                n = step["with"]["name"]
                assert n.startswith("${{ github.run_id }}-"), n
                names.append(n)
    assert len(names) == len(set(names))


def test_no_pull_request_target_and_pinned_checkout():
    for p in WF.glob("*.yml"):
        text = p.read_text(encoding="utf-8")
        assert "pull_request_target" not in text
        for uses in re.findall(r"uses: (actions/checkout@\S+)", text):
            assert uses == "actions/checkout@v4"


def test_publisher_is_the_only_writer(sentinel):
    text, _ = sentinel
    assert "git push" not in text and "git add" not in text
    assert text.count("scripts/push-with-retry.sh") == 1


def test_intel_watch_has_no_llm():
    text, d = load("intel-watch.yml")
    code = " ".join(line.split("#", 1)[0] for line in text.splitlines())   # 去掉註解
    assert "ANTHROPIC_API_KEY" not in code and "CLAUDE_CODE_OAUTH_TOKEN" not in code
    assert d["permissions"] == {"contents": "write", "actions": "write"}
