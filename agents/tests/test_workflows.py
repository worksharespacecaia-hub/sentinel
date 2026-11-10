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
            for clause in ("daily_intel == 'true'", "github.event_name == 'schedule'",
                           "inputs.scenario == 'daily'", "inputs.trigger_source == 'manual'"):
                assert clause in cond
            assert "execution_mode" not in cond          # 訂閱方案與 A1～A5 是否呼叫 API 無關
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


def _job_text(job):
    return yaml.safe_dump(job, allow_unicode=True)


def test_daily_intel_least_privilege_and_trusted_upload(sentinel):
    _, d = sentinel
    job = d["jobs"]["daily-intel"]
    assert job["permissions"] == {"contents": "read"}          # 不用 Claude GitHub App（OIDC），不給寫入權限
    claude = next(s for s in job["steps"] if str(s.get("uses", "")).startswith("anthropics/claude-code-action"))
    assert claude["with"]["github_token"] == "${{ github.token }}"
    assert set(claude["with"]) == {"claude_code_oauth_token", "github_token", "prompt", "claude_args"}
    args = claude["with"]["claude_args"]
    assert '--disallowedTools "Bash,Edit,NotebookEdit"' in args and "--settings .claude/daily-intel-settings.json" in args
    names = [s.get("name", s.get("uses", "")) for s in job["steps"]]
    check = names.index("確認 Claude 只寫了 out/")
    upload = next(i for i, s in enumerate(job["steps"]) if str(s.get("uses", "")).startswith("actions/upload-artifact"))
    assert check < upload and "if" not in job["steps"][upload]   # 檢查失敗就不上傳，A1 不會用到可疑結果


def test_deployments_fetched_once_and_shared(sentinel):
    _, d = sentinel
    assert d["env"]["DEPLOYMENTS_FILE"] == "gh/deployments.json"
    a0 = d["jobs"]["a0-assets"]["steps"]
    fetch = next(i for i, s in enumerate(a0) if "fetch-deployments.py" in str(s.get("run", "")))
    agent = next(i for i, s in enumerate(a0) if "run_agent.py a0" in str(s.get("run", "")))
    assert fetch < agent
    assert a0[fetch]["env"] == {"GH_READ_TOKEN": "${{ secrets.TARGET_READ_TOKEN }}"}
    assert "continue-on-error" not in a0[fetch]                  # 腳本本身不會失敗；失敗原因寫進檔案
    uploads = [s["with"] for s in a0 if str(s.get("uses", "")).startswith("actions/upload-artifact")]
    assert {"name": "${{ github.run_id }}-deployments", "path": "gh/deployments.json", "if-no-files-found": "error"} in uploads
    for name in ("a2-scan", "a3-signals", "a4-risk", "a5-report"):
        steps = d["jobs"][name]["steps"]
        dl = [s for s in steps if str(s.get("uses", "")).startswith("actions/download-artifact")
              and s["with"].get("name") == "${{ github.run_id }}-deployments"]
        assert len(dl) == 1 and dl[0]["with"]["path"] == "gh/" and dl[0]["continue-on-error"] is True, name
        agent = next(i for i, s in enumerate(steps) if "run_agent.py" in str(s.get("run", "")))
        assert steps.index(dl[0]) < agent, name


def test_target_read_token_never_reaches_agent_steps(sentinel):
    _, d = sentinel
    for name, job in d["jobs"].items():
        for step in job.get("steps", []):
            body = _job_text(step)
            if "TARGET_READ_TOKEN" not in body:
                continue
            # 只用於 checkout Repo ① 與讀取 Deployments 的腳本，不進入執行 Agent／LLM 的步驟
            allowed = str(step.get("uses", "")).startswith("actions/checkout") or "fetch-deployments.py" in str(step.get("run", ""))
            assert allowed, (name, body)


def test_daily_intel_diagnostics(sentinel):
    _, d = sentinel
    steps = d["jobs"]["daily-intel"]["steps"]
    idx = {s.get("id") or s.get("name") or s.get("uses"): i for i, s in enumerate(steps)}
    check = steps[idx["檢查訂閱 Token 格式（不印出 Token）"]]
    assert check["env"] == {"TOKEN": "${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}"} and "echo \"$TOKEN\"" not in check["run"]
    assert idx["檢查訂閱 Token 格式（不印出 Token）"] < idx["claude"]
    diag = next(s for s in steps if "claude-error-summary.py" in str(s.get("run", "")))
    assert diag["if"] == "${{ failure() && steps.claude.conclusion == 'failure' }}"
    assert steps.index(diag) == idx["claude"] + 1
    assert "secrets." not in yaml.safe_dump(diag)             # 診斷步驟拿不到任何 Secret
