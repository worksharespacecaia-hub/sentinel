"""Workflow 結構規則（第 14.3、14.4 節；specs/orchestrator design §2、R11.2）。actionlint 另由 scripts/lint-workflows.sh 檢查語法。"""
import re

import pytest
import yaml

from tools.common import SENTINEL_ROOT

WF = SENTINEL_ROOT / ".github" / "workflows"
RUN = "${{ github.run_id }}-"
# 訂閱方案的條件（daily-intel、claude-analysis 在 Job 層；Orchestrator 派工與驗收在訂閱步驟）
SUBSCRIPTION_CLAUSES = ("needs.router.outputs.daily_intel == 'true'", "github.event_name == 'schedule'",
                        "inputs.scenario == 'daily'", "inputs.trigger_source == 'manual'")
SUBSCRIPTION_JOBS = {"daily-intel", "orchestrator-dispatch", "orchestrator-review", "claude-analysis"}
MODES = ("dispatch", "review")


def load(name):
    text = (WF / name).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    data["on"] = data.pop(True, data.get("on"))      # PyYAML 把 on 解析成 True
    return text, data


@pytest.fixture(scope="module")
def sentinel():
    return load("sentinel.yml")


def _job_text(job):
    return yaml.safe_dump(job, allow_unicode=True)


def _uses(step, prefix):
    return str(step.get("uses", "")).startswith(prefix)


def _artifacts(step) -> set[str]:
    """download-artifact 步驟下載的 artifact（去掉 run_id 前綴；brace pattern 展開，scanner-* 原樣保留）。"""
    w = step["with"]
    if "name" in w:
        assert w["name"].startswith(RUN), w
        return {w["name"][len(RUN):]}
    pat = w["pattern"]
    assert pat.startswith(RUN), pat
    rest = pat[len(RUN):]
    m = re.fullmatch(r"\{([a-z0-9,-]+)\}", rest)
    return set(m.group(1).split(",")) if m else {rest}


def _downloads(job) -> dict[str, str]:
    """artifact → 下載路徑。"""
    out = {}
    for s in job["steps"]:
        if _uses(s, "actions/download-artifact"):
            assert s.get("continue-on-error") is True, s
            for a in _artifacts(s):
                out[a] = s["with"]["path"]
    return out


def _has_target_checkout(job) -> bool:
    return any(_uses(s, "actions/checkout") and (s.get("with") or {}).get("path") == "target" for s in job["steps"])


def test_concurrency_queues_and_no_cancel(sentinel):
    _, d = sentinel
    assert d["concurrency"] == {"group": "sentinel", "cancel-in-progress": False, "queue": "max"}
    _, w = load("intel-watch.yml")
    assert w["concurrency"]["queue"] == "max"


def test_router_renamed_everywhere(sentinel):
    """開工路由：Job 名稱 router、指令 run_agent.py router、artifact -router；不再有 orchestrator Job 與 needs.orchestrator。"""
    text, d = sentinel
    assert "orchestrator" not in d["jobs"] and "needs.orchestrator." not in text
    router = d["jobs"]["router"]
    assert "needs" not in router and "if" not in router
    plan = next(s for s in router["steps"] if s.get("id") == "plan")
    assert "python agents/run_agent.py router" in plan["run"]
    up = [s for s in router["steps"] if _uses(s, "actions/upload-artifact")]
    assert len(up) == 1 and up[0]["with"]["name"] == RUN + "router" and up[0]["if"] == "always()"
    assert set(router["outputs"]) == {"plan", "daily_intel", "as_of", "output_dir", "target_sha", "execution_mode", "scope"}


def test_jobs_reading_router_list_it_directly(sentinel):
    _, d = sentinel
    for name, job in d["jobs"].items():
        if "needs.router" in _job_text(job) and name != "router":
            assert "router" in job["needs"], name


def test_downstream_conditions_use_not_cancelled(sentinel):
    _, d = sentinel
    for name, job in d["jobs"].items():
        if name == "router":
            continue
        assert job["if"].startswith("${{ !cancelled()"), name
        assert "always()" not in job["if"], name
    a5 = d["jobs"]["a5-report"]
    assert a5["if"] == "${{ !cancelled() }}"
    assert set(a5["needs"]) == set(d["jobs"]) - {"a5-report"}


# 新 DAG（design §2 的表格）
DAG = {
    "a0-assets": {"router"},
    "scanners": {"router", "a0-assets"},
    "daily-intel": {"router", "a0-assets"},
    "a1-intel": {"router", "a0-assets", "daily-intel"},
    "orchestrator-dispatch": {"router", "a0-assets", "scanners", "daily-intel", "a1-intel"},
    "a2-scan": {"router", "a0-assets", "scanners", "orchestrator-dispatch"},
    "a3-signals": {"router", "a0-assets", "scanners", "orchestrator-dispatch"},
    "a4-risk": {"router", "a1-intel", "a2-scan", "a3-signals", "orchestrator-dispatch"},
    "orchestrator-review": {"router", "a1-intel", "a2-scan", "a3-signals", "a4-risk", "orchestrator-dispatch"},
    "claude-analysis": {"router", "a0-assets", "scanners", "daily-intel", "a1-intel", "orchestrator-dispatch", "a2-scan",
                        "a3-signals", "a4-risk", "orchestrator-review"},
}


def test_new_dag_needs(sentinel):
    _, d = sentinel
    assert list(d["jobs"]) == ["router", "a0-assets", "scanners", "daily-intel", "a1-intel", "orchestrator-dispatch", "a2-scan",
                               "a3-signals", "a4-risk", "orchestrator-review", "claude-analysis", "a5-report"]
    for name, needs in DAG.items():
        assert set(d["jobs"][name]["needs"]) == needs, name


def test_job_conditions(sentinel):
    _, d = sentinel
    jobs = d["jobs"]
    for name in ("orchestrator-dispatch", "orchestrator-review"):
        # 派工與驗收不看 plan、不看訂閱條件：公告與網站觸發照常執行（R1.4），訂閱條件只在訂閱步驟
        assert jobs[name]["if"] == "${{ !cancelled() && needs.router.result == 'success' }}", name
        assert "continue-on-error" not in jobs[name], name
    for name, key in (("a1-intel", "a1"), ("a2-scan", "a2"), ("a3-signals", "a3"), ("a4-risk", "a4"), ("scanners", "scanners")):
        cond = jobs[name]["if"]
        assert "needs.router.result == 'success'" in cond and f"fromJSON(needs.router.outputs.plan || '{{}}').{key} == true" in cond, name
        assert "orchestrator-dispatch" not in cond, name             # 派工失敗不影響下游（R1.5）
    ca = jobs["claude-analysis"]["if"]
    assert "needs.a4-risk.result == 'success'" in ca and all(c in ca for c in SUBSCRIPTION_CLAUSES)
    assert "orchestrator-review" not in ca                           # 驗收失敗不擋撰寫


def test_downloads_follow_dag(sentinel):
    """A2～A5 與派工、驗收各自重算評估並核對計畫：下載給齊，否則派工單會被停用（T3）。"""
    _, d = sentinel
    jobs = d["jobs"]
    expect = {
        "orchestrator-dispatch": {"a1": "out/", "scanner-*": "dl/", "deployments": "gh/"},
        "a2-scan": {"a1": "out/", "orchestrator-dispatch": "out/", "scanner-*": "dl/", "deployments": "gh/"},
        "a3-signals": {"a1": "out/", "orchestrator-dispatch": "out/", "scanner-*": "dl/", "deployments": "gh/"},
        "a4-risk": {"a1": "out/", "orchestrator-dispatch": "out/", "scanner-*": "dl/", "deployments": "gh/"},
        "orchestrator-review": {"a1": "out/", "orchestrator-dispatch": "out/", "a2": "out/", "a3": "out/", "a4": "out/",
                                "scanner-*": "dl/", "deployments": "gh/"},
    }
    for name, want in expect.items():
        assert _downloads(jobs[name]) == want, name
        assert _has_target_checkout(jobs[name]), name
        for s in jobs[name]["steps"]:
            if "run_agent.py" in str(s.get("run", "")):
                assert s["env"]["TARGET_DIR"] == "target" and s["env"]["SCANNERS_DIR"] == "dl/scanners", name
    for name in ("claude-analysis", "a5-report"):
        got = _downloads(jobs[name])
        for a in ("router", "a0", "a1", "a2", "a3", "a4", "intel-daily", "orchestrator-dispatch", "orchestrator-review"):
            assert got.get(a) == "out/", (name, a)
        assert "orchestrator" not in got, name


def test_agent_outputs_uploaded_whole(sentinel):
    """A2～A4 上傳整個 out/：event-explanations.json、retro.json、dispatch-outcomes.json 都在裡面（R5.2～R5.5）。"""
    _, d = sentinel
    for name, art in (("a2-scan", "a2"), ("a3-signals", "a3"), ("a4-risk", "a4")):
        up = [s["with"] for s in d["jobs"][name]["steps"] if _uses(s, "actions/upload-artifact")]
        assert up == [{"name": RUN + art, "path": "out/", "if-no-files-found": "error"}], name


def test_only_a5_can_write_contents(sentinel):
    _, d = sentinel
    assert d["permissions"] == {"contents": "read"}
    for name, job in d["jobs"].items():
        perms = job.get("permissions") or {}
        if name == "a5-report":
            assert perms == {"contents": "write"}
        else:
            assert perms.get("contents", "read") == "read", name


def test_subscription_token_only_in_subscription_steps(sentinel):
    """OAuth token 只在四個訂閱 Job（daily-intel、派工、驗收、claude-analysis），而且只在 Token 檢查與 claude-code-action 步驟；
    這些步驟不會同時拿到 API key，條件都是預設分支的排程或手動 daily（R6.4）。"""
    _, d = sentinel
    actions = []
    for name, job in d["jobs"].items():
        body = _job_text(job)
        if name not in SUBSCRIPTION_JOBS:
            assert "CLAUDE_CODE_OAUTH_TOKEN" not in body, name
            continue
        assert job["permissions"] == {"contents": "read"}, name
        assert job["steps"][[_uses(s, "actions/checkout") for s in job["steps"]].index(True)]["with"]["persist-credentials"] is False
        job_cond = job["if"]
        for s in job["steps"]:
            text = _job_text(s)
            if "CLAUDE_CODE_OAUTH_TOKEN" not in text:
                continue
            is_action = _uses(s, "anthropics/claude-code-action")
            assert is_action or s.get("name") == "檢查訂閱 Token 格式（不印出 Token）", (name, s.get("name"))
            assert "ANTHROPIC_API_KEY" not in text and "run_agent.py" not in text, name
            cond = job_cond + " " + str(s.get("if", ""))
            assert all(c in cond for c in SUBSCRIPTION_CLAUSES), (name, s.get("name"))
            assert "execution_mode" not in cond                    # 訂閱方案與 A1～A5 是否呼叫 API 無關
            if is_action:
                actions.append(name)
    assert sorted(actions) == sorted(SUBSCRIPTION_JOBS)               # 每個訂閱 Job 剛好一個 claude-code-action 步驟
    for name in ("daily-intel", "claude-analysis"):
        assert d["jobs"][name]["continue-on-error"] is True
        assert "ANTHROPIC_API_KEY" not in _job_text(d["jobs"][name])


def test_api_key_only_passed_in_live(sentinel):
    _, d = sentinel
    for name, job in d["jobs"].items():
        for step in job.get("steps", []):
            env = step.get("env") or {}
            if "ANTHROPIC_API_KEY" in env:
                assert env["ANTHROPIC_API_KEY"] == "${{ needs.router.outputs.execution_mode == 'live' && secrets.ANTHROPIC_API_KEY || '' }}", name
        assert "ANTHROPIC_API_KEY" not in (job.get("env") or {}), name


def test_artifact_names_are_unique_per_run(sentinel):
    _, d = sentinel
    names = []
    for job in d["jobs"].values():
        for step in job.get("steps", []):
            if _uses(step, "actions/upload-artifact"):
                n = step["with"]["name"]
                assert n.startswith(RUN), n
                names.append(n)
    assert len(names) == len(set(names))
    assert {RUN + "orchestrator-dispatch", RUN + "orchestrator-review", RUN + "router"} <= set(names)


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
    _, d = sentinel
    for name, job in d["jobs"].items():
        if "push-with-retry.sh" in _job_text(job):
            assert name == "a5-report"


def test_intel_watch_has_no_llm():
    text, d = load("intel-watch.yml")
    code = " ".join(line.split("#", 1)[0] for line in text.splitlines())   # 去掉註解
    assert "ANTHROPIC_API_KEY" not in code and "CLAUDE_CODE_OAUTH_TOKEN" not in code
    assert d["permissions"] == {"contents": "write", "actions": "write"}


def test_daily_intel_least_privilege_and_trusted_upload(sentinel):
    _, d = sentinel
    job = d["jobs"]["daily-intel"]
    assert job["permissions"] == {"contents": "read"}          # 不用 Claude GitHub App（OIDC），不給寫入權限
    claude = next(s for s in job["steps"] if _uses(s, "anthropics/claude-code-action"))
    assert claude["with"]["github_token"] == "${{ github.token }}"
    assert set(claude["with"]) == {"claude_code_oauth_token", "github_token", "prompt", "claude_args"}
    args = claude["with"]["claude_args"]
    assert '--disallowedTools "Bash,Edit,NotebookEdit,WebFetch"' in args and "--settings .claude/daily-intel-settings.json" in args
    # 文章由程式事先抓好（news_collect），Claude 不抓網頁：工具清單與自動核准都沒有 WebFetch
    assert '--tools "Read,Write,Agent,Skill,WebSearch"' in args and "WebFetch" not in args.split("--disallowedTools")[0]
    # Write(路徑) 不是有效的權限規則（不會放行，dontAsk 模式下 Write 被拒）；寫檔路徑規則用 Edit(...)，hook 再限制只能寫 intel-daily.json
    assert "Edit(./out/**)" in args and "Write(" not in args
    names = [s.get("name", s.get("uses", "")) for s in job["steps"]]
    check = names.index("確認 Claude 只寫了 out/")
    upload = next(i for i, s in enumerate(job["steps"]) if _uses(s, "actions/upload-artifact"))
    assert check < upload and "if" not in job["steps"][upload]   # 檢查失敗就不上傳，A1 不會用到可疑結果
    wrote = names.index("確認已寫出 out/intel-daily.json")
    assert names.index("anthropics/claude-code-action@v1") < wrote < check   # Claude 沒寫出檔案時 Job 明確失敗，並列出被拒絕的工具
    assert job["steps"][wrote]["run"].count("claude-error-summary.py --with-result --activity") == 2   # 成功與失敗都留下紀錄
    assert "exit 1" in job["steps"][wrote]["run"]
    collect = next(i for i, s in enumerate(job["steps"]) if "news_collect.py" in str(s.get("run", "")))
    assert collect < names.index("anthropics/claude-code-action@v1")         # 先由程式抓文章，再交給 Claude
    assert "sha256sum out/news.json" in job["steps"][collect]["run"] and "secrets." not in yaml.safe_dump(job["steps"][collect])
    assert 'sha256sum -c --quiet "$RUNNER_TEMP/news.sha256"' in job["steps"][check]["run"]   # Claude 執行後 news.json 不得被改動
    up = job["steps"][upload]["with"]
    assert up["path"].split() == ["out/intel-daily.json", "out/news.json"]   # A1 用同一份原文確認引用


def test_deployments_fetched_once_and_shared(sentinel):
    _, d = sentinel
    assert d["env"]["DEPLOYMENTS_FILE"] == "gh/deployments.json"
    a0 = d["jobs"]["a0-assets"]["steps"]
    fetch = next(i for i, s in enumerate(a0) if "fetch-deployments.py" in str(s.get("run", "")))
    agent = next(i for i, s in enumerate(a0) if "run_agent.py a0" in str(s.get("run", "")))
    assert fetch < agent
    assert a0[fetch]["env"] == {"GH_READ_TOKEN": "${{ secrets.TARGET_READ_TOKEN }}"}
    assert "continue-on-error" not in a0[fetch]                  # 腳本本身不會失敗；失敗原因寫進檔案
    uploads = [s["with"] for s in a0 if _uses(s, "actions/upload-artifact")]
    assert {"name": RUN + "deployments", "path": "gh/deployments.json", "if-no-files-found": "error"} in uploads
    for name in ("orchestrator-dispatch", "a2-scan", "a3-signals", "a4-risk", "orchestrator-review", "a5-report"):
        steps = d["jobs"][name]["steps"]
        dl = [s for s in steps if _uses(s, "actions/download-artifact") and s["with"].get("name") == RUN + "deployments"]
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
            allowed = _uses(step, "actions/checkout") or "fetch-deployments.py" in str(step.get("run", ""))
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


def test_budget_credentials_only_passed_in_live(sentinel):
    """live 時 A1～A5 與派工、驗收的程式步驟需要向 /api/budget 預留；replay 不傳 NOTIFY_TOKEN。只有發布後的通知步驟例外。"""
    _, d = sentinel
    agent_steps = []
    for name, job in d["jobs"].items():
        for step in job.get("steps", []):
            env = step.get("env") or {}
            if "run_agent.py" in str(step.get("run", "")) and "ANTHROPIC_API_KEY" in env:
                agent_steps.append(name)
                assert "execution_mode == 'live'" in env["NOTIFY_TOKEN"] and "execution_mode == 'live'" in env["SENTINEL_BASE_URL"], name
            elif "NOTIFY_TOKEN" in env:
                assert "/api/notify/light" in str(step.get("run", "")), name
    # A1～A5 各一個；派工與驗收只有採用提案的程式步驟（run_agent.py orchestrator）會呼叫 Agent SDK，整理輸入的步驟沒有金鑰
    assert sorted(agent_steps) == sorted(["a1-intel", "a2-scan", "a3-signals", "a4-risk", "a5-report",
                                          "orchestrator-dispatch", "orchestrator-review"])


# ---------------------------------------------------------------- Orchestrator 派工／驗收 Job（design §2 的 7 個步驟）
def _orchestrator_steps(d, mode):
    job = d["jobs"][f"orchestrator-{mode}"]
    steps = job["steps"]

    def find(pred, what):
        hits = [i for i, s in enumerate(steps) if pred(s)]
        assert len(hits) == 1, (mode, what, hits)
        return hits[0]
    idx = {
        "rm": 0,
        "checkout": find(lambda s: _uses(s, "actions/checkout") and "path" not in (s.get("with") or {}), "checkout"),
        "input": find(lambda s: f"run_agent.py orchestrator-input --mode {mode}" in str(s.get("run", "")), "input"),
        "token": find(lambda s: s.get("id") == "token", "token"),
        "snapshot": find(lambda s: s.get("id") == "snapshot", "snapshot"),
        "claude": find(lambda s: s.get("id") == "claude", "claude"),
        "verify": find(lambda s: "orchestrator-guard.py verify" in str(s.get("run", "")), "verify"),
        "run": find(lambda s: f"run_agent.py orchestrator --mode {mode}" in str(s.get("run", "")), "run"),
        "trace": find(lambda s: "claude-error-summary.py --trace" in str(s.get("run", "")), "trace"),
        "upload": find(lambda s: _uses(s, "actions/upload-artifact"), "upload"),
    }
    return job, steps, idx


@pytest.mark.parametrize("mode", MODES)
def test_orchestrator_job_steps_in_order(sentinel, mode):
    _, d = sentinel
    job, steps, idx = _orchestrator_steps(d, mode)
    downloads = [i for i, s in enumerate(steps) if _uses(s, "actions/download-artifact")]
    assert idx["rm"] < idx["checkout"] < min(downloads) and max(downloads) < idx["input"]
    order = ["input", "token", "snapshot", "claude", "verify", "run", "trace", "upload"]
    assert [idx[k] for k in order] == sorted(idx[k] for k in order)
    assert idx["upload"] == len(steps) - 1


@pytest.mark.parametrize("mode", MODES)
def test_orchestrator_job_deletes_old_proposal_first(sentinel, mode):
    """第一個步驟刪除舊的提案與採用標記（R6.1），程式只採用本次訂閱步驟寫出且通過檢查的提案。"""
    _, d = sentinel
    _, steps, _ = _orchestrator_steps(d, mode)
    first = steps[0]
    assert first["if"] == "${{ !cancelled() }}"
    assert first["run"] == (f"rm -f out/orchestrator-{mode}/{mode}-proposal.json "
                            f"out/orchestrator-{mode}/{mode}-proposal.accepted")


@pytest.mark.parametrize("mode", MODES)
def test_orchestrator_subscription_steps(sentinel, mode):
    _, d = sentinel
    _, steps, idx = _orchestrator_steps(d, mode)
    token, snap, claude, verify = (steps[idx[k]] for k in ("token", "snapshot", "claude", "verify"))
    # Token 檢查：與 daily-intel 相同的檢查內容；失敗只跳過訂閱步驟，程式步驟照常
    daily = next(s for s in d["jobs"]["daily-intel"]["steps"] if s.get("name") == "檢查訂閱 Token 格式（不印出 Token）")
    assert token["run"] == daily["run"] and token["env"] == daily["env"] and token["continue-on-error"] is True
    assert all(c in token["if"] for c in SUBSCRIPTION_CLAUSES)
    # 快照：訂閱步驟前、存在 RUNNER_TEMP（Claude 讀不到）；公開輸入不可用（A1 缺失）時失敗 → 訂閱步驟跳過（R6.1）
    assert snap["if"] == "${{ steps.token.outcome == 'success' }}" and snap["continue-on-error"] is True
    assert snap["run"] == (f'python3 scripts/orchestrator-guard.py snapshot --out out --dest "$RUNNER_TEMP/{mode}-snap.json" '
                           f"--input out/orchestrator-{mode}/{mode}-input.json")
    # claude-code-action：與 daily-intel 相同的版本與寫法，工具只開 Read、Write、Skill
    daily_action = next(s for s in d["jobs"]["daily-intel"]["steps"] if _uses(s, "anthropics/claude-code-action"))
    assert claude["uses"] == daily_action["uses"] and set(claude["with"]) == set(daily_action["with"])
    assert claude["with"]["claude_code_oauth_token"] == "${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}"
    assert claude["with"]["github_token"] == "${{ github.token }}" and claude["with"]["prompt"] == f"/orchestrator {mode}"
    assert claude["if"].startswith("${{ steps.snapshot.outcome == 'success' && ")
    assert all(c in claude["if"] for c in SUBSCRIPTION_CLAUSES)
    assert claude["continue-on-error"] is True and claude["timeout-minutes"] <= 15
    args = claude["with"]["claude_args"]
    assert '--tools "Read,Write,Skill"' in args and '--disallowedTools "Bash,Edit,NotebookEdit,WebFetch,WebSearch,Agent"' in args
    assert f"--settings .claude/orchestrator-{mode}-settings.json" in args and "--permission-mode dontAsk" in args
    assert "--strict-mcp-config" in args and "Write(" not in args
    allowed = re.search(r'--allowedTools "([^"]+)"', args).group(1).split(",")
    assert allowed == [f"Read(./out/orchestrator-{mode}/{mode}-input.json)", "Read(./.claude/skills/orchestrator/**)",
                       f"Edit(./out/orchestrator-{mode}/{mode}-proposal.json)"]
    # 驗證：只有 Claude 成功時才檢查；通過才寫入採用標記
    assert verify["if"] == "${{ steps.claude.outcome == 'success' }}" and verify["continue-on-error"] is True
    assert verify["run"] == f'python3 scripts/orchestrator-guard.py verify --mode {mode} --snap "$RUNNER_TEMP/{mode}-snap.json"'
    for s in (snap, verify):
        assert "secrets." not in _job_text(s) and "env" not in s


@pytest.mark.parametrize("mode", MODES)
def test_orchestrator_program_steps(sentinel, mode):
    _, d = sentinel
    job, steps, idx = _orchestrator_steps(d, mode)
    inp, run, trace, up = (steps[idx[k]] for k in ("input", "run", "trace", "upload"))
    # 整理輸入：不呼叫 LLM，沒有任何金鑰
    assert inp["run"] == f"python agents/run_agent.py orchestrator-input --mode {mode}" and "secrets." not in _job_text(inp)
    assert "if" not in inp
    # 採用提案或改用 Agent SDK：Token 或訂閱步驟失敗也照常執行；API key 只在 live
    assert run["run"] == f"python agents/run_agent.py orchestrator --mode {mode}" and run["if"] == "${{ !cancelled() }}"
    assert "execution_mode == 'live'" in run["env"]["ANTHROPIC_API_KEY"]
    for s in (inp, run):
        assert s["env"]["AS_OF"] == "${{ needs.router.outputs.as_of }}" and s["env"]["TARGET_SHA"] == "${{ needs.router.outputs.target_sha }}"
    # 訂閱步驟的紀錄：接在同一份 trace（A5 的 UPSTREAM 會合併 out/orchestrator-<m>/trace.jsonl）
    assert trace["if"].startswith("${{ !cancelled() && ") and all(c in trace["if"] for c in SUBSCRIPTION_CLAUSES)
    assert f"--trace out/orchestrator-{mode}/trace.jsonl --job orchestrator-{mode}" in trace["run"]
    assert "secrets." not in _job_text(trace)
    assert up["if"] == "always()" and up["with"] == {"name": f"{RUN}orchestrator-{mode}", "path": "out/", "if-no-files-found": "ignore"}


def test_job_results_only_in_review(sentinel):
    """驗收 Job 在 Job 層設定 JOB_RESULTS（程式只取 .result，R4.2）；派工 Job 與其他 Job 沒有。"""
    text, d = sentinel
    assert d["jobs"]["orchestrator-review"]["env"] == {"JOB_RESULTS": "${{ toJSON(needs) }}"}
    assert text.count("JOB_RESULTS") == 1
    for name, job in d["jobs"].items():
        if name != "orchestrator-review":
            assert "env" not in job, name


def test_orchestrator_paths_match_program():
    """workflow、settings 與程式使用同一組路徑：公開輸入、提案、採用標記、計畫與 trace。"""
    from types import SimpleNamespace

    from agents import orchestrator_agent as oa
    from tools import orchestration as o
    _, d = load("sentinel.yml")
    ctx = SimpleNamespace(out=SENTINEL_ROOT / "out")
    for mode in MODES:
        rel = lambda p: p.relative_to(SENTINEL_ROOT).as_posix()   # noqa: E731
        text = _job_text(d["jobs"][f"orchestrator-{mode}"])
        for path in (oa.input_path(ctx, mode), oa.proposal_path(ctx, mode), oa.accepted_path(ctx, mode)):
            assert rel(path) in text, (mode, path)
        assert o.PLAN_DIRS[mode] == f"orchestrator-{mode}" == oa.AGENT[mode]
