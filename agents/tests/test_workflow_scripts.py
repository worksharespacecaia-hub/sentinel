"""Workflow 在 GitHub 上才會執行的部分：本機 replay 測試跑不到，靠這裡的靜態檢查。

- 直接執行的腳本必須在 git 中標記為可執行（100755）：在 Windows 上 commit 時不會自動帶上執行位元，Actions 會得到 exit code 126。
- 以 docker -v 從 sentinel 掛進容器的檔案必須存在於 repo：路徑不存在時 Docker 會建立空目錄，工具讀設定檔時失敗。
"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
# 例如 `run: scripts/push-with-retry.sh "$X"` 或多行 run 區塊中的 `scripts/x.sh arg`
DIRECT_CALL = re.compile(r"(?:^|run:)\s*\.?/?((?:scripts|dashboard/scripts)/[\w.-]+\.sh)\b", re.M)
# 例如 -v "$PWD/.gitleaks.toml:/cfg/gitleaks.toml:ro"
MOUNT = re.compile(r'-v "\$PWD/([^":$]+):')
# 執行時才產生的目錄：Repo ① 的 checkout 與掃描輸出
RUNTIME_DIRS = ("target", "raw", "out")


def _git_modes() -> dict[str, str]:
    out = subprocess.run(["git", "ls-files", "-s"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return {line.split("\t", 1)[1]: line.split()[0] for line in out.splitlines()}


def _workflow_text() -> str:
    return "\n".join(wf.read_text(encoding="utf-8") for wf in sorted(WORKFLOWS.glob("*.yml")))


def test_scripts_called_by_workflows_are_executable():
    called = set(DIRECT_CALL.findall(_workflow_text()))
    assert "scripts/push-with-retry.sh" in called  # 確認比對規則有效
    modes = _git_modes()
    not_exec = sorted(p for p in called if modes.get(p) != "100755")
    assert not not_exec, f"以下腳本需要 git update-index --chmod=+x：{not_exec}"


def test_all_shell_scripts_are_executable():
    modes = _git_modes()
    not_exec = sorted(p for p, m in modes.items() if p.endswith(".sh") and m != "100755")
    assert not not_exec, f"以下腳本需要 git update-index --chmod=+x：{not_exec}"


def test_files_mounted_from_sentinel_are_tracked():
    mounts = set(MOUNT.findall(_workflow_text()))
    assert ".gitleaks.toml" in mounts  # 確認比對規則有效
    tracked = _git_modes()
    missing = sorted(m for m in mounts if m.split("/")[0] not in RUNTIME_DIRS and m not in tracked)
    assert not missing, f"workflow 掛載的檔案不在 repo 中：{missing}"


def test_python_scripts_and_settings_used_by_workflows_are_tracked():
    """workflow 以 python 執行的腳本、claude-code-action 的 --settings 與其中的 hook 都必須在 repo：缺少時 Actions 才會失敗。"""
    import json
    text = _workflow_text()
    scripts = set(re.findall(r"\bpython3? ((?:scripts|agents)/[\w./-]+\.py)\b", text))
    assert {"scripts/orchestrator-guard.py", "scripts/claude-error-summary.py", "agents/run_agent.py"} <= scripts
    settings = set(re.findall(r"--settings (\.claude/[\w.-]+\.json)", text))
    assert settings == {".claude/daily-intel-settings.json", ".claude/analysis-settings.json",
                        ".claude/orchestrator-dispatch-settings.json", ".claude/orchestrator-review-settings.json"}
    hooks = set()
    for s in settings:
        cfg = json.loads((ROOT / s).read_text(encoding="utf-8"))
        for entry in cfg["hooks"]["PreToolUse"]:
            for h in entry["hooks"]:
                hooks |= set(re.findall(r"(\.claude/hooks/[\w.-]+\.py)", h["command"]))
    assert hooks == {".claude/hooks/daily_intel_guard.py"}
    skills = {f".claude/skills/{m}/SKILL.md" for m in re.findall(r'prompt: "/([a-z-]+)', text)}
    assert ".claude/skills/orchestrator/SKILL.md" in skills
    tracked = _git_modes()
    missing = sorted(p for p in scripts | settings | hooks | skills if p not in tracked)
    assert not missing, f"workflow 用到但不在 repo 的檔案：{missing}"


def test_gitleaks_config_matches_target_baseline():
    # 規格 5.5：Repo ① 與 sentinel 的 scanners 共用同一份 .gitleaks.toml；sentinel 使用自己保存的副本，不讀受掃描 Repo 的設定
    ours = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
    baseline = (ROOT / "agents" / "fixtures" / "target-baseline" / ".gitleaks.toml").read_text(encoding="utf-8")
    assert ours == baseline
    assert 'id = "demo-fake-secret"' in ours and "useDefault = true" in ours
