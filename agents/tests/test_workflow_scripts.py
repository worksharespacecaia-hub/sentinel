"""Workflow 直接執行的腳本必須在 git 中標記為可執行（100755）。

在 Windows 上 commit 時檔案模式不會自動帶上執行位元，GitHub Actions 執行時會得到 exit code 126。
"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
# 例如 `run: scripts/push-with-retry.sh "$X"` 或多行 run 區塊中的 `scripts/x.sh arg`
DIRECT_CALL = re.compile(r"(?:^|run:)\s*\.?/?((?:scripts|dashboard/scripts)/[\w.-]+\.sh)\b", re.M)


def _git_modes() -> dict[str, str]:
    out = subprocess.run(["git", "ls-files", "-s"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return {line.split("\t", 1)[1]: line.split()[0] for line in out.splitlines()}


def test_scripts_called_by_workflows_are_executable():
    called = {m for wf in WORKFLOWS.glob("*.yml") for m in DIRECT_CALL.findall(wf.read_text(encoding="utf-8"))}
    assert "scripts/push-with-retry.sh" in called  # 確認比對規則有效
    modes = _git_modes()
    not_exec = sorted(p for p in called if modes.get(p) != "100755")
    assert not not_exec, f"以下腳本需要 git update-index --chmod=+x：{not_exec}"


def test_all_shell_scripts_are_executable():
    modes = _git_modes()
    not_exec = sorted(p for p, m in modes.items() if p.endswith(".sh") and m != "100755")
    assert not not_exec, f"以下腳本需要 git update-index --chmod=+x：{not_exec}"
