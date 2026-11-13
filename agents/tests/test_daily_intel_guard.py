"""訂閱方案 Job 的 PreToolUse hook（.claude/hooks/daily_intel_guard.py）：預設拒絕，只放行各 Job 需要的工具。

daily-intel 用預設參數；Orchestrator 派工與驗收另以 --read 白名單限制只能讀公開輸入與 orchestrator Skill（specs/orchestrator §3.6）。
"""
import json
import os
import shlex
import subprocess
import sys

import pytest

from tools.common import SENTINEL_ROOT

HOOK = SENTINEL_ROOT / ".claude" / "hooks" / "daily_intel_guard.py"


def decide(tool, inp):
    proc = subprocess.run([sys.executable, str(HOOK)], input=json.dumps({"tool_name": tool, "tool_input": inp}),
                          capture_output=True, text=True, encoding="utf-8", cwd=SENTINEL_ROOT, check=True)
    out = json.loads(proc.stdout or "{}")
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision", "allow"), \
        (out.get("hookSpecificOutput") or {}).get("permissionDecisionReason", "")


@pytest.mark.parametrize("tool,inp", [
    ("Read", {"file_path": "out/stack.json"}),
    ("Read", {"file_path": ".claude/skills/daily-intel/SKILL.md"}),
    ("Write", {"file_path": "out/intel-daily.json"}),
    ("Agent", {"subagent_type": "news-scout"}),
    ("Agent", {"subagent_type": "advisory-scout", "run_in_background": False}),
    ("Skill", {"skill": "daily-intel"}),
    ("WebSearch", {"query": "x"}),
])
def test_allowed(tool, inp):
    assert decide(tool, inp)[0] == "allow"


@pytest.mark.parametrize("tool,inp", [
    ("Read", {"file_path": "agents/registry.py"}),
    ("Read", {"file_path": "out/../.env"}),
    ("Write", {"file_path": "out/other.json"}),
    ("Write", {"file_path": "notes.txt"}),
    ("Agent", {"subagent_type": "general-purpose"}),
    ("Agent", {"subagent_type": "web-fetch"}),
    ("Skill", {"skill": "other"}),
    ("WebFetch", {"url": "https://www.ithome.com.tw/news/1"}),     # 文章由程式抓好，Claude 不抓網頁
    ("WebFetch", {"url": "https://evil.example/"}),
    ("Bash", {"command": "ls"}),
    ("Edit", {"file_path": "out/intel-daily.json"}),
])
def test_denied(tool, inp):
    assert decide(tool, inp)[0] == "deny"


def test_background_subagent_denied():
    """無人值守的單次執行：主 Agent 結束回合時背景 Subagent 會被中斷，結果寫不出來（0.4.1 診斷找到的問題）。"""
    decision, reason = decide("Agent", {"subagent_type": "news-scout", "run_in_background": True})
    assert decision == "deny" and "前景" in reason
    assert decide("Task", {"subagent_type": "news-scout", "run_in_background": True})[0] == "deny"


def test_settings_disable_background_tasks():
    cfg = json.loads((SENTINEL_ROOT / ".claude" / "daily-intel-settings.json").read_text(encoding="utf-8"))
    assert cfg["env"]["CLAUDE_CODE_DISABLE_BACKGROUND_TASKS"] == "1"
    assert cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "python3 .claude/hooks/daily_intel_guard.py"


def test_skill_reference_lists_same_domains_as_sources_yaml():
    """Job 中 Claude 只能讀 .claude/，讀不到 agents/intel/sources.yaml：參考檔必須列出相同網域。"""
    import re

    import yaml
    expected = [d["domain"] for d in yaml.safe_load((SENTINEL_ROOT / "agents" / "intel" / "sources.yaml").read_text(encoding="utf-8"))["domains"]]
    ref = (SENTINEL_ROOT / ".claude" / "skills" / "daily-intel" / "references" / "sources.md").read_text(encoding="utf-8")
    assert sorted(re.findall(r"`([a-z0-9.-]+\.[a-z]+)`", ref)) == sorted(expected)


def test_scouts_read_collected_news_without_webfetch():
    for name in ("news-scout", "advisory-scout"):
        text = (SENTINEL_ROOT / ".claude" / "agents" / f"{name}.md").read_text(encoding="utf-8")
        assert "tools: Read, WebSearch\n" in text and "out/news.json" in text and "WebFetch" not in text
    skill = (SENTINEL_ROOT / ".claude" / "skills" / "daily-intel" / "SKILL.md").read_text(encoding="utf-8")
    assert "out/news.json" in skill and "72 小時" in skill


# ---------------------------------------------------------------- Orchestrator 的 --read 白名單（specs/orchestrator design §3.6、§8）
MODES = ("dispatch", "review")
WINDOWS = os.name == "nt"


def orchestrator_args(mode):
    """settings 中的 hook 指令（shell 會去掉引號；`**` 必須加引號，否則會被 shell 展開）。"""
    cfg = json.loads((SENTINEL_ROOT / ".claude" / f"orchestrator-{mode}-settings.json").read_text(encoding="utf-8"))
    argv = shlex.split(cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"])
    assert argv[:2] == ["python3", ".claude/hooks/daily_intel_guard.py"]
    return argv[2:]


def run_hook(tool, inp, args, cwd=SENTINEL_ROOT, raw=None):
    proc = subprocess.run([sys.executable, str(HOOK), *args], input=raw if raw is not None else json.dumps({"tool_name": tool, "tool_input": inp}),
                          capture_output=True, text=True, encoding="utf-8", cwd=cwd, check=True,
                          env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    out = (json.loads(proc.stdout or "{}").get("hookSpecificOutput") or {})
    return out.get("permissionDecision", "allow"), out.get("permissionDecisionReason", "")


@pytest.mark.parametrize("mode", MODES)
def test_orchestrator_settings(mode):
    cfg = json.loads((SENTINEL_ROOT / ".claude" / f"orchestrator-{mode}-settings.json").read_text(encoding="utf-8"))
    assert cfg["env"] == {"CLAUDE_CODE_DISABLE_BACKGROUND_TASKS": "1"}
    assert len(cfg["hooks"]["PreToolUse"]) == 1 and cfg["hooks"]["PreToolUse"][0]["matcher"] == "*"
    assert orchestrator_args(mode) == ["--read", f"out/orchestrator-{mode}/{mode}-input.json", "--read", ".claude/skills/orchestrator/**",
                                       "--write", f"out/orchestrator-{mode}/{mode}-proposal.json", "--agents", "", "--no-websearch",
                                       "--skill", "orchestrator"]
    cmd = cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "'.claude/skills/orchestrator/**'" in cmd


def _variants(rel):
    """同一個檔案的不同寫法：相對、./ 開頭、絕對路徑。"""
    return [rel, "./" + rel, str(SENTINEL_ROOT / rel)]


@pytest.mark.parametrize("mode", MODES)
def test_orchestrator_reads_only_whitelist(mode):
    args = orchestrator_args(mode)
    other = "review" if mode == "dispatch" else "dispatch"
    allowed = [*_variants(f"out/orchestrator-{mode}/{mode}-input.json"),
               *_variants(".claude/skills/orchestrator/SKILL.md"),
               *_variants(".claude/skills/orchestrator/references/policy.md")]
    for path in allowed:
        assert run_hook("Read", {"file_path": path}, args)[0] == "allow", path
    denied = [
        f"out/orchestrator-{mode}/internal/context.json",                      # 內部政策上下文
        str(SENTINEL_ROOT / "out" / f"orchestrator-{mode}" / "internal" / "context.json"),
        f"out/orchestrator-{mode}/./internal/context.json",
        f"out/orchestrator-{mode}/{mode}-input.json/../internal/context.json",
        f"out/orchestrator-{mode}/{mode}-proposal.json",                       # 只能寫，不能讀
        f"out/orchestrator-{mode}/{mode}-plan.json",
        f"out/orchestrator-{other}/{other}-input.json",                        # 另一個模式的輸入
        f"out/orchestrator-{other}/internal/context.json",
        "out/a1/verified.json",                                                # A1 verified
        "out/a2/event-explanations.json", "out/a4/explanations.json", "out/intel-daily.json", "out/stack.json",   # 其他 artifact
        "out/llm/tasks.json",
        ".claude/skills/daily-intel/SKILL.md",
        ".claude/skills/orchestrator/../daily-intel/SKILL.md",
        ".claude/skills/orchestrator/references/../../../hooks/daily_intel_guard.py",
        ".claude/skills/orchestrator",                                          # 目錄本身不在 ** 範圍
        ".claude/skills/orchestrator-evil/SKILL.md",
        ".claude/orchestrator-dispatch-settings.json",
        "agents/registry.py", ".env", ".git/config", "/etc/passwd", "", "out/orchestrator-dispatch/dispatch-input.json\x00",
    ]
    for path in denied:
        decision, reason = run_hook("Read", {"file_path": path}, args)
        assert decision == "deny", path
        assert "只能讀" in reason or "預設拒絕" in reason
    assert run_hook("Read", {}, args)[0] == "deny"


def test_read_whitelist_separators_and_case():
    """分隔符與大小寫依作業系統：Windows 不分大小寫、\\ 是分隔符；Linux（GitHub runner）區分大小寫、\\ 是檔名的一部分。"""
    args = orchestrator_args("dispatch")
    backslash = "out\\orchestrator-dispatch\\dispatch-input.json"
    upper = "OUT/ORCHESTRATOR-DISPATCH/DISPATCH-INPUT.JSON"
    expected = "allow" if WINDOWS else "deny"
    assert run_hook("Read", {"file_path": backslash}, args)[0] == expected
    assert run_hook("Read", {"file_path": upper}, args)[0] == expected
    assert run_hook("Read", {"file_path": str(SENTINEL_ROOT / "out" / "orchestrator-dispatch" / "dispatch-input.json").upper()}, args)[0] == expected
    # 不論作業系統：反斜線的 .. 與大小寫變化都跳不出白名單
    for path in ("out\\orchestrator-dispatch\\..\\a1\\verified.json", "OUT/ORCHESTRATOR-DISPATCH/INTERNAL/CONTEXT.JSON",
                 ".claude\\skills\\orchestrator\\..\\daily-intel\\SKILL.md"):
        assert run_hook("Read", {"file_path": path}, args)[0] == "deny", path


def test_read_whitelist_rejects_symlinks(tmp_path):
    """白名單內的符號連結指向內部檔案時拒絕（以實際位置判斷）。"""
    skill = tmp_path / ".claude" / "skills" / "orchestrator"
    internal = tmp_path / "out" / "orchestrator-dispatch" / "internal"
    skill.mkdir(parents=True)
    internal.mkdir(parents=True)
    (skill / "SKILL.md").write_text("x", encoding="utf-8")
    (internal / "context.json").write_text("{}", encoding="utf-8")
    args = orchestrator_args("dispatch")
    assert run_hook("Read", {"file_path": ".claude/skills/orchestrator/SKILL.md"}, args, cwd=tmp_path)[0] == "allow"
    linked = []
    try:
        (skill / "leak.json").symlink_to(internal / "context.json")
        (tmp_path / "out" / "orchestrator-dispatch" / "dispatch-input.json").symlink_to(internal / "context.json")
        linked += [".claude/skills/orchestrator/leak.json", "out/orchestrator-dispatch/dispatch-input.json"]
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":                                   # Windows 沒有權限建立符號連結時，用目錄 junction 測同一條規則
        import _winapi
        _winapi.CreateJunction(str(internal), str(skill / "junction"))
        linked.append(".claude/skills/orchestrator/junction/context.json")
    if not linked:
        pytest.skip("這個環境不能建立符號連結")
    for path in linked:
        assert run_hook("Read", {"file_path": path}, args, cwd=tmp_path)[0] == "deny", path


@pytest.mark.parametrize("mode", MODES)
def test_orchestrator_other_tools(mode):
    args = orchestrator_args(mode)
    d = f"out/orchestrator-{mode}"
    assert run_hook("Write", {"file_path": f"{d}/{mode}-proposal.json"}, args)[0] == "allow"
    for path in (f"{d}/{mode}-proposal.accepted", f"{d}/{mode}-input.json", f"{d}/internal/context.json", f"{d}/{mode}-plan.json",
                 "out/llm/results.json"):
        assert run_hook("Write", {"file_path": path}, args)[0] == "deny", path
    assert run_hook("Skill", {"skill": "orchestrator"}, args)[0] == "allow"
    for tool, inp in (("Skill", {"skill": "daily-intel"}), ("Agent", {"subagent_type": "planner"}), ("Task", {"subagent_type": "reviewer"}),
                      ("WebSearch", {"query": "x"}), ("WebFetch", {"url": "https://www.ithome.com.tw/"}), ("Bash", {"command": "cat out/a1/verified.json"}),
                      ("Glob", {"pattern": "out/**"}), ("Grep", {"pattern": "x", "path": "out"}), ("Edit", {"file_path": f"{d}/{mode}-proposal.json"})):
        assert run_hook(tool, inp, args)[0] == "deny", (tool, inp)


def test_without_read_whitelist_behavior_unchanged():
    """沒有 --read 時（daily-intel、claude-analysis）維持原本規則：out/ 與 .claude/ 都可讀。"""
    for args in ([], ["--write", "out/llm/results.json", "--agents", "", "--no-websearch", "--skill", "analysis-writer"]):
        for path in ("out/orchestrator-dispatch/internal/context.json", "out/a1/verified.json", ".claude/skills/daily-intel/SKILL.md"):
            assert run_hook("Read", {"file_path": path}, args)[0] == "allow", (args, path)
        assert run_hook("Read", {"file_path": "agents/registry.py"}, args)[0] == "deny"


def test_hook_errors_fail_closed():
    """hook 自己出錯時明確拒絕（Claude Code 對 0、2 以外的結束碼不會擋下工具）。"""
    for args in ([], orchestrator_args("dispatch")):
        decision, reason = run_hook(None, None, args, raw="{not json")
        assert decision == "deny" and "預設拒絕" in reason
        assert run_hook("Read", {"file_path": ["out/a1/verified.json"]}, args)[0] == "deny"
