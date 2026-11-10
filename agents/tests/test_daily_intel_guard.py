"""daily-intel Job 的 PreToolUse hook（.claude/hooks/daily_intel_guard.py）：預設拒絕，只放行每日情資需要的工具。"""
import json
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
