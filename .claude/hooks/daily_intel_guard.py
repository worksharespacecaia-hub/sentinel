#!/usr/bin/env python3
"""daily-intel Job 的受信任 PreToolUse hook（claude-code-action 使用）。預設拒絕。

- Read：只允許 out/ 與 .claude/（Skill、Subagent 定義）；拒絕 ..、.git、.env
- Write：只允許 out/intel-daily.json
- Agent：只允許 4 個每日情資 Subagent，且必須在前景執行（無人值守的單次執行，主 Agent 結束回合時背景 Subagent 會被中斷）
- WebFetch：一律拒絕（文章由程式事先抓好放在 out/news.json）；WebSearch 允許（補充用，結果由程式抓頁面確認）
- Skill：只允許 daily-intel；其他工具一律拒絕
"""
import json
import sys
from pathlib import Path

ROOT = Path.cwd().resolve()
SUBAGENTS = {"news-scout", "advisory-scout", "incident-analyst", "stack-impact-analyst"}


def deny(reason):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}, ensure_ascii=False))
    sys.exit(0)


def allow():
    print("{}")
    sys.exit(0)


def inside(raw, *bases):
    if not raw or ".." in Path(raw).parts:
        return False
    p = (ROOT / raw).resolve() if not Path(raw).is_absolute() else Path(raw).resolve()
    if ".git" in p.parts or p.name.startswith(".env"):
        return False
    return any(p == b or b in p.parents for b in bases)


def main():
    data = json.load(sys.stdin)
    tool, inp = data.get("tool_name", ""), data.get("tool_input") or {}
    if tool == "Read":
        return allow() if inside(inp.get("file_path", ""), ROOT / "out", ROOT / ".claude") else deny("只能讀 out/ 與 .claude/")
    if tool == "Write":
        target = (ROOT / inp.get("file_path", "")).resolve() if inp.get("file_path") else None
        return allow() if target == ROOT / "out" / "intel-daily.json" else deny("只能寫 out/intel-daily.json")
    if tool in ("Agent", "Task"):
        if inp.get("subagent_type") not in SUBAGENTS:
            deny("只允許每日情資 Subagent")
        if inp.get("run_in_background"):
            deny("Subagent 必須在前景執行（不要設定 run_in_background）：這是無人值守的單次執行，結束回合流程就結束，請直接等它回報")
        return allow()
    if tool == "Skill":
        return allow() if inp.get("skill") == "daily-intel" else deny("只允許 daily-intel Skill")
    if tool == "WebSearch":
        return allow()
    if tool == "WebFetch":
        deny("每日情資不使用 WebFetch：文章已由程式抓好放在 out/news.json，請從中照抄引用")
    deny(f"工具 {tool} 未核准")


if __name__ == "__main__":
    main()
