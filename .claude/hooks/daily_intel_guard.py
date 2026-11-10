#!/usr/bin/env python3
"""daily-intel Job 的受信任 PreToolUse hook（claude-code-action 使用）。預設拒絕。

- Read：只允許 out/ 與 .claude/（Skill、Subagent 定義）；拒絕 ..、.git、.env
- Write：只允許 out/intel-daily.json
- Agent：只允許 4 個每日情資 Subagent，且必須在前景執行（無人值守的單次執行，主 Agent 結束回合時背景 Subagent 會被中斷）
- WebFetch：只允許 HTTPS 與受信任來源網域（agents/intel/sources.yaml）；WebSearch 允許
- Skill：只允許 daily-intel；其他工具一律拒絕
"""
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

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


def trusted_domains():
    domains = []
    for line in (ROOT / "agents" / "intel" / "sources.yaml").read_text(encoding="utf-8").splitlines():
        if "domain:" in line:
            domains.append(line.split("domain:")[1].split(",")[0].strip())
    return domains


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
        parts = urlsplit(inp.get("url", ""))
        host = (parts.hostname or "").lower()
        ok = parts.scheme == "https" and not parts.username and any(host == d or host.endswith("." + d) for d in trusted_domains())
        return allow() if ok else deny("WebFetch 只允許受信任來源的 HTTPS 網址")
    deny(f"工具 {tool} 未核准")


if __name__ == "__main__":
    main()
