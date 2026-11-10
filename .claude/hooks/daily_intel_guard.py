#!/usr/bin/env python3
"""claude-code-action（訂閱方案）Job 的受信任 PreToolUse hook。預設拒絕。

用於 daily-intel（預設參數）與 claude-analysis（--write out/llm/results.json --agents "" --no-websearch --skill analysis-writer）。
- Read：只允許 out/ 與 .claude/（Skill、Subagent 定義）；拒絕 ..、.git、.env
- Write：只允許 --write 指定的單一檔案
- Agent：只允許 --agents 列出的 Subagent，且必須在前景執行（無人值守的單次執行，主 Agent 結束回合時背景 Subagent 會被中斷）
- WebFetch：一律拒絕（文章由程式事先抓好）；WebSearch 只在沒有 --no-websearch 時允許
- Skill：只允許 --skill 指定的 Skill；其他工具一律拒絕
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path.cwd().resolve()
DAILY_SUBAGENTS = "news-scout,advisory-scout,incident-analyst,stack-impact-analyst"


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


def config(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", default="out/intel-daily.json")
    ap.add_argument("--agents", default=DAILY_SUBAGENTS)
    ap.add_argument("--no-websearch", action="store_true")
    ap.add_argument("--skill", default="daily-intel")
    c = ap.parse_args(argv)
    c.agents = {a for a in c.agents.split(",") if a}
    return c


def main(argv=None):
    cfg = config(sys.argv[1:] if argv is None else argv)
    data = json.load(sys.stdin)
    tool, inp = data.get("tool_name", ""), data.get("tool_input") or {}
    if tool == "Read":
        return allow() if inside(inp.get("file_path", ""), ROOT / "out", ROOT / ".claude") else deny("只能讀 out/ 與 .claude/")
    if tool == "Write":
        target = (ROOT / inp.get("file_path", "")).resolve() if inp.get("file_path") else None
        return allow() if target == (ROOT / cfg.write).resolve() else deny(f"只能寫 {cfg.write}")
    if tool in ("Agent", "Task"):
        if inp.get("subagent_type") not in cfg.agents:
            deny("這個 Job 不允許此 Subagent" if cfg.agents else "這個 Job 不使用 Subagent，請直接完成")
        if inp.get("run_in_background"):
            deny("Subagent 必須在前景執行（不要設定 run_in_background）：這是無人值守的單次執行，結束回合流程就結束，請直接等它回報")
        return allow()
    if tool == "Skill":
        return allow() if inp.get("skill") == cfg.skill else deny(f"只允許 {cfg.skill} Skill")
    if tool == "WebSearch":
        return deny("這個 Job 不上網：所需資料都在 out/ 中") if cfg.no_websearch else allow()
    if tool == "WebFetch":
        deny("不使用 WebFetch：資料已由程式準備好放在 out/，請從中照抄")
    deny(f"工具 {tool} 未核准")


if __name__ == "__main__":
    main()
