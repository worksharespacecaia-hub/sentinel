#!/usr/bin/env python3
"""claude-code-action（訂閱方案）Job 的受信任 PreToolUse hook。預設拒絕。

用於 daily-intel（預設參數）、claude-analysis（--write out/llm/results.json --agents "" --no-websearch --skill analysis-writer）
與 Orchestrator 的派工／驗收（--read 白名單，見 .claude/orchestrator-<m>-settings.json；specs/orchestrator design §3.6）。
- Read：
  - 沒有 --read 時（daily-intel、claude-analysis）：只允許 out/ 與 .claude/（Skill、Subagent 定義）；拒絕 ..、.git、.env
  - 有 --read 時（可重複）：只允許符合白名單的路徑，其他一律拒絕（包括 out/ 下的其他檔案與 internal/）。
    白名單相對工作目錄，`*` 只配一層、`**` 配任意層；以正規化後的絕對路徑判斷，大小寫依作業系統
    （Windows 不分、Linux 區分）；含 ..、NUL，或路徑經過符號連結（實際位置與字面不同）時一律拒絕
- Write：只允許 --write 指定的單一檔案
- Agent：只允許 --agents 列出的 Subagent，且必須在前景執行（無人值守的單次執行，主 Agent 結束回合時背景 Subagent 會被中斷）
- WebFetch：一律拒絕（文章由程式事先抓好）；WebSearch 只在沒有 --no-websearch 時允許
- Skill：只允許 --skill 指定的 Skill；其他工具一律拒絕
- hook 本身出錯時拒絕（不放行）
"""
import argparse
import fnmatch
import json
import os
import re
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


# ---------------------------------------------------------------- --read 白名單
def _parts(path: str) -> tuple[str, ...]:
    return Path(os.path.normcase(path)).parts


def literal_path(raw) -> str | None:
    """Read 的路徑 → 正規化的絕對路徑。含 ..、NUL、空白，或經過符號連結（realpath 與字面不同）時回傳 None。"""
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        return None
    if ".." in re.split(r"[\\/]+", raw):                  # 兩種分隔符都檢查（Linux 上的 ..\ 也拒絕）
        return None
    try:
        lexical = os.path.normpath(raw if os.path.isabs(raw) else os.path.join(str(ROOT), raw))
        real = os.path.realpath(lexical)
    except (OSError, ValueError):
        return None
    if os.path.normcase(real) != os.path.normcase(lexical):
        return None
    return lexical


def _glob(parts: tuple[str, ...], pats: tuple[str, ...]) -> bool:
    if not pats:
        return not parts
    head, rest = pats[0], pats[1:]
    if head == "**":
        if not rest:
            return len(parts) >= 1                          # 結尾的 ** 只配目錄底下的項目
        return any(_glob(parts[i:], rest) for i in range(len(parts) + 1))
    return bool(parts) and fnmatch.fnmatchcase(parts[0], head) and _glob(parts[1:], rest)


def readable(raw, patterns) -> bool:
    path = literal_path(raw)
    if path is None:
        return False
    parts, root = _parts(path), _parts(str(ROOT))
    if parts[:len(root)] != root:
        return False
    rel = parts[len(root):]
    if not rel or ".git" in rel or rel[-1].startswith(".env"):
        return False
    for pat in patterns:
        segs = tuple(os.path.normcase(s) for s in pat.split("/") if s not in ("", "."))
        if not segs or ".." in segs or os.path.isabs(pat):
            continue                                        # 設定錯誤的白名單不放行任何路徑
        if _glob(rel, segs):
            return True
    return False


def config(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--read", action="append", default=None, metavar="GLOB",
                    help="可重複；設定後 Read 只允許符合白名單的路徑（相對工作目錄）")
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
        if cfg.read is not None:
            return allow() if readable(inp.get("file_path", ""), cfg.read) else \
                deny("這個 Job 只能讀：" + "、".join(cfg.read))
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
    try:
        main()
    except Exception:                                       # noqa: BLE001 - 結束碼不是 0 或 2 時 Claude Code 不會擋下工具：出錯一律明確拒絕
        deny("hook 檢查失敗，預設拒絕")
