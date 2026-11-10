#!/usr/bin/env python3
"""daily-intel 失敗時，從 claude-code-action 的執行紀錄只列出錯誤原因（公開 Repo 的 log 是公開的）。

只印：模型、驗證來源、結果類型、回合數、錯誤代碼與錯誤訊息（截斷並遮蔽疑似金鑰）。不印對話內容、工具輸入或網頁內容。
用法：python3 scripts/claude-error-summary.py <execution_file>
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SECRET_RE = re.compile(r"sk-ant-[A-Za-z0-9_-]+|[A-Za-z0-9_-]{40,}")
LIMIT = 300


def clean(value) -> str:
    text = " ".join(str(value).split())
    return SECRET_RE.sub("[REDACTED]", text)[:LIMIT]


def load_messages(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    try:
        data = json.loads(text)
    except ValueError:
        data = [json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]
    if isinstance(data, dict):
        data = data.get("messages") or [data]
    return [m for m in data if isinstance(m, dict)]


def summarize(messages: list[dict]) -> list[str]:
    lines = []
    init = next((m for m in messages if m.get("type") == "system" and m.get("subtype") == "init"), None)
    if init:
        lines.append(f"模型：{clean(init.get('model', '?'))}；驗證來源：{clean(init.get('apiKeySource', '?'))}")
    for m in messages:
        if m.get("type") == "assistant":
            err = m.get("error") or (m.get("message") or {}).get("error")
            if err:
                lines.append(f"API 錯誤：{clean(err)}")
    result = next((m for m in reversed(messages) if m.get("type") == "result"), None)
    if result:
        lines.append(f"結果：subtype={clean(result.get('subtype'))} is_error={result.get('is_error')} "
                     f"回合={result.get('num_turns')} 時間={result.get('duration_ms')}ms")
        if result.get("is_error") and result.get("result"):
            lines.append(f"錯誤訊息：{clean(result['result'])}")
        for e in (result.get("errors") or [])[:5]:
            lines.append(f"錯誤：{clean(e)}")
    return lines or ["執行紀錄中沒有可辨識的訊息"]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("用法：claude-error-summary.py <execution_file>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    if not path.is_file():
        print(f"找不到執行紀錄：{path.name}")
        return 0
    for line in summarize(load_messages(path)):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
