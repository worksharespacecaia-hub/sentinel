#!/usr/bin/env python3
"""daily-intel 失敗時，從 claude-code-action 的執行紀錄只列出錯誤原因（公開 Repo 的 log 是公開的）。

只印：模型、驗證來源、結果類型、回合數、錯誤代碼與錯誤訊息（截斷並遮蔽疑似金鑰），以及被拒絕的工具
（只列工具名稱、工作目錄內的相對路徑或網址的主機名稱）、各工具呼叫次數與工具錯誤（截斷）。
不印對話內容、工具輸入內容或網頁內容。
--with-result：Claude 結束卻沒有寫出結果時，另外印出它最後的說明（截斷、遮蔽疑似金鑰），用來判斷它為什麼停下來。
用法：python3 scripts/claude-error-summary.py [--with-result] <execution_file>
"""
from __future__ import annotations

import json
import os
from collections import Counter
import re
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import urlsplit

SECRET_RE = re.compile(r"sk-ant-[A-Za-z0-9_-]+|[A-Za-z0-9_-]{40,}")
LIMIT = 300


def clean(value) -> str:
    text = " ".join(str(value).split())
    return SECRET_RE.sub("[REDACTED]", text)[:LIMIT]


def denial_target(tool_input) -> str:
    if not isinstance(tool_input, dict):
        return ""
    if tool_input.get("url"):
        return urlsplit(str(tool_input["url"])).hostname or "?"
    raw = tool_input.get("file_path") or tool_input.get("path")
    if raw:
        cwd = os.getcwd().replace("\\", "/").rstrip("/") + "/"
        path = str(raw).replace("\\", "/")
        if path.startswith(cwd):
            return path[len(cwd):]
        if not (path.startswith("/") or re.match(r"^[A-Za-z]:/", path)):
            return path                                   # 相對路徑（相對工作目錄）
        name = (PureWindowsPath if "\\" in str(raw) else PurePosixPath)(str(raw)).name
        return f"（工作目錄外）…/{name}"
    if tool_input.get("subagent_type"):
        return f"subagent={tool_input['subagent_type']}"
    if tool_input.get("skill"):
        return f"skill={tool_input['skill']}"
    return ""


def load_messages(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    try:
        data = json.loads(text)
    except ValueError:
        data = [json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]
    if isinstance(data, dict):
        data = data.get("messages") or [data]
    return [m for m in data if isinstance(m, dict)]


def _blocks(m: dict) -> list:
    content = (m.get("message") or {}).get("content")
    return [c for c in content if isinstance(c, dict)] if isinstance(content, list) else []


def tool_activity(messages: list[dict]) -> list[str]:
    """各工具呼叫次數（主 Agent／Subagent 分開）與工具錯誤；只列工具名稱與 Subagent 類型。"""
    labels, counts = {}, {"主 Agent": Counter(), "Subagent": Counter()}
    for m in messages:
        if m.get("type") != "assistant":
            continue
        scope = "Subagent" if m.get("parent_tool_use_id") else "主 Agent"
        for c in _blocks(m):
            if c.get("type") == "tool_use":
                inp = c.get("input") if isinstance(c.get("input"), dict) else {}
                label = str(c.get("name", "?"))
                if inp.get("subagent_type"):
                    label += f"({inp['subagent_type']})"
                labels[c.get("id")] = label
                counts[scope][label] += 1
    lines = [f"工具呼叫（{scope}）：" + "、".join(f"{clean(k)}×{v}" for k, v in sorted(cnt.items()))
             for scope, cnt in counts.items() if cnt]
    if not lines:
        lines.append("工具呼叫：無")
    errors = []
    for m in messages:
        if m.get("type") != "user":
            continue
        for c in _blocks(m):
            if c.get("type") == "tool_result" and c.get("is_error"):
                body = c.get("content")
                if isinstance(body, list):
                    body = " ".join(str(x.get("text", "")) for x in body if isinstance(x, dict))
                errors.append(f"工具錯誤：{clean(labels.get(c.get('tool_use_id'), '?'))}：{clean(body)[:150]}")
    lines += errors[:8]
    if len(errors) > 8:
        lines.append(f"工具錯誤：另有 {len(errors) - 8} 筆")
    return lines


def summarize(messages: list[dict], with_result: bool = False) -> list[str]:
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
        denials = result.get("permission_denials") or []
        for d in denials[:10]:
            if isinstance(d, dict):
                lines.append(f"權限拒絕：{clean(d.get('tool_name', '?'))} {clean(denial_target(d.get('tool_input')))}".rstrip())
        if len(denials) > 10:
            lines.append(f"權限拒絕：另有 {len(denials) - 10} 筆")
    if messages:
        lines += tool_activity(messages)
    if with_result and result and not result.get("is_error") and result.get("result"):
        lines.append(f"Claude 最後的說明：{clean(result['result'])}")
    return lines or ["執行紀錄中沒有可辨識的訊息"]


def main(argv: list[str]) -> int:
    args = argv[1:]
    with_result = "--with-result" in args
    args = [a for a in args if a != "--with-result"]
    if len(args) != 1:
        print("用法：claude-error-summary.py [--with-result] <execution_file>", file=sys.stderr)
        return 2
    path = Path(args[0])
    if not path.is_file():
        print(f"找不到執行紀錄：{path.name}")
        return 0
    for line in summarize(load_messages(path), with_result=with_result):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
