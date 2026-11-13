#!/usr/bin/env python3
"""daily-intel 失敗時，從 claude-code-action 的執行紀錄只列出錯誤原因（公開 Repo 的 log 是公開的）。

只印：模型、驗證來源、結果類型、回合數、錯誤代碼與錯誤訊息（截斷並遮蔽疑似金鑰），以及被拒絕的工具
（只列工具名稱、工作目錄內的相對路徑或網址的主機名稱）、各工具呼叫次數與工具錯誤（截斷）。
不印對話內容、工具輸入內容或網頁內容。
--with-result：另外印出 Claude 最後的說明（截斷、遮蔽疑似金鑰），用來判斷它為什麼停下來、為什麼沒列入事件。
--activity：逐筆列出工具呼叫（工具、查詢字詞或網站主機、結果類型：成功／HTTP 403／轉址／被擋），不含網頁內容。
--trace <輸出檔> [--job <Job>]：寫出給「Agent 執行」頁的執行紀錄（只含工具名稱、次數與數量）。Job 為 daily-intel（預設）、
  claude-analysis，或 Orchestrator 的 orchestrator-dispatch／orchestrator-review（訂閱步驟；接在程式步驟的 trace 後面，
  不讀提案內容，只看提案檔與採用標記是否存在、雜湊是否相符）。
用法：python3 scripts/claude-error-summary.py [--with-result] [--activity] [--trace <輸出檔> [--job <Job>]] <execution_file>
"""
from __future__ import annotations

import hashlib
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
    labels, hosts, counts = {}, {}, {"主 Agent": Counter(), "Subagent": Counter()}
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
                if inp.get("url"):
                    hosts[c.get("id")] = urlsplit(str(inp["url"])).hostname or "?"
                counts[scope][label] += 1
    lines = [f"工具呼叫（{scope}）：" + "、".join(f"{clean(k)}×{v}" for k, v in sorted(cnt.items()))
             for scope, cnt in counts.items() if cnt]
    if not lines:
        lines.append("工具呼叫：無")
    errors, blocked = [], Counter()
    for m in messages:
        if m.get("type") != "user":
            continue
        for c in _blocks(m):
            if c.get("type") == "tool_result" and c.get("is_error"):
                body = c.get("content")
                if isinstance(body, list):
                    body = " ".join(str(x.get("text", "")) for x in body if isinstance(x, dict))
                tid = c.get("tool_use_id")
                where = f"{labels.get(tid, '?')} {hosts[tid]}" if tid in hosts else labels.get(tid, "?")
                if tid in hosts and "受信任" in str(body):
                    blocked[hosts[tid]] += 1            # hook 擋下的清單外網站：調整信任清單的依據
                    continue
                errors.append(f"工具錯誤：{clean(where)}：{clean(body)[:150]}")
    if blocked:
        lines.append("WebFetch 被擋的網站（不在信任清單）：" + "、".join(f"{clean(h)}×{n}" for h, n in blocked.most_common(15)))
    lines += errors[:8]
    if len(errors) > 8:
        lines.append(f"工具錯誤：另有 {len(errors) - 8} 筆")
    return lines


def _result_text(c: dict) -> str:
    body = c.get("content")
    if isinstance(body, list):
        body = " ".join(str(x.get("text", "")) for x in body if isinstance(x, dict))
    return str(body or "")


def _outcome(name: str, c: dict | None) -> str:
    if c is None:
        return "沒有結果"
    text = _result_text(c)
    if c.get("is_error"):
        return "被擋（不在信任清單）" if "受信任" in text else "被 hook 擋下" if "hook" in text else "錯誤"
    if name == "WebFetch":
        m = re.search(r"\bHTTP (\d{3})\b", text[:300])        # 只看開頭的狀態說明，不誤判內文中的數字
        if m and m.group(1) == "403":
            return "HTTP 403（網站擋機器人）"
        if m and m.group(1) != "200":
            return f"HTTP {m.group(1)}"
        return "轉址（未跟隨）" if "REDIRECT" in text[:300] else "成功"
    if name == "WebSearch":
        n = text.count('"url"')
        return f"{n} 筆結果"
    return "完成" if name in ("Agent", "Task") else "成功"


def activity_log(messages: list[dict], limit: int = 80) -> list[str]:
    """逐筆工具呼叫：只列工具、查詢字詞（截斷）或網址主機、相對路徑與結果類型。"""
    results = {c.get("tool_use_id"): c for m in messages if m.get("type") == "user" for c in _blocks(m)
               if c.get("type") == "tool_result"}
    lines = []
    for m in messages:
        if m.get("type") != "assistant":
            continue
        who = "Subagent" if m.get("parent_tool_use_id") else "主 Agent"
        for c in _blocks(m):
            if c.get("type") != "tool_use":
                continue
            name, inp = str(c.get("name", "?")), c.get("input") if isinstance(c.get("input"), dict) else {}
            if inp.get("query"):
                target = f"「{clean(inp['query'])[:60]}」"
            elif inp.get("subagent_type"):
                target = f"({clean(inp['subagent_type'])})"
            else:
                target = clean(denial_target(inp))
            lines.append(f"  [{who}] {clean(name)} {target} → {_outcome(name, results.get(c.get('id')))}")
    if len(lines) > limit:
        lines = lines[:limit] + [f"  另有 {len(lines) - limit} 筆"]
    return ["工具呼叫紀錄：", *lines] if lines else []


def summarize(messages: list[dict], with_result: bool = False, activity: bool = False) -> list[str]:
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
    if activity and messages:
        lines += activity_log(messages)
    if with_result and result and not result.get("is_error") and result.get("result"):
        lines.append(f"Claude 最後的說明：{clean(result['result'])}")
    return lines or ["執行紀錄中沒有可辨識的訊息"]


def trace_events(messages: list[dict], news: dict | None, intel: dict | None, now: str) -> list[dict]:
    """給「Agent 執行」頁的 daily-intel 執行紀錄（格式同 agents/tools/trace.py）。只含工具名稱、次數與數量，不含網頁或對話內容。"""
    def ev(kind, detail, subagent=None, source=None):
        return {"ts": now, "agent": "daily-intel", "subagent": subagent, "kind": kind, "detail": clean(detail)[:500],
                "source": source, "cost_usd": None}
    out = []
    if news:
        srcs = news.get("sources") or []
        ok = sum(1 for s in srcs if s.get("status") == "ok")
        out.append(ev("start", f"程式抓取近 {news.get('window_hours', 72)} 小時資安新聞：{len(news.get('items') or [])} 篇"
                                f"（{ok}/{len(srcs)} 個來源成功），交給 Claude（訂閱方案）判讀"))
        kept = "、".join(f"{s.get('name')} {s.get('kept')}" for s in srcs if s.get("kept"))
        if kept:
            out.append(ev("tool", f"news_collect：{kept}"))
    else:
        out.append(ev("start", "Claude（訂閱方案）判讀今日資安新聞"))
    if not messages:
        out.append(ev("error", "Claude 沒有執行（Token 檢查失敗或設定錯誤）"))
        return out
    out.append(ev("skill", "載入 daily-intel Skill"))
    results = {c.get("tool_use_id"): c for m in messages if m.get("type") == "user" for c in _blocks(m)
               if c.get("type") == "tool_result"}
    sub_tools: dict[str, Counter] = {}
    for m in messages:
        parent = m.get("parent_tool_use_id")
        if m.get("type") == "assistant" and parent:
            for c in _blocks(m):
                if c.get("type") == "tool_use":
                    sub_tools.setdefault(parent, Counter())[str(c.get("name", "?"))] += 1
    main_tools = Counter()
    for m in messages:
        if m.get("type") != "assistant" or m.get("parent_tool_use_id"):
            continue
        for c in _blocks(m):
            if c.get("type") != "tool_use":
                continue
            name, inp = str(c.get("name", "?")), c.get("input") if isinstance(c.get("input"), dict) else {}
            if name in ("Agent", "Task") and inp.get("subagent_type"):
                res = results.get(c.get("id"))
                used = "、".join(f"{k}×{v}" for k, v in sorted((sub_tools.get(c.get("id")) or {}).items())) or "沒有使用工具"
                if res is not None and res.get("is_error"):
                    out.append(ev("error", f"{inp['subagent_type']} 被拒絕或失敗", subagent=str(inp["subagent_type"])))
                else:
                    out.append(ev("subagent", f"{inp['subagent_type']} 完成（{used}）", subagent=str(inp["subagent_type"]), source="live"))
            else:
                main_tools[name] += 1
    if main_tools:
        out.append(ev("tool", "主 Agent 工具：" + "、".join(f"{k}×{v}" for k, v in sorted(main_tools.items()))))
    result = next((m for m in reversed(messages) if m.get("type") == "result"), None) or {}
    events = (intel or {}).get("events") if isinstance(intel, dict) else None
    secs = round((result.get("duration_ms") or 0) / 1000)
    if isinstance(events, list):
        out.append(ev("result", f"寫出 {len(events)} 件事件（{result.get('num_turns', '?')} 回合、{secs} 秒）；A1 以抓取的原文確認引用"))
    else:
        out.append(ev("error", f"沒有寫出結果（{result.get('num_turns', '?')} 回合、{secs} 秒）"))
    return out


def analysis_trace_events(messages: list[dict], tasks_doc: dict | None, validated: dict | None, now: str) -> list[dict]:
    """claude-analysis Job 的執行紀錄：各 Agent 交給 Claude 的任務數、通過程式驗證的數量與工具次數；不含任何撰寫內容。"""
    def ev(kind, detail, subagent=None, source=None):
        return {"ts": now, "agent": "claude-analysis", "subagent": subagent, "kind": kind, "detail": clean(detail)[:500],
                "source": source, "cost_usd": None}
    tasks = (tasks_doc or {}).get("tasks") or []
    by = Counter(f"{t.get('agent')}/{t.get('subagent')}" for t in tasks if isinstance(t, dict))
    out = [ev("start", f"程式整理 {len(tasks)} 個要請 Claude（訂閱方案）撰寫的任務；分數、等級與燈號已由程式算好")]
    if not messages:
        out.append(ev("error", "Claude 沒有執行（Token 檢查失敗或設定錯誤），A5 改用程式範本"))
        return out
    out.append(ev("skill", "載入 analysis-writer Skill"))
    ok_keys = set((validated or {}).keys())
    for name, n in sorted(by.items()):
        passed = sum(1 for t in tasks if isinstance(t, dict) and f"{t.get('agent')}/{t.get('subagent')}" == name and t.get("key") in ok_keys)
        agent, sub = name.split("/", 1)
        out.append(ev("subagent", f"{agent} 的 {sub}：撰寫 {n} 個任務，程式驗證通過 {passed} 個", subagent=sub,
                      source="live" if passed else "template"))
    tools = Counter(str(c.get("name", "?")) for m in messages if m.get("type") == "assistant" and not m.get("parent_tool_use_id")
                    for c in _blocks(m) if c.get("type") == "tool_use")
    if tools:
        out.append(ev("tool", "工具：" + "、".join(f"{k}×{v}" for k, v in sorted(tools.items()))))
    result = next((m for m in reversed(messages) if m.get("type") == "result"), None) or {}
    secs = round((result.get("duration_ms") or 0) / 1000)
    out.append(ev("result", f"通過驗證 {len(ok_keys)}／{len(tasks)} 個任務（{result.get('num_turns', '?')} 回合、{secs} 秒）；"
                            "未通過或未撰寫的項目由 A5 改用程式範本"))
    return out


ORCHESTRATOR_JOBS = {"orchestrator-dispatch": "dispatch", "orchestrator-review": "review"}
JOBS = ("daily-intel", "claude-analysis", *ORCHESTRATOR_JOBS)
MODE_ZH = {"dispatch": "派工", "review": "驗收"}


def proposal_state(out: Path, mode: str) -> str:
    """訂閱步驟的提案狀態：accepted（有採用標記且雜湊相符）、rejected（有提案但沒有通過檢查）、missing（沒有提案）。

    只計算提案檔位元組的 sha256，不解析、不輸出提案內容。
    """
    d = out / f"orchestrator-{mode}"
    proposal, accepted = d / f"{mode}-proposal.json", d / f"{mode}-proposal.accepted"
    if not proposal.is_file():
        return "missing"
    try:
        digest = hashlib.sha256(proposal.read_bytes()).hexdigest()
        mark = accepted.read_text(encoding="utf-8").strip().lower() if accepted.is_file() else ""
    except (OSError, UnicodeDecodeError):
        return "rejected"
    return "accepted" if mark == digest else "rejected"


def orchestrator_trace_events(messages: list[dict], mode: str, state: str, now: str) -> list[dict]:
    """Orchestrator 派工／驗收 Job 的訂閱步驟紀錄：工具次數、被拒絕的工具與提案是否通過檢查；不含提案或對話內容。

    提案是否採用、核准幾項，由程式步驟（run_agent.py orchestrator）寫在同一份 trace。
    """
    agent, zh = f"orchestrator-{mode}", MODE_ZH[mode]

    def ev(kind, detail):
        return {"ts": now, "agent": agent, "subagent": None, "kind": kind, "detail": clean(detail)[:500], "source": None,
                "cost_usd": None}
    out = [ev("start", f"Claude（訂閱方案）執行 orchestrator Skill（{zh}）：只讀公開輸入與核准政策，寫出提案交給程式核准")]
    if not messages:
        out.append(ev("error", f"Claude 沒有執行（Token 檢查失敗或設定錯誤），{zh}改用 Agent SDK 或空提案"))
        return out
    out.append(ev("skill", f"載入 orchestrator Skill（{zh}）"))
    tools = Counter(str(c.get("name", "?")) for m in messages if m.get("type") == "assistant" and not m.get("parent_tool_use_id")
                    for c in _blocks(m) if c.get("type") == "tool_use")
    if tools:
        out.append(ev("tool", "工具：" + "、".join(f"{k}×{v}" for k, v in sorted(tools.items()))))
    result = next((m for m in reversed(messages) if m.get("type") == "result"), None) or {}
    denials = Counter(str(d.get("tool_name", "?")) for d in result.get("permission_denials") or [] if isinstance(d, dict))
    if denials:
        out.append(ev("skip", "被拒絕的工具呼叫（hook 或權限設定）：" + "、".join(f"{k}×{v}" for k, v in sorted(denials.items()))))
    secs = round((result.get("duration_ms") or 0) / 1000)
    took = f"{result.get('num_turns', '?')} 回合、{secs} 秒"
    if state == "accepted":
        out.append(ev("result", f"寫出提案並通過程式檢查（{took}）；由程式政策逐項核准"))
    elif state == "rejected":
        out.append(ev("error", f"寫出提案但沒有通過程式檢查，不採用（{took}）；{zh}改用 Agent SDK 或空提案"))
    else:
        out.append(ev("error", f"沒有寫出提案（{took}）；{zh}改用 Agent SDK 或空提案"))
    return out


def main(argv: list[str]) -> int:
    args = argv[1:]
    with_result, activity = "--with-result" in args, "--activity" in args
    trace_out, job = None, "daily-intel"
    if "--trace" in args:                       # --trace <輸出檔>：寫出給「Agent 執行」頁的執行紀錄
        i = args.index("--trace")
        trace_out = Path(args[i + 1]) if i + 1 < len(args) else None
        args = args[:i] + args[i + 2:]
    if "--job" in args:                         # --job daily-intel｜claude-analysis｜orchestrator-dispatch｜orchestrator-review
        i = args.index("--job")
        job = args[i + 1] if i + 1 < len(args) else ""
        args = args[:i] + args[i + 2:]
    args = [a for a in args if a not in ("--with-result", "--activity")]
    if len(args) != 1 or ("--trace" in argv and trace_out is None) or job not in JOBS:
        print("用法：claude-error-summary.py [--with-result] [--activity] [--trace <輸出檔> [--job " + "|".join(JOBS) + "]] "
              "<execution_file>", file=sys.stderr)
        return 2
    path = Path(args[0])
    messages = load_messages(path) if path.is_file() else []
    if trace_out is not None:
        def read(p):
            try:
                return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None
            except ValueError:
                return None
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        append = job in ORCHESTRATOR_JOBS                 # 派工／驗收 Job：程式步驟已寫入同一份 trace，接在後面
        if job == "claude-analysis":
            evs = analysis_trace_events(messages, read(Path("out/llm/tasks.json")), read(Path("out/llm/validated.json")), now)
        elif append:
            mode = ORCHESTRATOR_JOBS[job]
            evs = orchestrator_trace_events(messages, mode, proposal_state(Path("out"), mode), now)
        else:
            evs = trace_events(messages, read(Path("out/news.json")), read(Path("out/intel-daily.json")), now)
        trace_out.parent.mkdir(parents=True, exist_ok=True)
        with trace_out.open("a" if append else "w", encoding="utf-8", newline="\n") as f:
            f.write("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in evs))
        print(f"寫出 {len(evs)} 筆執行紀錄：{trace_out}")
        return 0
    if not path.is_file():
        print(f"找不到執行紀錄：{path.name}")
        return 0
    for line in summarize(messages, with_result=with_result, activity=activity):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
