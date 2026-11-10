"""每日情資放進「Agent 執行」頁：daily-intel Job 以程式整理執行紀錄（只含工具名稱與次數），A5 合併進執行樹。"""
import importlib.util
import json
from dataclasses import replace

import yaml

from tools.common import SENTINEL_ROOT
from tools.trace import read_trace

spec = importlib.util.spec_from_file_location("ces", SENTINEL_ROOT / "scripts" / "claude-error-summary.py")
ces = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ces)

NOW = "2026-11-10T09:00:00+00:00"
MSGS = [
    {"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": "r1", "name": "Read", "input": {"file_path": "out/news.json"}},
        {"type": "tool_use", "id": "a1", "name": "Agent", "input": {"subagent_type": "news-scout", "prompt": "秘密指示"}},
        {"type": "tool_use", "id": "a2", "name": "Agent", "input": {"subagent_type": "advisory-scout", "prompt": "x"}}]}},
    {"type": "assistant", "parent_tool_use_id": "a1", "message": {"content": [
        {"type": "tool_use", "id": "s1", "name": "Read", "input": {"file_path": "out/news.json"}}]}},
    {"type": "assistant", "parent_tool_use_id": "a2", "message": {"content": [
        {"type": "tool_use", "id": "s2", "name": "WebSearch", "input": {"query": "Next.js CVE"}},
        {"type": "tool_use", "id": "s3", "name": "WebSearch", "input": {"query": "PHP CVE"}}]}},
    {"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "a1", "is_error": False, "content": "網頁內容不該出現"},
        {"type": "tool_result", "tool_use_id": "a2", "is_error": False, "content": "report"}]}},
    {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "w1", "name": "Write", "input": {"file_path": "out/intel-daily.json"}}]}},
    {"type": "result", "subtype": "success", "is_error": False, "num_turns": 10, "duration_ms": 102000, "result": "最後的說明"},
]
NEWS = {"window_hours": 72, "items": [{}, {}, {}], "sources": [{"name": "iThome", "status": "ok", "kept": 2},
                                                                {"name": "INSIDE", "status": "failed", "kept": 0}]}


def test_trace_events_summarize_without_content():
    evs = ces.trace_events(MSGS, NEWS, {"events": [{}, {}]}, NOW)
    rows = [(e["kind"], e["subagent"], e["source"], e["detail"]) for e in evs]
    assert rows == [
        ("start", None, None, "程式抓取近 72 小時資安新聞：3 篇（1/2 個來源成功），交給 Claude（訂閱方案）判讀"),
        ("tool", None, None, "news_collect：iThome 2"),
        ("skill", None, None, "載入 daily-intel Skill"),
        ("subagent", "news-scout", "live", "news-scout 完成（Read×1）"),
        ("subagent", "advisory-scout", "live", "advisory-scout 完成（WebSearch×2）"),
        ("tool", None, None, "主 Agent 工具：Read×1、Write×1"),
        ("result", None, None, "寫出 2 件事件（10 回合、102 秒）；A1 以抓取的原文確認引用"),
    ]
    text = json.dumps(evs, ensure_ascii=False)
    assert "秘密指示" not in text and "網頁內容不該出現" not in text and "最後的說明" not in text
    assert all(e["agent"] == "daily-intel" and e["ts"] == NOW and e["cost_usd"] is None for e in evs)


def test_trace_when_claude_did_not_run_or_wrote_nothing():
    evs = ces.trace_events([], NEWS, None, NOW)
    assert evs[-1]["kind"] == "error" and "沒有執行" in evs[-1]["detail"]
    evs = ces.trace_events(MSGS, None, None, NOW)
    assert evs[0]["detail"] == "Claude（訂閱方案）判讀今日資安新聞" and evs[-1]["kind"] == "error"


def test_trace_cli_writes_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "news.json").write_text(json.dumps(NEWS), encoding="utf-8")
    (tmp_path / "out" / "intel-daily.json").write_text(json.dumps({"events": [{}]}), encoding="utf-8")
    exec_file = tmp_path / "exec.json"
    exec_file.write_text(json.dumps(MSGS, ensure_ascii=False), encoding="utf-8")
    assert ces.main(["x", "--trace", "out/daily-intel/trace.jsonl", str(exec_file)]) == 0
    evs = read_trace(tmp_path / "out" / "daily-intel" / "trace.jsonl")
    assert evs[-1]["detail"].startswith("寫出 1 件事件")
    assert ces.main(["x", "--trace", "out/t.jsonl", str(tmp_path / "missing.json")]) == 0      # 沒有執行紀錄也寫出
    assert "沒有執行" in read_trace(tmp_path / "out" / "t.jsonl")[-1]["detail"]


def test_workflow_uploads_trace_and_a5_downloads_it():
    wf = yaml.safe_load((SENTINEL_ROOT / ".github" / "workflows" / "sentinel.yml").read_text(encoding="utf-8"))
    steps = wf["jobs"]["daily-intel"]["steps"]
    i = next(i for i, s in enumerate(steps) if "--trace out/daily-intel/trace.jsonl" in str(s.get("run", "")))
    assert steps[i]["if"] == "${{ !cancelled() }}"                            # Claude 失敗也留下紀錄
    up = steps[i + 1]
    assert up["with"]["name"] == "${{ github.run_id }}-daily-intel-trace" and up["if"] == "${{ !cancelled() }}"
    dl = [s for s in wf["jobs"]["a5-report"]["steps"] if str(s.get("uses", "")).startswith("actions/download-artifact")
          and s["with"].get("name") == "${{ github.run_id }}-daily-intel-trace"]
    assert len(dl) == 1 and dl[0]["with"]["path"] == "out/daily-intel/" and dl[0]["continue-on-error"] is True


def test_a5_merges_daily_intel_trace(monkeypatch, tmp_path):
    from agents import a0_assets, a1_intel, a2_scan, a3_signals, a4_risk, a5_report, orchestrator
    from context import build_ctx
    env = {"SCENARIO": "daily", "TRIGGER_SOURCE": "manual", "EVENT_NAME": "local", "AS_OF": "2026-11-09T01:00:00Z", "RUN_ID": "t-run"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    for k in ("EXECUTION_MODE", "GITHUB_OUTPUT", "TARGET_DIR", "DEPLOYMENTS_FILE"):
        monkeypatch.delenv(k, raising=False)
    ctx = replace(build_ctx(), out=tmp_path / "out", data_dir=tmp_path / "data", reports_dir=tmp_path / "reports")
    (ctx.out / "daily-intel").mkdir(parents=True)
    (ctx.out / "daily-intel" / "trace.jsonl").write_text(json.dumps(
        {"ts": "2026-11-09T01:00:30+00:00", "agent": "daily-intel", "subagent": "news-scout", "kind": "subagent",
         "detail": "news-scout 完成（Read×1）", "source": "live", "cost_usd": None}, ensure_ascii=False) + "\n", encoding="utf-8")
    for m in (orchestrator, a0_assets, a1_intel, a2_scan, a3_signals, a4_risk, a5_report):
        m.run(ctx)
    trace = read_trace(ctx.data_dir / "daily" / "trace.jsonl")
    assert any(e["agent"] == "daily-intel" and e["source"] == "live" for e in trace)
