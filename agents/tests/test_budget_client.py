"""Workflow 端的 API 預算預留（tools/budget.py）與 LLMRunner 的結算：鍵格式、序號、只結算本次用量、失敗時用範本。"""
import json
import re
import urllib.error

import pytest

from llm import LLMRunner, Task
from tools import budget as budget_mod
from tools.budget import RemoteBudget, budget_for
from tools.cache import LLMCache, ReplayStore
from tools.trace import Tracer, read_trace

# 與 dashboard/lib/budget.ts 的 KEY_RE 相同
SERVER_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}(/[A-Za-z0-9][A-Za-z0-9._-]{0,39}){1,4}$")


class FakeServer:
    def __init__(self, reserve_ok=True):
        self.calls, self.reserve_ok = [], reserve_ok

    def __call__(self, body):
        self.calls.append(body)
        if body["action"] == "reserve":
            return {"ok": True, "key": body["key"]} if self.reserve_ok else {"ok": False, "reason": "本月預算不足"}
        return {"ok": True, "key": body["key"]}


def remote(monkeypatch, server, run_key="42779838559-2/a5"):
    b = RemoteBudget("https://sentinel.example", "notify-token", run_key)
    monkeypatch.setattr(b, "_post", server)
    return b


def test_keys_follow_server_format_and_increase(monkeypatch):
    server = FakeServer()
    b = remote(monkeypatch, server)
    r1, r2 = b.reserve("a5", 0.5), b.reserve("a5", 0.5)
    assert [c["key"] for c in server.calls] == ["42779838559-2/a5/a5/1", "42779838559-2/a5/a5/2"]
    assert all(SERVER_KEY_RE.match(c["key"]) for c in server.calls)
    b.settle(r1, 0.12)
    assert server.calls[-1] == {"action": "settle", "key": "42779838559-2/a5/a5/1", "actual_usd": 0.12}
    assert r2["key"].endswith("/2")


def test_reserve_failure_returns_none(monkeypatch):
    assert remote(monkeypatch, FakeServer(reserve_ok=False)).reserve("a5", 0.5) is None
    b = RemoteBudget("https://sentinel.example", "t", "r-1/a2")

    def http_error(body):
        raise urllib.error.HTTPError("u", 409, "Conflict", {}, None)
    monkeypatch.setattr(b, "_post", http_error)
    assert b.reserve("a2", 0.05) is None                        # 409（額度不足）或網路錯誤 → 範本


def test_budget_for_live_requires_https_base_and_token(monkeypatch):
    monkeypatch.delenv("SENTINEL_BASE_URL", raising=False)
    monkeypatch.delenv("NOTIFY_TOKEN", raising=False)
    assert isinstance(budget_for("live", "r-1/a2"), budget_mod._Unavailable)
    monkeypatch.setenv("SENTINEL_BASE_URL", "https://sentinel.example")
    monkeypatch.setenv("NOTIFY_TOKEN", "t")
    assert isinstance(budget_for("live", "r-1/a2"), RemoteBudget)
    assert budget_for("replay", "r-1/a2") is None
    monkeypatch.setenv("SENTINEL_BASE_URL", "http://insecure.example")
    with pytest.raises(ValueError):
        budget_for("live", "r-1/a2")


def _runner(tmp_path, budget):
    return LLMRunner(agent="a2", mode="live", scope="daily", target_sha="a" * 40, advisory_revision=None,
                     tracer=Tracer(tmp_path / "trace.jsonl", "a2"), cache=LLMCache(tmp_path / "llm.json"),
                     replay=ReplayStore(tmp_path / "replay"), budget=budget)


def _task(i):
    return Task(id=f"t{i}", subagent="secret-analyst", payload={"ids": [f"f{i}"], "items": [i]})


def test_runner_settles_only_this_calls_cost(tmp_path, monkeypatch):
    server = FakeServer()
    b = remote(monkeypatch, server, "run-1/a2")
    r = _runner(tmp_path, b)
    costs = iter([0.03, 0.02])

    async def fake_query(self, pending, graph_query):
        return {t.id: [{"id": t.payload["ids"][0], "explanation": "說明", "confidence": "high"}] for t, _ in pending}, next(costs)
    monkeypatch.setattr(LLMRunner, "_query", fake_query)
    assert r.run([_task(1)])["t1"]["source"] == "live"
    assert r.run([_task(2)])["t2"]["source"] == "live"
    settles = [c for c in server.calls if c["action"] == "settle"]
    assert [s["actual_usd"] for s in settles] == [0.03, 0.02]       # 不是累計的 0.03、0.05
    assert r.cost["per_agent"]["a2"] == 0.05


def test_runner_uses_template_when_budget_refused(tmp_path, monkeypatch):
    r = _runner(tmp_path, remote(monkeypatch, FakeServer(reserve_ok=False), "run-1/a2"))

    async def must_not_call(self, pending, graph_query):
        raise AssertionError("預留失敗時不得呼叫 API")
    monkeypatch.setattr(LLMRunner, "_query", must_not_call)
    assert r.run([_task(1)])["t1"]["source"] == "template"
    assert any("預算預留失敗" in e["detail"] for e in read_trace(tmp_path / "trace.jsonl"))
