"""SENTINEL_MODEL_OVERRIDE（成本量測用）與 token 用量累計：不使用真實 Token、不呼叫 API。"""
import asyncio

import pytest

from llm import LLMRunner, Task
from registry import AGENTS, MODELS, agent_definitions, model_id
from tools.cache import LLMCache, ReplayStore
from tools.trace import Tracer


WRITERS = {"planner", "remediation-advisor", "brand-notice-writer", "ceo-briefer", "intel-report-writer", "containment-advisor"}


def test_all_subagents_default_to_haiku(monkeypatch):
    monkeypatch.delenv("SENTINEL_MODEL_OVERRIDE", raising=False)
    assert model_id("haiku") == MODELS["haiku"]
    assert model_id("sonnet") == MODELS["sonnet"]
    for spec in AGENTS.values():
        assert {d.model for d in agent_definitions(spec).values()} == {MODELS["haiku"]}


def test_writer_subagents_keep_measured_settings():
    subs = {n: s for spec in AGENTS.values() for n, s in spec.subagents.items()}
    for name, s in subs.items():
        if name in WRITERS:
            assert s.effort == "medium" and s.max_turns == (6 if s.graph else 3), name
        else:
            assert s.effort == "low" and s.max_turns == (6 if s.graph else 2), name


def test_override_forces_haiku_everywhere(monkeypatch):
    monkeypatch.setenv("SENTINEL_MODEL_OVERRIDE", "haiku")
    for spec in AGENTS.values():
        assert {d.model for d in agent_definitions(spec).values()} == {MODELS["haiku"]}


def test_override_rejects_unknown(monkeypatch):
    monkeypatch.setenv("SENTINEL_MODEL_OVERRIDE", "gpt")
    with pytest.raises(ValueError):
        model_id("haiku")


def test_override_changes_cache_key(tmp_path, monkeypatch):
    r = LLMRunner(agent="a5", mode="record", scope="daily", target_sha="0" * 40, advisory_revision=None,
                  tracer=Tracer(tmp_path / "trace.jsonl", "a5"), cache=LLMCache(tmp_path / "c.json"),
                  replay=ReplayStore(tmp_path / "replay"))
    task = Task(id="t1", subagent="ceo-briefer", payload={"x": 1})
    monkeypatch.delenv("SENTINEL_MODEL_OVERRIDE", raising=False)
    k_default = r.key(task)
    monkeypatch.setenv("SENTINEL_MODEL_OVERRIDE", "haiku")
    assert r.key(task) == k_default                 # 預設就是 Haiku
    monkeypatch.setenv("SENTINEL_MODEL_OVERRIDE", "sonnet")
    assert r.key(task) != k_default                 # 換模型不得共用快取


def test_usage_accumulates_per_agent_and_model(tmp_path, monkeypatch):
    r = LLMRunner(agent="a2", mode="record", scope="daily", target_sha="0" * 40, advisory_revision=None,
                  tracer=Tracer(tmp_path / "trace.jsonl", "a2"), cache=LLMCache(tmp_path / "c.json"),
                  replay=ReplayStore(tmp_path / "replay"))
    usages = iter([
        {"turns": 2, "tokens": {"input": 10, "output": 5, "cache_write": 100, "cache_read": 0},
         "models": {"claude-haiku-5-5": {"input": 10, "output": 5, "cache_write": 100, "cache_read": 0, "cost_usd": 0.001}}},
        {"turns": 3, "tokens": {"input": 20, "output": 7, "cache_write": 0, "cache_read": 100},
         "models": {"claude-haiku-5-5": {"input": 20, "output": 7, "cache_write": 0, "cache_read": 100, "cost_usd": 0.0005}}},
    ])

    async def fake_query(self, pending, graph_query):
        self._last_usage = next(usages)
        return {t.id: [{"id": t.payload["ids"][0], "explanation": "說明", "confidence": "high"}] for t, _ in pending}, 0.001

    monkeypatch.setattr(LLMRunner, "_query", fake_query)
    for i in (1, 2):
        r.run([Task(id=f"t{i}", subagent="secret-analyst", payload={"ids": [f"f{i}"], "items": [i]})])
    agg = r.cost["usage"]["a2"]
    assert agg["calls"] == 2 and agg["turns"] == 5
    assert agg["tokens"] == {"input": 30, "output": 12, "cache_write": 100, "cache_read": 100}
    assert agg["models"]["claude-haiku-5-5"]["cost_usd"] == pytest.approx(0.0015)
    assert r.cost["total_usd"] == pytest.approx(0.002)
    assert asyncio.iscoroutinefunction(LLMRunner._query)


def test_solutions_drop_extra_fields_so_report_validates():
    from llm import _validate
    from schemas import Solution
    out = _validate("solutions", [{"risk_id": "r1", "temporary": "t", "permanent": "p", "options": [], "verify": "v",
                                   "confidence": "low", "score": 99, "level": "low", "status": "done"}], {"r1"})
    assert set(out[0]) == {"risk_id", "temporary", "permanent", "options", "verify"}
    Solution.model_validate({**out[0], "source": "live", "suggested_owner": None})   # 與 A5 組裝方式相同，不得報錯
