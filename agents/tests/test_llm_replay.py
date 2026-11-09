"""replay 模式不呼叫任何 LLM 網路服務；快取鍵完整；輸出驗證。"""
import os

import pytest

import llm
from llm import LLMRunner, Task, _validate, scrubbed_environ
from tools.cache import LLMCache, ReplayStore, cache_key
from tools.trace import Tracer, read_trace


@pytest.fixture()
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("replay 模式不得呼叫 SDK")
    import claude_agent_sdk
    monkeypatch.setattr(claude_agent_sdk, "query", boom)
    monkeypatch.setattr(LLMRunner, "_call_live", boom)


def _runner(tmp_path, mode="replay"):
    return LLMRunner(agent="a2", mode=mode, scope="daily", target_sha="a" * 40, advisory_revision=None,
                     tracer=Tracer(tmp_path / "trace.jsonl", "a2"), cache=LLMCache(tmp_path / "llm.json"),
                     replay=ReplayStore(tmp_path / "replay"))


def test_replay_without_fixture_uses_template(tmp_path, no_network):
    r = _runner(tmp_path)
    res = r.run([Task(id="t1", subagent="secret-analyst", payload={"ids": ["f1"], "items": []})])
    assert res["t1"]["source"] == "template"
    assert any("未錄製" in e["detail"] for e in read_trace(tmp_path / "trace.jsonl"))


def test_replay_with_fixture(tmp_path, no_network):
    r = _runner(tmp_path)
    t = Task(id="t1", subagent="secret-analyst", payload={"ids": ["f1"], "items": []})
    r.replay.put("a2", "secret-analyst", r.key(t), [{"id": "f1", "explanation": "正式環境金鑰", "confidence": "high"}], {})
    res = r.run([t])
    assert res["t1"]["source"] == "replay" and res["t1"]["output"][0]["id"] == "f1"


def test_cache_key_changes_with_any_input():
    base = dict(scope="daily", agent="a5", subagent="remediation-advisor", payload={"x": 1}, target_sha="a" * 40,
                advisory_revision=None, prompt="p", skills=["sentinel-guardrails"], model="m", sdk_version="1", cli_version="1")
    k = cache_key(**base)
    for change in ({"payload": {"x": 2}}, {"scope": "scenario"}, {"prompt": "p2"}, {"skills": ["secret-triage"]},
                   {"model": "m2"}, {"advisory_revision": "r2"}, {"target_sha": "b" * 40}, {"sdk_version": "2"}):
        assert cache_key(**{**base, **change}) != k, change


def test_validation_rejects_out_of_scope_and_secret():
    with pytest.raises(ValueError):
        _validate("explanations", [{"id": "other", "explanation": "x"}], {"f1"})
    with pytest.raises(ValueError):
        _validate("explanations", [{"id": "f1", "explanation": "DEMO-FAKE-PASSWORD-0000"}], {"f1"})
    sol = _validate("solutions", [{"risk_id": "r1", "temporary": "a", "permanent": "b", "options": [], "verify": "c",
                                   "score": 0, "level": "low"}], {"r1"})
    assert "score" not in sol[0] and "level" not in sol[0]     # LLM 不能改程式判定


def test_scrubbed_environ_hides_write_tokens(monkeypatch):
    monkeypatch.setenv("NOTIFY_TOKEN", "x")
    monkeypatch.setenv("GH_TOKEN", "y")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "z")
    with scrubbed_environ():
        assert "NOTIFY_TOKEN" not in os.environ and "GH_TOKEN" not in os.environ
        assert os.environ.get("ANTHROPIC_API_KEY") == "z"
    assert os.environ["NOTIFY_TOKEN"] == "x"


def test_extract_json():
    assert llm._extract_json('結果：```json\n{"a": 1}\n```') == {"a": 1}
    assert llm._extract_json(None) is None
