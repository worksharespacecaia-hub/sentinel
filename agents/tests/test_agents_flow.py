"""orchestrator → a5 在 replay 模式下的完整流程（輸出寫到暫存目錄，不動正式資料）。"""
import json
import re
from dataclasses import replace

import pytest

from agents import a0_assets, a1_intel, a2_scan, a3_signals, a4_risk, a5_report, orchestrator
from context import build_ctx
from tools.common import AGENTS_DIR
from tools.trace import read_trace

ENV = {"SCENARIO": "daily", "TRIGGER_SOURCE": "manual", "EVENT_NAME": "workflow_dispatch", "AS_OF": "2026-11-09T01:00:00Z",
       "RUN_ID": "test-run"}


@pytest.fixture()
def ctx(monkeypatch, tmp_path):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    for k in ("EXECUTION_MODE", "GITHUB_OUTPUT", "TARGET_DIR", "ADVISORY_ID", "ASSETS", "TARGET_SHA"):
        monkeypatch.delenv(k, raising=False)
    import claude_agent_sdk
    monkeypatch.setattr(claude_agent_sdk, "query", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM")))
    c = build_ctx()
    return replace(c, out=tmp_path / "out", data_dir=tmp_path / "data", reports_dir=tmp_path / "reports")


def run_all(ctx, skip=()):
    for m in (orchestrator, a0_assets, a1_intel, a2_scan, a3_signals, a4_risk, a5_report):
        if m.__name__.split(".")[-1] not in skip:
            m.run(ctx)


def test_full_replay_flow(ctx, monkeypatch):
    run_all(ctx)
    out = ctx.data_dir / "daily"
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert rep["light"] == "red" and rep["execution_mode"] == "replay" and rep["cost"]["total_usd"] == 0
    assert len(list((out / "intel").glob("evt-*.json"))) == 6
    trace = read_trace(out / "trace.jsonl")
    agents = {e["agent"] for e in trace}
    assert {"orchestrator", "a0", "a1", "a2", "a3", "a4", "a5"} <= agents
    assert any(e["kind"] == "subagent" and e["source"] == "template" for e in trace)
    for p in out.rglob("*"):
        if p.is_file():
            assert "DEMO-FAKE" not in p.read_text(encoding="utf-8")
    idx = json.loads((ctx.data_dir / "index.json").read_text(encoding="utf-8"))
    assert idx["latest_daily"]["path"] == "daily"


def test_scenario_output_isolated(ctx):
    sc = replace(ctx, scenario="intel-demo", scope="scenario", output_dir="scenarios/intel-demo")
    run_all(sc)
    assert (ctx.data_dir / "scenarios" / "intel-demo" / "report.json").is_file()
    assert not (ctx.data_dir / "daily").exists()
    idx = json.loads((ctx.data_dir / "index.json").read_text(encoding="utf-8"))
    assert "latest_daily" not in idx and "intel-demo" in idx["scenarios"]


def test_a5_runs_when_upstream_missing(ctx):
    a5_report.run(ctx)                     # 沒有 orchestrator 計畫 → failures/<run_id>，不覆蓋 daily
    assert (ctx.data_dir / "failures" / ctx.run_id / "report.json").is_file()
    assert not (ctx.data_dir / "daily").exists()
    rep = json.loads((ctx.data_dir / "failures" / ctx.run_id / "report.json").read_text(encoding="utf-8"))
    assert any(i["source"].startswith("job/") for i in rep["data_issues"])


@pytest.mark.parametrize("mode,event,scenario,trigger,ref,expected", [
    ("live", "schedule", "daily", "schedule", "main", True),
    ("live", "workflow_dispatch", "daily", "manual", "main", True),
    ("live", "workflow_dispatch", "daily", "web", "main", False),
    ("live", "workflow_dispatch", "intel-demo", "manual", "main", False),
    ("replay", "schedule", "daily", "schedule", "main", True),        # 訂閱方案與 A1～A5 是否呼叫 API 無關
    ("replay", "workflow_dispatch", "daily", "manual", "main", True),
    ("replay", "local", "daily", "manual", None, False),              # 本機執行不跑
    ("replay", "workflow_dispatch", "peer-incident", "web", "main", False),
    ("live", "schedule", "daily", "schedule", "feature/x", False),
    ("live", "workflow_dispatch", "advisory", "intel-watch", "main", False),
])
def test_daily_intel_trigger_matrix(ctx, mode, event, scenario, trigger, ref, expected):
    c = replace(ctx, mode=mode, scenario=scenario, trigger_source=trigger)
    d = orchestrator.decide(c, event_name=event, ref_name=ref, default_branch="main")
    assert d["daily_intel"] is expected


def test_orchestrator_writes_github_output(ctx, tmp_path, monkeypatch):
    gh = tmp_path / "gh_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(gh))
    orchestrator.run(ctx)
    text = gh.read_text(encoding="utf-8")
    assert re.search(r"^plan=\{.*\"a5\":true.*\}$", text, flags=re.M)
    assert "daily_intel=true" in text and "output_dir=daily" in text     # 手動 daily 會排每日情資


def _report(ctx):
    return json.loads((ctx.data_dir / "daily" / "report.json").read_text(encoding="utf-8"))


def test_daily_intel_missing_output_is_reported_in_replay(ctx):
    run_all(ctx)                           # 手動 daily（replay）：有排 daily-intel，但沒有 intel-daily.json
    rep = _report(ctx)
    assert rep["daily_intel_status"] == "failed"
    assert {"source": "daily-intel", "status": "failed", "impact": "今日新聞情資未更新"} in rep["data_issues"]


def test_local_replay_marks_daily_intel_as_replay(ctx, monkeypatch):
    monkeypatch.setenv("EVENT_NAME", "local")
    run_all(ctx)
    rep = _report(ctx)
    assert rep["daily_intel_status"] == "replay"
    assert not any(i["source"] == "daily-intel" for i in rep["data_issues"])


def test_daily_intel_events_are_sanitized_and_verified_online(ctx, monkeypatch):
    """LLM 輸出不可信：不能冒充收錄事件、不能自稱已驗證；replay 模式也要實際抓來源確認引用。"""
    from tools import intel_verify
    from tools.safe_fetch import FetchResult
    quote = "攻擊者利用外掛漏洞取得後台權限"
    fetched = []

    def fake_fetch(url, allowlist, **kw):
        fetched.append(url)
        return FetchResult(url=url, status=200, text=f"<p>{quote}</p>", content_type="text/html")

    monkeypatch.setattr(intel_verify, "fetch", fake_fetch)
    ctx.out.mkdir(parents=True, exist_ok=True)
    good = {"id": "evt-php2shell-2026-10", "kind": "archive", "demo": True, "title": "某電商後台遭入侵", "date": "2026-11-09",
            "confidence": "confirmed", "revision": "1",
            "products": [{"name": "php", "ecosystem": "php", "known_exploited": True, "confirmed": True,
                          "affected": [{"introduced": "8.2.0", "fixed": "8.2.35"}]}],
            "sources": [{"url": "https://www.ithome.com.tw/news/1", "title": "iThome", "quote": quote,
                         "verified": True, "fetch_status": "ok", "verification_basis": "archived"}]}
    bad = {"id": "x", "title": "沒有來源", "date": "2026-11-09", "sources": []}
    (ctx.out / "intel-daily.json").write_text(json.dumps({"events": [good, bad], "impacts": []}, ensure_ascii=False),
                                              encoding="utf-8")
    run_all(ctx)
    verified = json.loads((ctx.out / "a1" / "verified.json").read_text(encoding="utf-8"))
    live = [v for v in verified if v["event"]["kind"] == "live"]
    assert len(live) == 1
    ev = live[0]["event"]
    assert ev["id"] == "live-evt-php2shell-2026-10" and ev["demo"] is False
    assert "known_exploited" not in ev["products"][0] and "confirmed" not in ev["products"][0]
    assert ev["sources"][0]["verification_basis"] == "live" and ev["sources"][0]["fetch_status"] == "ok"
    assert fetched == ["https://www.ithome.com.tw/news/1"]                  # 只有新事件需要抓頁面
    assert ev["confidence"] == "provisional"                                  # 只有一個媒體來源，不能自稱 confirmed
    archive = next(v["event"] for v in verified if v["event"]["id"] == "evt-php2shell-2026-10")
    assert archive["kind"] == "archive"                                       # 收錄事件沒有被覆蓋
    rep = _report(ctx)
    assert rep["daily_intel_status"] == "ok"
    assert any(i["source"] == "daily-intel" and i["status"] == "partial" for i in rep["data_issues"])


def test_no_pr_or_push_to_target_in_code():
    code = "\n".join(p.read_text(encoding="utf-8") for p in AGENTS_DIR.rglob("*.py") if "tests" not in p.parts)
    for pattern in ("pulls.create", "create_pull", "gh pr create", "git push", "createPullRequest"):
        assert pattern not in code, pattern


# ── 資安事件整理（specs/security-digest T4）：A5 在報告寫出前準備與提交 digest ─────────────

from datetime import datetime, timezone  # noqa: E402

from schemas import DigestLatest, DigestSeen, DigestStore  # noqa: E402
from tools import digest as dg  # noqa: E402

GENERATED = datetime(2026, 11, 9, 1, 20, tzinfo=timezone.utc)   # 凍結的實際產生時間（as_of 為 01:00Z）
DIGEST_FILES = ("store.json", "latest.json", "seen.json")


@pytest.fixture()
def frozen_clock(monkeypatch):
    monkeypatch.setattr(a5_report, "_clock", lambda: GENERATED)


def _digest_files(ctx):
    d = ctx.data_dir / "digest"
    return {n: (d / n).read_bytes() for n in DIGEST_FILES if (d / n).is_file()}


def _digest_trace(ctx):
    return [e for e in read_trace(ctx.data_dir / "daily" / "trace.jsonl") if "資安事件整理" in e["detail"]]


def test_daily_replay_writes_digest_beside_daily(ctx, frozen_clock):
    run_all(ctx)
    d = ctx.data_dir / "digest"
    store = DigestStore.model_validate_json((d / "store.json").read_text(encoding="utf-8"))
    latest = DigestLatest.model_validate_json((d / "latest.json").read_text(encoding="utf-8"))
    seen = DigestSeen.model_validate_json((d / "seen.json").read_text(encoding="utf-8"))
    assert not (ctx.data_dir / "daily" / "digest").exists()            # 不落入 daily/（每次發布會整個覆蓋）
    rep = _report(ctx)
    assert rep["completeness"] == "complete"
    real = [e for e in rep["events"] if e["kind"] in ("live", "archive", "advisory") and not e["demo"]]
    assert sorted(store.events) == sorted(e["id"] for e in real) and len(seen.first_seen_by_key) == len(real)
    # 首次建置：收錄事件都放在上線當天（台灣日期）
    assert [day.date for day in latest.days] == ["2026-11-09"] and latest.counts.total == len(real)
    assert latest.as_of == "2026-11-09T01:00:00Z" and latest.updated_at == "2026-11-09T01:20:00Z"
    assert latest.next_update_at == "2026-11-10T00:00:00Z" and latest.run_id == "test-run"
    assert latest.daily_intel_status == rep["daily_intel_status"]
    for ev in store.events.values():
        assert ev.assessment is not None and ev.assessment.run_id == "test-run"
        for imp in ev.assessment.impacts:
            assert imp.asset_label != imp.asset_id                       # 內部 ID 不作顯示名稱
    text = "".join(b.decode("utf-8") for b in _digest_files(ctx).values())
    assert "DEMO-FAKE" not in text and "quote" not in text
    # trace：整理結果在合併後的 daily trace，且沒有新增任何 LLM 來源節點
    entries = _digest_trace(ctx)
    assert entries and all(e["agent"] == "a5" and e["source"] is None and e["subagent"] is None for e in entries)
    assert any(e["kind"] == "result" and "latest 已重建" in e["detail"] for e in entries)


def test_web_daily_and_other_scopes_do_not_write_digest(ctx, frozen_clock):
    run_all(replace(ctx, trigger_source="web"))
    assert not (ctx.data_dir / "digest").exists()
    assert any(e["kind"] == "skip" for e in _digest_trace(ctx))
    sc = replace(ctx, scenario="intel-demo", scope="scenario", output_dir="scenarios/intel-demo")
    run_all(sc)
    assert not (ctx.data_dir / "digest").exists()


def test_advisory_run_does_not_write_digest(ctx, frozen_clock):
    adv = replace(ctx, scenario="advisory", scope="advisory", trigger_source="intel-watch",
                  output_dir="advisories/adv-opsbuilder-2026-001/test-run", advisory_id="adv-opsbuilder-2026-001",
                  assets=["internal-tool"])
    a5_report.run(adv)
    assert not (ctx.data_dir / "digest").exists()


def test_digest_prepare_failure_keeps_nothing_and_reports_safe_reason(ctx, frozen_clock, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("ghp_abcdefghijklmnopqrstuvwxyz 原始輸入")
    monkeypatch.setattr(dg, "merge_store", boom)
    run_all(ctx)
    assert not (ctx.data_dir / "digest").exists()                     # 首次產生失敗：三檔皆不存在
    rep = _report(ctx)
    issue = next(i for i in rep["data_issues"] if i["source"] == "digest")
    assert issue["required"] is False and issue["status"] == "failed" and "RuntimeError" in issue["impact"]
    assert "ghp_" not in json.dumps(rep, ensure_ascii=False)          # 只記安全錯誤碼
    err = [e for e in _digest_trace(ctx) if e["kind"] == "error"]
    assert err and "ghp_" not in err[0]["detail"]                      # 已發布（合併後）的 trace 可見原因


@pytest.mark.parametrize("failure", ["serialize", "second_commit"])
def test_digest_commit_failure_restores_previous_bundle(ctx, frozen_clock, monkeypatch, failure):
    run_all(ctx)                                                       # 第一次成功：建立前版
    before = _digest_files(ctx)
    assert set(before) == set(DIGEST_FILES)
    if failure == "serialize":
        real = dg.serialize

        def bad(value):
            if isinstance(value, dict) and "days" in value:
                raise ValueError("cannot serialize")
            return real(value)
        monkeypatch.setattr(dg, "serialize", bad)
    else:
        calls = {"n": 0}
        real_replace = dg._replace

        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("disk full")
            real_replace(src, dst)
        monkeypatch.setattr(dg, "_replace", flaky)
    later = datetime(2026, 11, 10, 1, 20, tzinfo=timezone.utc)
    monkeypatch.setattr(a5_report, "_clock", lambda: later)
    run_all(replace(ctx, as_of=datetime(2026, 11, 10, 1, 0, tzinfo=timezone.utc), run_id="test-run-2"))
    assert _digest_files(ctx) == before                                # 沒有半套新資料
    assert not list((ctx.data_dir / "digest").glob("*.tmp*")) and sorted(p.name for p in (ctx.data_dir / "digest").iterdir()) == \
        sorted(DIGEST_FILES)
    assert not any((ctx.out / "a5" / "digest-staging").iterdir())      # 暫存目錄已清除
    rep = _report(ctx)
    expected = "ValueError" if failure == "serialize" else "OSError"
    assert any(i["source"] == "digest" and expected in i["impact"] for i in rep["data_issues"])
    assert any(e["kind"] == "error" and expected in e["detail"] for e in _digest_trace(ctx))


def test_incomplete_daily_keeps_latest_times_and_content(ctx, frozen_clock, monkeypatch):
    run_all(ctx)
    before = json.loads((ctx.data_dir / "digest" / "latest.json").read_text(encoding="utf-8"))
    from tools import report_builder
    real = report_builder.assemble

    def partial(*a, **k):
        built = real(*a, **k)
        built["report"]["completeness"] = "partial"
        return built
    monkeypatch.setattr(a5_report, "assemble", partial)
    run_all(replace(ctx, as_of=datetime(2026, 11, 10, 1, 0, tzinfo=timezone.utc), run_id="test-run-2"))
    after = json.loads((ctx.data_dir / "digest" / "latest.json").read_text(encoding="utf-8"))
    assert after == before                                             # 不重建、不改最後更新時間
    store = json.loads((ctx.data_dir / "digest" / "store.json").read_text(encoding="utf-8"))
    ev = next(iter(store["events"].values()))
    assert ev["observed_run_id"] == "test-run-2" and ev["assessment"]["run_id"] == "test-run"
    assert any("沿用前版" in e["detail"] for e in _digest_trace(ctx))
