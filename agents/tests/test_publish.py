"""發布合併：較舊的 run 不覆蓋新狀態、done 不被覆蓋、不允許的路徑拒絕。"""
import json

import pytest

from tools.publish_merge import DATA, apply, merge_index, merge_watch


def _w(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_merge_index_keeps_newer_entries():
    cur = {"latest_daily": {"run_id": "2", "generated_at": "2026-11-09T02:00:00Z"},
           "scenarios": {"a": {"run_id": "s2", "generated_at": "2026-11-09T02:00:00Z"}}}
    cand = {"latest_daily": {"run_id": "1", "generated_at": "2026-11-09T01:00:00Z"},
            "scenarios": {"a": {"run_id": "s1", "generated_at": "2026-11-09T01:00:00Z"},
                          "b": {"run_id": "s3", "generated_at": "2026-11-09T03:00:00Z"}},
            "advisories": {"adv-x": {"run_id": "9", "generated_at": "2026-11-09T03:00:00Z"}}}
    out = merge_index(cand, cur)
    assert out["latest_daily"]["run_id"] == "2" and out["scenarios"]["a"]["run_id"] == "s2"
    assert out["scenarios"]["b"]["run_id"] == "s3" and out["advisories"]["adv-x"]["run_id"] == "9"


def test_merge_watch_done_not_overwritten():
    cur = {"checked_at": "2026-11-09T02:00:00Z", "items": [{"advisory_id": "a", "input_hash": "h", "status": "done"}]}
    cand = {"checked_at": "2026-11-09T01:00:00Z", "items": [{"advisory_id": "a", "input_hash": "h", "status": "pending"},
                                                           {"advisory_id": "b", "input_hash": "h2", "status": "pending"}]}
    out = merge_watch(cand, cur)
    st = {i["advisory_id"]: i["status"] for i in out["items"]}
    assert st == {"a": "done", "b": "pending"}


def test_apply_skips_older_output(tmp_path):
    cand, repo = tmp_path / "cand", tmp_path / "repo"
    _w(cand / DATA / "daily" / "report.json", {"generated_at": "2026-11-09T01:00:00Z", "v": "old"})
    _w(repo / DATA / "daily" / "report.json", {"generated_at": "2026-11-09T02:00:00Z", "v": "new"})
    rep = apply(cand, repo, "daily")
    assert rep["skipped"] and json.loads((repo / DATA / "daily" / "report.json").read_text())["v"] == "new"


@pytest.mark.parametrize("bad", ["../x", "agents", "dashboard"])
def test_apply_rejects_disallowed_dirs(tmp_path, bad):
    with pytest.raises(ValueError):
        apply(tmp_path, tmp_path, bad)


# ── 資安事件整理（specs/security-digest T5）：digest/ 的合併與到期清理 ────────────────

import re  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

from schemas import DigestLatest, DigestSeen, DigestStore  # noqa: E402
from tests.test_digest import _impact, make_report  # noqa: E402
from tools import digest as dg  # noqa: E402
from tools.common import SENTINEL_ROOT  # noqa: E402

DIG = DATA / "digest"
T0 = datetime(2026, 11, 1, 0, 0, tzinfo=timezone.utc)      # 台灣 2026-11-01 08:00


def at(days, hours=0):
    return T0 + timedelta(days=days, hours=hours)


def produce(prev_dir, reps, as_of, run_id, *, complete=True, generated=None):
    """以 A5 相同的程式產生一份 digest bundle（不寫檔），回傳 {檔名: dict}。"""
    files = dg.prepare_bundle(prev_dir, {"run_id": run_id, "completeness": "complete" if complete else "partial",
                                         "daily_intel_status": "ok"}, reps, as_of=as_of,
                              generated_at=generated or as_of + timedelta(minutes=20), run_id=run_id, asset_labels={})
    return {n: json.loads(b) for n, b in files.items()}


def put(root, files):
    for name, value in files.items():
        _w(root / DIG / name, value)


def read(root, name):
    return json.loads((root / DIG / name).read_text(encoding="utf-8"))


def ids(latest):
    return sorted(ev["id"] for ev in dg.flatten_latest(latest))


def test_push_with_retry_covers_digest_paths():
    text = (SENTINEL_ROOT / "scripts" / "push-with-retry.sh").read_text(encoding="utf-8")
    m = re.search(r"^\s*daily\|[^)]*\)\s*ALLOWED=\(([^)]*)\)", text, flags=re.M)
    allowed = m.group(1).split()
    for name in ("store.json", "latest.json", "seen.json"):
        path = f"dashboard/public/data/digest/{name}"
        assert any(path == a or path.startswith(a.rstrip("/") + "/") for a in allowed), path
    assert 'cp -R "$p" "$CANDIDATE/$p"' in text                       # 候選複製整個允許路徑（含 digest/）
    loop = text[text.index("for attempt in 1 2 3"):]
    assert 'git add -- "${ALLOWED[@]}"' in loop and "publish_merge.py" in loop   # 每次重試都重新合併並 stage
    assert '--now "$PUBLISH_NOW"' in loop and text.index("PUBLISH_NOW=") < text.index("for attempt in 1 2 3")


def test_retry_does_not_lose_events_when_remote_store_is_newer(tmp_path):
    """候選帶 A、B；main 已有另一個 run 產生的 A（較新）與 C：合併後三件都在，A 用較新的評估。"""
    first = produce(tmp_path / "base", [make_report("live-a-2026"), make_report("live-b-2026")], at(1), "run-1")
    cand, repo = tmp_path / "cand", tmp_path / "repo"
    put(cand, first)
    other = produce(tmp_path / "nothing", [make_report("live-a-2026", status="not_affected",
                                                       impacts=[_impact("live-a-2026", "s", "not_affected")]),
                                           make_report("live-c-2026")], at(1, 3), "run-2")
    put(repo, other)
    apply(cand, repo, "daily", now=at(1, 4))
    store = DigestStore.model_validate(read(repo, "store.json"))
    assert sorted(store.events) == ["live-a-2026", "live-b-2026", "live-c-2026"]
    assert store.events["live-a-2026"].assessment.run_id == "run-2"
    seen = DigestSeen.model_validate(read(repo, "seen.json"))
    assert len(seen.first_seen_by_key) == 3
    latest = DigestLatest.model_validate(read(repo, "latest.json"))
    assert latest.run_id == "run-2" and ids(read(repo, "latest.json")) == ["live-a-2026", "live-c-2026"]   # 不塞入未發布事件


def test_seen_union_takes_earliest_date_and_fixes_latest_grouping(tmp_path):
    cand, repo = tmp_path / "cand", tmp_path / "repo"
    late = produce(tmp_path / "x", [make_report("live-d-2026")], at(3), "run-3")
    put(cand, late)
    _w(repo / DIG / "seen.json", {"schema_version": 1, "first_seen_by_key": {dg.seen_key("live-d-2026"): "2026-11-02",
                                                                            dg.seen_key("live-z-2026"): "2026-10-01"}})
    apply(cand, repo, "daily", now=at(3, 1))
    seen = read(repo, "seen.json")["first_seen_by_key"]
    assert seen[dg.seen_key("live-d-2026")] == "2026-11-02" and seen[dg.seen_key("live-z-2026")] == "2026-10-01"
    assert read(repo, "store.json")["events"]["live-d-2026"]["first_seen"] == "2026-11-02"
    latest = read(repo, "latest.json")
    assert [d["date"] for d in latest["days"]] == ["2026-11-02"]       # 去重日期較早：重新分組
    assert latest["days"][0]["events"][0]["assessment"]["evaluated_at"] == "2026-11-04T00:00:00Z"   # 不假裝有新評估
    assert latest["updated_at"] == late["latest.json"]["updated_at"]


def test_same_day_two_conclusions_and_reverse_order_are_deterministic(tmp_path):
    eid = "live-e-2026"
    morning = produce(tmp_path / "x", [make_report(eid, status="need_check")], at(1), "run-am")
    noon = produce(tmp_path / "y", [make_report(eid, status="open", impacts=[_impact(eid, "s", "affected", "r")],
                                                max_level="high", levels={("s", "affected"): "high"})], at(1, 4), "run-pm")
    results = []
    for first, second in ((morning, noon), (noon, morning)):            # 反向發布：結果相同
        root = tmp_path / f"r{len(results)}"
        put(root / "repo", first)
        put(root / "cand", second)
        apply(root / "cand", root / "repo", "daily", now=at(1, 5))
        results.append({n: read(root / "repo", n) for n in dg.FILES})
    assert results[0] == results[1]
    assert results[0]["store.json"]["events"][eid]["assessment"]["run_id"] == "run-pm"
    assert results[0]["latest.json"]["run_id"] == "run-pm"


def test_older_candidate_finishing_later_does_not_roll_back_latest(tmp_path):
    """舊評估（as_of 較早）較晚才完成：latest 先比 as_of，不因 updated_at 較晚而倒退。"""
    cand, repo = tmp_path / "cand", tmp_path / "repo"
    put(repo, produce(tmp_path / "x", [make_report("live-f-2026", status="need_check")], at(2), "run-new",
                      generated=at(2, 1)))
    put(cand, produce(tmp_path / "y", [make_report("live-f-2026", status="not_affected",
                                                   impacts=[_impact("live-f-2026", "s", "not_affected")])], at(1), "run-old",
                      generated=at(2, 6)))
    apply(cand, repo, "daily", now=at(2, 7))
    latest = read(repo, "latest.json")
    assert latest["run_id"] == "run-new" and latest["updated_at"] == "2026-11-03T01:00:00Z"
    assert read(repo, "store.json")["events"]["live-f-2026"]["assessment"]["run_id"] == "run-new"


def test_later_incomplete_observation_does_not_override_complete_assessment(tmp_path):
    eid = "live-g-2026"
    cand, repo = tmp_path / "cand", tmp_path / "repo"
    complete = produce(tmp_path / "x", [make_report(eid, status="need_check")], at(1), "run-full")
    put(repo, complete)
    prev = tmp_path / "prev"
    put(prev, complete)                                               # 不完整 run 的 checkout 已有前版
    partial = produce(prev / DIG, [make_report(eid, status="not_affected", impacts=[_impact(eid, "s", "not_affected")]),
                                   make_report("live-new-2026")], at(1, 6), "run-partial", complete=False)
    put(cand, partial)
    apply(cand, repo, "daily", now=at(1, 7))
    ev = read(repo, "store.json")["events"][eid]
    assert ev["assessment"]["run_id"] == "run-full" and ev["observed_run_id"] == "run-partial"
    assert read(repo, "store.json")["events"]["live-new-2026"]["assessment"] is None
    assert ids(read(repo, "latest.json")) == [eid]                     # 待評估事件不發布
    assert read(repo, "latest.json")["updated_at"] == complete["latest.json"]["updated_at"]


def test_same_run_conflict_keeps_remote_and_is_reported(tmp_path):
    eid = "live-h-2026"
    cand, repo = tmp_path / "cand", tmp_path / "repo"
    a = produce(tmp_path / "x", [make_report(eid, summary="遠端摘要")], at(1), "run-same")
    b = produce(tmp_path / "y", [make_report(eid, summary="候選摘要")], at(1), "run-same")
    put(repo, a)
    put(cand, b)
    rep = apply(cand, repo, "daily", now=at(1, 1))
    assert read(repo, "store.json")["events"][eid]["summary"] == "遠端摘要"
    assert read(repo, "latest.json") == a["latest.json"]
    assert any("live-h-2026" in c for c in rep["conflicts"]) and any("latest" in c for c in rep["conflicts"])
    assert any(i["code"] == "merge_conflict" for i in read(repo, "store.json")["data_issues"])


@pytest.mark.parametrize("broken", ["missing_as_of", "bad_time", "bad_schema"])
def test_invalid_candidate_never_overwrites_valid_remote(tmp_path, broken):
    cand, repo = tmp_path / "cand", tmp_path / "repo"
    good = produce(tmp_path / "x", [make_report("live-i-2026")], at(1), "run-1")
    put(repo, good)
    newer = produce(tmp_path / "y", [make_report("live-j-2026")], at(2), "run-2")
    latest, store = newer["latest.json"], newer["store.json"]
    if broken == "missing_as_of":
        latest.pop("as_of")
        store["events"]["live-j-2026"].pop("last_seen_at")
    elif broken == "bad_time":
        latest["as_of"] = "2026-13-45"
        store["updated_at"] = "not-a-time"
    else:
        latest["days"] = "oops"
        store["events"]["live-j-2026"]["assessment"]["relation"] = "maybe"
    put(cand, {"latest.json": latest, "store.json": store})
    rep = apply(cand, repo, "daily", now=at(2, 1))
    assert read(repo, "latest.json") == good["latest.json"]
    assert "live-j-2026" not in read(repo, "store.json")["events"]
    assert len(rep["digest_issues"]) == 2


def test_cleanup_runs_without_new_digest_and_removes_expired_parent_and_child(tmp_path):
    """沒有候選 digest（例如網站觸發的 daily）也要清理 main；時間不刷新，main 的實際 JSON 不含過期事件。"""
    parent = make_report("evt-par-2026", kind="archive", status="not_affected", title="原事件標題",
                         impacts=[_impact("evt-par-2026", "s", "not_affected")])
    child = make_report("live-kid-2026", is_update_of="evt-par-2026", title="子事件舊標題")
    young = make_report("live-young-2026", is_update_of="evt-par-2026", title="未過期的新進度")
    prev = tmp_path / "prev"
    put(prev, produce(tmp_path / "x", [parent, child], at(0), "run-0"))
    files = produce(prev / DIG, [young], at(5), "run-5")
    cand, repo = tmp_path / "cand", tmp_path / "repo"
    put(repo, files)
    (cand / DATA).mkdir(parents=True)
    before = read(repo, "latest.json")
    assert ids(before) == ["evt-par-2026", "live-kid-2026", "live-young-2026"]
    apply(cand, repo, "daily", now=at(30, 1))                          # 台灣 12/01：11/01 的父子事件到期
    latest, store = read(repo, "latest.json"), read(repo, "store.json")
    DigestLatest.model_validate(latest)
    assert ids(latest) == ["live-young-2026"] and sorted(store["events"]) == ["live-young-2026"]
    text = (repo / DIG / "latest.json").read_text(encoding="utf-8") + (repo / DIG / "store.json").read_text(encoding="utf-8")
    assert "原事件標題" not in text and "子事件舊標題" not in text and "live-kid-2026" not in text
    head = latest["days"][0]["events"][0]
    assert head["standalone_reason"] == "parent_missing"               # 原事件過期：子事件提升為獨立卡片
    for k in ("updated_at", "as_of", "run_id", "next_update_at"):
        assert latest[k] == before[k]                                  # 清理不刷新時間
    assert store["updated_at"] == files["store.json"]["updated_at"]
    assert head["assessment"]["evaluated_at"] == "2026-11-06T00:00:00Z"
    assert dg.seen_key("evt-par-2026") in read(repo, "seen.json")["first_seen_by_key"]   # seen 保留


def test_cleanup_when_daily_candidate_skipped(tmp_path):
    cand, repo = tmp_path / "cand", tmp_path / "repo"
    _w(cand / DATA / "daily" / "report.json", {"generated_at": "2026-11-01T01:00:00Z"})
    _w(repo / DATA / "daily" / "report.json", {"generated_at": "2026-12-05T01:00:00Z"})
    put(repo, produce(tmp_path / "x", [make_report("live-old-2026")], at(0), "run-0"))
    put(cand, produce(tmp_path / "y", [make_report("live-old-2026")], at(0), "run-0"))
    rep = apply(cand, repo, "daily", now=at(31))
    assert rep["skipped"]                                              # daily 候選被略過
    assert ids(read(repo, "latest.json")) == [] and read(repo, "store.json")["events"] == {}


def test_retry_with_fixed_now_is_idempotent(tmp_path):
    cand, repo = tmp_path / "cand", tmp_path / "repo"
    put(cand, produce(tmp_path / "x", [make_report("live-k-2026")], at(1), "run-1"))
    apply(cand, repo, "daily", now=at(1, 1))
    first = {n: (repo / DIG / n).read_bytes() for n in dg.FILES}
    apply(cand, repo, "daily", now=at(1, 1))                          # 重試：同一個 now、遠端已是上次結果
    assert {n: (repo / DIG / n).read_bytes() for n in dg.FILES} == first
    assert not list(repo.glob(".digest-staging-*"))


@pytest.mark.parametrize("output_dir", ["scenarios/intel-demo", "advisories/adv-x/1", "failures/1", "intel-watch"])
def test_non_daily_publish_does_not_touch_digest(tmp_path, output_dir):
    cand, repo = tmp_path / "cand", tmp_path / "repo"
    put(repo, produce(tmp_path / "x", [make_report("live-l-2026")], at(0), "run-0"))
    put(cand, produce(tmp_path / "y", [make_report("live-m-2026")], at(1), "run-1"))
    before = {n: (repo / DIG / n).read_bytes() for n in dg.FILES}
    apply(cand, repo, output_dir, now=at(40))
    assert {n: (repo / DIG / n).read_bytes() for n in dg.FILES} == before


def test_main_accepts_fixed_now(tmp_path):
    from tools.publish_merge import main
    cand, repo = tmp_path / "cand", tmp_path / "repo"
    put(repo, produce(tmp_path / "x", [make_report("live-n-2026")], at(0), "run-0"))
    (cand / DATA).mkdir(parents=True)
    assert main(["--candidate", str(cand), "--repo", str(repo), "--output-dir", "daily", "--now", "2026-12-15T00:00:00Z"]) == 0
    assert read(repo, "store.json")["events"] == {}
