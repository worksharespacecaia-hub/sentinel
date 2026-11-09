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
