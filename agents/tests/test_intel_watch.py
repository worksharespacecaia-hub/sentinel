import types

from tools.common import AGENTS_DIR, iso
from tools.intel_watch import check_advisory, run

PHP_DIR = AGENTS_DIR / "scenarios" / "php2shell" / "advisories"


def _graph(baseline, as_of):
    return {**baseline["graph_json"], "generated_at": iso(as_of)}


def test_php_advisory_hits_marketing_and_phpmyadmin(baseline, as_of, tmp_path):
    graph_path = tmp_path / "graph.json"
    import json
    graph_path.write_text(json.dumps(_graph(baseline, as_of), ensure_ascii=False, default=str), encoding="utf-8")
    res = run([PHP_DIR], graph_path, tmp_path / "state.json", as_of=as_of)
    assert res["hits"] and set(res["hits"][0]["asset_ids"]) == {"marketing-site", "phpmyadmin"}   # "PHP" 經 aliases 正規化
    assert res["items"][0]["status"] == "pending"                 # A5 完成前不能標 done
    assert res["dispatched"] is False


def test_unrelated_advisory_not_hit(baseline, as_of):
    adv = {"id": "adv-erp", "revision": "1", "products": [{"name": "demo-erp-suite", "ecosystem": "generic",
                                                            "affected": [{"introduced": "0", "fixed": "9.0"}]}]}
    res = check_advisory(adv, _graph(baseline, as_of), graph_fresh=True)
    assert res["verdict"] == "not_affected" and res["asset_ids"] == []


def test_missing_or_stale_graph_is_need_check():
    adv = {"id": "adv-x", "revision": "1", "products": []}
    assert check_advisory(adv, None, graph_fresh=False)["verdict"] == "need_check"


def test_dispatch_uses_argument_list_and_records_failure(baseline, as_of, tmp_path):
    import json
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(json.dumps(_graph(baseline, as_of), ensure_ascii=False, default=str), encoding="utf-8")
    calls = []

    def failing_runner(args, **_kw):
        calls.append(args)
        return types.SimpleNamespace(returncode=1, stderr="queue full")

    res = run([PHP_DIR], graph_path, tmp_path / "state.json", as_of=as_of, dispatch=True, runner=failing_runner)
    assert isinstance(calls[0], list) and calls[0][:3] == ["gh", "workflow", "run"]
    assert "scenario=advisory" in calls[0] and "trigger_source=intel-watch" in calls[0]
    assert res["items"][0]["status"] == "failed"                  # 下次輪詢可恢復

    ok_runner = lambda args, **_kw: types.SimpleNamespace(returncode=0, stderr="")   # noqa: E731
    res2 = run([PHP_DIR], graph_path, tmp_path / "state.json", as_of=as_of, dispatch=True, runner=ok_runner)
    assert res2["items"][0]["status"] == "pending" and res2["dispatched"] is True
    res3 = run([PHP_DIR], graph_path, tmp_path / "state.json", as_of=as_of, dispatch=True, runner=failing_runner)
    assert res3["dispatched"] is False and res3["items"][0]["status"] == "pending"   # 相同輸入不重複派工
