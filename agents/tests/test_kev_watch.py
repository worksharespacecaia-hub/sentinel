"""intel-watch 的自動公告（CISA KEV 新列入 → NVD → 公告）與事件新進度（is_update_of）的連動。"""
import json
import types
from datetime import timedelta

from tests.conftest import AS_OF
from tests.test_vulndb import PHP, WIN, FakeFetch, nvd_cve
from tools.common import iso
from tools.intel_verify import verify_event
from tools.intel_watch import dispatch_queued, load_auto_advisories, refresh_auto_advisories, run
from tools.loaders import FIXTURE_SCANNERS, FIXTURE_TARGET
from tools.pipeline import EvalInput, evaluate
from tools.publish_merge import merge_watch
from tools.report_builder import assemble

KEV_RAW = {"catalogVersion": "2026.11.09", "dateReleased": "2026-11-09T00:00:00Z", "vulnerabilities": [
    {"cveID": "CVE-2026-90001", "vendorProject": "PHP", "product": "PHP", "vulnerabilityName": "PHP RCE",
     "dateAdded": "2026-11-08"},
    {"cveID": "CVE-2026-90002", "vendorProject": "Zyxel", "product": "USG", "vulnerabilityName": "Zyxel RCE",
     "dateAdded": "2026-11-07"},
    {"cveID": "CVE-2020-12345", "vendorProject": "PHP", "product": "PHP", "dateAdded": "2020-01-01"},   # 窗口外
]}
PHP_RCE = nvd_cve("CVE-2026-90001", (PHP, {"versionStartIncluding": "8.1.0", "versionEndExcluding": "8.1.40"}))
ZYXEL = nvd_cve("CVE-2026-90002", ("cpe:2.3:o:zyxel:usg_firmware:*:*:*:*:*:*:*:*", {}))


def _fetch(php=PHP_RCE):
    return FakeFetch({"cveId=CVE-2026-90001": {"vulnerabilities": [{"cve": php}]},
                      "cveId=CVE-2026-90002": {"vulnerabilities": [{"cve": ZYXEL}]}})


def _graph(baseline, tmp_path):
    p = tmp_path / "graph.json"
    p.write_text(json.dumps({**baseline["graph_json"], "generated_at": iso(AS_OF)}, ensure_ascii=False, default=str),
                 encoding="utf-8")
    return p


def test_kev_refresh_creates_advisory_only_for_our_products():
    state, fake = {}, _fetch()
    st = refresh_auto_advisories(state, as_of=AS_OF, fetcher=fake, kev_raw=KEV_RAW)
    assert st["status"] == "ok" and st["new"] == ["kev-cve-2026-90001"]
    assert [a["id"] for a in state["auto_advisories"]] == ["kev-cve-2026-90001"]
    assert state["kev_checked"]["CVE-2026-90002"]["mapped"] is False                 # 不涉及我們的產品：記錄但不產生公告
    assert "CVE-2020-12345" not in state["kev_checked"] and len(fake.calls) == 2      # 窗口外不查
    assert fake.calls[0][1] == ["services.nvd.nist.gov"]


def test_kev_advisory_queued_then_dispatched_after_publish(baseline, tmp_path):
    state_path, graph = tmp_path / "state.json", _graph(baseline, tmp_path)
    refresh = lambda s: refresh_auto_advisories(s, as_of=AS_OF, fetcher=_fetch(), kev_raw=KEV_RAW)   # noqa: E731
    res = run([], graph, state_path, as_of=AS_OF, defer_dispatch=True, refresh=refresh)
    hit = next(h for h in res["hits"] if h["advisory_id"] == "kev-cve-2026-90001")
    assert hit["asset_ids"] == ["marketing-site"]                                     # php 8.3.20／8.4.27 不在範圍
    item = next(i for i in res["items"] if i["advisory_id"] == "kev-cve-2026-90001")
    assert item["status"] == "queued" and res["dispatched"] is False                 # 先發布，再派工
    assert load_auto_advisories(state_path)[0]["id"] == "kev-cve-2026-90001"         # 已寫進要發布的狀態

    calls = []
    ok = lambda args, **_kw: calls.append(args) or types.SimpleNamespace(returncode=0, stderr="")   # noqa: E731
    out = dispatch_queued(state_path, [], runner=ok)
    assert out["dispatched"] == ["kev-cve-2026-90001"] and "advisory_id=kev-cve-2026-90001" in calls[0]
    assert "assets=marketing-site" in calls[0]
    res2 = run([], graph, state_path, as_of=AS_OF + timedelta(hours=1), defer_dispatch=True)
    assert next(i for i in res2["items"] if i["advisory_id"] == "kev-cve-2026-90001")["status"] == "pending"   # 不重複派工


def test_kev_refresh_rechecks_daily_and_new_revision_requeues(baseline, tmp_path):
    state_path, graph = tmp_path / "state.json", _graph(baseline, tmp_path)
    run([], graph, state_path, as_of=AS_OF, defer_dispatch=True,
        refresh=lambda s: refresh_auto_advisories(s, as_of=AS_OF, fetcher=_fetch(), kev_raw=KEV_RAW))
    dispatch_queued(state_path, [], runner=lambda a, **k: types.SimpleNamespace(returncode=0, stderr=""))
    quiet = _fetch()
    run([], graph, state_path, as_of=AS_OF + timedelta(hours=2), defer_dispatch=True,
        refresh=lambda s: refresh_auto_advisories(s, as_of=AS_OF + timedelta(hours=2), fetcher=quiet, kev_raw=KEV_RAW))
    assert quiet.calls == []                                                          # 24 小時內不重查
    later = AS_OF + timedelta(hours=25)
    changed = nvd_cve("CVE-2026-90001", (PHP, {"versionStartIncluding": "8.1.0", "versionEndExcluding": "8.1.41"}),
                      last="2026-11-10T03:00:00.000")
    res = run([], graph, state_path, as_of=later, defer_dispatch=True,
              refresh=lambda s: refresh_auto_advisories(s, as_of=later, fetcher=_fetch(changed), kev_raw=KEV_RAW))
    assert res["auto_status"]["updated"] == ["kev-cve-2026-90001"]
    item = next(i for i in res["items"] if i["advisory_id"] == "kev-cve-2026-90001")
    assert item["status"] == "queued" and item["revision"] == "2026-11-10T03:00:00.000"   # NVD 更新 → 重新評估


def test_kev_refresh_failure_keeps_existing_advisories():
    state = {}
    refresh_auto_advisories(state, as_of=AS_OF, fetcher=_fetch(), kev_raw=KEV_RAW)
    before = list(state["auto_advisories"])
    st = refresh_auto_advisories(state, as_of=AS_OF, fetcher=FakeFetch({"cisa.gov": ConnectionError("down")}))
    assert st["status"] == "failed" and "CISA KEV" in st["reason"] and state["auto_advisories"] == before


def test_platform_conditional_kev_advisory_needs_manual_check(baseline):
    win = nvd_cve("CVE-2026-90001", (PHP, {"versionStartIncluding": "8.1.0", "versionEndExcluding": "8.1.40"}), platforms=[WIN])
    state = {}
    refresh_auto_advisories(state, as_of=AS_OF, fetcher=_fetch(win), kev_raw=KEV_RAW)
    res = evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS,
                             auto_advisories=load_auto_advisories(state)))
    m = next(m for m in res["matches"] if m["event"]["id"] == "kev-cve-2026-90001")
    assert m["status"] == "need_check"                                                # 只影響 Windows：不直接算受影響
    assert any("平台條件" in t for i in m["impacts"] for t in i.get("to_verify", []))


def test_auto_advisories_untrusted_shapes_rejected():
    state = {"auto_advisories": [
        {"id": "kev-cve-2026-90001", "kind": "advisory", "generated_by": "kev-nvd"},
        {"id": "adv-fake", "kind": "advisory", "generated_by": "kev-nvd"},           # ID 不是程式產生的格式
        {"id": "kev-cve-2026-90003", "kind": "advisory"},                             # 沒有 generated_by
        {"id": "kev-cve-2026-90004", "kind": "live", "generated_by": "kev-nvd"}]}
    assert [a["id"] for a in load_auto_advisories(state)] == ["kev-cve-2026-90001"]


def test_auto_advisory_verified_as_official_api_and_evaluated_in_daily():
    state = {}
    refresh_auto_advisories(state, as_of=AS_OF, fetcher=_fetch(), kev_raw=KEV_RAW)
    adv = load_auto_advisories(state)[0]
    v = verify_event(dict(adv), as_of=AS_OF)
    assert v["event"]["confidence"] == "confirmed"
    assert {s["verification_basis"] for s in v["event"]["sources"]} == {"official_api"}
    forged = verify_event({**adv, "id": "adv-forged"}, as_of=AS_OF)                   # 其他 ID 不能借用這條路徑
    assert {s["verification_basis"] for s in forged["event"]["sources"]} == {"unverified"}
    res = evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS, auto_advisories=[adv]))
    m = next(m for m in res["matches"] if m["event"]["id"] == "kev-cve-2026-90001")
    assert m["status"] == "open" and {i["asset_id"] for i in m["impacts"] if i["verdict"] == "affected"} == {"marketing-site"}
    f = next(f for f in res["findings"] if f["id"] == "marketing-site:php:vuln")
    assert f["known_exploited"] is True and "kev-cve-2026-90001" in f["advisory_ids"]


def test_merge_watch_unions_auto_advisories_and_prunes_expired():
    old = {"id": "kev-cve-2026-80001", "date": "2026-09-01", "generated_at": "2026-09-01T00:00:00Z"}
    keep = {"id": "kev-cve-2026-80002", "date": "2026-11-01", "generated_at": "2026-11-01T00:00:00Z"}
    newer = {"id": "kev-cve-2026-80002", "date": "2026-11-01", "generated_at": "2026-11-09T00:00:00Z", "revision": "2"}
    fresh = {"id": "kev-cve-2026-80003", "date": "2026-11-08", "generated_at": "2026-11-09T00:00:00Z"}
    cur = {"checked_at": "2026-11-09T01:00:00Z", "items": [], "auto_advisories": [old, keep],
           "kev_checked": {"CVE-2026-80001": {"checked_at": "2026-09-01T00:00:00Z"}}}
    cand = {"checked_at": "2026-11-09T00:30:00Z", "items": [], "auto_advisories": [newer, fresh],
            "kev_checked": {"CVE-2026-80003": {"checked_at": "2026-11-09T00:00:00Z"}}}
    out = merge_watch(cand, cur)                       # 例如 A5 帶著較早 checkout 的副本發布
    assert [a["id"] for a in out["auto_advisories"]] == ["kev-cve-2026-80002", "kev-cve-2026-80003"]
    assert out["auto_advisories"][0]["revision"] == "2"                               # 同一公告取較新者
    assert set(out["kev_checked"]) == {"CVE-2026-80003"}                              # 過期的不會被舊副本加回來


# ---------------------------------------------------------------- 事件新進度

FOLLOWUP = {"id": "live-php2shell-followup", "kind": "live", "title": "PHP2Shell 新進度：更多分支受影響",
            "date": "2026-11-09", "revision": "1", "confidence": "provisional", "is_update_of": "evt-php2shell-2026-10",
            "sources": [{"url": None, "title": "示範來源", "quote": None, "published": "2026-11-09"}],
            "products": [], "cves": [], "controls": []}


def test_update_inherits_original_criteria_and_reports_link():
    res = evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS,
                             live_events=[dict(FOLLOWUP)]))
    assert res["event_updates"] == {"evt-php2shell-2026-10": ["live-php2shell-followup"]}
    up = next(m for m in res["matches"] if m["event"]["id"] == FOLLOWUP["id"])
    orig = next(m for m in res["matches"] if m["event"]["id"] == "evt-php2shell-2026-10")
    assert up["status"] != "not_affected"                                             # 沒寫產品也沿用原事件的產品與條件
    assert {i["asset_id"] for i in up["impacts"]} == {i["asset_id"] for i in orig["impacts"]}
    assert up["event"]["products"][0].get("conditions") == orig["event"]["products"][0].get("conditions")
    built = assemble(res, run_id="t", scenario="daily", trigger_source="manual", scope="daily", generated_at=AS_OF)
    reps = {r["event"]["id"]: r for r in built["intel_reports"]}
    assert reps["evt-php2shell-2026-10"]["updates"][0]["id"] == FOLLOWUP["id"]
    assert reps[FOLLOWUP["id"]]["update_of"]["id"] == "evt-php2shell-2026-10"
    ev = next(e for e in built["report"]["events"] if e["id"] == "evt-php2shell-2026-10")
    assert ev["updates"] == [FOLLOWUP["id"]]
    from tools.intel_report import to_markdown
    assert "## 事件進度" in to_markdown(reps["evt-php2shell-2026-10"])


def test_update_product_ranges_are_unioned_not_replaced():
    extra = {"name": "php", "ecosystem": "php", "affected": [{"introduced": "8.4.0", "fixed": "8.4.99"}]}
    res = evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS,
                             live_events=[{**FOLLOWUP, "products": [extra]}]))
    up = next(m for m in res["matches"] if m["event"]["id"] == FOLLOWUP["id"])["event"]
    orig = next(m for m in res["matches"] if m["event"]["id"] == "evt-php2shell-2026-10")["event"]
    php = up["products"][0]
    assert all(iv in php["affected"] for iv in orig["products"][0]["affected"])       # 原本的範圍還在
    assert {"introduced": "8.4.0", "fixed": "8.4.99"} in php["affected"]
    assert orig["products"][0]["affected"] != php["affected"]                          # 原事件本身不改
