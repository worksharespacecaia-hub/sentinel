"""第 7.4 節凍結測試資料的預期分數。每列明確列出所有因子真假，不依網路即時值。as_of = 2026-11-09。"""
import pytest

from tools.scoring import Factors, score

AS_OF = "2026-11-09"

ROWS = [
    # (列, 因子, 預期分數, 預期等級)
    ("php2shell → marketing-site",
     Factors(base_kind="vuln", cvss=9.8, known_exploited=True, exposed=True, eol_no_fix=True, peer_event=True), 9, "high"),
    ("php2shell → phpMyAdmin",
     Factors(base_kind="vuln", cvss=9.8, known_exploited=True, data_sensitive=True, peer_event=True,
             compensating_effective=True), 4, "medium"),
    ("91app → internal-tool",
     Factors(base_kind="vuln", cvss=9.8, known_exploited=True, exposed=True, on_attack_chain=True, peer_event=True), 11, "high"),
    ("91app → config/db.yml",
     Factors(base_kind="control", base_points=2, data_sensitive=True, on_attack_chain=True, platform=True, peer_event=True), 8, "high"),
    ("1shop → mail-api-key",
     Factors(base_kind="control", base_points=2, exposed=True, data_sensitive=True, peer_event=True), 6, "medium"),
    ("binance → laptop-eng-07 部署權杖",
     Factors(base_kind="control", base_points=2, on_attack_chain=True, platform=True, peer_event=True), 7, "high"),
    ("synology → nas-office-01",
     Factors(base_kind="vuln", cvss=9.8, known_exploited=True, exposed=True, peer_event=True), 8, "high"),
    ("nextjs → storefront（known_exploited=false 凍結）",
     Factors(base_kind="vuln", cvss=9.1, exposed=True, data_sensitive=True, platform=True, peer_event=True), 8, "high"),
    ("demo-firebase-public",
     Factors(base_kind="control", base_points=3, exposed=True, data_sensitive=True, platform=True), 7, "high"),
    ("demo-push-sdk-rce",
     Factors(base_kind="vuln", cvss=9.8, exposed=True, data_sensitive=True, platform=True), 7, "high"),
    ("demo-clone-app-fraud",
     Factors(base_kind="other", category="clone_app", exposed=True), 4, "medium"),
    ("demo-cache-plaintext",
     Factors(base_kind="control", base_points=1, data_sensitive=True), 2, "low"),
]


@pytest.mark.parametrize("name,factors,expected,level", ROWS, ids=[r[0] for r in ROWS])
def test_frozen_rows(name, factors, expected, level):
    r = score(factors)
    assert r.score == expected
    assert r.level == level
    assert sum(b["points"] for b in r.breakdown) == r.raw_score
    assert r.breakdown, "每個風險都要有分數拆解"


def test_nextjs_known_exploited_true_is_10():
    r = score(Factors(base_kind="vuln", cvss=9.1, known_exploited=True, exposed=True, data_sensitive=True,
                      platform=True, peer_event=True))
    assert r.score == 10 and r.level == "high"


def test_demo_erp_not_affected_has_no_risk():
    # 不受影響的事件不產生風險：由 intel_match 測試涵蓋；這裡確認低於 4 的 CVSS 基礎分為 0
    assert score(Factors(base_kind="vuln", cvss=3.9)).score == 0


def test_cvss_unknown_marks_need_check():
    r = score(Factors(base_kind="vuln", cvss=None, exposed=True))
    assert r.need_check and r.score == 2


def test_provisional_caps_at_medium_but_keeps_score():
    r = score(Factors(base_kind="vuln", cvss=9.8, known_exploited=True, exposed=True, provisional=True))
    assert r.score == 7 and r.score_level == "high" and r.level == "medium"
    assert "暫定" in r.level_reason


def test_level_floor_raises_level():
    r = score(Factors(base_kind="other", category="shadow_it", level_floor="high", floor_reason="影子 IT"))
    assert r.score == 2 and r.score_level == "low" and r.level == "high" and r.deadline_hours == 24


def test_floor_applied_after_provisional_cap():
    r = score(Factors(base_kind="vuln", cvss=9.8, exposed=True, known_exploited=True, provisional=True, level_floor="high"))
    assert r.level == "high"


def test_negative_raw_score_floors_at_zero():
    r = score(Factors(base_kind="control", base_points=1, compensating_effective=True))
    assert r.raw_score == -2 and r.score == 0


def test_missing_rule_mapping_is_need_check():
    r = score(Factors(base_kind="rule", rule_key="config:unknown"))
    assert r.need_check and r.score == 0


def test_control_missing_base_points_is_need_check():
    assert score(Factors(base_kind="control", base_points=None)).need_check
