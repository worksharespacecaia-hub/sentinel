"""燈號權重設定（rules/scoring.json）：驗證規則、權重確實改變分數、無效時退回預設並記錄、網站範圍檔一致。"""
import json

import pytest

from tools.common import SENTINEL_ROOT
from tools.scoring import (COMPENSATING_RANGE, DEFAULT_FACTORS, DEFAULT_THRESHOLDS, DEFAULT_WEIGHTS, FACTOR_LABELS,
                           FACTOR_RANGE, HIGH_MAX, MEDIUM_RANGE, Factors, Weights, load_weights, score, validate_scoring)


def cfg(**over):
    base = {"version": 2, "factors": dict(DEFAULT_FACTORS), "thresholds": dict(DEFAULT_THRESHOLDS)}
    for k, v in over.items():
        base[k] = {**base[k], **v} if isinstance(v, dict) else v
    return base


def test_repo_config_is_valid_and_defaults_match_spec():
    raw = json.loads((SENTINEL_ROOT / "rules" / "scoring.json").read_text(encoding="utf-8"))
    validate_scoring(raw)
    assert DEFAULT_FACTORS == {"known_exploited": 2, "exposed": 2, "data_sensitive": 1, "platform": 1, "peer_event": 1,
                               "on_attack_chain": 3, "eol_no_fix": 1, "compensating": -3}
    assert DEFAULT_THRESHOLDS == {"high": 7, "medium": 4}


@pytest.mark.parametrize("bad", [
    cfg(factors={"exposed": 6}), cfg(factors={"compensating": 1}), cfg(factors={"exposed": 1.5}),
    cfg(thresholds={"medium": 7}), cfg(thresholds={"high": 16}), cfg(version=0),
    {**cfg(), "extra": 1}, {"version": 1, "factors": {"exposed": 2}, "thresholds": DEFAULT_THRESHOLDS},
])
def test_invalid_configs_rejected(bad):
    with pytest.raises(ValueError):
        validate_scoring(bad)


def test_weights_change_score_and_level():
    f = Factors(base_kind="vuln", cvss=7.5, exposed=True, on_attack_chain=True)       # 2 + 2 + 3 = 7 → 高
    assert score(f).level == "high"
    low_chain = Weights(factors={**DEFAULT_FACTORS, "on_attack_chain": 1}, thresholds=dict(DEFAULT_THRESHOLDS))
    r = score(f, low_chain)
    assert (r.score, r.level) == (5, "medium")
    assert {"factor": FACTOR_LABELS["on_attack_chain"], "points": 1, "reason": "攻擊路徑前提的必要一步"} in r.breakdown
    strict = Weights(factors=dict(DEFAULT_FACTORS), thresholds={"high": 9, "medium": 6})
    assert score(f, strict).level == "medium"
    # 規則下限與暫定上限不受權重影響
    floor = score(Factors(base_kind="other", category="shadow_it", level_floor="high", floor_reason="影子 IT"), strict)
    assert floor.level == "high"


def test_load_weights_falls_back_with_data_issue(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps(cfg(factors={"on_attack_chain": 1}, updated_by="admin")), encoding="utf-8")
    w, info, issue = load_weights(good)
    assert w.factors["on_attack_chain"] == 1 and issue is None
    assert info["is_default"] is False and info["version"] == 2 and info["updated_by"] == "admin"
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    w, info, issue = load_weights(bad)
    assert w == DEFAULT_WEIGHTS and info["is_default"] is True
    assert issue["source"] == "rules/scoring.json" and issue["required"] is False
    _, missing_info, missing_issue = load_weights(tmp_path / "missing.json")
    assert missing_issue is not None and missing_info["is_default"]
    assert load_weights(good)[1]["hash"] == load_weights(good)[1]["hash"]


def test_dashboard_limits_match_python():
    lim = json.loads((SENTINEL_ROOT / "dashboard" / "lib" / "scoring-limits.json").read_text(encoding="utf-8"))
    assert set(lim["factors"]) == set(DEFAULT_FACTORS)
    for k, v in lim["factors"].items():
        rng = COMPENSATING_RANGE if k == "compensating" else FACTOR_RANGE
        assert (v["label"], v["default"], v["min"], v["max"]) == (FACTOR_LABELS[k], DEFAULT_FACTORS[k], *rng), k
    t = lim["thresholds"]
    assert (t["high"]["default"], t["high"]["max"]) == (DEFAULT_THRESHOLDS["high"], HIGH_MAX)
    assert (t["medium"]["default"], t["medium"]["min"], t["medium"]["max"]) == (DEFAULT_THRESHOLDS["medium"], *MEDIUM_RANGE)


def test_report_records_scoring(baseline):
    assert baseline["scoring"]["is_default"] is True
    assert baseline["scoring"]["thresholds"] == DEFAULT_THRESHOLDS
    assert not any(i["source"] == "rules/scoring.json" for i in baseline["data_issues"])
