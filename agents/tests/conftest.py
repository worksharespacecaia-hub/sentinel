from datetime import datetime, timezone

import pytest

from tools.loaders import FIXTURE_SCANNERS, FIXTURE_TARGET, load_target
from tools.pipeline import EvalInput, evaluate
from tools.reconcile import reconcile
from tools.graph_builder import build_graph

AS_OF = datetime(2026, 11, 9, 1, 0, tzinfo=timezone.utc)   # 凍結邏輯時間


@pytest.fixture(scope="session", autouse=True)
def default_scoring(tmp_path_factory):
    """固定使用預設燈號權重：網站調整 rules/scoring.json 不會讓情境與分數測試失敗。"""
    import json
    import os
    from tools.scoring import DEFAULT_FACTORS, DEFAULT_THRESHOLDS
    p = tmp_path_factory.mktemp("scoring") / "scoring.json"
    p.write_text(json.dumps({"version": 1, "factors": DEFAULT_FACTORS, "thresholds": DEFAULT_THRESHOLDS}), encoding="utf-8")
    old = os.environ.get("SENTINEL_SCORING_FILE")
    os.environ["SENTINEL_SCORING_FILE"] = str(p)
    yield p
    if old is None:
        os.environ.pop("SENTINEL_SCORING_FILE", None)
    else:
        os.environ["SENTINEL_SCORING_FILE"] = old


@pytest.fixture(scope="session")
def as_of():
    return AS_OF


@pytest.fixture(scope="session")
def baseline():
    return evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS))


@pytest.fixture(scope="session")
def demo_result():
    return evaluate(EvalInput(target_root=FIXTURE_TARGET, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS, intel_kinds=("demo",)))


@pytest.fixture()
def target_data():
    return load_target(FIXTURE_TARGET, as_of=AS_OF, scanners_dir=FIXTURE_SCANNERS)


@pytest.fixture()
def graph_and_recon(target_data):
    recon = reconcile(target_data)
    return build_graph(target_data, recon), recon, target_data


def risk(result, rid):
    return next(r for r in result["risks"] if r["id"] == rid)
