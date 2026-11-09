from datetime import datetime, timezone

import pytest

from tools.loaders import FIXTURE_SCANNERS, FIXTURE_TARGET, load_target
from tools.pipeline import EvalInput, evaluate
from tools.reconcile import reconcile
from tools.graph_builder import build_graph

AS_OF = datetime(2026, 11, 9, 1, 0, tzinfo=timezone.utc)   # 凍結邏輯時間


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
