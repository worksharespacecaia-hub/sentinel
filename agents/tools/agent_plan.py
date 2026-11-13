"""舊模組名稱（v0.11.0 動態派工）。v0.13.0 起核准規則擴充為 tools/orchestration.py（specs/orchestrator §3.2）。

這裡只 re-export，避免一次改太多 import；新程式請直接匯入 tools.orchestration。
"""
from tools.orchestration import *  # noqa: F401,F403
from tools.orchestration import __all__  # noqa: F401
