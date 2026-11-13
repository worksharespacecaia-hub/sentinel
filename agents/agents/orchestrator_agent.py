"""Orchestrator（AI 派工與驗收）：run_agent 的 `orchestrator-input --mode <m>` 與 `orchestrator --mode <m>` 指令。

specs/orchestrator design §3.3。核准規則與計畫檔在 tools/orchestration.py（build_plan、resolve_plans）。
T1 只接上 CLI；build_input（評估快照、政策上下文、§4 投影）與 run（提案來源、核准、計畫檔、trace）在 T2 實作。
"""
from __future__ import annotations

from context import RunCtx


def build_input(ctx: RunCtx, mode: str) -> dict:
    raise NotImplementedError(f"orchestrator-input --mode {mode} 尚未實作（T2）")


def run(ctx: RunCtx, mode: str) -> dict:
    raise NotImplementedError(f"orchestrator --mode {mode} 尚未實作（T2）")
