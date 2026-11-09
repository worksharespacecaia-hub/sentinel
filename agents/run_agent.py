"""入口：python agents/run_agent.py <agent-name> [--replay | --record | --live] [--scenario NAME]

agent-name：orchestrator、a0、a1、a2、a3、a4、a5、incident，或 all（本機依序執行 orchestrator → a5）。
模式優先順序：CLI 指定 > 環境變數 EXECUTION_MODE > replay。replay 不呼叫任何 LLM 網路服務。
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from context import OUT_DIR, ScenarioDisabled, build_ctx  # noqa: E402

ORDER = ["orchestrator", "a0", "a1", "a2", "a3", "a4", "a5"]


def _module(name: str):
    from agents import a0_assets, a1_intel, a2_scan, a3_signals, a4_risk, a5_report, orchestrator
    mods = {"orchestrator": orchestrator, "a0": a0_assets, "a1": a1_intel, "a2": a2_scan, "a3": a3_signals,
            "a4": a4_risk, "a5": a5_report}
    if name == "incident":
        from agents import incident
        return incident
    return mods[name]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("agent", choices=[*ORDER, "incident", "all"])
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--replay", dest="mode", action="store_const", const="replay")
    g.add_argument("--record", dest="mode", action="store_const", const="record")
    g.add_argument("--live", dest="mode", action="store_const", const="live")
    ap.add_argument("--scenario")
    ap.add_argument("--fresh", action="store_true", help="執行前清空 out/（本機）")
    a = ap.parse_args(argv)
    try:
        ctx = build_ctx(mode=a.mode, scenario=a.scenario)
    except ScenarioDisabled as exc:
        print(f"[{a.agent}] 未啟用：{exc}", file=sys.stderr)
        return 2
    if a.fresh and OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    names = ORDER if a.agent == "all" else [a.agent]
    for name in names:
        try:
            result = _module(name).run(ctx)
        except RuntimeError as exc:   # incident 的上下文驗證、留言或回報失敗：明確結束，不印出敏感內容
            if name != "incident":
                raise
            print(f"[incident] 失敗：{exc}", file=sys.stderr)
            return 1
        print(f"[{name}] {result}")
    if a.agent in ("all", "a5"):
        print(f"cost_usd={ctx.cost['total_usd']} mode={ctx.mode}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
