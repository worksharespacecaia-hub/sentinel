"""Orchestrator（程式為主）：讀取情境與觸發來源，決定派工，寫入 $GITHUB_OUTPUT。"""
from __future__ import annotations

import json
import os

from agents.common import save
from tools.common import iso
from context import RunCtx


def decide(ctx: RunCtx, *, event_name: str, ref_name: str | None, default_branch: str | None) -> dict:
    on_default = ref_name is None or default_branch is None or ref_name == default_branch
    # 每日情資用訂閱方案（claude-code-action），與 A1～A5 是否呼叫 API（execution_mode）無關
    daily_intel = (on_default and ctx.scenario == "daily"
                   and (event_name == "schedule" or (event_name == "workflow_dispatch" and ctx.trigger_source == "manual")))
    plan = {"scanners": True, "a1": True, "a2": True, "a3": True, "a4": True, "a5": True}
    if ctx.scenario == "advisory":
        plan["scanners"] = False          # 公告調查比對已存的 SBOM，不重新掃描
    return {"plan": plan, "daily_intel": daily_intel, "execution_mode": ctx.mode, "output_dir": ctx.output_dir,
            "target_sha": ctx.target_sha, "run_id": ctx.run_id, "scope": ctx.scope, "scenario": ctx.scenario,
            "assets": ctx.assets, "advisory_id": ctx.advisory_id}


def run(ctx: RunCtx) -> dict:
    tr = ctx.tracer("orchestrator")
    tr.emit("start", f"scenario={ctx.scenario} trigger={ctx.trigger_source} mode={ctx.mode}")
    d = decide(ctx, event_name=os.environ.get("EVENT_NAME", "local"), ref_name=os.environ.get("GITHUB_REF_NAME"),
               default_branch=os.environ.get("DEFAULT_BRANCH"))
    tr.emit("skip", "planner 只在有新同業事件時呼叫（本次不需要）", subagent="planner", source="template")
    if not d["daily_intel"]:
        tr.emit("skip", "daily-intel 不執行（只在預設分支的每日排程或手動 daily 執行）")
    save(ctx, "orchestrator", "plan.json", d)
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8", newline="\n") as f:
            f.write(f"plan={json.dumps(d['plan'], separators=(',', ':'))}\n")
            for k in ("execution_mode", "output_dir", "target_sha", "run_id", "scope"):
                f.write(f"{k}={d[k]}\n")
            f.write(f"daily_intel={'true' if d['daily_intel'] else 'false'}\n")
            # 同一次執行的所有 Job 使用同一個邏輯時間：報告時間一致，交給 claude-analysis 的任務鍵也一致
            f.write(f"as_of={iso(ctx.as_of)}\n")
    tr.emit("result", json.dumps(d["plan"]))
    return d
