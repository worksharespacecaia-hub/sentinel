"""量測每日例行（daily）的 Claude API 實際花費：冷啟動（無快取）與有快取各跑一次，輸出報告與月費推算。

用法（在 workspace/sentinel 下）：
  python scripts/cost_probe.py --dry-run     # replay 模式試跑流程，不呼叫 API、不需要 key
  python scripts/cost_probe.py               # 實際呼叫 API（record 模式，上限 --cap，預設 US$2）
選項：--cap 2.0  --model none|haiku|sonnet（預設 none：用 registry 的設定，目前全部 Haiku；其他值強制所有 Subagent 用該模型）  --keep（保留錄製結果，不還原）

安全：.env 只讀進子行程的環境變數，不印出任何值。執行前備份會被 record 寫入的路徑，結束後還原（除非 --keep）。
本報告只含 Claude API 費用；daily-intel 與 claude-analysis 使用訂閱方案，不產生 API 費用。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT_ORDER = ["router", "a0", "a1", "orchestrator-dispatch", "a2", "a3", "a4", "orchestrator-review", "a5"]
# record 會寫入的路徑（相對 ROOT）
TOUCHED = ["agents/cache", "agents/fixtures/replay", "out", "dashboard/public/data", "reports"]
# Claude Haiku 5.5 單價（US$／百萬 token，prompt ≤100K）；快取倍率為假設值，只作對照，以 CLI 回報的 costUSD 為準
PRICE = {"claude-haiku-5-5": {"input": 0.10, "output": 0.50},
         "claude-sonnet-5-5": {"input": 2.00, "output": 10.00}}
CACHE_WRITE_X, CACHE_READ_X = 1.25, 0.10
RUN_TIMEOUT_S = 30 * 60


def load_dotenv(path: Path) -> dict[str, str]:
    env = {}
    if not path.is_file():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def backup(dest: Path) -> dict[str, bool]:
    existed = {}
    for rel in TOUCHED:
        src = ROOT / rel
        existed[rel] = src.exists()
        if src.is_dir():
            shutil.copytree(src, dest / rel)
        elif src.is_file():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / rel)
    (dest / "existed.json").write_text(json.dumps(existed, indent=2), encoding="utf-8")
    return existed


def restore(src: Path, existed: dict[str, bool]) -> None:
    for rel, was in existed.items():
        cur = ROOT / rel
        if cur.is_dir():
            shutil.rmtree(cur)
        elif cur.exists():
            cur.unlink()
        if was:
            if (src / rel).is_dir():
                shutil.copytree(src / rel, cur)
            else:
                shutil.copy2(src / rel, cur)


def run_daily(env: dict[str, str], mode: str, log: Path) -> dict:
    cmd = [sys.executable, str(ROOT / "agents" / "run_agent.py"), "all", f"--{mode}", "--scenario", "daily", "--fresh"]
    ledger_before = _ledger_usd()
    t0 = time.monotonic()
    with log.open("w", encoding="utf-8") as f:
        proc = subprocess.run(cmd, cwd=ROOT, env=env, stdout=f, stderr=subprocess.STDOUT, timeout=RUN_TIMEOUT_S)
    elapsed = round(time.monotonic() - t0, 1)
    agents, results = {}, []
    for name in AGENT_ORDER:
        c = _read(ROOT / "out" / name / "cost.json") or {}
        agents[name] = {"usd": c.get("usd", 0.0), "usage": c.get("usage")}
        trace = ROOT / "out" / name / "trace.jsonl"
        if trace.is_file():
            for line in trace.read_text(encoding="utf-8").splitlines():
                ev = json.loads(line) if line.strip() else {}
                if ev.get("kind") in ("result", "error", "skip") and (ev.get("cost_usd") is not None or ev.get("kind") != "result"):
                    results.append({"agent": name, "kind": ev["kind"], "detail": ev["detail"][:200], "cost_usd": ev.get("cost_usd")})
    report = _read(ROOT / "dashboard" / "public" / "data" / "daily" / "report.json") or {}
    # 成本簿在每次呼叫結算時寫入，Agent 中途失敗也會記到；以它為準
    return {"exit_code": proc.returncode, "elapsed_s": elapsed, "total_usd": round(_ledger_usd() - ledger_before, 6),
            "agents_sum_usd": round(sum(a["usd"] for a in agents.values()), 6),
            "cache_hit_rate": (report.get("cost") or {}).get("cache_hit_rate"), "agents": agents,
            "models": _sum_models(agents), "events": results, "log": str(log.relative_to(ROOT))}


def save_outputs(dest: Path) -> None:
    """還原前另存這次產出的報告與 LLM 文字，方便檢視品質（.cost-test 不進版控）。"""
    for rel in ("dashboard/public/data/daily", "reports", "agents/cache/llm.json"):
        src = ROOT / rel
        if src.is_dir():
            shutil.copytree(src, dest / rel, dirs_exist_ok=True)
        elif src.is_file():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / rel)


def _ledger_usd() -> float:
    return float((_read(ROOT / "agents" / "cache" / "local-budget.json") or {}).get("spent_usd") or 0.0)


def _read(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _sum_models(agents: dict) -> dict:
    out: dict[str, dict] = {}
    for a in agents.values():
        for m, u in ((a.get("usage") or {}).get("models") or {}).items():
            dst = out.setdefault(m, {"input": 0, "output": 0, "cache_write": 0, "cache_read": 0, "cost_usd": 0.0})
            for k in dst:
                dst[k] = round(dst[k] + (u.get(k) or 0), 6)
    for m, u in out.items():
        p = PRICE.get(m)
        if p:
            u["est_usd"] = round((u["input"] * p["input"] + u["cache_write"] * p["input"] * CACHE_WRITE_X
                                  + u["cache_read"] * p["input"] * CACHE_READ_X + u["output"] * p["output"]) / 1e6, 6)
    return out


def write_md(path: Path, data: dict) -> None:
    runs = data["runs"]
    lines = [f"# 每日例行（daily）API 花費量測 {data['started_at']}", "",
             f"- 模式：{data['mode']}；模型設定：{data['model_override'] or 'registry 設定'}；上限 US${data['cap_usd']}",
             "- 只含 Claude API 費用；daily-intel、claude-analysis 走訂閱方案，不在內", ""]
    for label, r in runs.items():
        lines += [f"## {label}", "", f"總花費 **US${r['total_usd']:.4f}**（成本簿；各 Agent 加總 {r['agents_sum_usd']:.4f}），耗時 {r['elapsed_s']} 秒，結束碼 {r['exit_code']}，"
                  f"快取命中率 {r['cache_hit_rate']}", "", "token 數含各 Agent 派發的 Subagent。", "", "| Agent | US$ | 呼叫 | input | output | cache 寫 | cache 讀 |",
                  "|---|---:|---:|---:|---:|---:|---:|"]
        for name, a in r["agents"].items():
            u = a.get("usage") or {}
            # 頂層 usage 只含主 Agent；model_usage 含所有 Subagent，以它加總
            t = {k: sum((m.get(k) or 0) for m in (u.get("models") or {}).values())
                 for k in ("input", "output", "cache_write", "cache_read")}
            lines.append(f"| {name} | {a['usd']:.4f} | {u.get('calls', 0)} | {t.get('input', 0)} | {t.get('output', 0)} | "
                         f"{t.get('cache_write', 0)} | {t.get('cache_read', 0)} |")
        lines += ["", "| 模型 | CLI 回報 US$ | 單價反算 US$ |", "|---|---:|---:|"]
        for m, u in r["models"].items():
            lines.append(f"| {m} | {u['cost_usd']:.4f} | {u.get('est_usd', '—')} |")
        lines.append("")
    if "projection" in data:
        p = data["projection"]
        lines += ["## 月費推算（30 天）", "", f"- 每天都冷啟動（上限）：US${p['all_cold']:.2f}",
                  f"- 每天都命中快取（下限）：US${p['all_warm']:.2f}",
                  f"- 第一天冷啟動＋29 天命中快取：US${p['cold_then_warm']:.2f}", "",
                  "實際每日介於上下限之間：有新弱點、新公告或程式／規則改版時，對應任務的快取會失效而重新呼叫。"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--cap", type=float, default=2.0)
    ap.add_argument("--model", default="none", choices=["none", "haiku", "sonnet"])
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()

    mode = "replay" if a.dry_run else "record"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    work = ROOT / ".cost-test"
    bdir = work / f"backup-{stamp}"
    work.mkdir(exist_ok=True)

    dotenv = load_dotenv(ROOT / ".env")
    key = dotenv.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY", "")
    if mode == "record" and not (key.startswith("sk-ant-") and len(key) > 30):
        print("找不到有效的 ANTHROPIC_API_KEY（.env 或環境變數），停止。", file=sys.stderr)
        return 2

    env = {k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "GITHUB_ACTIONS")}
    env.update({"PYTHONUTF8": "1", "EXECUTION_MODE": mode, "SCENARIO": "daily", "LOCAL_RECORD_CAP_USD": str(a.cap)})
    if a.model != "none":
        env["SENTINEL_MODEL_OVERRIDE"] = a.model
    if mode == "record":
        env["ANTHROPIC_API_KEY"] = key

    print(f"備份到 {bdir.relative_to(ROOT)} …")
    existed = backup(bdir)
    data = {"started_at": stamp, "mode": mode, "cap_usd": a.cap, "model_override": env.get("SENTINEL_MODEL_OVERRIDE"),
            "runs": {}}
    try:
        # 冷啟動：清空 LLM 快取與本機成本簿（上限 --cap 對兩次執行合計生效）
        for p in (ROOT / "agents/cache/llm.json", ROOT / "agents/cache/local-budget.json"):
            if p.exists():
                p.unlink()
        print(f"第 1 次（冷啟動，{mode}）執行中 …")
        data["runs"]["第 1 次：冷啟動（無快取）"] = run_daily(env, mode, work / f"run-{stamp}-cold.log")
        cold_run = data["runs"]["第 1 次：冷啟動（無快取）"]
        save_outputs(work / f"output-{stamp}")
        print(f"  → US${cold_run['total_usd']}（結束碼 {cold_run['exit_code']}）")
        if cold_run["exit_code"] != 0:
            print(f"第 1 次失敗，快取未寫回，第 2 次不具意義，停止。請看 {cold_run['log']}", file=sys.stderr)
            return 1
        print(f"第 2 次（有快取，{mode}）執行中 …")
        data["runs"]["第 2 次：有快取"] = run_daily(env, mode, work / f"run-{stamp}-warm.log")
        print(f"  → US${data['runs']['第 2 次：有快取']['total_usd']}（結束碼 {data['runs']['第 2 次：有快取']['exit_code']}）")
        cold, warm = (r["total_usd"] for r in data["runs"].values())
        data["projection"] = {"all_cold": cold * 30, "all_warm": warm * 30, "cold_then_warm": cold + warm * 29}
    finally:
        if a.keep:
            print(f"--keep：保留錄製結果；備份留在 {bdir.relative_to(ROOT)}")
        else:
            restore(bdir, existed)
            print("已還原備份")
        out_json = work / f"report-{stamp}.json"
        out_json.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        write_md(work / f"report-{stamp}.md", data)
        print(f"報告：{out_json.relative_to(ROOT)}、report-{stamp}.md")
    return 0 if all(r["exit_code"] == 0 for r in data["runs"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
