"""各 Agent 共用的執行環境：模式、範圍、路徑、情境疊加、trace、快取與成本。"""
from __future__ import annotations

import csv
import io
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from llm import LLMRunner
from tools.budget import budget_for
from tools.cache import LLMCache, ReplayStore
from tools.common import AGENTS_DIR, SENTINEL_ROOT, parse_time, read_json
from tools.daily_intel import load_daily_intel
from tools.loaders import FIXTURE_SCANNERS, FIXTURE_TARGET
from tools.pipeline import EvalInput
from tools.trace import Tracer

SCENARIOS = ["daily", "intel-demo", "peer-incident", "early-signal", "php2shell", "nas", "insider-path", "mobile-sdk", "advisory"]
WEB_SCENARIOS = ["daily", "intel-demo", "peer-incident", "early-signal", "php2shell", "nas", "insider-path", "mobile-sdk"]
P2_SCENARIOS = {"nas", "insider-path", "mobile-sdk"}      # 第 12.0 節 P2：尚未提供輸入時明確拒絕，不產出看似完成的報告
TRIGGERS = ["schedule", "manual", "web", "intel-watch"]


class ScenarioDisabled(ValueError):
    pass
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,80}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DATA_DIR = SENTINEL_ROOT / "dashboard" / "public" / "data"
OUT_DIR = SENTINEL_ROOT / "out"


def resolve_mode(cli: str | None) -> str:
    """CLI 指定 > EXECUTION_MODE > replay。record 只供本機，在 GitHub Actions 中拒絕。"""
    mode = cli or os.environ.get("EXECUTION_MODE") or "replay"
    if mode not in ("replay", "record", "live"):
        raise ValueError(f"未知的 execution_mode：{mode}")
    if mode == "record" and os.environ.get("GITHUB_ACTIONS") == "true":
        raise ValueError("record 只能在本機使用")
    return mode


@dataclass
class RunCtx:
    run_id: str
    scenario: str
    scope: str
    trigger_source: str
    event_name: str
    mode: str
    as_of: datetime
    target_root: Path
    scanners_dir: Path | None
    target_sha: str
    output_dir: str
    out: Path = OUT_DIR
    data_dir: Path = DATA_DIR
    reports_dir: Path = SENTINEL_ROOT / "reports"
    advisory_id: str | None = None
    advisory_revision: str | None = None
    assets: list[str] = field(default_factory=list)
    deployments_file: Path | None = None
    cost: dict = field(default_factory=lambda: {"total_usd": 0.0, "per_agent": {}})
    cache: LLMCache = field(default_factory=LLMCache)
    replay: ReplayStore = field(default_factory=ReplayStore)
    llm_plan: list = field(default_factory=list)          # replay 時改用範本的任務（交給 claude-analysis Job 撰寫）
    _llm_results: dict | None = field(default=None, repr=False)

    def llm_results(self) -> dict:
        """claude-analysis Job（訂閱方案）撰寫且通過程式驗證的結果；只用在 daily（排程或手動）。"""
        if self._llm_results is None:
            path = self.out / "llm" / "validated.json"
            self._llm_results = (read_json(path, {}) or {}) if self.scenario == "daily" else {}
        return self._llm_results

    @property
    def scenario_dir(self) -> Path:
        return AGENTS_DIR / "scenarios" / self.scenario

    @property
    def scenario_cfg(self) -> dict:
        p = self.scenario_dir / "scenario.yaml"
        return (yaml.safe_load(p.read_text(encoding="utf-8")) if p.is_file() else {}) or {}

    def tracer(self, agent: str) -> Tracer:
        return Tracer(self.out / agent / "trace.jsonl", agent)

    def runner(self, agent: str) -> LLMRunner:
        return LLMRunner(agent=agent, mode=self.mode, scope=self.scope, target_sha=self.target_sha,
                         advisory_revision=self.advisory_revision, tracer=self.tracer(agent), cache=self.cache,
                         replay=self.replay, budget=budget_for(self.mode, f"{self.run_id}-{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}/{agent}"),
                         cost=self.cost, collected=self.llm_results(), plan=self.llm_plan)

    def eval_input(self, **kw) -> EvalInput:
        cfg = self.scenario_cfg
        kinds = tuple(cfg.get("intel_kinds") or ("archive", "advisory"))
        extra = [self.scenario_dir / d for d in cfg.get("extra_event_dirs", [])]
        overrides = {}
        for name in cfg.get("signals", []):
            text = (self.scenario_dir / "signals" / name).read_text(encoding="utf-8")
            overrides[name] = list(csv.DictReader(io.StringIO(text))) if name.endswith(".csv") else \
                [json.loads(x) for x in text.splitlines() if x.strip()]
        # daily-intel（LLM）的輸出不可信：先清理、驗證格式，強制為 live 事件
        live = load_daily_intel(self.out / "intel-daily.json")[0] if self.scenario == "daily" else []
        prev = read_json(self.data_dir / "daily" / "state" / "risks.json", {}) if self.scope == "daily" else {}
        return EvalInput(target_root=self.target_root, as_of=self.as_of, scanners_dir=self.scanners_dir,
                         intel_kinds=kinds, extra_event_dirs=extra, live_events=live, prev_risks=prev or {},
                         signal_overrides=overrides or None, target_sha=self.target_sha,
                         deployments_file=self.deployments_file, **kw)


def build_ctx(*, mode: str | None = None, scenario: str | None = None) -> RunCtx:
    env = os.environ
    scenario = scenario or env.get("SCENARIO") or "daily"
    if scenario not in SCENARIOS:
        raise ValueError(f"未知情境：{scenario}")
    if scenario in P2_SCENARIOS and not (AGENTS_DIR / "scenarios" / scenario / "scenario.yaml").is_file():
        raise ScenarioDisabled(f"情境 {scenario} 屬 P2，尚未提供輸入資料（未啟用），不產出報告")
    trigger = env.get("TRIGGER_SOURCE") or ("schedule" if env.get("EVENT_NAME") == "schedule" else "manual")
    if trigger not in TRIGGERS:
        raise ValueError(f"未知觸發來源：{trigger}")
    run_id = env.get("GITHUB_RUN_ID") or env.get("RUN_ID") or datetime.now(timezone.utc).strftime("local-%Y%m%d%H%M%S")
    advisory_id = env.get("ADVISORY_ID") or None
    assets = [a for a in (env.get("ASSETS") or "").split(",") if a]
    if scenario == "advisory":
        if not advisory_id or not ID_RE.match(advisory_id):
            raise ValueError("advisory 需要合法的 advisory_id")
        if not assets or not all(ID_RE.match(a) for a in assets):
            raise ValueError("advisory 需要合法且非空的受影響資產清單")
        output_dir = f"advisories/{advisory_id}/{run_id}"
        scope = "advisory"
    elif scenario == "daily":
        output_dir, scope = "daily", "daily"
    else:
        output_dir, scope = f"scenarios/{scenario}", "scenario"
    target = Path(env.get("TARGET_DIR") or SENTINEL_ROOT / "target")
    scanners = Path(env["SCANNERS_DIR"]) if env.get("SCANNERS_DIR") else None
    if not (target / "ops").is_dir():
        target, scanners = FIXTURE_TARGET, scanners or FIXTURE_SCANNERS   # 本機開發：使用 baseline 凍結副本
    sha = env.get("TARGET_SHA") or (read_json(target / ".fixture.json", {}) or {}).get("target_sha") or _git_sha(target)
    if not SHA_RE.match(sha or ""):
        raise ValueError("target_sha 格式錯誤")
    cfg_path = AGENTS_DIR / "scenarios" / scenario / "scenario.yaml"
    cfg = (yaml.safe_load(cfg_path.read_text(encoding="utf-8")) if cfg_path.is_file() else {}) or {}
    # 情境 fixture 可凍結邏輯時間（畫面會標示）；正式 daily 使用實際時間
    as_of = parse_time(env.get("AS_OF") or cfg.get("as_of")) or datetime.now(timezone.utc)
    if scanners is not None and not any(scanners.glob("*.json")):
        scanners = None
    if scanners is None and target != FIXTURE_TARGET:
        scanners = reusable_scanners(sha, as_of)
    return RunCtx(run_id=run_id, scenario=scenario, scope=scope, trigger_source=trigger, event_name=env.get("EVENT_NAME", "local"),
                  mode=resolve_mode(mode), as_of=as_of, target_root=target, scanners_dir=scanners, target_sha=sha,
                  output_dir=output_dir, advisory_id=advisory_id, advisory_revision=env.get("ADVISORY_REVISION") or None,
                  assets=assets, deployments_file=Path(env["DEPLOYMENTS_FILE"]) if env.get("DEPLOYMENTS_FILE") else None)


def reusable_scanners(target_sha: str | None, as_of: datetime) -> Path | None:
    """沿用 daily/state/scanners：只有 manifest 的 target_sha 相同、狀態 ok 且未過期才可沿用；否則回傳 None（記為 missing）。"""
    d = DATA_DIR / "daily" / "state" / "scanners"
    manifests = [read_json(p) for p in d.glob("*.manifest.json")] if d.is_dir() else []
    if not manifests:
        return None
    for m in manifests:
        until = parse_time(m.get("valid_until"))
        if m.get("status") != "ok" or m.get("target_sha") != target_sha or until is None or until < as_of:
            return None
    return d


def _git_sha(path: Path) -> str | None:
    import subprocess
    proc = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else None
