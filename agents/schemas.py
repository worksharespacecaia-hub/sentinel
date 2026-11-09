"""資料格式（第 9 節）。所有 Agent 的輸入輸出都以這些 pydantic 模型驗證。"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Level = Literal["high", "medium", "low"]
ResultSource = Literal["live", "replay", "template"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Asset(_Model):
    id: str
    type: Literal["service", "internal_tool", "datastore", "device", "saas", "vendor", "identity",
                  "token", "ai_tool", "zone", "app", "app_version", "sdk", "api"]
    env: Literal["prod", "test", "office"] | None
    owner: str | None
    sources: list[str]
    registered: bool
    deployed_via_ci: bool | None
    components: list[dict]
    exposed_to_internet: bool | None
    crown_jewel: bool = False
    management_interface: bool = False
    compensating: list[str] = Field(default_factory=list)
    platform_layer: bool = False
    data_classes: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    model_config = ConfigDict(extra="allow")   # 最低欄位之外，允許規則附加 rule_key、version 等程式欄位

    id: str
    asset_id: str
    category: Literal["vuln", "secret", "config", "eol", "identity", "backup", "shadow_it", "signal",
                      "mobile", "clone_app", "shadow_api"]
    control_id: str | None
    title: str
    evidence: list[str]
    status: Literal["provisional", "confirmed"]
    source: str
    cvss: float | None = None
    base_points: int | None = None
    credential_id: str | None = None
    level_floor: Level | None = None
    observed_at: str
    source_sha: str
    # 漏洞類的附加資訊（程式填入，LLM 不得改動）
    vuln_id: str | None = None
    component: str | None = None
    known_exploited: bool | None = None
    eol_no_fix: bool = False
    impact: str | None = None
    advisory_ids: list[str] = Field(default_factory=list)


class SecretFinding(_Model):
    id: str
    location: str
    secret_type: str
    env: Literal["prod", "test", "unknown"]
    grants: list[str]
    is_test_value: bool
    fixture: bool = False
    modeled_env: Literal["prod", "test", "unknown"]
    credential_id: str | None = None
    credential_status: Literal["active", "revoked", "unknown"]
    confidence: Literal["high", "low"]


class Solution(_Model):
    risk_id: str
    temporary: str
    permanent: str
    options: list[dict]
    suggested_owner: str | None
    verify: str
    source: ResultSource


class Risk(_Model):
    id: str
    finding_ids: list[str]
    asset_id: str
    title: str
    category: str
    level: Level
    score: int
    raw_score: int
    score_level: Level
    level_reason: str
    breakdown: list[dict]
    attack_path: list[str] | None
    matched_events: list[str]
    deadline_hours: int
    solution: Solution | None
    status: Literal["open", "fixed", "need_check"]
    first_seen: str
    last_evaluated: str
    verification_evidence: list[str] = Field(default_factory=list)


class TraceEvent(_Model):
    ts: str
    agent: str
    subagent: str | None
    kind: Literal["start", "tool", "skill", "subagent", "result", "error", "skip"]
    detail: str
    source: ResultSource | None
    cost_usd: float | None


class Alert(_Model):
    id: str
    rule_id: str
    level: Level
    asset_id: str | None
    simulation_id: str | None = None
    simulated: bool
    summary: str
    maps_to_event: str | None
    issue_url: str | None
    issue_number: int | None
    source_event_ids: list[str]
    delivery: dict
    timeline: dict
    status: Literal["open", "contained", "closed"]
    status_history: list[dict]


class Source(_Model):
    url: str | None
    title: str
    quote: str | None
    published: str | None
    fetch_status: Literal["ok", "fetch_failed", "quote_mismatch", "skipped"] = "skipped"
    verified: bool = False
    verified_at: str | None = None
    content_hash: str | None = None
    verification_basis: Literal["live", "archived", "demo", "unverified"] = "unverified"


class IntelEvent(_Model):
    id: str
    kind: Literal["live", "archive", "demo", "advisory"]
    is_update_of: str | None = None
    title: str
    date: str
    industry: str | None = None
    attack_chain: list[str] = Field(default_factory=list)
    attck: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    products: list[dict] = Field(default_factory=list)
    revision: str
    controls: list[str] = Field(default_factory=list)
    confidence: Literal["confirmed", "provisional"]
    sources: list[Source]
    proposed_controls: list[dict] = Field(default_factory=list)
    demo: bool = False
    facts: list[dict] = Field(default_factory=list)
    summary: str | None = None
    fixture_note: str | None = None


class StackImpact(_Model):
    event_id: str
    asset_id: str
    basis: Literal["version", "control", "condition"]
    our_state: str
    llm_verdict: Literal["affected", "not_affected", "need_check"] | None = None
    verdict: Literal["affected", "not_affected", "need_check"]
    risk_id: str | None = None
    to_verify: list[str] = Field(default_factory=list)
    reason: str = ""


class IntelMatchReport(_Model):
    event: IntelEvent
    conclusion: str
    affected_count: int
    max_level: Level | None
    impacts: list[StackImpact]
    solutions: list[Solution]
    notice: dict | None
    status: Literal["open", "fixed", "not_affected", "need_check"]
    evaluated_asset_ids: list[str]
    complete: bool
    summary_source: ResultSource
    summary: str = ""
    blocks: dict = Field(default_factory=dict)


class Manifest(_Model):
    schema_version: int = 1
    run_id: str
    job: str
    scope: str
    target_sha: str
    input_hash: str
    observed_at: str
    valid_until: str | None
    tool_version: dict = Field(default_factory=dict)
    database_revision: dict = Field(default_factory=dict)
    status: Literal["ok", "reused", "failed", "missing"]
    reason: str | None = None
    files: dict = Field(default_factory=dict)


class Report(_Model):
    run_id: str
    scenario: str
    trigger_source: Literal["schedule", "manual", "web", "intel-watch"]
    scope: Literal["daily", "advisory", "scenario"]
    target_sha: str
    completeness: Literal["complete", "partial", "failed"]
    data_issues: list[dict]
    generated_at: str
    as_of: str
    light: Literal["red", "yellow", "green"]
    light_reasons: list[str]
    ceo_summary: list[str]
    decisions: list[str]
    counts: dict
    coverage: dict
    risks: list[Risk]
    events: list[dict]
    proposed_controls: list[dict]
    open_alerts: list[Alert]
    intel_summary: dict
    daily_intel_status: Literal["ok", "failed", "skipped", "replay"]
    cost: dict
    signals: list[dict] = Field(default_factory=list)
    reconcile: list[dict] = Field(default_factory=list)
    app_impact: dict = Field(default_factory=dict)
    execution_mode: Literal["replay", "record", "live", "template"] = "template"


class IntelWatchResult(_Model):
    checked_at: str
    advisories_checked: int
    hits: list[dict]
    dispatched: bool
    items: list[dict]
