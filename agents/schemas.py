"""資料格式（第 9 節）。所有 Agent 的輸入輸出都以這些 pydantic 模型驗證。"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

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
    explanation: str | None = None             # A2／A4 Subagent 的說明文字（不影響分數）
    explanation_source: ResultSource | None = None
    level_floor: Level | None = None           # 規則下限（網站權重試算用）
    provisional_basis: bool = False            # 暫定情資：最高只到中


class ScoringFactors(_Model):
    """rules/scoring.json 的加分因子；範圍與 tools/scoring.py、dashboard/lib/scoring-limits.json 一致。"""
    known_exploited: int = Field(ge=0, le=5)
    exposed: int = Field(ge=0, le=5)
    data_sensitive: int = Field(ge=0, le=5)
    platform: int = Field(ge=0, le=5)
    peer_event: int = Field(ge=0, le=5)
    on_attack_chain: int = Field(ge=0, le=5)
    eol_no_fix: int = Field(ge=0, le=5)
    compensating: int = Field(ge=-5, le=0)


class ScoringThresholds(_Model):
    high: int = Field(ge=2, le=15)
    medium: int = Field(ge=1, le=14)

    @model_validator(mode="after")
    def _order(self):
        if self.medium >= self.high:
            raise ValueError("中門檻必須小於高門檻")
        return self


class ScoringConfig(_Model):
    version: int = Field(ge=1)
    factors: ScoringFactors
    thresholds: ScoringThresholds
    updated_at: str | None = None
    updated_by: str | None = None
    reason: str | None = None


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
    verification_basis: Literal["live", "archived", "demo", "unverified", "official_api"] = "unverified"


class EntryPoint(_Model):
    """daily-intel 的 AI 推測「可能從哪裡進來」（specs/check-hints R4）：只用於顯示，不進比對與評分。"""
    topic: str | None = None                       # rules/check-hints.json 的 target ID
    text: str = Field(min_length=1, max_length=100)
    basis: str = Field(min_length=1, max_length=120)


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
    # 只有 daily-intel 入口可帶（pipeline.event_sources 移除其他來源的這個欄位，R4.6）
    possible_entry_points: list[EntryPoint] = Field(default_factory=list, max_length=3)


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
    suggestions: list[dict] = Field(default_factory=list)   # 查核建議：只有 need_check 有內容；由 tools/check_hints 產生（specs/check-hints）


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
    scoring: dict | None = None                # 本次使用的燈號權重（rules/scoring.json）
    execution_mode: Literal["replay", "record", "live", "template"] = "template"
    agent_plan: dict | None = None             # 動態派工：AI 建議、程式核准的計數與明細（不影響分數、燈號、結論）


class IntelWatchResult(_Model):
    checked_at: str
    advisories_checked: int
    hits: list[dict]
    dispatched: bool
    items: list[dict]


# ── 資安事件整理（0.10.0，specs/security-digest）：dashboard/public/data/digest/ 的三份公開檔案 ──
# 收錄時間（first_seen／last_seen_at）、完整評估時間（assessment.evaluated_at）與實際產生時間（updated_at）分開記錄。
DigestRelation = Literal["affected", "need_check", "not_affected", "fixed"]
_DATE = r"^\d{4}-\d{2}-\d{2}$"
_UTC = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
_SHA256 = r"^[0-9a-f]{64}$"


class DigestSource(_Model):
    title: str
    domain: str | None                         # 媒體網域（可公開）；網址無法安全清理時仍保留
    url: str | None                            # 只接受 http(s)、無 userinfo、已移除敏感參數；否則 None
    verified: bool


class DigestImpact(_Model):
    asset_id: str                              # 內部索引用，不直接顯示
    asset_label: str                           # 可公開名稱；找不到為「未命名系統」，"*" 為「待確認系統」
    verdict: Literal["affected", "not_affected", "need_check"]
    level: Level | None                        # 由同份報告 blocks 依 (asset_id, verdict) 對應；StackImpact 本身沒有 level


class DigestAssessment(_Model):
    """最近一次完整評估的不可拆分快照：整組替換，不與其他 run 混用。"""
    evaluated_at: str = Field(pattern=_UTC)
    run_id: str
    relation: DigestRelation
    max_level: Level | None
    affected_count: int = Field(ge=0)
    conclusion: str
    impacts: list[DigestImpact] = Field(max_length=20)
    impacts_total: int = Field(ge=0)
    impacts_truncated: bool
    relation_changed_at: str | None = Field(default=None, pattern=_UTC)

    @model_validator(mode="after")
    def _truncation(self):
        if self.impacts_total < len(self.impacts) or self.impacts_truncated != (self.impacts_total > len(self.impacts)):
            raise ValueError("impacts_total／impacts_truncated 與實際筆數不一致")
        return self


class DigestEvent(_Model):
    id: str
    kind: Literal["live", "archive", "advisory"]   # 不收 demo
    title: str
    event_date: str | None = Field(pattern=_DATE)
    first_seen: str = Field(pattern=_DATE)         # 第一次被 daily 看到的台灣日期，之後不變
    last_seen: str = Field(pattern=_DATE)
    last_seen_at: str = Field(pattern=_UTC)        # 最後一次觀察的 UTC 時間（該次 as_of）
    observed_run_id: str
    confidence: Literal["confirmed", "provisional"]
    is_update_of: str | None
    cves: list[str]
    summary: str = Field(max_length=300)
    sources: list[DigestSource]
    assessment: DigestAssessment | None            # 只有不完整收錄紀錄時為 None（待評估，不進 latest）


class DigestIssue(_Model):
    code: Literal["capacity", "pending_assessment", "future_first_seen", "invalid_update_link", "seen_size",
                  "merge_conflict", "invalid_candidate", "asset_labels_invalid"]
    impact: str                                    # 白話說明，網站可直接顯示
    omitted: int = Field(default=0, ge=0)          # 省略／受影響的事件數
    date: str | None = Field(default=None, pattern=_DATE)


class DigestStore(_Model):
    schema_version: Literal[1] = 1
    updated_at: str = Field(pattern=_UTC)
    data_issues: list[DigestIssue] = Field(default_factory=list)
    events: dict[str, DigestEvent]

    @model_validator(mode="after")
    def _keys(self):
        for k, ev in self.events.items():
            if k != ev.id:
                raise ValueError("events 的鍵必須等於事件 ID")
        return self


class DigestSeen(_Model):
    """最小去重紀錄：只有 sha256(UTF-8 事件 ID) → 首次收錄日期。不含任何事件內容；雜湊不是保密措施。"""
    schema_version: Literal[1] = 1
    first_seen_by_key: dict[str, str]

    @model_validator(mode="after")
    def _entries(self):
        for k, v in self.first_seen_by_key.items():
            if not re.match(_SHA256, k) or not re.match(_DATE, v):
                raise ValueError("seen 只能包含 sha256 鍵與 YYYY-MM-DD 日期")
        return self


class DigestLatestEvent(DigestEvent):
    assessment: DigestAssessment                   # latest 只發布有完整評估的事件
    updates: list[DigestLatestEvent] = Field(default_factory=list)   # 新進度（子事件），子事件本身不再巢狀
    standalone_reason: Literal["parent_missing", "link_invalid"] | None = None   # 有 is_update_of 卻獨立顯示的原因


class DigestDay(_Model):
    date: str = Field(pattern=_DATE)
    count: int = Field(ge=0)                       # 唯一事件 ID 數（含 updates）
    events: list[DigestLatestEvent]


class DigestCounts(_Model):
    total: int = Field(ge=0)
    affected: int = Field(ge=0)
    need_check: int = Field(ge=0)
    not_affected: int = Field(ge=0)
    fixed: int = Field(ge=0)


class DigestLatest(_Model):
    schema_version: Literal[1] = 1
    updated_at: str = Field(pattern=_UTC)          # 本次整理實際成功產生的 UTC 時間
    as_of: str = Field(pattern=_UTC)               # 本次評估的邏輯時間
    run_id: str
    next_update_at: str = Field(pattern=_UTC)      # 嚴格晚於 updated_at 的下一個 UTC 00:00（台灣 08:00）
    daily_intel_status: Literal["ok", "failed", "skipped", "replay"]   # 只代表快照產生時；網站須另讀最新 daily
    window_days: Literal[30] = 30
    data_issues: list[DigestIssue] = Field(default_factory=list)
    counts: DigestCounts
    days: list[DigestDay]
