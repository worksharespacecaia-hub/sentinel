"""Orchestrator 的核准政策（specs/orchestrator design §3.2；由 v0.11.0 動態派工的 agent_plan 擴充）。純規則層，不呼叫 LLM、不連網路。

- AI（orchestrator-dispatch 的 planner、orchestrator-review 的 reviewer）只能提案：追加任務與排優先。必要任務一定照跑，
  不能省略任何 AI 說明，也不能跳過檢查；結果不影響分數、燈號與結論
- 程式從本次可信資料算出政策上下文（PolicyContext），逐項核准：欄位白名單、範圍、資格、上限、去重；每項拒絕附白話原因
- 計畫檔（schema_version 2）綁定本次執行識別與 A1 verified 雜湊。建立（派工、驗收 Job）與載入核對（A2～A5、llm-plan）
  共用 approve_core（R5.1）；載入時必須完全重現檔案中的 approved，否則只停用那一份（R5.1a）

模組載入時只匯入 tools.common；pipeline、registry、digest、stack 等在函式內延遲匯入（pipeline 也會匯入本模組，避免循環匯入）。
"""
from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import asdict, dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tools.common import SECRET_RE, sha256_json, stable_id

if TYPE_CHECKING:  # pragma: no cover
    from context import RunCtx

__all__ = [
    "CATEGORY_ZH", "OUTCOME_AGENTS", "OUTCOME_FILE", "OUTCOME_READ_REASONS", "OUTCOME_REASONS", "OUTCOME_STATUSES",
    "OUTCOME_UNKNOWN", "outcome_key", "outcome_row", "read_outcomes", "safe_id", "write_outcomes",
    "A2_EVENT_CATEGORY", "BaseInputs", "CONTROL_KEYS", "DISPATCH_KEYS", "DISPATCH_TASKS", "LEVEL_RANK", "MAX_A2_FINDINGS",
    "MAX_A3_SYSTEMS", "MAX_A4_BASELINE", "MAX_A5_CEO", "MAX_A5_REMEDIATION", "MAX_CHAIN", "MAX_CTRL_PER_EVENT", "MAX_CTRL_TOTAL",
    "MAX_DISPATCH_TASKS", "MAX_EVENTS", "MAX_PRIORITIES", "MAX_REASON", "MAX_REVIEW_TASKS", "MAX_RISKS_PER_TASK", "MAX_SUMMARY",
    "MAX_TEXT", "MENUS", "MODES", "NOTE_NO_PREV", "NOTE_PENDING", "PEER_KINDS", "PLAN_DIRS", "PLAN_FILES", "PRIORITY_AGENT",
    "PRIORITY_KEYS", "PolicyContext", "REASONS", "REASON_HELP", "REVIEW_KEYS", "REVIEW_TASKS", "RISK_TASK_KEYS", "Resolved",
    "R_BASELINE", "R_CONTROL", "R_DUP", "R_EVENT", "R_FIELDS", "R_LIMIT", "R_MAPPED", "R_NOTICE_NEEDED", "R_NOT_KEYROT",
    "R_NOT_NEED_CHECK", "R_NO_TARGET", "R_ONLY_ADD", "R_PRIORITY", "R_REASON", "R_SUMMARY", "R_TASK", "SCHEMA_VERSION", "SHA_RE",
    "SOURCES", "SOURCE_TEXT", "STATUS_TEXT", "TASK_KEYS", "TASK_LIMITS", "TOP_KEYS",
    "a2_candidates", "a3_systems", "a4_baseline", "a4_extra_candidates", "a5_lists", "ai_asset_ids", "approve", "approve_core",
    "base_inputs", "blocked_text", "build_plan", "clean_summary", "control_titles", "counts", "dispatch_context",
    "evaluate_snapshot",
    "effective_events", "empty_plan", "event_relations", "keyrot_candidates", "load_verified", "new_peer_events",
    "pending_plan", "pick_extra_risks", "plan_items", "plan_path", "planner_checks", "prev_daily_ids", "public_plan",
    "public_safe", "read_plan", "resolve_plans", "review_context", "run_ident", "safe_text", "scope_events",
    "validate_plan_shape", "validate_review_shape", "write_plan",
]

# ---------------------------------------------------------------- 上限與選單
MAX_EVENTS = 5                     # 每日與情境：最新的 5 件新同業事件
MAX_CTRL_PER_EVENT, MAX_CTRL_TOTAL = 3, 8
MAX_DISPATCH_TASKS, MAX_REVIEW_TASKS, MAX_PRIORITIES = 5, 3, 5
MAX_REASON, MAX_SUMMARY = 120, 300
MAX_RISKS_PER_TASK = 3             # A4 追加說明：每件事件最多 3 個風險（pick_extra_risks）
MAX_A2_FINDINGS = 12               # A2 事件導向解讀：每項最多 12 個 finding（R3.2）
MAX_A3_SYSTEMS = 5                 # A3 回溯搜查：最多 5 個系統（R3.3）
MAX_A4_BASELINE = 10               # A4 必要任務：前 10 個高風險
MAX_A5_REMEDIATION, MAX_A5_CEO = 12, 5
MAX_TEXT, MAX_CHAIN = 120, 5
SCHEMA_VERSION = 2

MODES = ("dispatch", "review")
DISPATCH_KEYS = ("extra_controls", "extra_tasks", "priorities")
REVIEW_KEYS = ("extra_tasks", "priorities", "summary")
TOP_KEYS = DISPATCH_KEYS            # 舊名：daily_intel.load_daily_plan 仍在用（T4 移除）
CONTROL_KEYS = frozenset({"event_id", "control_id", "reason"})
TASK_KEYS = frozenset({"agent", "subagent", "event_id", "reason"})
RISK_TASK_KEYS = frozenset({"agent", "subagent", "risk_id", "reason"})
PRIORITY_KEYS = frozenset({"agent", "risk_id", "reason"})
KIND_OF = {"extra_controls": "control", "extra_tasks": "task", "priorities": "priority", "summary": "summary"}

# (agent, subagent) → 目標類型與用途（policy.md 由這裡產生）
DISPATCH_TASKS: dict[tuple[str, str], dict] = {
    ("a2", "dependency-analyst"): {"target": "event", "what": "依事件解讀相同產品的套件漏洞（程式挑選項目，最多 12 項）"},
    ("a2", "runtime-analyst"): {"target": "event", "what": "依事件解讀相同產品的執行環境與支援期限（程式挑選項目，最多 12 項）"},
    ("a3", "retro-hunter"): {"target": "event",
                             "what": "回溯搜查事件日期前 7 天到現在、相關系統的登入與資料庫紀錄（只限每日與情境；公告調查本來就會跑）"},
    ("a4", "impact-analyst"): {"target": "event", "what": "說明與此事件相關的風險影響（程式挑選風險，每件最多 3 個）"},
}
REVIEW_TASKS: dict[tuple[str, str], dict] = {
    ("a5", "intel-report-writer"): {"target": "event", "what": "為需確認的事件撰寫情資報告摘要"},
    ("a5", "key-rotation-advisor"): {"target": "risk", "what": "為本次事件相關、必要任務沒有涵蓋的金鑰風險撰寫輪替建議"},
    ("a5", "brand-notice-writer"): {"target": "event",
                                    "what": "為受影響、但程式未要求通知的事件撰寫通知草稿（另外標示，不改變是否需要通知）"},
}
MENUS = {"dispatch": DISPATCH_TASKS, "review": REVIEW_TASKS}
TASK_LIMITS = {"dispatch": MAX_DISPATCH_TASKS, "review": MAX_REVIEW_TASKS}
PRIORITY_AGENT = {"dispatch": "a4", "review": "a5"}
A2_EVENT_CATEGORY = {"dependency-analyst": "vuln", "runtime-analyst": "eol"}   # 與 agents.common.CATEGORY_SUBAGENT 一致（測試核對）

# 風險類別的白話（給 AI 的風險標籤「類別：系統名稱」，design §4；風險標題含存放位置，不交給 AI）
CATEGORY_ZH = {"vuln": "套件漏洞", "secret": "金鑰外洩", "config": "設定缺失", "eol": "停止支援", "identity": "身分與權杖",
               "backup": "備份韌性", "shadow_it": "未登記的系統", "signal": "早期訊號", "mobile": "App 設定",
               "clone_app": "山寨 App", "shadow_api": "影子 API"}

PEER_KINDS = ("live", "demo")
SOURCES = ("subscription", "live", "replay", "template", "skipped")
SOURCE_TEXT = {"subscription": "訂閱方案", "live": "即時呼叫", "replay": "重播錄製", "template": "程式範本", "skipped": "未觸發"}
STATUS_TEXT = {"pass": "符合", "fail": "不符合", "unknown": "資料不足"}
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PLAN_DIRS = {"dispatch": "orchestrator-dispatch", "review": "orchestrator-review"}
PLAN_FILES = {"dispatch": "dispatch-plan.json", "review": "review-plan.json"}
MAX_NOTE = 300

# ---------------------------------------------------------------- 拒絕原因（每項只保留第一個）
R_ONLY_ADD = "只能追加，不能關閉或改變必要評估"
R_FIELDS = "欄位缺漏或格式不符"
R_EVENT = "事件不在本次範圍"
R_CONTROL = "不在控制項清單"
R_TASK = "不在可追加的工作清單"
R_MAPPED = "事件已對應此控制項"
R_REASON = "缺少理由"
R_DUP = "重複的建議"
R_LIMIT = "超過上限"
R_NO_TARGET = "沒有符合條件的對象"
R_BASELINE = "必要任務已包含"
R_PRIORITY = "不在可排優先的清單"
R_NOT_NEED_CHECK = "事件不是需確認"
R_NOT_KEYROT = "不是本次相關的金鑰風險"
R_NOTICE_NEEDED = "程式已要求通知"
R_SUMMARY = "摘要含不允許的內容"
REASON_HELP = {
    R_ONLY_ADD: "頂層有規定以外的欄位，或某一項多寫了欄位（整項拒絕，不會移除欄位後核准）",
    R_FIELDS: "缺少必要欄位，或欄位不是字串",
    R_EVENT: "事件不在本次範圍（每日與情境：最新的 5 件新同業事件；公告調查：本次公告）",
    R_CONTROL: "控制項 ID 不在控制項清單",
    R_MAPPED: "事件已經直接對應這個控制項",
    R_TASK: "agent 與 subagent 不在本模式可追加的任務清單",
    R_NO_TARGET: "程式依本次資料挑不出可以處理的對象",
    R_BASELINE: "必要任務已經包含這項工作",
    R_PRIORITY: "排優先的風險不在可排優先的清單，或 agent 不對",
    R_NOT_NEED_CHECK: "事件不是需確認",
    R_NOT_KEYROT: "風險不是本次事件相關、必要任務沒有涵蓋的金鑰風險",
    R_NOTICE_NEEDED: "程式已經要求這件事件發通知",
    R_SUMMARY: "執行摘要含金鑰、個資、檔案路徑、IP、連接埠、設定鍵或控制項 ID 等不允許的內容",
    R_REASON: "理由空白",
    R_DUP: "同一項重複提出",
    R_LIMIT: "超過數量或字數上限（被拒絕的項目不佔配額）",
}
REASONS = frozenset(REASON_HELP)
NOTE_NO_PREV = "讀不到上次清單，本次同業事件全部視為新事件"
NOTE_PENDING = "處理未完成"


# ---------------------------------------------------------------- 文字
def safe_text(value, limit: int = MAX_TEXT) -> str | None:
    """公開文字：去控制字元、遮蔽金鑰與個資後再截斷；仍疑似機敏或空白時回傳 None。"""
    if not isinstance(value, str):
        return None
    from tools.digest import has_sensitive, public_text   # 延遲匯入：digest 會匯入 llm
    text = public_text(value, limit)
    if not text or SECRET_RE.search(text) or has_sensitive(text):
        return None
    return text


def blocked_text(text: str) -> bool:
    """像檔案路徑、設定鍵、控制項 ID、連接埠或 IP 的文字（design §4 的投影規則，給 AI 與公開的文字共用）。"""
    from tools.digest import _INTERNAL_TOKEN_RE, SUGGESTION_BLOCK_RE
    from tools.stack import _has_ip
    return bool(SUGGESTION_BLOCK_RE.search(text) or _INTERNAL_TOKEN_RE.search(text) or _has_ip(text))


def public_safe(value, limit: int = MAX_TEXT) -> str | None:
    """safe_text 之後，若仍命中 blocked_text 就整段丟掉（不嘗試修補）。"""
    text = safe_text(value, limit)
    return None if text is None or blocked_text(text) else text


# 給 AI 的 ID（事件、風險）：只能是程式產生的識別字串。ID 以「:」分段，每段是一般代號或 npm scoped 套件名稱；
# 含空白、檔案副檔名、連接埠、IP、反斜線、# 或機敏內容的 ID 整筆不交給 AI（不嘗試修補）
_ID_SEG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_ID_SCOPED_RE = re.compile(r"@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*")
_ID_FILE_RE = re.compile(r"\.(?:json|jsonl|ya?ml|tsx?|jsx?|py|csv|php|conf|env|tf|xml|gradle|ini|toml|sh|pem|key|p12|jks|crt)"
                         r"(?![A-Za-z0-9])", re.I)
MAX_ID = 160


def safe_id(value) -> bool:
    """事件 ID、風險 ID 能不能原樣交給 AI（design §4 的投影；R2.3 不得含路徑、IP、連接埠、金鑰與個資）。"""
    if not isinstance(value, str) or not 0 < len(value) <= MAX_ID:
        return False
    from tools.digest import has_sensitive
    from tools.stack import _has_ip
    if SECRET_RE.search(value) or has_sensitive(value) or _has_ip(value) or _ID_FILE_RE.search(value):
        return False
    parts = value.split(":")
    return all((_ID_SEG_RE.fullmatch(p) and not re.fullmatch(r"\d{2,5}", p)) or _ID_SCOPED_RE.fullmatch(p) for p in parts)


def clean_summary(value) -> tuple[str | None, str | None]:
    """驗收的執行摘要（R4.3）：回傳（文字, 拒絕原因）。含機敏或不允許的內容整段拒絕，不遮蔽後採用；超過 300 字拒絕，不截斷。"""
    if not isinstance(value, str) or not value.strip():
        return None, R_FIELDS
    from tools.digest import has_sensitive, public_text
    if SECRET_RE.search(value) or has_sensitive(value):
        return None, R_SUMMARY
    text = public_text(value, 10 ** 6)                    # 只合併空白與移除控制字元（上面已確認沒有要遮蔽的內容）
    if blocked_text(text):
        return None, R_SUMMARY
    if len(text) > MAX_SUMMARY:
        return None, R_LIMIT
    return text, None


def _strip(item: dict, key: str):
    v = item.get(key)
    return v.strip() if isinstance(v, str) else v


# ---------------------------------------------------------------- 事件範圍
def _event_of(v):
    return v.get("event") if isinstance(v, dict) and isinstance(v.get("event"), dict) else None


def effective_events(verified: list[dict]) -> list[dict]:
    """A1 verified 的事件獨立拷貝，套用既有的新進度繼承（控制項取聯集）；不修改原始 verified。"""
    from tools.intel_match import inherit_updates
    events = [copy.deepcopy(e) for e in (_event_of(v) for v in verified) if e is not None]
    inherit_updates(events)
    return events


def _date_key(ev: dict):
    d = ev.get("date")
    if isinstance(d, str) and DATE_RE.match(d):
        try:
            return date.fromisoformat(d)
        except ValueError:
            return None
    return None


def new_peer_events(events: list[dict], prev_ids: set[str] | None) -> tuple[list[dict], str | None]:
    """選出本次的新同業事件（最多 5 件）。prev_ids=None 表示讀不到上次清單：本次 live／demo 全部視為新事件。"""
    notes = []
    if prev_ids is None:
        notes.append(NOTE_NO_PREV)
    seen, cands = set(), []
    for ev in events:
        eid = ev.get("id")
        if ev.get("kind") not in PEER_KINDS or not isinstance(eid, str) or not eid or eid in seen:
            continue
        seen.add(eid)
        if prev_ids is not None and eid in prev_ids:
            continue
        cands.append(ev)
    valid = sorted((e for e in cands if _date_key(e)), key=lambda e: e["id"])
    valid.sort(key=_date_key, reverse=True)
    invalid = sorted((e for e in cands if not _date_key(e)), key=lambda e: e["id"])
    if invalid:
        notes.append(f"{len(invalid)} 件同業事件日期無效，排在最後")
    return [*valid, *invalid][:MAX_EVENTS], ("；".join(notes) or None)


def prev_daily_ids(data_dir: Path) -> set[str] | None:
    """上次 daily 的事件 ID（daily/state/intel.json 的 events[*].id）。缺檔、壞檔或結構錯誤回傳 None。"""
    try:
        data = json.loads((Path(data_dir) / "daily" / "state" / "intel.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    events = data.get("events") if isinstance(data, dict) else None
    if not isinstance(events, list):
        return None
    ids = set()
    for e in events:
        eid = e.get("id") if isinstance(e, dict) else None
        if not isinstance(eid, str):
            return None
        ids.add(eid)
    return ids


def scope_events(verified: list[dict], *, scope: str, prev_ids: set[str] | None,
                 advisory_id: str | None = None) -> tuple[list[dict], str | None]:
    """本次可核准的事件範圍（R2.1）：每日與情境為 new_peer_events；公告調查為本次 advisory_id 對應的公告事件。"""
    events = effective_events(verified)
    if scope == "advisory":
        hit = [e for e in events if e.get("kind") == "advisory" and isinstance(advisory_id, str) and e.get("id") == advisory_id]
        return hit[:1], None
    return new_peer_events(events, prev_ids)


# ---------------------------------------------------------------- 政策上下文
@dataclass
class PolicyContext:
    """程式從本次可信資料算出的「可以核准的對象」（design §3.2）。清單一律穩定排序，不依賴雜湊順序。"""
    mode: str                                                            # dispatch | review
    events: dict[str, dict] = field(default_factory=dict)                # 範圍內事件（id → 有效事件，依範圍順序）
    controls: dict[str, str] = field(default_factory=dict)               # id → 標題（dispatch）
    a2: dict[str, dict[str, list[str]]] = field(default_factory=dict)    # event_id → subagent → finding ids
    a3: dict[str, list[str]] = field(default_factory=dict)               # event_id → retro 對象系統
    a4_baseline: list[str] = field(default_factory=list)                 # highs[:10] 的 id
    a4_extra: dict[str, list[str]] = field(default_factory=dict)         # event_id → pick_extra_risks 的 id
    need_check: list[str] = field(default_factory=list)                  # review：需確認事件
    keyrot: list[str] = field(default_factory=list)                      # review：金鑰輪替候選風險
    notice: list[str] = field(default_factory=list)                      # review：通知草稿候選事件
    a5_remediation: list[str] = field(default_factory=list)              # review：A5 解法清單（前 12）
    a5_ceo: list[str] = field(default_factory=list)                      # review：CEO 摘要參考清單（前 5）
    # 以下為 design §3.2 之外補充的欄位：拒絕原因與範圍註記需要
    scope: str = "scenario"                                              # daily | scenario | advisory（advisory 的 retro 是必要任務）
    notice_needed: list[str] = field(default_factory=list)               # review：程式已要求通知的事件（拒絕原因「程式已要求通知」）
    note: str | None = None                                              # 範圍註記（例如讀不到上次清單）

    def known_risks(self) -> set[str]:
        """拒絕明細可以保留的風險 ID（只限本次上下文中出現過的，避免保存 AI 編造的字串）。"""
        return {*self.a4_baseline, *(r for v in self.a4_extra.values() for r in v), *self.keyrot, *self.a5_remediation,
                *self.a5_ceo}

    def to_json(self) -> dict:
        return asdict(self)


def control_titles() -> dict[str, str]:
    from tools.controls import load_controls
    return {c["id"]: c["title"] for c in sorted(load_controls(), key=lambda c: c["id"])}


def ai_asset_ids(res: dict) -> set[str]:
    """可以給 AI 的系統 ID（與 stack.json、check_hints 共用 stack.ai_assets）。"""
    from tools.stack import ai_assets
    return {a["id"] for a in ai_assets(res["graph"], None)}


def _impact_systems(match: dict | None) -> set[str]:
    """事件受影響或需確認的系統（不含 `*`）。"""
    return {i["asset_id"] for i in (match or {}).get("impacts") or []
            if i.get("verdict") in ("affected", "need_check") and isinstance(i.get("asset_id"), str) and i["asset_id"] != "*"}


def _hypothesis_systems(match: dict | None) -> set[str]:
    """破口推測（check_hints 的 inferred 建議）挑出的系統。"""
    out = set()
    for i in (match or {}).get("impacts") or []:
        for s in i.get("suggestions") or []:
            if isinstance(s, dict) and s.get("inferred") is True:
                out |= {x["asset_id"] for x in s.get("systems") or [] if isinstance(x, dict) and isinstance(x.get("asset_id"), str)}
    return out


def a2_candidates(events: list[dict], matches: dict[str, dict], findings: list[dict]) -> dict[str, dict[str, list[str]]]:
    """A2 事件導向解讀的對象（R3.2）：產品名稱與 finding component 正規化後相同、類別對應 Subagent、資產是事件受影響或需確認的系統。"""
    from tools.aliases import normalize
    out: dict[str, dict[str, list[str]]] = {}
    for ev in events:
        names = {normalize(p.get("name")) for p in ev.get("products") or [] if isinstance(p, dict) and isinstance(p.get("name"), str)}
        names.discard(None)
        systems = _impact_systems(matches.get(ev["id"]))
        per = {}
        for sub, cat in sorted(A2_EVENT_CATEGORY.items()):
            hits: dict[str, dict] = {}
            for f in findings:
                if (f.get("category") == cat and isinstance(f.get("id"), str) and f.get("asset_id") in systems
                        and normalize(f.get("component")) in names):
                    hits.setdefault(f["id"], f)
            ids = [f["id"] for f in sorted(hits.values(), key=lambda f: (f["asset_id"], f["id"]))][:MAX_A2_FINDINGS]
            if ids:
                per[sub] = ids
        if per:
            out[ev["id"]] = per
    return out


def a3_systems(events: list[dict], matches: dict[str, dict], assets: set[str]) -> dict[str, list[str]]:
    """A3 回溯搜查的系統（R3.3 的系統部分；紀錄篩選屬 tools/retro.py）：受影響或需確認＋破口推測的系統，只取 ai_assets。"""
    out = {}
    for ev in events:
        m = matches.get(ev["id"])
        systems = sorted((_impact_systems(m) | _hypothesis_systems(m)) & set(assets))[:MAX_A3_SYSTEMS]
        if systems:
            out[ev["id"]] = systems
    return out


def a4_baseline(risks: list[dict]) -> list[str]:
    """A4 必要任務：前 10 個未修復的高風險（與 a4_risk.run 相同順序）。"""
    return [r["id"] for r in risks if r.get("level") == "high" and r.get("status") != "fixed"][:MAX_A4_BASELINE]


def a4_extra_candidates(events: list[dict], matches: dict[str, dict], risks: list[dict],
                        baseline: list[str]) -> dict[str, list[str]]:
    """A4 追加說明的對象（R3.4，pick_extra_risks）。每件事件各自計算（只排除必要任務）；跨事件去重由 A4 執行時處理。"""
    out = {}
    for ev in events:
        picked = pick_extra_risks(ev["id"], risks, (matches.get(ev["id"]) or {}).get("planner_checks") or [], set(baseline))
        if picked:
            out[ev["id"]] = [r["id"] for r in picked]
    return out


def a5_lists(risks: list[dict]) -> tuple[list[str], list[str], set[str]]:
    """A5 的必要清單（與 a5_report._llm_texts 相同）：解法前 12、CEO 摘要前 5，以及必要任務已涵蓋的金鑰風險。"""
    a5 = [r for r in risks if r.get("level") in ("high", "medium") and r.get("status") != "fixed"]
    keyrot = {r["id"] for r in a5 if r.get("category") in ("secret", "identity")}
    return [r["id"] for r in a5[:MAX_A5_REMEDIATION]], [r["id"] for r in a5[:MAX_A5_CEO]], keyrot


def keyrot_candidates(events: list[dict], matches: dict[str, dict], risks: list[dict]) -> list[str]:
    """金鑰輪替候選（R4.1）：secret／identity、未修復、不在 A5 必要任務，且和本次事件相關（命中事件，或資產在事件的影響或推測系統）。"""
    _, _, baseline = a5_lists(risks)
    ids = {ev["id"] for ev in events}
    systems = set()
    for ev in events:
        m = matches.get(ev["id"])
        systems |= _impact_systems(m) | _hypothesis_systems(m)
    return [r["id"] for r in risks
            if r.get("category") in ("secret", "identity") and r.get("status") != "fixed" and r["id"] not in baseline
            and (ids & set(r.get("matched_events") or []) or r.get("asset_id") in systems)]


def event_relations(events: list[dict], matches: dict[str, dict], risks: list[dict]) -> dict[str, tuple[str, bool]]:
    """事件 ID → （情資報告的處理狀態, 程式是否要求通知）。與 intel_report.build_report 共用 event_status。"""
    from tools.intel_report import event_status
    by_id = {r["id"]: r for r in risks}
    return {ev["id"]: event_status(matches[ev["id"]], by_id) for ev in events if ev["id"] in matches}


def dispatch_context(verified: list[dict], res: dict, *, scope: str, prev_ids: set[str] | None, assets: set[str] | None = None,
                     advisory_id: str | None = None) -> PolicyContext:
    """派工的政策上下文（R2.1）。res 是同一份輸入的評估快照（已含核准 control 的 planner_checks）。"""
    events, note = scope_events(verified, scope=scope, prev_ids=prev_ids, advisory_id=advisory_id)
    matches = {m["event"]["id"]: m for m in res.get("matches") or []}
    base = a4_baseline(res["risks"])
    return PolicyContext(
        mode="dispatch", scope=scope, note=note, events={e["id"]: e for e in events}, controls=control_titles(),
        a2=a2_candidates(events, matches, res.get("findings") or []),
        a3=a3_systems(events, matches, ai_asset_ids(res) if assets is None else set(assets)) if scope != "advisory" else {},
        a4_baseline=base, a4_extra=a4_extra_candidates(events, matches, res["risks"], base))


def review_context(verified: list[dict], res: dict, *, scope: str, prev_ids: set[str] | None, assets: set[str] | None = None,
                   advisory_id: str | None = None) -> PolicyContext:
    """驗收的政策上下文（R4.1）。res 是 resolve_plans 解析後的評估（派工單有效時含其 control）。assets 保留給投影使用。"""
    del assets
    events, note = scope_events(verified, scope=scope, prev_ids=prev_ids, advisory_id=advisory_id)
    matches = {m["event"]["id"]: m for m in res.get("matches") or []}
    rel = event_relations(events, matches, res["risks"])
    remediation, ceo, _ = a5_lists(res["risks"])
    return PolicyContext(
        mode="review", scope=scope, note=note, events={e["id"]: e for e in events},
        need_check=[e["id"] for e in events if rel.get(e["id"], ("", False))[0] == "need_check"],
        keyrot=keyrot_candidates(events, matches, res["risks"]),
        notice=[e["id"] for e in events if rel.get(e["id"]) == ("open", False)],
        notice_needed=[e["id"] for e in events if rel.get(e["id"]) == ("open", True)],
        a5_remediation=remediation, a5_ceo=ceo)


# ---------------------------------------------------------------- 格式與核准
def _check_lists(output: dict, keys: tuple[str, ...]) -> None:
    for k in keys:
        if k in output:
            if not isinstance(output[k], list):
                raise ValueError(f"{k} 需要陣列")
            if any(not isinstance(i, dict) for i in output[k]):
                raise ValueError(f"{k} 的元素需要物件")


def validate_plan_shape(output) -> dict:
    """派工提案的整份格式檢查：物件、三個可省略的陣列、物件元素、不含機敏值。未知鍵與欄位錯誤留給 approve 逐項拒絕。"""
    if not isinstance(output, dict):
        raise ValueError("需要 JSON 物件")
    _check_lists(output, DISPATCH_KEYS)
    if SECRET_RE.search(json.dumps(output, ensure_ascii=False, default=str)):
        raise ValueError("輸出含疑似機敏值")
    return output


def validate_review_shape(output) -> dict:
    """驗收提案的整份格式檢查：物件、extra_tasks／priorities 為物件陣列、summary 為字串、不含機敏值。"""
    if not isinstance(output, dict):
        raise ValueError("需要 JSON 物件")
    _check_lists(output, ("extra_tasks", "priorities"))
    if "summary" in output and not isinstance(output["summary"], str):
        raise ValueError("summary 需要字串")
    if SECRET_RE.search(json.dumps(output, ensure_ascii=False, default=str)):
        raise ValueError("輸出含疑似機敏值")
    return output


def _registry_ok(agent: str, subagent: str) -> bool:
    from registry import AGENTS
    return agent in AGENTS and subagent in AGENTS[agent].subagents


def _task_ineligible(pair: tuple[str, str], target: str, ctx: PolicyContext) -> str | None:
    """各任務的資格（依政策上下文）；回傳拒絕原因，None 表示符合。"""
    agent, sub = pair
    if agent == "a2":
        return None if (ctx.a2.get(target) or {}).get(sub) else R_NO_TARGET
    if pair == ("a3", "retro-hunter"):
        if ctx.scope == "advisory":
            return R_BASELINE
        return None if ctx.a3.get(target) else R_NO_TARGET
    if pair == ("a4", "impact-analyst"):
        return None if ctx.a4_extra.get(target) else R_NO_TARGET
    if pair == ("a5", "intel-report-writer"):
        return None if target in ctx.need_check else R_NOT_NEED_CHECK
    if pair == ("a5", "key-rotation-advisor"):
        return None if target in ctx.keyrot else R_NOT_KEYROT
    if pair == ("a5", "brand-notice-writer"):
        if target in ctx.notice:
            return None
        return R_NOTICE_NEEDED if target in ctx.notice_needed else R_NO_TARGET
    return R_TASK


class _Approval:
    """approve 的累計狀態：核准、拒絕、配額與去重。"""

    def __init__(self, ctx: PolicyContext):
        self.ctx, self.approved, self.rejected = ctx, [], []
        self.risks = ctx.known_risks()

    def reject(self, kind: str, item: dict, reason: str, *, keep_reason: bool = True, **ids) -> None:
        row = {"type": kind}
        eid = _strip(item, "event_id")
        if isinstance(eid, str) and eid in self.ctx.events:
            row["event_id"] = eid
        cid = ids.pop("control_id", None)
        if isinstance(cid, str) and cid in self.ctx.controls:
            row["control_id"] = cid
        if ids.get("agent") and ids.get("subagent"):
            row["agent"], row["subagent"] = ids["agent"], ids["subagent"]
        rid = _strip(item, "risk_id")
        if isinstance(rid, str) and rid in self.risks:
            row["risk_id"] = rid
        sr = safe_text(_strip(item, "reason"), MAX_REASON) if keep_reason else None
        if sr:
            row["suggested_reason"] = sr
        row["reason"] = reason
        self.rejected.append(row)

    def items(self, output: dict, key: str) -> list[dict]:
        """取出某一類的項目；不是陣列或元素不是物件時直接拒絕（整份格式檢查通常已先擋下）。"""
        value = output.get(key)
        if value is None:
            return []
        if not isinstance(value, list):
            self.rejected.append({"type": KIND_OF[key], "reason": R_FIELDS})
            return []
        out = []
        for item in value:
            if isinstance(item, dict):
                out.append(item)
            else:
                self.rejected.append({"type": KIND_OF[key], "reason": R_FIELDS})
        return out


def _approve_controls(st: _Approval, items: list[dict]) -> None:
    ctx = st.ctx
    per_event: dict[str, int] = {}
    seen = set()
    for item in items:
        eid, cid = _strip(item, "event_id"), _strip(item, "control_id")
        if set(item) - CONTROL_KEYS:
            st.reject("control", item, R_ONLY_ADD, control_id=cid)
            continue
        if not all(isinstance(_strip(item, k), str) for k in CONTROL_KEYS):
            st.reject("control", item, R_FIELDS, control_id=cid)
            continue
        if eid not in ctx.events:
            st.reject("control", item, R_EVENT, control_id=cid)
            continue
        if cid not in ctx.controls:
            st.reject("control", item, R_CONTROL)
            continue
        if cid in (ctx.events[eid].get("controls") or []):
            st.reject("control", item, R_MAPPED, control_id=cid)
            continue
        reason = safe_text(_strip(item, "reason"), MAX_REASON)
        if not reason:
            st.reject("control", item, R_REASON, control_id=cid)
            continue
        if (eid, cid) in seen:
            st.reject("control", item, R_DUP, control_id=cid)
            continue
        if per_event.get(eid, 0) >= MAX_CTRL_PER_EVENT or len(seen) >= MAX_CTRL_TOTAL:
            st.reject("control", item, R_LIMIT, control_id=cid)
            continue
        seen.add((eid, cid))
        per_event[eid] = per_event.get(eid, 0) + 1
        st.approved.append({"type": "control", "event_id": eid, "control_id": cid, "reason": reason})


def _approve_tasks(st: _Approval, items: list[dict]) -> None:
    ctx = st.ctx
    menu, limit = MENUS[ctx.mode], TASK_LIMITS[ctx.mode]
    allowed = TASK_KEYS if ctx.mode == "dispatch" else TASK_KEYS | RISK_TASK_KEYS
    seen = set()
    for item in items:
        agent, sub = _strip(item, "agent"), _strip(item, "subagent")
        pair = (agent, sub) if isinstance(agent, str) and isinstance(sub, str) else None
        spec = menu.get(pair) if pair is not None and _registry_ok(*pair) else None
        ids = {"agent": agent, "subagent": sub} if spec else {}
        if set(item) - allowed:
            st.reject("task", item, R_ONLY_ADD, **ids)
            continue
        if pair is None or not isinstance(_strip(item, "reason"), str):
            st.reject("task", item, R_FIELDS, **ids)
            continue
        if spec is None:
            st.reject("task", item, R_TASK)
            continue
        tkey, other = ("event_id", "risk_id") if spec["target"] == "event" else ("risk_id", "event_id")
        if other in item:
            st.reject("task", item, R_ONLY_ADD, **ids)
            continue
        target = _strip(item, tkey)
        if not isinstance(target, str):
            st.reject("task", item, R_FIELDS, **ids)
            continue
        if tkey == "event_id" and target not in ctx.events:
            st.reject("task", item, R_EVENT, **ids)
            continue
        why = _task_ineligible(pair, target, ctx)
        if why:
            st.reject("task", item, why, **ids)
            continue
        reason = safe_text(_strip(item, "reason"), MAX_REASON)
        if not reason:
            st.reject("task", item, R_REASON, **ids)
            continue
        if (agent, sub, target) in seen:
            st.reject("task", item, R_DUP, **ids)
            continue
        if len(seen) >= limit:
            st.reject("task", item, R_LIMIT, **ids)
            continue
        seen.add((agent, sub, target))
        st.approved.append({"type": "task", "agent": agent, "subagent": sub, tkey: target, "reason": reason})


def _approve_priorities(st: _Approval, items: list[dict]) -> None:
    ctx = st.ctx
    want = PRIORITY_AGENT[ctx.mode]
    allowed = ctx.a4_baseline if ctx.mode == "dispatch" else [*ctx.a5_remediation, *ctx.a5_ceo]
    seen: list[str] = []
    for item in items:
        if set(item) - PRIORITY_KEYS:
            st.reject("priority", item, R_ONLY_ADD)
            continue
        if not all(isinstance(_strip(item, k), str) for k in PRIORITY_KEYS):
            st.reject("priority", item, R_FIELDS)
            continue
        rid = _strip(item, "risk_id")
        if _strip(item, "agent") != want or rid not in allowed:
            st.reject("priority", item, R_PRIORITY)
            continue
        reason = safe_text(_strip(item, "reason"), MAX_REASON)
        if not reason:
            st.reject("priority", item, R_REASON)
            continue
        if rid in seen:
            st.reject("priority", item, R_DUP)
            continue
        if len(seen) >= MAX_PRIORITIES:
            st.reject("priority", item, R_LIMIT)
            continue
        seen.append(rid)
        st.approved.append({"type": "priority", "agent": want, "risk_id": rid, "reason": reason})


def approve(output: dict, ctx: PolicyContext) -> dict:
    """依模式逐項核准（R3.7、R4.3）。回傳 {"suggested": N, "approved": [...], "rejected": [...]}，N = M + K。

    固定順序：dispatch 為 extra_controls → extra_tasks → priorities；review 為 extra_tasks → priorities → summary。
    頂層未知欄位各記一筆拒絕；項目多出欄位整項拒絕。拒絕不佔配額，每項只保留第一個原因；
    拒絕明細只保留安全欄位（白名單內的 ID、去敏後的建議理由與程式的拒絕原因），不保存原始未知欄位與值。
    """
    if ctx.mode not in MODES:
        raise ValueError(f"未知模式：{ctx.mode}")
    top = DISPATCH_KEYS if ctx.mode == "dispatch" else REVIEW_KEYS
    st = _Approval(ctx)
    for _ in range(sum(1 for k in output if k not in top)):
        st.rejected.append({"type": "field", "reason": R_ONLY_ADD})
    if ctx.mode == "dispatch":
        _approve_controls(st, st.items(output, "extra_controls"))
    _approve_tasks(st, st.items(output, "extra_tasks"))
    _approve_priorities(st, st.items(output, "priorities"))
    if ctx.mode == "review" and "summary" in output:
        text, why = clean_summary(output["summary"])
        if why:
            st.reject("summary", {}, why, keep_reason=False)        # 不保存被拒絕的摘要原文
        else:
            st.approved.append({"type": "summary", "text": text})
    return {"suggested": len(st.approved) + len(st.rejected), "approved": st.approved, "rejected": st.rejected}


# ---------------------------------------------------------------- 加查結果與追加風險（pipeline、A4 使用）
def planner_checks(event_id: str, approved: list[dict], control_results: dict[str, dict]) -> list[dict]:
    """只把這件事件核准的控制項，轉成本次已算好的檢查結果。缺結果視為資料不足，不當成符合。"""
    out = []
    for a in approved:
        if a.get("type") != "control" or a.get("event_id") != event_id:
            continue
        res = control_results.get(a["control_id"])
        if not res:
            out.append({"control_id": a["control_id"], "title": a["control_id"], "status": "unknown", "assets": [],
                        "check_reason": "本次檢查結果缺失", "suggested_reason": a["reason"]})
            continue
        status = res.get("status") if res.get("status") in STATUS_TEXT else "unknown"
        assets = [{"asset_id": x["asset_id"], "evidence": [e for e in (safe_text(t, 200) for t in (x.get("evidence") or [])[:3]) if e]}
                  for x in (res.get("assets") or []) if isinstance(x, dict) and isinstance(x.get("asset_id"), str)]
        out.append({"control_id": a["control_id"], "title": res.get("title") or a["control_id"], "status": status,
                    "assets": assets, "check_reason": safe_text(res.get("reason"), 200) or "",
                    "suggested_reason": a["reason"]})
    return out


LEVEL_RANK = {"high": 2, "medium": 1, "low": 0}


def pick_extra_risks(event_id: str, risks: list[dict], checks: list[dict], already: set[str]) -> list[dict]:
    """程式挑選要追加說明的風險：這件事件命中的風險，或加查不符合且資產與控制項同時符合的風險。"""
    fail = {(c["control_id"], a["asset_id"]) for c in checks if c.get("status") == "fail" for a in c.get("assets", [])}
    picked = []
    for r in risks:
        if r.get("status") == "fixed" or r["id"] in already:
            continue
        hit = event_id in (r.get("matched_events") or [])
        if not hit:
            hit = any(r.get("asset_id") == asset and stable_id(asset, cid) in (r.get("finding_ids") or [r["id"]])
                      for cid, asset in fail)
        if hit:
            picked.append(r)
    picked.sort(key=lambda r: (-LEVEL_RANK.get(r.get("level"), -1), -(r.get("score") or 0), r["id"]))
    return picked[:MAX_RISKS_PER_TASK]


# ---------------------------------------------------------------- 計畫檔（schema_version 2）
def run_ident(ctx: "RunCtx") -> dict:
    try:
        attempt = int(os.environ.get("GITHUB_RUN_ATTEMPT") or 1)
    except ValueError:
        attempt = 1
    return {"run_id": ctx.run_id, "run_attempt": attempt if attempt > 0 else 1, "scope": ctx.scope,
            "scenario": ctx.scenario, "target_sha": ctx.target_sha}


def plan_path(out: Path, mode: str) -> Path:
    """out/orchestrator-dispatch/dispatch-plan.json、out/orchestrator-review/review-plan.json。"""
    return Path(out) / PLAN_DIRS[mode] / PLAN_FILES[mode]


def empty_plan(ctx: "RunCtx", mode: str, *, status: str, source: str, note: str | None, verified_sha256: str | None = None,
               events: list[str] | None = None, dispatch_plan_sha256: str | None = None) -> dict:
    if mode not in MODES:
        raise ValueError(f"未知模式：{mode}")
    plan = {"schema_version": SCHEMA_VERSION, "mode": mode, "status": status, **run_ident(ctx),
            "verified_sha256": verified_sha256, "source": source, "note": (note or None) and note[:MAX_NOTE],
            "events": list(events or []), "suggested": 0, "approved": [], "rejected": []}
    if mode == "review":
        plan.update(dispatch_plan_sha256=dispatch_plan_sha256, summary=None)
    return plan


def pending_plan(ctx: "RunCtx", mode: str) -> dict:
    """Job 開始時先原子寫入的占位計畫：下游不會讀到上一次留下的舊檔（status=pending 一律停用）。"""
    return empty_plan(ctx, mode, status="pending", source="template", note=NOTE_PENDING)


def write_plan(path: Path, plan: dict) -> None:
    """同目錄暫存檔＋原子替換；寫入失敗直接拋錯（Job 明確失敗，下游依 R5.1a 停用這份計畫）。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def load_verified(ctx: "RunCtx") -> tuple[list[dict] | None, str | None]:
    """安全讀取 A1 的 verified.json：缺檔、壞檔或結構錯誤回傳 (None, 原因)，不拋錯。回傳的是原始解析資料（雜湊用）。"""
    from pydantic import ValidationError
    from schemas import IntelEvent
    path = ctx.out / "a1" / "verified.json"
    if not path.is_file():
        return None, "verified_missing"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None, "verified_unreadable"
    if not isinstance(data, list):
        return None, "verified_invalid"
    for v in data:
        if not isinstance(v, dict) or not isinstance(v.get("event"), dict) or not isinstance(v.get("verification"), dict):
            return None, "verified_invalid"
        try:
            IntelEvent.model_validate({k: x for k, x in v["event"].items() if k in IntelEvent.model_fields})
        except ValidationError:
            return None, "verified_invalid"
    return data, None


# ---------------------------------------------------------------- 核准核心（R5.1）
@dataclass
class BaseInputs:
    """evaluate 的共同輸入（target、scanner、deployments、AS_OF）與範圍。preverified、agent_plan 由核心每次帶入。"""
    eval_input: Any                  # tools.pipeline.EvalInput
    scope: str                       # daily | scenario | advisory
    prev_ids: set[str] | None        # daily 上次的事件 ID；None 表示讀不到
    advisory_id: str | None = None


def base_inputs(ctx: "RunCtx") -> BaseInputs:
    prev = prev_daily_ids(ctx.data_dir) if ctx.scope == "daily" else set()
    return BaseInputs(eval_input=ctx.eval_input(), scope=ctx.scope, prev_ids=prev, advisory_id=ctx.advisory_id)


def evaluate_snapshot(base: BaseInputs, verified: list[dict] | None, agent_plan: dict | None) -> dict:
    from tools.pipeline import evaluate
    res = evaluate(replace(base.eval_input, preverified=verified, agent_plan=agent_plan))
    # 報告公開的計畫（Report.agent_plan）由 A5 依最終有效的派工單與驗收單設定；評估快照本身不帶計畫
    res["agent_plan"] = None
    return res


def _context(mode: str, verified: list[dict], res: dict, base: BaseInputs) -> PolicyContext:
    fn = dispatch_context if mode == "dispatch" else review_context
    return fn(verified, res, scope=base.scope, prev_ids=base.prev_ids, advisory_id=base.advisory_id)


def approve_core(mode: str, items: dict, *, verified: list[dict], base_inputs: BaseInputs,
                 dispatch_res: dict | None = None) -> tuple[dict, PolicyContext, dict]:
    """建立與載入共用的核准核心（R5.1），回傳 (res, policy, result)。

    dispatch：1. 只用事件與控制項核准 control 類項目 → 2. 用「只含核准 control 的計畫」執行 evaluate
              → 3. 用這次的結果（已含 planner_checks）算出最終政策上下文 → 4. 用最終上下文核准全部項目
    review：沒有 control；直接用 dispatch_res（resolve_plans 解析後的評估）算政策上下文再核准。
            dispatch_res 為 None 時用 agent_plan=None 的必要任務評估。
    items 是提案格式（{extra_controls?, extra_tasks?, priorities?, summary?}）；載入時由 plan_items 從檔案的 approved 轉回。
    """
    if mode not in MODES:
        raise ValueError(f"未知模式：{mode}")
    if verified is None:
        raise ValueError("需要 A1 verified 才能核准")
    base = base_inputs
    items = items if isinstance(items, dict) else {}
    if mode == "dispatch":
        events, _ = scope_events(verified, scope=base.scope, prev_ids=base.prev_ids, advisory_id=base.advisory_id)
        first = PolicyContext(mode="dispatch", scope=base.scope, events={e["id"]: e for e in events}, controls=control_titles())
        only = {"extra_controls": items["extra_controls"]} if "extra_controls" in items else {}
        controls = [a for a in approve(only, first)["approved"] if a["type"] == "control"]
        res = evaluate_snapshot(base, verified, {"approved": controls} if controls else None)
    else:
        res = dispatch_res if dispatch_res is not None else evaluate_snapshot(base, verified, None)
    policy = _context(mode, verified, res, base)
    return res, policy, approve(items, policy)


def build_plan(mode: str, proposal: dict | None, *, ctx: "RunCtx", verified: list[dict], source: str, note: str | None = None,
               dispatch_res: dict | None = None, dispatch_plan: dict | None = None, base: BaseInputs | None = None) -> dict:
    """建立計畫（派工、驗收 Job）：用 approve_core 核准提案，把 approved、rejected 寫成 complete 計畫（呼叫端原子寫入）。

    - source 為 template／skipped 時不採用任何提案（計數為 0）
    - review：dispatch_plan 是 resolve_plans 解析後的派工單；None（缺失、pending、無效）時 dispatch_plan_sha256 為 null（R4.4）
    """
    if source not in SOURCES:
        raise ValueError(f"未知來源：{source}")
    base = base or base_inputs(ctx)
    items = {} if source in ("template", "skipped") or not isinstance(proposal, dict) else proposal
    _, policy, result = approve_core(mode, items, verified=verified, base_inputs=base, dispatch_res=dispatch_res)
    notes = "；".join(n for n in (policy.note, note) if n) or None
    plan = empty_plan(ctx, mode, status="complete", source=source, note=notes, verified_sha256=sha256_json(verified),
                      events=list(policy.events),
                      dispatch_plan_sha256=sha256_json(dispatch_plan) if dispatch_plan is not None else None)
    plan.update(result)
    if mode == "review":
        plan["summary"] = next((a["text"] for a in result["approved"] if a["type"] == "summary"), None)
    return plan


def plan_items(plan: dict) -> dict | None:
    """把計畫檔的 approved 轉回提案格式（載入時重跑核心用）。型別不明或摘要重複回傳 None。"""
    out: dict = {}
    for a in plan.get("approved") or []:
        if not isinstance(a, dict):
            return None
        kind = a.get("type")
        body = {k: v for k, v in a.items() if k != "type"}
        if kind == "control":
            out.setdefault("extra_controls", []).append(body)
        elif kind == "task":
            out.setdefault("extra_tasks", []).append(body)
        elif kind == "priority":
            out.setdefault("priorities", []).append(body)
        elif kind == "summary" and "summary" not in out and set(body) == {"text"}:
            out["summary"] = body["text"]
        else:
            return None
    return out


def _nonneg_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def read_plan(ctx: "RunCtx", mode: str, verified: list[dict]) -> tuple[dict | None, str | None]:
    """讀取並核對計畫檔的基本欄位（schema、mode、status、執行識別、verified_sha256、source、計數）。內容核對在 resolve_plans。"""
    path = plan_path(ctx.out, mode)
    if not path.is_file():
        return None, "plan_missing"
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None, "plan_unreadable"
    if not isinstance(plan, dict) or plan.get("schema_version") != SCHEMA_VERSION:
        return None, "plan_version"
    if plan.get("mode") != mode:
        return None, "plan_mode"
    if plan.get("status") != "complete":
        return None, "plan_pending"
    if any(plan.get(k) != v for k, v in run_ident(ctx).items()):
        return None, "plan_other_run"
    sha = plan.get("verified_sha256")
    if not isinstance(sha, str) or not SHA_RE.match(sha) or sha != sha256_json(verified):
        return None, "plan_verified_mismatch"
    note = plan.get("note")
    if plan.get("source") not in SOURCES or not (note is None or (isinstance(note, str) and len(note) <= MAX_NOTE)):
        return None, "plan_invalid"
    approved, rejected = plan.get("approved"), plan.get("rejected")
    if not isinstance(approved, list) or not isinstance(rejected, list) or not _nonneg_int(plan.get("suggested")):
        return None, "plan_invalid"
    if plan["suggested"] != len(approved) + len(rejected):
        return None, "plan_counts"
    if plan["source"] in ("template", "skipped") and plan["suggested"]:
        return None, "plan_counts"
    ids = plan.get("events")
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids) or len(set(ids)) != len(ids):
        return None, "plan_events"
    if mode == "review":
        bound, summary = plan.get("dispatch_plan_sha256"), plan.get("summary")
        if not (bound is None or (isinstance(bound, str) and SHA_RE.match(bound))):
            return None, "plan_invalid"
        if not (summary is None or (isinstance(summary, str) and len(summary) <= MAX_SUMMARY)):
            return None, "plan_invalid"
    return plan, None


def _valid_rejected(row, policy: PolicyContext) -> bool:
    """拒絕明細只能有安全欄位：白名單內的 ID、程式的拒絕原因、去敏後的建議理由。"""
    if not isinstance(row, dict) or row.get("type") not in ("control", "task", "priority", "summary", "field"):
        return False
    allowed = {"type", "event_id", "control_id", "agent", "subagent", "risk_id", "suggested_reason", "reason"}
    if set(row) - allowed or row.get("reason") not in REASONS:
        return False
    if "event_id" in row and row["event_id"] not in policy.events:
        return False
    if "control_id" in row and row["control_id"] not in policy.controls:
        return False
    if ("agent" in row or "subagent" in row) and (row.get("agent"), row.get("subagent")) not in MENUS[policy.mode]:
        return False
    if "risk_id" in row and row["risk_id"] not in policy.known_risks():
        return False
    sr = row.get("suggested_reason")
    return sr is None or (isinstance(sr, str) and len(sr) <= MAX_REASON and not SECRET_RE.search(sr))


def _rerun_mismatch(mode: str, plan: dict, result: dict, policy: PolicyContext) -> str | None:
    """重跑核心後的核對（R5.1）：approved 內容與順序完全一致、沒有新的拒絕、事件範圍一致、拒絕明細格式合法。"""
    if result["rejected"] or result["approved"] != plan["approved"]:
        return "plan_approved_invalid"
    if plan["events"] != list(policy.events):
        return "plan_events"
    if not all(_valid_rejected(r, policy) for r in plan["rejected"]):
        return "plan_rejected_invalid"
    if mode == "review" and plan.get("summary") != next((a["text"] for a in result["approved"] if a["type"] == "summary"), None):
        return "plan_invalid"
    return None


@dataclass
class Resolved:
    """resolve_plans 的結果。policies 為 design §3.2 之外補充的欄位：有效計畫的政策上下文（下游挑對象用）。"""
    res: dict                                            # 評估快照：派工單有效時含其 control，否則為 agent_plan=None 的必要任務評估
    dispatch: dict | None                                # 有效的派工單（檔案原樣）；None 表示停用
    review: dict | None                                  # 有效的驗收單；None 表示停用或未要求
    reasons: dict[str, str | None] = field(default_factory=dict)   # mode → 停用原因碼（None 表示有效）
    policies: dict[str, PolicyContext] = field(default_factory=dict)


def resolve_plans(ctx_run: "RunCtx", *, verified: list[dict] | None, want: tuple[str, ...] = ("dispatch",),
                  base: BaseInputs | None = None) -> Resolved:
    """載入並核對計畫（R5.1、R5.1a）。兩份計畫各自判斷，不互相連坐：

    | 派工單 | res | 驗收單 |
    | 有效 | 用派工單的 control 評估 | 綁定 sha 必須等於這份派工單的 sha256_json；用這份 res 重跑核心，不符只停用驗收單 |
    | 缺失或無效 | agent_plan=None 的必要任務評估 | 綁定 sha 必須是 null；用這份 res 重跑核心；綁定非 null 就停用驗收單 |

    派工單一律解析（驗收單的綁定與 res 都依賴它）；want 含 "review" 時才解析驗收單。
    verified 為 None（A1 結果缺失或損壞）時兩份都停用，res 由 evaluate 離線重建。
    """
    base = base or base_inputs(ctx_run)
    reasons: dict[str, str | None] = {}
    policies: dict[str, PolicyContext] = {}
    dispatch, res = None, None
    if verified is None:
        reasons["dispatch"] = "verified_unavailable"
    else:
        plan, why = read_plan(ctx_run, "dispatch", verified)
        if plan is not None:
            items = plan_items(plan)
            if items is None:
                why = "plan_approved_invalid"
            else:
                res_d, policy, result = approve_core("dispatch", items, verified=verified, base_inputs=base)
                why = _rerun_mismatch("dispatch", plan, result, policy)
                if why is None:
                    dispatch, res, policies["dispatch"] = plan, res_d, policy
        reasons["dispatch"] = why
    if res is None:
        res = evaluate_snapshot(base, verified, None)
    review = None
    if "review" in want:
        if verified is None:
            why = "verified_unavailable"
        else:
            plan, why = read_plan(ctx_run, "review", verified)
            if plan is not None:
                expected = sha256_json(dispatch) if dispatch is not None else None
                items = plan_items(plan)
                if plan.get("dispatch_plan_sha256") != expected:
                    why = "review_dispatch_mismatch"
                elif items is None:
                    why = "plan_approved_invalid"
                else:
                    _, policy, result = approve_core("review", items, verified=verified, base_inputs=base, dispatch_res=res)
                    why = _rerun_mismatch("review", plan, result, policy)
                    if why is None:
                        review, policies["review"] = plan, policy
        reasons["review"] = why
    return Resolved(res=res, dispatch=dispatch, review=review, reasons=reasons, policies=policies)


# ---------------------------------------------------------------- 派工結果（R4.2、R5.5）
# A2、A3、A4 各寫 out/<agent>/dispatch-outcomes.json（T3），驗收輸入讀它（orchestrator_agent.build_input）。
# 格式：{"schema_version": 1, "agent": "a2", "dispatch_plan_sha256": <派工單的 sha256_json>, "items": [outcome_row(...)]}
OUTCOME_FILE = "dispatch-outcomes.json"
OUTCOME_AGENTS = ("a2", "a3", "a4")
OUTCOME_STATUSES = ("completed", "template", "skipped")
# A2～A4 可寫的原因代碼（固定代碼，驗收輸入只轉交代碼）
OUTCOME_REASONS = {
    "done": "已完成",
    "llm_template": "AI 沒有產出可用結果，改用程式範本",
    "no_target": "挑不到對象",
    "no_records": "回溯期間沒有符合特徵的紀錄",
    "reordered": "已調整說明順序",
    "error": "執行失敗",
}
# 驗收輸入自己標記的代碼：讀不到結果、結果不屬於這份派工單、加查控制項的檢查結果
OUTCOME_UNKNOWN = "unknown"
OUTCOME_READ_REASONS = {
    "outcome_missing": "讀不到執行結果",
    "outcome_invalid": "執行結果格式不符",
    "outcome_mismatch": "執行結果不是這份派工單的",
    "check_pass": "加查結果：符合",
    "check_fail": "加查結果：不符合",
    "check_unknown": "加查結果：資料不足",
}
_OUTCOME_TARGETS = ("event_id", "control_id", "risk_id")


def outcome_key(item: dict) -> tuple:
    """派工單核准項目與執行結果的對應鍵：(type, agent, subagent, event_id, control_id, risk_id)。"""
    return (item.get("type"), item.get("agent"), item.get("subagent"), *(item.get(k) for k in _OUTCOME_TARGETS))


def outcome_row(item: dict, status: str, reason: str) -> dict:
    """A2～A4 寫結果的一列：核准項目的識別欄位（不含理由）＋狀態＋原因代碼。"""
    if status not in OUTCOME_STATUSES or reason not in OUTCOME_REASONS:
        raise ValueError(f"未知的派工結果：{status}／{reason}")
    row = {k: item[k] for k in ("type", "agent", "subagent", *_OUTCOME_TARGETS) if k in item}
    row.update(status=status, reason=reason)
    return row


def write_outcomes(out: Path, agent: str, dispatch_plan: dict | None, rows: list[dict]) -> None:
    """原子寫入 out/<agent>/dispatch-outcomes.json；綁定派工單的 sha256_json（派工單停用時為 null、items 應為空）。"""
    write_plan(Path(out) / agent / OUTCOME_FILE, {"schema_version": 1, "agent": agent,
                                                  "dispatch_plan_sha256": sha256_json(dispatch_plan) if dispatch_plan else None,
                                                  "items": list(rows)})


def read_outcomes(out: Path, agent: str, dispatch_plan: dict) -> tuple[dict[tuple, tuple[str, str]] | None, str | None]:
    """讀取某個 Agent 的派工結果：回傳 ({outcome_key: (status, reason)}, None) 或 (None, 原因代碼)。

    缺檔 → outcome_missing；不是合法 JSON 或結構不符 → outcome_invalid；綁定的不是這份派工單 → outcome_mismatch。
    單列格式不符（狀態或原因不在固定代碼）的直接略過，對應的項目視為讀不到結果。
    """
    path = Path(out) / agent / OUTCOME_FILE
    if not path.is_file():
        return None, "outcome_missing"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None, "outcome_invalid"
    if not isinstance(data, dict) or data.get("agent") != agent or not isinstance(data.get("items"), list):
        return None, "outcome_invalid"
    if data.get("dispatch_plan_sha256") != sha256_json(dispatch_plan):
        return None, "outcome_mismatch"
    found: dict[tuple, tuple[str, str]] = {}
    for row in data["items"]:
        if (isinstance(row, dict) and row.get("status") in OUTCOME_STATUSES and row.get("reason") in OUTCOME_REASONS
                and row.get("agent") == agent):
            found.setdefault(outcome_key(row), (row["status"], row["reason"]))
    return found, None


# ---------------------------------------------------------------- 報告出口（v0.11.0 的單一計畫格式；T3 改為 {dispatch, review}）
def counts(plan: dict | None) -> tuple[int, int, int]:
    if not plan:
        return 0, 0, 0
    return plan.get("suggested", 0), len(plan.get("approved") or []), len(plan.get("rejected") or [])


def public_plan(plan: dict | None) -> dict | None:
    """Report.agent_plan：經核對的計畫（不含執行識別與雜湊）＋計數。"""
    if not plan:
        return None
    n, m, k = counts(plan)
    from tools.controls import load_controls
    used = {r.get("control_id") for r in [*(plan.get("approved") or []), *(plan.get("rejected") or [])]}
    titles = {c["id"]: c["title"] for c in load_controls() if c["id"] in used}   # 網站顯示控制項名稱，不顯示內部 ID
    return {"source": plan["source"], "note": plan.get("note"), "events": list(plan.get("events") or []),
            "suggested": n, "approved_count": m, "rejected_count": k, "control_titles": titles,
            "approved": copy.deepcopy(plan.get("approved") or []), "rejected": copy.deepcopy(plan.get("rejected") or [])}
