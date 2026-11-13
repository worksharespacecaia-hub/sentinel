"""Orchestrator（AI 派工與驗收）：run_agent 的 `orchestrator-input --mode <m>` 與 `orchestrator --mode <m>` 指令。

specs/orchestrator design §2（派工／驗收 Job 的步驟 3、6）、§3.3、§4。核准規則與計畫檔在 tools/orchestration.py。

- build_input（步驟 3）：計算評估快照與政策上下文，依 design §4 的白名單投影寫出給 AI 的公開輸入
  out/orchestrator-<m>/<m>-input.json；政策上下文另存 out/orchestrator-<m>/internal/context.json
  （訂閱步驟的讀取白名單只有公開輸入，不含 internal/）
  - dispatch：用 approve_core(m, {}) 取得「沒有加查控制項」的參考候選（最終資格在核准時重算，R5.1）
  - review：先用 resolve_plans 解析派工單與評估結果，再算驗收的政策上下文；Job 結果只取 JOB_RESULTS 各 Job 的 .result，
    派工項目的執行結果讀 A2～A4 的 dispatch-outcomes.json（讀不到記為 unknown，不失敗）
- run（步驟 6）：先原子寫入 pending 計畫；提案來源依序為
  1. 訂閱方案：<m>-proposal.json，而且 <m>-proposal.accepted 的內容等於提案檔的 sha256
  2. Agent SDK：planner（派工）或 reviewer（驗收）；live 呼叫 API，replay 查錄製或快取，查不到就是範本（空提案）
  3. 都沒有：空提案
  提案格式不符時整份當作空提案並記錄原因；用 build_plan（approve_core）核准後原子寫入 <m>-plan.json 與 trace
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from agents.common import finish
from context import RunCtx
from llm import Task
from tools import orchestration as o
from tools import retro

AGENT = {"dispatch": "orchestrator-dispatch", "review": "orchestrator-review"}
# 派發的 Subagent（registry 的 orchestrator-dispatch／orchestrator-review）：網站測試以這兩個字串確認 Subagent 有被程式派發
SUBAGENT = {"dispatch": "planner", "review": "reviewer"}
MODE_ZH = {"dispatch": "派工", "review": "驗收"}
SUBAGENT_TIMEOUT_S = 60          # 每次嘗試的上限（沿用 v0.11.0 planner；LLMRunner 最多兩次）
MAX_REJECT_TRACE = 10
INPUT_SCHEMA = 1
JOB_RESULTS_ENV = "JOB_RESULTS"  # 驗收 Job 的 env：${{ toJSON(needs) }}；只取各 Job 的 .result
JOB_RESULT_VALUES = ("success", "failure", "skipped", "cancelled")
JOB_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
NOTE_DISPATCH_UNAVAILABLE = "派工單不可用"
NOTE_UNAVAILABLE = "A1 結果不可用，本次只跑必要任務，沒有可追加的對象"

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ATTCK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
CVE_LIKE_RE = re.compile(r"^[A-Z]{2,10}-\d{4}-\d{3,7}$")
COMPONENT_RE = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9._+-]{0,99}(?:/[A-Za-z0-9][A-Za-z0-9._+-]{0,99})?$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,39}$")
LEVELS = ("high", "medium", "low")
LABEL_LIMIT, INDUSTRY_LIMIT, HYPOTHESIS_LIMIT = 60, 40, 300

LIMITS = {
    "dispatch": {"events": o.MAX_EVENTS, "controls_per_event": o.MAX_CTRL_PER_EVENT, "controls_total": o.MAX_CTRL_TOTAL,
                 "extra_tasks": o.MAX_DISPATCH_TASKS, "priorities": o.MAX_PRIORITIES, "reason_chars": o.MAX_REASON,
                 "a2_items_per_task": o.MAX_A2_FINDINGS, "a3_systems": o.MAX_A3_SYSTEMS,
                 "a4_risks_per_event": o.MAX_RISKS_PER_TASK, "a4_baseline": o.MAX_A4_BASELINE},
    "review": {"extra_tasks": o.MAX_REVIEW_TASKS, "priorities": o.MAX_PRIORITIES, "reason_chars": o.MAX_REASON,
               "summary_chars": o.MAX_SUMMARY, "a5_remediation": o.MAX_A5_REMEDIATION, "a5_ceo": o.MAX_A5_CEO},
}


def _check(mode: str) -> None:
    if mode not in o.MODES:
        raise ValueError(f"未知模式：{mode}")


# ---------------------------------------------------------------- 路徑
def mode_dir(ctx: RunCtx, mode: str) -> Path:
    return ctx.out / o.PLAN_DIRS[mode]


def input_path(ctx: RunCtx, mode: str) -> Path:
    """公開輸入：訂閱步驟唯一能讀的 out/ 檔案。"""
    return mode_dir(ctx, mode) / f"{mode}-input.json"


def internal_path(ctx: RunCtx, mode: str) -> Path:
    """內部政策上下文（不在訂閱步驟的讀取白名單內）。"""
    return mode_dir(ctx, mode) / "internal" / "context.json"


def proposal_path(ctx: RunCtx, mode: str) -> Path:
    return mode_dir(ctx, mode) / f"{mode}-proposal.json"


def accepted_path(ctx: RunCtx, mode: str) -> Path:
    return mode_dir(ctx, mode) / f"{mode}-proposal.accepted"


# ---------------------------------------------------------------- 投影（design §4）
def _clean_list(values, pattern: re.Pattern) -> list[str]:
    return sorted({v for v in values or [] if isinstance(v, str) and pattern.match(v)})


class _Projector:
    """把評估快照與政策上下文投影成給 AI 的白名單欄位。文字經 public_safe（safe_text＋路徑／設定鍵／控制項／連接埠／IP 擋字），
    命中就整段丟掉；系統只放 ai_assets 內的 ID；ID 不合 safe_id 的事件與風險整筆不放。"""

    def __init__(self, policy: o.PolicyContext, res: dict):
        from tools.digest import load_asset_label_file, public_asset_labels
        self.policy, self.res = policy, res
        self.assets = o.ai_asset_ids(res)
        data = res.get("data")
        file_labels, _ = load_asset_label_file()
        self.labels = public_asset_labels(getattr(data, "services", None), getattr(data, "vendors", None),
                                          dict(res["graph"].nodes(data=True)), file_labels)
        self.internal_ids = set(res["graph"].nodes)
        self.matches = {m["event"]["id"]: m for m in res.get("matches") or []}
        self.relations = o.event_relations(list(policy.events.values()), self.matches, res["risks"])
        self.risk_by_id = {r["id"]: r for r in res["risks"]}
        self.risk_order = {r["id"]: i for i, r in enumerate(res["risks"])}

    # 事件
    def events(self, *, mapped_controls: bool) -> list[dict]:
        rows = [self.event(ev, mapped_controls=mapped_controls) for ev in self.policy.events.values()]
        return [r for r in rows if r is not None]

    def event(self, ev: dict, *, mapped_controls: bool) -> dict | None:
        from tools.digest import RELATION
        eid = ev.get("id")
        if not o.safe_id(eid):
            return None
        m = self.matches.get(eid)
        rel = self.relations.get(eid)
        date = ev.get("date")
        row = {
            "id": eid,
            "title": o.public_safe(ev.get("title")),
            "date": date if isinstance(date, str) and DATE_RE.match(date) else None,
            "industry": o.public_safe(ev.get("industry"), INDUSTRY_LIMIT),
            "attck": _clean_list(ev.get("attck"), ATTCK_RE),
            "cves": _clean_list(ev.get("cves"), CVE_LIKE_RE),
            "attack_chain": [t for t in (o.public_safe(s) for s in (ev.get("attack_chain") or [])[:o.MAX_CHAIN]) if t],
            "relation": RELATION.get(rel[0]) if rel else None,
            "systems": sorted((o._impact_systems(m) | o._hypothesis_systems(m)) & self.assets),
            "hypotheses": self.hypotheses(m),
        }
        if mapped_controls:
            # design §4 之外補充：事件已直接對應的控制項（只放控制項清單內的 ID），避免提出會被拒絕的重複加查
            row["mapped_controls"] = sorted({c for c in ev.get("controls") or [] if c in self.policy.controls})
        return row

    def hypotheses(self, match: dict | None) -> list[str]:
        """破口推測的公開白話：只用 public_suggestions 的 text，再經 public_safe。"""
        from tools.digest import public_suggestions
        if not match:
            return []
        out: list[str] = []
        for s in public_suggestions({"impacts": match.get("impacts") or []}, self.labels, self.internal_ids):
            text = o.public_safe(s.get("text"), HYPOTHESIS_LIMIT)
            if text and text not in out:
                out.append(text)
        return out

    # 風險
    def risk_ids(self, ids) -> list[str]:
        """依評估結果的順序去重；不合 safe_id 或不在本次風險中的整筆不放。"""
        keep = {i for i in ids if isinstance(i, str) and i in self.risk_by_id and o.safe_id(i)}
        return sorted(keep, key=self.risk_order.__getitem__)

    def risk(self, rid: str) -> dict:
        r = self.risk_by_id[rid]
        cat = r.get("category")
        row = {"id": rid, "level": r.get("level") if r.get("level") in LEVELS else None,
               "category": cat if cat in o.CATEGORY_ZH else None}
        aid = r.get("asset_id")
        if aid in self.assets:
            # 標籤由程式產生：「類別：系統名稱」，沒有可公開的名稱時用系統 ID；不放風險標題（金鑰類標題含存放位置）
            name = self.labels.get(aid)
            name = o.public_safe(name, LABEL_LIMIT) if isinstance(name, str) else None
            row["asset_id"] = aid
            row["label"] = f"{o.CATEGORY_ZH.get(cat, '其他')}：{name or aid}"
        return row

    # A2 候選的元件
    def components(self, finding_ids: list[str]) -> list[dict]:
        from tools.aliases import normalize
        by_id = {f["id"]: f for f in self.res.get("findings") or [] if isinstance(f.get("id"), str)}
        seen, out = set(), []
        for fid in finding_ids:
            f = by_id.get(fid) or {}
            name, version = f.get("component"), f.get("version")
            if version is None and isinstance(name, str) and f.get("asset_id") in self.res["graph"]:
                node = self.res["graph"].nodes[f["asset_id"]]
                version = next((c.get("version") for c in node.get("components") or []
                                if isinstance(c, dict) and normalize(c.get("name")) == normalize(name)), None)
            if not _safe_component(name):
                continue
            version = version if isinstance(version, str) and VERSION_RE.match(version) else None
            if (name, version) not in seen:
                seen.add((name, version))
                out.append({"name": name, "version": version})
        return sorted(out, key=lambda c: (c["name"], c["version"] or ""))


def _safe_component(name) -> bool:
    """元件名稱：套件名稱格式（允許 npm scope 的一個 /），不得像檔案路徑、IP 或含機敏內容。"""
    if not isinstance(name, str) or not COMPONENT_RE.match(name):
        return False
    from tools.digest import has_sensitive
    from tools.stack import _has_ip
    return not (has_sensitive(name) or _has_ip(name) or o._ID_FILE_RE.search(name))


def _menu(mode: str) -> list[dict]:
    return [{"agent": a, "subagent": s, "target": v["target"], "what": v["what"]} for (a, s), v in sorted(o.MENUS[mode].items())]


def dispatch_payload(policy: o.PolicyContext, res: dict, *, as_of, baselines: dict | None = None) -> dict:
    """派工的公開輸入（R2.2）。候選是 approve_core(m, {}) 的參考清單；A3 只放系統與有特徵的紀錄數。"""
    pj = _Projector(policy, res)
    events = pj.events(mapped_controls=True)
    kept = {e["id"] for e in events}
    baseline = pj.risk_ids(policy.a4_baseline)
    extra = [{"event_id": eid, "risk_ids": pj.risk_ids(rids)} for eid, rids in policy.a4_extra.items() if eid in kept]
    extra = [x for x in extra if x["risk_ids"]]
    risks = [pj.risk(r) for r in pj.risk_ids([*baseline, *(r for x in extra for r in x["risk_ids"])])]
    a2 = [{"event_id": eid, "subagent": sub, "count": len(fids), "components": pj.components(fids)}
          for eid, per in policy.a2.items() if eid in kept for sub, fids in sorted(per.items())]
    signals = getattr(res.get("data"), "signals", None) or {}
    a3 = []
    for eid, systems in policy.a3.items():
        if eid not in kept:
            continue
        systems = [s for s in systems if s in pj.assets]
        hit = retro.hunt(signals, systems=systems, event_date=policy.events[eid].get("date"), as_of=as_of, baselines=baselines)
        a3.append({"event_id": eid, "systems": systems, "flagged_count": hit.flagged_total})
    controls = [{"id": cid, "title": o.safe_text(title) or cid} for cid, title in policy.controls.items()]
    return {"schema_version": INPUT_SCHEMA, "mode": "dispatch", "available": True, "scope": policy.scope, "note": policy.note,
            "events": events, "risks": risks, "controls": controls,
            "candidates": {"a2": a2, "a3": a3, "a4_baseline": baseline, "a4_extra": extra},
            "menu": _menu("dispatch"), "limits": dict(LIMITS["dispatch"])}


def review_payload(policy: o.PolicyContext, res: dict, *, dispatch_plan: dict | None, dispatch_reason: str | None,
                   jobs: dict[str, str], outcomes: list[dict]) -> dict:
    """驗收的公開輸入（R4.2）：四類候選、各 Job 的結果、派工項目的執行結果、派工單是否有效。"""
    pj = _Projector(policy, res)
    events = pj.events(mapped_controls=False)
    kept = {e["id"] for e in events}
    keyrot, remediation, ceo = pj.risk_ids(policy.keyrot), pj.risk_ids(policy.a5_remediation), pj.risk_ids(policy.a5_ceo)
    risks = [pj.risk(r) for r in pj.risk_ids([*keyrot, *remediation, *ceo])]
    valid = dispatch_plan is not None
    return {"schema_version": INPUT_SCHEMA, "mode": "review", "available": True, "scope": policy.scope, "note": policy.note,
            "dispatch_plan": {"available": valid, "reason": None if valid else (dispatch_reason or "plan_missing"),
                              "note": None if valid else NOTE_DISPATCH_UNAVAILABLE},
            "jobs": dict(jobs), "dispatch_outcomes": outcomes, "events": events, "risks": risks,
            "candidates": {"need_check": [e for e in policy.need_check if e in kept], "key_rotation": keyrot,
                           "notice": [e for e in policy.notice if e in kept], "a5_remediation": remediation, "a5_ceo": ceo},
            "menu": _menu("review"), "limits": dict(LIMITS["review"])}


def unavailable_payload(mode: str, why: str | None) -> dict:
    return {"schema_version": INPUT_SCHEMA, "mode": mode, "available": False, "reason": why or "verified_unavailable",
            "note": NOTE_UNAVAILABLE, "menu": _menu(mode), "limits": dict(LIMITS[mode])}


def job_results(raw: str | None) -> dict[str, str]:
    """JOB_RESULTS（toJSON(needs)）只取各 Job 的 .result；不使用 outputs。格式不符的整份或單項略過。"""
    try:
        data = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {job: v["result"] for job, v in sorted(data.items())
            if isinstance(job, str) and JOB_RE.match(job) and isinstance(v, dict) and v.get("result") in JOB_RESULT_VALUES}


def dispatch_outcomes(out: Path, dispatch_plan: dict | None, res: dict) -> list[dict]:
    """派工單每一項的執行結果（R4.2）：control 由評估結果的加查狀態得知；task／priority 讀 A2～A4 的 dispatch-outcomes.json。

    讀不到、格式不符或不是這份派工單的結果記為 unknown（不失敗）。派工單停用時沒有項目。
    """
    if dispatch_plan is None:
        return []
    files = {agent: o.read_outcomes(out, agent, dispatch_plan) for agent in o.OUTCOME_AGENTS}
    checks = {(m["event"]["id"], c.get("control_id")): c.get("status")
              for m in res.get("matches") or [] for c in m.get("planner_checks") or []}
    rows = []
    for a in dispatch_plan.get("approved") or []:
        item = {k: a[k] for k in ("type", "agent", "subagent", "event_id", "control_id", "risk_id") if k in a}
        if any(not o.safe_id(item[k]) for k in ("event_id", "risk_id") if k in item):
            continue
        if a.get("type") == "control":
            status = checks.get((a.get("event_id"), a.get("control_id")))
            rows.append({"item": item, "status": "completed",
                         "reason": f"check_{status if status in o.STATUS_TEXT else 'unknown'}"})
            continue
        found, why = files.get(a.get("agent"), (None, "outcome_missing"))
        hit = (found or {}).get(o.outcome_key(a))
        if hit is None:
            rows.append({"item": item, "status": o.OUTCOME_UNKNOWN, "reason": why or "outcome_missing"})
        else:
            rows.append({"item": item, "status": hit[0], "reason": hit[1]})
    return rows


# ---------------------------------------------------------------- 評估快照
@dataclass
class Snapshot:
    payload: dict
    policy: o.PolicyContext
    res: dict
    resolved: o.Resolved | None = None           # review：resolve_plans 的結果（派工單與 res）


def snapshot(ctx: RunCtx, mode: str, verified: list[dict], base: o.BaseInputs, *,
             resolved: o.Resolved | None = None) -> Snapshot:
    if mode == "dispatch":
        res, policy, _ = o.approve_core("dispatch", {}, verified=verified, base_inputs=base)
        return Snapshot(dispatch_payload(policy, res, as_of=ctx.as_of), policy, res)
    r = resolved or o.resolve_plans(ctx, verified=verified, want=("dispatch",), base=base)
    res, policy, _ = o.approve_core("review", {}, verified=verified, base_inputs=base, dispatch_res=r.res)
    payload = review_payload(policy, res, dispatch_plan=r.dispatch, dispatch_reason=r.reasons.get("dispatch"),
                             jobs=job_results(os.environ.get(JOB_RESULTS_ENV)), outcomes=dispatch_outcomes(ctx.out, r.dispatch, res))
    return Snapshot(payload, policy, res, r)


def build_input(ctx: RunCtx, mode: str) -> dict:
    """步驟 3：寫出公開輸入與內部政策上下文（皆原子寫入）。A1 verified 不可用時寫出 available=false 的輸入，不失敗。"""
    _check(mode)
    tr = ctx.tracer(AGENT[mode])
    tr.emit("start", f"整理 Orchestrator {MODE_ZH[mode]}的輸入（程式：評估快照、政策上下文、白名單投影）")
    verified, why = o.load_verified(ctx)
    if verified is None:
        o.write_plan(input_path(ctx, mode), unavailable_payload(mode, why))
        o.write_plan(internal_path(ctx, mode), {"mode": mode, "unavailable": why})
        tr.emit("error", f"A1 結果不可用（{why}）：{MODE_ZH[mode]}只跑必要任務", source="template")
        return {"mode": mode, "available": False, "reason": why}
    snap = snapshot(ctx, mode, verified, o.base_inputs(ctx))
    o.write_plan(input_path(ctx, mode), snap.payload)
    o.write_plan(internal_path(ctx, mode), snap.policy.to_json())
    p = snap.payload
    if mode == "dispatch":
        c = p["candidates"]
        detail = (f"派工輸入：{len(p['events'])} 件事件、{len(p['risks'])} 個風險；候選 A2 {len(c['a2'])} 項、A3 {len(c['a3'])} 件、"
                  f"A4 追加 {len(c['a4_extra'])} 件")
    else:
        c = p["candidates"]
        detail = (f"驗收輸入：派工單{'有效' if p['dispatch_plan']['available'] else '不可用'}、派工結果 {len(p['dispatch_outcomes'])} 項；"
                  f"需確認 {len(c['need_check'])} 件、金鑰輪替候選 {len(c['key_rotation'])} 個、通知草稿候選 {len(c['notice'])} 件")
    tr.emit("tool", detail)
    return {"mode": mode, "available": True, "events": len(p["events"]), "risks": len(p["risks"])}


# ---------------------------------------------------------------- 提案來源
def read_subscription(ctx: RunCtx, mode: str) -> tuple[bool, object, str | None]:
    """訂閱方案的提案：回傳（是否採用, 提案內容, 未採用原因）。採用條件：採用標記的內容等於提案檔位元組的 sha256。

    沒有提案檔回傳 (False, None, None)；已採用但不是合法 JSON 時內容為 None（交給格式檢查，整份當作空提案）。
    """
    proposal, accepted = proposal_path(ctx, mode), accepted_path(ctx, mode)
    if not proposal.is_file():
        return False, None, None
    if not accepted.is_file():
        return False, None, "沒有採用標記"
    try:
        raw = proposal.read_bytes()
        mark = accepted.read_text(encoding="utf-8").strip().lower()
    except (OSError, UnicodeDecodeError):
        return False, None, "無法讀取提案或採用標記"
    if not o.SHA_RE.match(mark) or mark != hashlib.sha256(raw).hexdigest():
        return False, None, "採用標記與提案內容不符"
    try:
        return True, json.loads(raw.decode("utf-8")), None
    except (UnicodeDecodeError, ValueError):
        return True, None, None


def call_subagent(ctx: RunCtx, mode: str, payload: dict) -> dict:
    """Agent SDK 路徑（R6.2）：{"output", "source": live|replay|template, ...}。replay 只查錄製與快取，不呼叫 API。"""
    runner = ctx.runner(AGENT[mode])
    runner.timeout_s = SUBAGENT_TIMEOUT_S
    if mode == "dispatch":
        task = Task(id=mode, subagent="planner", payload=payload)
    else:
        task = Task(id=mode, subagent="reviewer", payload=payload)
    return runner.run([task]).get(mode) or {}


def _shaped(mode: str, proposal, source: str, tr, notes: list[str]) -> tuple[dict, str]:
    check = o.validate_plan_shape if mode == "dispatch" else o.validate_review_shape
    try:
        return check(proposal), source
    except ValueError as exc:
        notes.append(f"{o.SOURCE_TEXT[source]}的提案格式無效（{str(exc)[:60]}），改用空提案")
        tr.emit("error", notes[-1], subagent=SUBAGENT[mode], source="template")
        return {}, "template"


def get_proposal(ctx: RunCtx, mode: str, tr, *, verified: list[dict], base: o.BaseInputs,
                 resolved: o.Resolved | None = None) -> tuple[dict, str, list[str]]:
    """提案來源的優先順序（design §3.3）：訂閱方案（標記相符）→ Agent SDK → 空提案。回傳（提案, 來源, 註記）。"""
    sub, notes = SUBAGENT[mode], []
    adopted, raw, why = read_subscription(ctx, mode)
    if adopted:
        tr.emit("subagent", "提案來源：訂閱方案（採用標記與提案內容相符）", subagent=sub)
        proposal, source = _shaped(mode, raw, "subscription", tr, notes)
        return proposal, source, notes
    if why:
        notes.append(f"訂閱方案的提案未採用（{why}），改用 Agent SDK")
        tr.emit("skip", notes[-1], subagent=sub)
    if mode == "dispatch":
        events, _ = o.scope_events(verified, scope=base.scope, prev_ids=base.prev_ids, advisory_id=base.advisory_id)
        if not events:
            notes.append("沒有新同業事件，不需要 AI 派工")
            tr.emit("skip", notes[-1], subagent=sub, source="template")
            return {}, "skipped", notes
    payload = snapshot(ctx, mode, verified, base, resolved=resolved).payload
    got = call_subagent(ctx, mode, payload)
    source = got.get("source") if got.get("source") in ("live", "replay", "template") else "template"
    if got.get("output") is None:
        notes.append(f"{sub} 沒有可用的提案（{o.SOURCE_TEXT[source]}），改用空提案")
        tr.emit("skip", notes[-1], subagent=sub, source="template")
        return {}, "template", notes
    tr.emit("subagent", f"提案來源：{o.SOURCE_TEXT[source]}（{sub}）", subagent=sub, source=source)
    proposal, source = _shaped(mode, got["output"], source, tr, notes)
    return proposal, source, notes


# ---------------------------------------------------------------- 執行（步驟 6）
def _describe(item: dict, titles: dict[str, str]) -> str:
    kind = item.get("type")
    if kind == "control":
        return f"{item['event_id']} 加查「{titles.get(item['control_id'], item['control_id'])}」"
    if kind == "task":
        return f"{item['agent']} 的 {item['subagent']}：{item.get('event_id') or item.get('risk_id')}"
    if kind == "priority":
        return f"{item['agent']} 先說明 {item['risk_id']}"
    return f"執行摘要（{len(item.get('text') or '')} 字）"


def _trace_plan(tr, plan: dict, mode: str) -> None:
    sub = SUBAGENT[mode]
    n, m, k = o.counts(plan)
    titles = o.control_titles() if any(a.get("type") == "control" for a in plan["approved"]) else {}
    for a in plan["approved"]:
        tr.emit("tool", "核准：" + _describe(a, titles), subagent=sub)
    for r in plan["rejected"][:MAX_REJECT_TRACE]:
        tr.emit("skip", f"拒絕：{r['reason']}", subagent=sub)
    if k > MAX_REJECT_TRACE:
        tr.emit("skip", f"另有 {k - MAX_REJECT_TRACE} 筆拒絕，詳見計畫檔", subagent=sub)
    tr.emit("result", f"{MODE_ZH[mode]}：AI 建議 {n} 項、程式核准 {m} 項、拒絕 {k} 項"
                      f"（提案來源：{o.SOURCE_TEXT[plan['source']]}，{plan['source']}）")


def _summary(plan: dict) -> dict:
    n, m, k = o.counts(plan)
    return {"mode": plan["mode"], "source": plan["source"], "suggested": n, "approved": m, "rejected": k}


def run(ctx: RunCtx, mode: str) -> dict:
    """步驟 6：先寫 pending，再取得提案、由程式核准，原子寫入 <m>-plan.json。失敗時留下 pending（下游一律停用這份計畫）。"""
    _check(mode)
    agent, sub = AGENT[mode], SUBAGENT[mode]
    tr = ctx.tracer(agent)
    tr.emit("start", f"Orchestrator {MODE_ZH[mode]}：取得 AI 提案，由程式政策核准（只能追加任務與排優先）")
    path = o.plan_path(ctx.out, mode)
    o.write_plan(path, o.pending_plan(ctx, mode))            # 下游不會讀到上一次留下的舊檔
    verified, why = o.load_verified(ctx)
    if verified is None:
        # approve_core 需要 verified：自行寫出範本空計畫（下游核對 verified 時也會停用它）
        note = f"A1 結果不可用（{why}），本次只跑必要任務"
        plan = o.empty_plan(ctx, mode, status="complete", source="template", note=note)
        tr.emit("skip", note, subagent=sub, source="template")
    else:
        base = o.base_inputs(ctx)
        resolved, notes = None, []
        if mode == "review":
            resolved = o.resolve_plans(ctx, verified=verified, want=("dispatch",), base=base)
            if resolved.dispatch is None:
                notes.append(f"{NOTE_DISPATCH_UNAVAILABLE}（{resolved.reasons.get('dispatch')}），驗收單不綁定派工單")
                tr.emit("skip", notes[-1], subagent=sub)
        proposal, source, more = get_proposal(ctx, mode, tr, verified=verified, base=base, resolved=resolved)
        plan = o.build_plan(mode, proposal, ctx=ctx, verified=verified, source=source, note="；".join([*notes, *more]) or None,
                            dispatch_res=resolved.res if resolved else None,
                            dispatch_plan=resolved.dispatch if resolved else None, base=base)
    o.write_plan(path, plan)
    _trace_plan(tr, plan, mode)
    finish(ctx, agent)
    return _summary(plan)
