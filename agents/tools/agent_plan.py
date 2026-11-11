"""動態派工：AI 建議、程式核准（specs/dynamic-planner）。純規則層，不呼叫 LLM、不連網路。

- AI（daily-intel 的訂閱方案建議，或 A1 planner）只能建議兩種追加工作：
  加查控制項（只列出本次已算好的檢查結果）與請 A4 多說明相關風險；不能關閉必要評估，也不影響分數、燈號、結論
- 程式逐項核准：白名單、本次範圍、數量上限、只能追加；每個拒絕都有白話原因
- 計畫檔 out/a1/agent-plan.json 綁定本次執行識別與 verified.json 雜湊，下游讀到舊檔、壞檔或不符的計畫一律停用

模組載入時只匯入 tools 層，不匯入 context、llm、daily_intel，避免循環匯入。
"""
from __future__ import annotations

import copy
import json
import os
import re
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING

from tools.common import SECRET_RE, read_json, sha256_json, stable_id

if TYPE_CHECKING:  # pragma: no cover
    from context import RunCtx

ALLOWED_EXTRA = {("a4", "impact-analyst")}
TASK_MENU = [{"agent": "a4", "subagent": "impact-analyst", "what": "說明與此事件相關的風險影響（由程式挑選風險）"}]
MAX_EVENTS, MAX_CTRL_PER_EVENT, MAX_CTRL_TOTAL, MAX_TASKS, MAX_REASON = 5, 3, 8, 3, 120
MAX_RISKS_PER_TASK = 3
MAX_TEXT, MAX_CHAIN = 120, 5
SCHEMA_VERSION = 1
PLAN_FILE = "agent-plan.json"
TOP_KEYS = ("extra_controls", "extra_tasks")
CONTROL_KEYS = frozenset({"event_id", "control_id", "reason"})
TASK_KEYS = frozenset({"agent", "subagent", "event_id", "reason"})
PEER_KINDS = ("live", "demo")
SOURCES = ("subscription", "live", "replay", "template", "skipped")
SOURCE_TEXT = {"subscription": "訂閱方案", "live": "即時呼叫", "replay": "重播錄製", "template": "程式範本", "skipped": "未觸發"}
STATUS_TEXT = {"pass": "符合", "fail": "不符合", "unknown": "資料不足"}
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

R_ONLY_ADD = "只能追加，不能關閉或改變必要評估"
R_FIELDS = "欄位缺漏或格式不符"
R_EVENT = "事件不在本次範圍"
R_CONTROL = "不在控制項清單"
R_TASK = "不在可追加的工作清單"
R_MAPPED = "事件已對應此控制項"
R_REASON = "缺少理由"
R_DUP = "重複的建議"
R_LIMIT = "超過上限"
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


# ---------------------------------------------------------------- 事件
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


def build_payload(events: list[dict], controls: list[dict]) -> dict | None:
    """A1 planner 的輸入：去敏事件摘要＋控制項（只有 ID 與標題）＋可追加工作清單。不含時間、資產與檢查結果。"""
    rows = []
    for ev in events:
        title = safe_text(ev.get("title"))
        if not title:
            return None                                   # 無法安全組成輸入 → 範本
        rows.append({
            "id": ev["id"], "title": title, "industry": safe_text(ev.get("industry")),
            "attack_chain": [t for t in (safe_text(s) for s in (ev.get("attack_chain") or [])[:MAX_CHAIN]) if t],
            "attck": sorted({a for a in ev.get("attck") or [] if isinstance(a, str)}),
            "cves": sorted({c for c in ev.get("cves") or [] if isinstance(c, str)}),
            "controls_already": sorted({c for c in ev.get("controls") or [] if isinstance(c, str)}),
        })
    return {"ids": sorted({r["id"] for r in rows}), "events": rows,
            "controls": sorted(({"id": c["id"], "title": c["title"]} for c in controls), key=lambda c: c["id"]),
            "extra_task_menu": sorted(TASK_MENU, key=lambda t: (t["agent"], t["subagent"]))}


# ---------------------------------------------------------------- 格式與核准
def validate_plan_shape(output) -> dict:
    """整份格式檢查（R3）：物件、兩個可省略的陣列、物件元素、不含機敏值。未知鍵與欄位錯誤留給 approve 逐項拒絕。"""
    if not isinstance(output, dict):
        raise ValueError("需要 JSON 物件")
    for k in TOP_KEYS:
        if k in output:
            if not isinstance(output[k], list):
                raise ValueError(f"{k} 需要陣列")
            if any(not isinstance(i, dict) for i in output[k]):
                raise ValueError(f"{k} 的元素需要物件")
    if SECRET_RE.search(json.dumps(output, ensure_ascii=False, default=str)):
        raise ValueError("輸出含疑似機敏值")
    return output


def _registry_ok(agent: str, subagent: str) -> bool:
    from registry import AGENTS
    return (agent, subagent) in ALLOWED_EXTRA and agent in AGENTS and subagent in AGENTS[agent].subagents


def _strip(item: dict, key: str):
    v = item.get(key)
    return v.strip() if isinstance(v, str) else v


def approve(output: dict, *, events: list[dict], controls: list[dict]) -> dict:
    """逐項核准。events 是本次選出的新事件（含有效控制項對應）；controls 是 controls.yaml 白名單。

    回傳 {"suggested": N, "approved": [...], "rejected": [...]}，N = M + K。先處理 extra_controls 再處理 extra_tasks，
    拒絕不占配額；每項只保留第一個拒絕原因。拒絕明細只保留安全欄位，不保存原始未知欄位與值。
    """
    ev_by_id = {e["id"]: e for e in events}
    titles = {c["id"]: c["title"] for c in controls}
    approved, rejected = [], []
    for _ in sorted(k for k in output if k not in TOP_KEYS):
        rejected.append({"type": "field", "reason": R_ONLY_ADD})
    per_event: dict[str, int] = {}
    n_ctrl = n_task = 0
    seen_ctrl, seen_task = set(), set()

    def reject(kind: str, item: dict, reason: str, **ids) -> None:
        row = {"type": kind}
        eid = _strip(item, "event_id")
        if isinstance(eid, str) and eid in ev_by_id:
            row["event_id"] = eid
        row.update({k: v for k, v in ids.items() if v})
        sr = safe_text(_strip(item, "reason"), MAX_REASON)
        if sr:
            row["suggested_reason"] = sr
        row["reason"] = reason
        rejected.append(row)

    for item in output.get("extra_controls") or []:
        eid, cid = _strip(item, "event_id"), _strip(item, "control_id")
        safe_cid = cid if isinstance(cid, str) and cid in titles else None
        if set(item) - CONTROL_KEYS:
            reject("control", item, R_ONLY_ADD, control_id=safe_cid)
            continue
        if not all(isinstance(_strip(item, k), str) for k in CONTROL_KEYS):
            reject("control", item, R_FIELDS, control_id=safe_cid)
            continue
        if eid not in ev_by_id:
            reject("control", item, R_EVENT, control_id=safe_cid)
            continue
        if safe_cid is None:
            reject("control", item, R_CONTROL)
            continue
        if cid in (ev_by_id[eid].get("controls") or []):
            reject("control", item, R_MAPPED, control_id=cid)
            continue
        reason = safe_text(_strip(item, "reason"), MAX_REASON)
        if not reason:
            reject("control", item, R_REASON, control_id=cid)
            continue
        if (eid, cid) in seen_ctrl:
            reject("control", item, R_DUP, control_id=cid)
            continue
        if per_event.get(eid, 0) >= MAX_CTRL_PER_EVENT or n_ctrl >= MAX_CTRL_TOTAL:
            reject("control", item, R_LIMIT, control_id=cid)
            continue
        seen_ctrl.add((eid, cid))
        per_event[eid] = per_event.get(eid, 0) + 1
        n_ctrl += 1
        approved.append({"type": "control", "event_id": eid, "control_id": cid, "reason": reason})

    for item in output.get("extra_tasks") or []:
        eid, agent, sub = _strip(item, "event_id"), _strip(item, "agent"), _strip(item, "subagent")
        ok_pair = isinstance(agent, str) and isinstance(sub, str) and _registry_ok(agent, sub)
        ids = {"agent": agent, "subagent": sub} if ok_pair else {}
        if set(item) - TASK_KEYS:
            reject("task", item, R_ONLY_ADD, **ids)
            continue
        if not all(isinstance(_strip(item, k), str) for k in TASK_KEYS):
            reject("task", item, R_FIELDS, **ids)
            continue
        if eid not in ev_by_id:
            reject("task", item, R_EVENT, **ids)
            continue
        if not ok_pair:
            reject("task", item, R_TASK)
            continue
        reason = safe_text(_strip(item, "reason"), MAX_REASON)
        if not reason:
            reject("task", item, R_REASON, **ids)
            continue
        if (eid, agent, sub) in seen_task:
            reject("task", item, R_DUP, **ids)
            continue
        if n_task >= MAX_TASKS:
            reject("task", item, R_LIMIT, **ids)
            continue
        seen_task.add((eid, agent, sub))
        n_task += 1
        approved.append({"type": "task", "agent": agent, "subagent": sub, "event_id": eid, "reason": reason})
    return {"suggested": len(approved) + len(rejected), "approved": approved, "rejected": rejected}


# ---------------------------------------------------------------- 加查結果與追加風險
def planner_checks(event_id: str, approved: list[dict], control_results: dict[str, dict]) -> list[dict]:
    """只把這件事件核准的控制項，轉成本次已算好的檢查結果（R5.3）。缺結果視為資料不足，不當成符合。"""
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
    """程式挑選要追加說明的風險（R6.1）：這件事件命中的風險，或加查不符合且資產與控制項同時符合的風險。"""
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


# ---------------------------------------------------------------- 計畫檔
def run_ident(ctx: "RunCtx") -> dict:
    try:
        attempt = int(os.environ.get("GITHUB_RUN_ATTEMPT") or 1)
    except ValueError:
        attempt = 1
    return {"run_id": ctx.run_id, "run_attempt": attempt if attempt > 0 else 1, "scope": ctx.scope,
            "scenario": ctx.scenario, "target_sha": ctx.target_sha}


def empty_plan(ctx: "RunCtx", *, status: str, source: str, note: str | None, verified_sha256: str | None = None,
               events: list[str] | None = None) -> dict:
    return {"schema_version": SCHEMA_VERSION, "status": status, **run_ident(ctx), "verified_sha256": verified_sha256,
            "source": source, "note": note, "events": events or [], "suggested": 0, "approved": [], "rejected": []}


def write_plan(path: Path, plan: dict) -> None:
    """同目錄暫存檔＋原子替換；寫入失敗直接拋錯（A1 明確失敗，下游依 R7.3 用空計畫）。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def load_verified(ctx: "RunCtx") -> tuple[list[dict] | None, str | None]:
    """安全讀取 A1 的 verified.json：缺檔、壞檔或結構錯誤回傳 (None, 原因)，不拋錯。"""
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


def _nonneg_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _valid_rejected(row, ev_ids: set[str], ctrl_ids: set[str]) -> bool:
    if not isinstance(row, dict) or row.get("type") not in ("control", "task", "field"):
        return False
    allowed = {"type", "event_id", "control_id", "agent", "subagent", "suggested_reason", "reason"}
    if set(row) - allowed or not isinstance(row.get("reason"), str) or len(row["reason"]) > 200:
        return False
    if "event_id" in row and row["event_id"] not in ev_ids:
        return False
    if "control_id" in row and row["control_id"] not in ctrl_ids:
        return False
    if ("agent" in row or "subagent" in row) and (row.get("agent"), row.get("subagent")) not in ALLOWED_EXTRA:
        return False
    sr = row.get("suggested_reason")
    return sr is None or (isinstance(sr, str) and len(sr) <= MAX_REASON and not SECRET_RE.search(sr))


def load_agent_plan(ctx: "RunCtx", verified: list[dict] | None) -> tuple[dict | None, str | None]:
    """下游（A4、A5、llm-plan）讀取並核對 A1 的計畫；任何不符整份停用，回傳 (None, 安全原因碼)。"""
    if verified is None:
        return None, "verified_unavailable"
    path = ctx.out / "a1" / PLAN_FILE
    if not path.is_file():
        return None, "plan_missing"
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None, "plan_unreadable"
    if not isinstance(plan, dict) or plan.get("schema_version") != SCHEMA_VERSION:
        return None, "plan_version"
    if plan.get("status") != "complete":
        return None, "plan_pending"
    if any(plan.get(k) != v for k, v in run_ident(ctx).items()):
        return None, "plan_other_run"
    sha = plan.get("verified_sha256")
    if not isinstance(sha, str) or not SHA_RE.match(sha) or sha != sha256_json(verified):
        return None, "plan_verified_mismatch"
    if plan.get("source") not in SOURCES or not (plan.get("note") is None or (isinstance(plan["note"], str) and len(plan["note"]) <= 300)):
        return None, "plan_invalid"
    approved, rejected = plan.get("approved"), plan.get("rejected")
    if not isinstance(approved, list) or not isinstance(rejected, list) or not _nonneg_int(plan.get("suggested")):
        return None, "plan_invalid"
    if plan["suggested"] != len(approved) + len(rejected):
        return None, "plan_counts"
    if plan["source"] in ("template", "skipped") and plan["suggested"]:
        return None, "plan_counts"
    events = effective_events(verified)
    peer = {e["id"]: e for e in events if e.get("kind") in PEER_KINDS}
    ids = plan.get("events")
    if not isinstance(ids, list) or len(ids) > MAX_EVENTS or len(set(ids)) != len(ids) or any(i not in peer for i in ids):
        return None, "plan_events"
    from tools.controls import load_controls
    controls = [{"id": c["id"], "title": c["title"]} for c in load_controls()]
    selected = [peer[i] for i in ids]
    # 核准項目重新以同一套規則核對（不直接信任檔案裡的 approved）
    re_out = {"extra_controls": [{k: a.get(k) for k in CONTROL_KEYS} for a in approved if isinstance(a, dict) and a.get("type") == "control"],
              "extra_tasks": [{k: a.get(k) for k in TASK_KEYS} for a in approved if isinstance(a, dict) and a.get("type") == "task"]}
    shapes_ok = all(isinstance(a, dict) and a.get("type") in ("control", "task")
                    and set(a) == ({"type"} | (CONTROL_KEYS if a["type"] == "control" else TASK_KEYS)) for a in approved)
    again = approve(re_out, events=selected, controls=controls)
    if not shapes_ok or again["rejected"] or len(again["approved"]) != len(approved):
        return None, "plan_approved_invalid"
    ctrl_ids = {c["id"] for c in controls}
    if not all(_valid_rejected(r, set(ids), ctrl_ids) for r in rejected):
        return None, "plan_rejected_invalid"
    return {**plan, "approved": again["approved"]}, None


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


def read_plan_file(ctx: "RunCtx") -> dict | None:
    return read_json(ctx.out / "a1" / PLAN_FILE)
