"""風險評分（第 7.4 節）。純函式：輸入因子真假，輸出分數、等級與拆解。

分數 = 基礎分（只取一項）＋ 加分因子。漏洞以 CVSS 為基礎，控制項以 base_points 為基礎，兩者不相加。
先依分數得 score_level，再套用暫定情資上限（最高中），最後套用對帳／訊號下限。
"""
from __future__ import annotations

from dataclasses import dataclass, field

DEADLINE_HOURS = {"high": 24, "medium": 168, "low": 720}
LEVEL_RANK = {"low": 0, "medium": 1, "high": 2}
OTHER_BASE = {"clone_app": 2, "shadow_api": 2, "shadow_it": 2}
# 未列入 controls.yaml 的類別：版本化確定性規則提供基礎分（缺少映射＝規則錯誤 → need_check）
RULE_POINTS_VERSION = "2026-11-09.1"
RULE_POINTS = {
    "eol:exposed": 2,
    "eol:internal": 1,
    "secret:test_env": 1,
    "mobile:android-debuggable": 2,
    "mobile:android-cleartext": 1,
    "mobile:android-exported-component": 1,
    "mobile:target-sdk-outdated": 1,
    "mobile:signing-or-push-key-shared": 2,
    "signal:confirmed": 3,
}


@dataclass
class Factors:
    base_kind: str                      # vuln | control | other | rule
    cvss: float | None = None
    base_points: int | None = None
    category: str | None = None         # other 類：clone_app／shadow_api／shadow_it
    rule_key: str | None = None         # rule 類：RULE_POINTS 的 key
    known_exploited: bool = False
    exposed: bool = False
    data_sensitive: bool = False
    platform: bool = False
    peer_event: bool = False
    on_attack_chain: bool = False
    eol_no_fix: bool = False
    compensating_effective: bool = False
    provisional: bool = False
    level_floor: str | None = None
    floor_reason: str | None = None
    notes: dict = field(default_factory=dict)


@dataclass
class ScoreResult:
    score: int
    raw_score: int
    score_level: str
    level: str
    level_reason: str
    breakdown: list[dict]
    deadline_hours: int
    need_check: bool


def level_from_score(score: int) -> str:
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def cvss_points(cvss: float | None) -> int | None:
    if cvss is None:
        return None
    if cvss >= 9:
        return 3
    if cvss >= 7:
        return 2
    if cvss >= 4:
        return 1
    return 0


def score(f: Factors) -> ScoreResult:
    breakdown: list[dict] = []
    need_check = False
    if f.base_kind == "vuln":
        pts = cvss_points(f.cvss)
        if pts is None:
            need_check = True
            pts = 0
            breakdown.append({"factor": "基礎分：漏洞", "points": 0, "reason": "CVSS 未知，標記待確認"})
        else:
            breakdown.append({"factor": "基礎分：漏洞", "points": pts, "reason": f"CVSS {f.cvss}"})
    elif f.base_kind == "control":
        if f.base_points is None:
            need_check = True
            pts = 0
            breakdown.append({"factor": "基礎分：控制項不符", "points": 0, "reason": "缺少 base_points（規則錯誤）"})
        else:
            pts = f.base_points
            breakdown.append({"factor": "基礎分：控制項不符", "points": pts, "reason": "controls.yaml base_points"})
    elif f.base_kind == "other":
        pts = OTHER_BASE.get(f.category or "")
        if pts is None:
            need_check, pts = True, 0
        breakdown.append({"factor": "基礎分：其他類別", "points": pts, "reason": f.category or "未知類別"})
    else:
        pts = RULE_POINTS.get(f.rule_key or "")
        if pts is None:
            need_check, pts = True, 0
            breakdown.append({"factor": "基礎分：規則", "points": 0, "reason": f"缺少規則映射 {f.rule_key}（need_check）"})
        else:
            breakdown.append({"factor": "基礎分：規則", "points": pts, "reason": f"{f.rule_key}（規則版 {RULE_POINTS_VERSION}）"})

    def add(cond: bool, factor: str, points: int, reason: str):
        if cond:
            breakdown.append({"factor": factor, "points": points, "reason": reason})

    add(f.known_exploited, "已遭實際利用", 2, "KEV 或官方確認")
    add(f.exposed, "對外暴露", 2, f.notes.get("exposed", "可從 internet 連到"))
    add(f.data_sensitive, "資料敏感", 1, f.notes.get("data", "個資、訂單、金流"))
    add(f.platform, "影響範圍", 1, "平台層，影響所有品牌")
    add(f.peer_event, "同業事件命中", 1, f.notes.get("peer", "至少一件真實事件命中"))
    add(f.on_attack_chain, "位於完整攻擊鏈", 3, f.notes.get("chain", "攻擊路徑前提的必要一步"))
    add(f.eol_no_fix, "已停止支援", 1, "無修補可用")
    add(f.compensating_effective, "補償措施", -3, f.notes.get("compensating", "有本次證據證明有效"))

    raw = sum(b["points"] for b in breakdown)
    total = max(raw, 0)
    score_level = level_from_score(total)
    level, reasons = score_level, []
    if f.provisional and LEVEL_RANK[level] > LEVEL_RANK["medium"]:
        level = "medium"
        reasons.append("暫定情資：最高只到中")
    if f.level_floor and LEVEL_RANK[f.level_floor] > LEVEL_RANK[level]:
        level = f.level_floor
        reasons.append(f"規則下限：{f.floor_reason or f.level_floor}")
    reason = "；".join(reasons) if reasons else "依分數"
    return ScoreResult(score=total, raw_score=raw, score_level=score_level, level=level, level_reason=reason,
                       breakdown=breakdown, deadline_hours=DEADLINE_HOURS[level], need_check=need_check)
