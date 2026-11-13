"""需確認項目的可能破口與查核建議（0.12.0 specs/check-hints；0.12.1 specs/check-hints-ai）：不連網路、不呼叫 LLM。

- R2：依 need_check 的原因（intel_match 寫的私有欄位 _need）產生具體建議，範本寫在程式中，不讀規則表
- 無比對依據事件的破口推測，採用順序（specs/check-hints-ai R3）：
  1. daily-intel 寫在事件上的 possible_entry_points（AI 推測），使用前再檢查一次；systems 只留本次 ai_assets 中的 ID
  2. 沒有合格的 AI 推測時，依 rules/check-hints.json 判斷「被打到的地方」，列出破口假設（規則推測，備援）
  3. 都沒有時，退回寫在程式內的通用建議（與既有 to_verify 相同）

建議只附在 impact 的 suggestions，不改 verdict／reason／risk_id／to_verify，也不影響分數、等級、燈號與結論。
規則表、事件內容與 AI 推測都只當資料。
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import yaml

from tools.common import INTEL_DIR, RULES_DIR
from tools.stack import ai_assets, nodes_of

CHECK_HINTS_FILE = RULES_DIR / "check-hints.json"
RULES_SOURCE = "rules/check-hints.json"
INVALID_ISSUE = {"source": RULES_SOURCE, "status": "invalid", "required": False,
                 "impact": "查核建議規則無效，改用通用建議"}

ID_RE = re.compile(r"^[a-z0-9-]{2,40}$")
ATTCK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

LIMITS = {"hypothesis": 120, "why": 120, "check": 160, "how": 200, "plain": 80, "basis": 160}
LABEL_LIMIT = 40
KEYWORD_LIMIT = 40
MAX_SYSTEMS = 5
MAX_INFERRED = 4          # 規則推測上限（v0.12.0 R3.6）
MAX_REASON_BASED = 6      # R2.7：依原因的建議與通用建議
MAX_AI_ITEMS = 3          # specs/check-hints-ai R2.1、R3
AI_TEXT_LIMIT = 80
AI_CHECK_LIMIT = 160
AI_BASIS_LIMIT = 120

STATUS_LABEL = {"pass": "符合", "fail": "不符合", "unknown": "資料不足"}
SOURCE_NAMES = {0: "事件標題", 2: "事件摘要", 3: "建議新增的控制項"}

SELECTOR_KEYS = {"types", "data_classes_any", "exposed", "management_interface", "crown_jewel", "env", "has_vendor",
                 "id_contains"}
TARGET_KEYS = {"id", "label", "keywords", "attck", "hypotheses"}
HYPOTHESIS_KEYS = {"id", "hypothesis", "why", "check", "how", "plain", "attck", "selector", "related_controls"}
TOP_KEYS = {"schema_version", "initial_access_attck", "unstated_words", "targets"}

# ── R2：依原因的範本 ─────────────────────────────────────────────

ECOSYSTEM_HOW = {
    "npm": "查 lockfile 中的版本，或在該服務目錄執行 `npm ls {name}`",
    "php": "在主機執行 `php -v`，並確認 SAPI（`php -i` 的 Server API）",
    "synology-dsm": "DSM「控制台 → 資訊中心」的 DSM 版本",
    **{e: "查該專案的相依鎖定檔" for e in ("composer", "pypi", "maven", "go", "nuget", "rubygems")},
    "deb": "在主機查已安裝套件版本（`dpkg -l`／`rpm -q`）",
    "rpm": "在主機查已安裝套件版本（`dpkg -l`／`rpm -q`）",
    "docker": "查映像標籤與 digest",
}
ECOSYSTEM_HOW_DEFAULT = "補 runtime 盤點中的版本欄位"

CONDITION_HOW = {
    "serves_web_requests": ("PHP 是否直接處理網頁請求",
                            "查 php-config 快照的 SAPI；apache2handler、fpm-fcgi 等網頁 SAPI 才算"),
    "hosting": ("是否為自行部署", "查部署方式（自架主機或託管平台）"),
    "middleware_auth": ("授權檢查是否只在 middleware 執行",
                        "檢查 middleware 是否負責登入導向，以及頁面與 API 是否有第二層檢查"),
    "management_interface_internet_exposed": ("管理介面是否對外", "查 network 盤點與防火牆、反向代理、UPnP 設定"),
    "login_reachable": ("登入頁是否從外部連得到", "從外部網路測試登入頁網址"),
}

GENERIC_CHECKS = ("人工判斷事件的攻擊手法是否適用於我們的系統",
                  "把事件對應到 controls.yaml 的控制項；沒有合適的就建議新增")
GENERIC_PLAIN = "依事件內容人工判斷是否適用"
GENERIC_BASIS = "事件沒有可比對的產品、CVE 或控制項"


# ── 規則表 ─────────────────────────────────────────────────────

def _control_catalog() -> dict[str, str]:
    """controls.yaml 的 {ID: 標題}。"""
    rows = yaml.safe_load((INTEL_DIR / "controls.yaml").read_text(encoding="utf-8")) or []
    return {c["id"]: c.get("title") or c["id"] for c in rows if isinstance(c, dict) and c.get("id")}


def _str(value, limit: int, what: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{what} 必須是 1～{limit} 字的字串")
    return value


def _str_list(value, what: str, *, allow_empty: bool, limit: int = KEYWORD_LIMIT, pattern: re.Pattern | None = None):
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ValueError(f"{what} 必須是{'' if allow_empty else '非空'}陣列")
    for v in value:
        _str(v, limit, what)
        if pattern is not None and not pattern.match(v):
            raise ValueError(f"{what} 格式不符：{v}")
    return value


def _validate_selector(selector) -> None:
    if not isinstance(selector, list) or not selector:
        raise ValueError("selector 必須是非空清單")
    for clause in selector:
        if not isinstance(clause, dict) or not clause:
            raise ValueError("selector 子句必須是非空物件")
        for k, v in clause.items():
            if k not in SELECTOR_KEYS:
                raise ValueError(f"selector 不認得的條件：{k}")
            if k in ("types", "data_classes_any", "id_contains"):
                _str_list(v, f"selector.{k}", allow_empty=False)
            elif k in ("exposed", "management_interface", "crown_jewel"):
                if not isinstance(v, bool):
                    raise ValueError(f"selector.{k} 必須是 bool")
            elif k == "env":
                _str(v, KEYWORD_LIMIT, "selector.env")
            elif k == "has_vendor" and v is not True:
                raise ValueError("selector.has_vendor 只能為 true")


def validate_rules(raw, control_ids: set[str] | None = None) -> dict:
    """驗證規則表格式（design §3.7）；任一條不符就丟出 ValueError。"""
    if control_ids is None:
        control_ids = set(_control_catalog())
    if not isinstance(raw, dict) or set(raw) != TOP_KEYS:
        raise ValueError("最上層欄位必須是 " + "、".join(sorted(TOP_KEYS)))
    if raw["schema_version"] != 1 or isinstance(raw["schema_version"], bool):
        raise ValueError("schema_version 必須為 1")
    _str_list(raw["initial_access_attck"], "initial_access_attck", allow_empty=False, pattern=ATTCK_RE)
    _str_list(raw["unstated_words"], "unstated_words", allow_empty=True)
    targets = raw["targets"]
    if not isinstance(targets, list) or not targets:
        raise ValueError("targets 必須是非空陣列")
    seen: set[str] = set()

    def new_id(value, what):
        _str(value, 40, what)
        if not ID_RE.match(value):
            raise ValueError(f"{what} 只能用小寫英數與連字號：{value}")
        if value in seen:
            raise ValueError(f"ID 重複：{value}")
        seen.add(value)

    for t in targets:
        if not isinstance(t, dict) or set(t) - TARGET_KEYS or not {"id", "label", "hypotheses"} <= set(t):
            raise ValueError("target 欄位不符")
        new_id(t["id"], "target.id")
        _str(t["label"], LABEL_LIMIT, "target.label")
        kws = _str_list(t.get("keywords", []), "target.keywords", allow_empty=True)
        atk = _str_list(t.get("attck", []), "target.attck", allow_empty=True, pattern=ATTCK_RE)
        if not kws and not atk:
            raise ValueError(f"target {t['id']} 需要至少 1 個 keywords 或 attck")
        hyps = t["hypotheses"]
        if not isinstance(hyps, list) or not 1 <= len(hyps) <= 3:
            raise ValueError(f"target {t['id']} 需要 1～3 個 hypotheses")
        for h in hyps:
            if not isinstance(h, dict) or set(h) - HYPOTHESIS_KEYS or not (HYPOTHESIS_KEYS - {"attck"}) <= set(h):
                raise ValueError("hypothesis 欄位不符")
            new_id(h["id"], "hypothesis.id")
            for k in ("hypothesis", "why", "check", "how", "plain"):
                _str(h[k], LIMITS[k], f"hypothesis.{k}")
            _str_list(h.get("attck", []), "hypothesis.attck", allow_empty=True, pattern=ATTCK_RE)
            _validate_selector(h["selector"])
            rc = _str_list(h["related_controls"], "related_controls", allow_empty=True)
            unknown = [c for c in rc if c not in control_ids]
            if unknown:
                raise ValueError(f"related_controls 不在 controls.yaml：{unknown}")
    return raw


def load_rules(path: Path | None = None) -> tuple[dict | None, dict | None]:
    """讀 rules/check-hints.json 並驗證格式；成功回傳 (rules, None)，失敗回傳 (None, data_issue)。

    路徑可用環境變數 SENTINEL_CHECK_HINTS_FILE 覆寫（測試用，比照 SENTINEL_SCORING_FILE）。永不丟出例外。
    """
    p = Path(path or os.environ.get("SENTINEL_CHECK_HINTS_FILE") or CHECK_HINTS_FILE)
    try:
        return validate_rules(json.loads(p.read_text(encoding="utf-8"))), None
    except Exception:                                        # 缺檔、JSON 錯誤、格式不符
        return None, dict(INVALID_ISSUE)


# ── 共用 ───────────────────────────────────────────────────────

def _clip(value, limit: int):
    if value is None:
        return None
    value = str(value)
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _suggestion(id_: str, *, check: str, source: str = "rule", inferred: bool = False, target=None, hypothesis=None,
                why=None, how=None, plain=None, basis=None, systems=None, controls=None) -> dict:
    return {"id": id_, "source": source, "inferred": inferred, "target": target,
            "hypothesis": _clip(hypothesis, LIMITS["hypothesis"]), "why": _clip(why, LIMITS["why"]),
            "check": _clip(check, LIMITS["check"]), "how": _clip(how, LIMITS["how"]),
            "plain": _clip(plain, LIMITS["plain"]), "basis": _clip(basis, LIMITS["basis"]),
            "systems": list(systems or [])[:MAX_SYSTEMS], "controls": list(controls or [])}


def _cap_reason_based(items: list[dict]) -> list[dict]:
    """R2.7：最多 6 條；超過時保留前 5 條，第 6 條為剩餘項目提示。"""
    if len(items) <= MAX_REASON_BASED:
        return items
    rest = len(items) - (MAX_REASON_BASED - 1)
    return [*items[: MAX_REASON_BASED - 1], _suggestion("more", check=f"另有 {rest} 項待確認，見原始待確認清單")]


def _clause_ok(asset_id: str, node: dict, clause: dict) -> bool:
    for k, v in clause.items():
        if k == "types":
            ok = node.get("type") in v
        elif k == "data_classes_any":
            ok = bool(set(node.get("data_classes") or []) & set(v))
        elif k == "exposed":
            ok = node.get("exposed_to_internet") is v
        elif k in ("management_interface", "crown_jewel"):
            ok = node.get(k) is v
        elif k == "env":
            ok = node.get("env") == v
        elif k == "has_vendor":
            ok = bool(node.get("vendor"))
        elif k == "id_contains":
            ok = any(s in asset_id for s in v)
        else:
            ok = False
        if not ok:
            return False
    return True


def select_systems(graph, selector: list[dict], labels: dict[str, str]) -> list[dict]:
    """selector 子句之間 OR、子句內 AND；排除 zone，依 asset_id 排序，最多 5 個。"""
    hits = sorted(nid for nid, node in nodes_of(graph)
                  if node.get("type") != "zone" and any(_clause_ok(nid, node, c) for c in selector))
    return [{"asset_id": a, "label": labels.get(a)} for a in hits[:MAX_SYSTEMS]]


def _control_results(ids: list[str], controls: dict[str, dict]) -> list[dict]:
    """相關控制項本次結果；沒有結果時為資料不足（不得當成符合）。"""
    catalog = None
    out = []
    for cid in ids:
        res = (controls or {}).get(cid) or {}
        status = res.get("status") if res.get("status") in STATUS_LABEL else "unknown"
        title = res.get("title")
        if not title:
            catalog = catalog if catalog is not None else _control_catalog()
            title = catalog.get(cid, cid)
        out.append({"control_id": cid, "title": title, "status": status, "status_label": STATUS_LABEL[status]})
    return out


def _system(asset_id: str, labels: dict[str, str]) -> list[dict]:
    return [] if not asset_id or asset_id == "*" else [{"asset_id": asset_id, "label": labels.get(asset_id)}]


# ── R2 ────────────────────────────────────────────────────────

def _fmt_iv(iv) -> str:
    if not isinstance(iv, dict):
        return str(iv)
    if "introduced" in iv or "fixed" in iv:
        lo = iv.get("introduced")
        lo = "所有版本" if lo in (None, "0") else f"{lo} 起"
        return f"{lo}～{iv['fixed']} 前" if iv.get("fixed") else f"{lo}（無修補）"
    return "、".join(f"{k}={v}" for k, v in iv.items() if v is not None)


def _ranges(affected) -> tuple[str, str]:
    if isinstance(affected, str):
        return affected, "見來源"
    if isinstance(affected, list) and affected:
        ranges = "；".join(_fmt_iv(iv) for iv in affected)
        fixed = [str(iv["fixed"]) for iv in affected if isinstance(iv, dict) and iv.get("fixed")]
        return ranges, "、".join(fixed) if fixed else "來源未列出"
    return "來源未列出", "來源未列出"


def _condition(key: str) -> tuple[str, str | None]:
    if key in CONDITION_HOW:
        return CONDITION_HOW[key]
    if key.startswith("session.") or key.startswith("php."):
        return f"php.ini 設定 {key}", f"在主機執行 `php -i`，或查 php.ini 的 {key}"
    return f"{key} 的實際設定", None


def reason_suggestions(imp: dict, need: dict, *, controls: dict, labels: dict[str, str]) -> list[dict]:
    """R2：依 _need 的原因產生建議（不讀規則表）。"""
    kind = need.get("kind")
    asset = imp.get("asset_id")
    sys_ = _system(asset, labels)
    product = need.get("product") or ""
    out: list[dict] = []
    if kind == "stack_incomplete":
        out.append(_suggestion("stack-incomplete", check=f"確認我們是否使用 {product}",
                               how=f"補齊 runtime 快照後重新評估，或在各系統查詢 {product}",
                               plain=f"確認我們有沒有用到 {product}", basis="資產清單缺失或過期"))
    elif kind == "version_unknown":
        ranges, fixed = _ranges(need.get("affected"))
        how = ECOSYSTEM_HOW.get(need.get("ecosystem") or "", ECOSYSTEM_HOW_DEFAULT).replace("{name}", product)
        out.append(_suggestion("version-unknown", check=f"取得 {asset} 上 {product} 的實際版本，對照受影響範圍 {ranges}（修補版本 {fixed}）",
                               how=how, plain=f"確認 {product} 的版本是否需要更新", basis="版本未知或範圍無法判斷",
                               systems=sys_))
    elif kind == "unknown_below":
        out.append(_suggestion("unknown-below", check=f"{product} {need.get('version') or ''} 是來源未涵蓋的舊分支，向原廠確認是否受影響",
                               how="查原廠公告的支援分支；規劃升級到受支援分支", plain="舊版本是否受影響要再向原廠確認",
                               basis=f"來源只涵蓋 {need.get('unknown_below')} 以上的版本", systems=sys_))
    elif kind == "conditions_unknown":
        for i, key in enumerate(need.get("keys") or [], 1):
            desc, how = _condition(str(key))
            out.append(_suggestion(f"condition-{i}", check=("確認 " if desc[:1].isascii() else "確認") + desc,
                                   how=how, basis="利用條件缺少資料", systems=sys_))
    elif kind == "control_unknown":
        cid = need.get("control_id")
        out.append(_suggestion("control-unknown", check=f"{need.get('title')}：缺少資料（{need.get('reason')}）",
                               how="補上資料後重新評估", basis="控制項資料不足",
                               controls=_control_results([cid], controls) if cid else []))
    elif kind == "manual_check":
        for i, item in enumerate(need.get("items") or [], 1):
            out.append(_suggestion(f"manual-check-{i}", check=str(item), basis="事件要求人工確認", systems=sys_))
    return _cap_reason_based(out)


# ── 規則推測（備援）與 AI 推測 ─────────────────────────────────

def _segments(ev: dict) -> list[tuple[int, int, str, str]]:
    """(出處層級, 段落序號, 出處名稱, 文字)：標題 0 → 攻擊過程 1 → 摘要 2 → 建議新增的控制項 3。"""
    segs = []
    if isinstance(ev.get("title"), str):
        segs.append((0, 0, SOURCE_NAMES[0], ev["title"]))
    for i, step in enumerate(ev.get("attack_chain") or [], 1):
        if isinstance(step, str):
            segs.append((1, i, f"攻擊過程第 {i} 步", step))
    if isinstance(ev.get("summary"), str):
        segs.append((2, 0, SOURCE_NAMES[2], ev["summary"]))
    for pc in ev.get("proposed_controls") or []:
        if isinstance(pc, dict):
            for k in ("title", "reason"):
                if isinstance(pc.get(k), str):
                    segs.append((3, 0, SOURCE_NAMES[3], pc[k]))
    return segs


def _attck_hit(event_ids: list[str], rule_ids: list[str]) -> str | None:
    """事件 attck 等於規則 ID，或以「規則 ID.」開頭（子技術）；回傳事件中命中的 ID。"""
    for e in event_ids:
        if any(e == r or e.startswith(r + ".") for r in rule_ids):
            return e
    return None


def detect_targets(ev: dict, rules: dict | None) -> list[dict]:
    """R3.1／R3.1a：命中的被打到的地方，依（出處層級, 段落序號, 規則表序號）排序。"""
    if not rules:
        return []
    segs = _segments(ev)
    ev_attck = [a for a in ev.get("attck") or [] if isinstance(a, str)]
    hits = []
    for idx, t in enumerate(rules["targets"]):
        kw_hit = None
        for level, seg_i, name, text in segs:
            low = text.lower()
            found = [(low.find(k.lower()), n, k) for n, k in enumerate(t.get("keywords", [])) if k.lower() in low]
            if found:
                kw_hit = (level, seg_i, name, min(found)[2])
                break
        atk = _attck_hit(ev_attck, t.get("attck", []))
        if kw_hit is None and atk is None:
            continue
        if kw_hit:
            level, seg_i, name, kw = kw_hit
            basis = f"{name}提到「{kw}」" + (f"；ATT&CK {atk}" if atk else "")
        else:
            level, seg_i, basis = 4, 0, f"ATT&CK {atk}"
        hits.append({"target": t, "key": (level, seg_i, idx), "basis": basis})
    hits.sort(key=lambda h: h["key"])
    return hits


def is_stated(ev: dict, rules: dict) -> bool:
    """R3.5：事件 attck 含初始入侵類技術，而且文字沒有「未說明」等字。"""
    if not _attck_hit([a for a in ev.get("attck") or [] if isinstance(a, str)], rules["initial_access_attck"]):
        return False
    text = "\n".join(s[3] for s in _segments(ev)).lower()
    return not any(w.lower() in text for w in rules["unstated_words"])


def _from_hypothesis(t: dict, h: dict, basis: str, *, graph, controls, labels) -> dict:
    return _suggestion(h["id"], source="rule", inferred=True, target=t["id"], hypothesis=h["hypothesis"], why=h["why"],
                       check=h["check"], how=h["how"], plain=h["plain"], basis=basis,
                       systems=select_systems(graph, h["selector"], labels),
                       controls=_control_results(h["related_controls"], controls))


def _rule_suggestions(ev: dict, hits: list[dict], rules: dict, *, graph, controls, labels) -> list[dict]:
    picked: list[tuple[dict, dict, str]] = []
    ids: set[str] = set()
    ev_attck = [a for a in ev.get("attck") or [] if isinstance(a, str)]
    if is_stated(ev, rules):
        # 全域優先：假設本身的 attck 與事件交集者，依 target 排序、再依 target 內順序放最前面
        for hit in hits:
            for h in hit["target"]["hypotheses"]:
                if h["id"] not in ids and _attck_hit(ev_attck, h.get("attck", [])):
                    picked.append((hit["target"], h, hit["basis"]))
                    ids.add(h["id"])
    queues = [[(hit["target"], h, hit["basis"]) for h in hit["target"]["hypotheses"]] for hit in hits]
    while len(picked) < MAX_INFERRED and any(queues):
        for q in queues:
            while q and q[0][1]["id"] in ids:
                q.pop(0)
            if q and len(picked) < MAX_INFERRED:
                t, h, basis = q.pop(0)
                picked.append((t, h, basis))
                ids.add(h["id"])
    return [_from_hypothesis(t, h, basis, graph=graph, controls=controls, labels=labels)
            for t, h, basis in picked[:MAX_INFERRED]]


def _clean_ai_text(value) -> str | None:
    if not isinstance(value, str):
        return None
    value = " ".join(CONTROL_CHARS_RE.sub(" ", value).split())
    return value or None


def _valid_items(raw) -> list[dict]:
    """合格的 AI 推測項目（specs/check-hints-ai R4.2，比照 v0.12.0 R4.3a 再檢查一次）；不合格的整項丟掉。

    text、basis 為非空字串；check 為字串或空值；清理後長度在上限內；原文與清理後都不含機敏內容；systems 是陣列。
    """
    from tools.digest import has_sensitive   # 延遲匯入：digest 會匯入 llm

    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if hasattr(item, "model_dump"):
            item = item.model_dump()
        if not isinstance(item, dict):
            continue
        raw_text, raw_check, raw_basis = item.get("text"), item.get("check"), item.get("basis")
        if raw_check is not None and not isinstance(raw_check, str):
            continue
        if not isinstance(item.get("systems"), list):
            continue
        text, check, basis = _clean_ai_text(raw_text), _clean_ai_text(raw_check), _clean_ai_text(raw_basis)
        if not text or not basis or len(text) > AI_TEXT_LIMIT or len(basis) > AI_BASIS_LIMIT:
            continue
        if check is not None and len(check) > AI_CHECK_LIMIT:
            continue
        if any(has_sensitive(v) for v in (raw_text, raw_check, raw_basis, text, check, basis) if isinstance(v, str)):
            continue
        out.append({"text": text, "check": check, "basis": basis,
                    "systems": [a for a in item["systems"] if isinstance(a, str)]})
    return out


def ai_suggestions(ev: dict, *, graph, labels: dict[str, str]) -> list[dict]:
    """possible_entry_points 轉成建議（specs/check-hints-ai R4）。

    回傳 list（不是 generator），呼叫端用 `if ai:` 判斷才正確（R4.3）。systems 只保留本次 ai_assets 中的 ID（R4.2）：
    graph 不存在的、被排除的類型（app_version、sdk、zone 等）、值驗證不合格的都移除。
    """
    labels = labels or {}
    items = _valid_items(ev.get("possible_entry_points"))[:MAX_AI_ITEMS]
    if not items:
        return []
    allowed = {a["id"] for a in ai_assets(graph, labels)}
    out: list[dict] = []
    for item in items:
        systems = [a for a in dict.fromkeys(item["systems"]) if a in allowed][:MAX_SYSTEMS]
        out.append(_suggestion(f"ai-{len(out) + 1}", source="ai", inferred=True, target=None,
                               hypothesis=item["text"], plain=item["text"], check=item.get("check") or item["text"],
                               how=None, basis=f"AI 依事件推測：{item['basis']}",
                               systems=[{"asset_id": a, "label": labels.get(a)} for a in systems], controls=[]))
    return out


def generic_suggestions(ev: dict) -> list[dict]:
    """R3.7：寫在程式內的通用建議（與既有 to_verify 相同），上限依 R2.7。"""
    proposed = [pc.get("title") or pc.get("id") for pc in ev.get("proposed_controls") or [] if isinstance(pc, dict)]
    checks = [*GENERIC_CHECKS, *[f"建議新增控制項：{t}" for t in proposed if t]]
    return _cap_reason_based([_suggestion(f"generic-{i}", check=c, plain=GENERIC_PLAIN if i == 1 else None,
                                          basis=GENERIC_BASIS)
                              for i, c in enumerate(checks, 1)])


def suggest_for_event(ev: dict, *, graph, controls, rules, labels) -> list[dict]:
    """無比對依據事件的破口推測（specs/check-hints-ai R3）：AI 推測 → 規則推測 → 通用建議，不混用。"""
    labels = labels or {}
    ai = ai_suggestions(ev, graph=graph, labels=labels)
    if ai:
        return ai
    hits = detect_targets(ev, rules)
    if hits:
        return _rule_suggestions(ev, hits, rules, graph=graph, controls=controls, labels=labels)
    return generic_suggestions(ev)


# ── 對外 ───────────────────────────────────────────────────────

def strip_private(impacts: list[dict]) -> list[dict]:
    """移除實作用的私有欄位（_need），就地修改並回傳同一份清單。"""
    for imp in impacts or []:
        imp.pop("_need", None)
    return impacts


def attach(match: dict, *, graph, controls: dict[str, dict], rules: dict | None, labels: dict[str, str]) -> None:
    """就地處理 match["impacts"]：need_check 加 suggestions、所有 impact 移除 _need。

    不修改 verdict／reason／risk_id／to_verify；affected／not_affected 不加 suggestions 鍵。
    """
    labels = labels or {}
    ev = match.get("event") or {}
    for imp in match.get("impacts") or []:
        need = imp.pop("_need", None)
        if imp.get("verdict") != "need_check":
            continue
        if not need:
            imp["suggestions"] = []
        elif need.get("kind") == "no_criteria":
            imp["suggestions"] = suggest_for_event(ev, graph=graph, controls=controls, rules=rules, labels=labels)
        else:
            imp["suggestions"] = reason_suggestions(imp, need, controls=controls, labels=labels)
