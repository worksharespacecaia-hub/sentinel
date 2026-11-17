"""程式範本：LLM 失敗、超出預算或 replay 未錄製時的降級文字。只建議，不執行任何修改。

v0.14.0（specs/plain-brief）：
- solution_for 另外產生給 CEO 看的白話標題（plain_title）與「不處理的話」（if_ignored），temporary 改白話（design §4）
- CEO 摘要與決策改白話，決策加「——不決定的話：」後果（design §5.1）
- 數字與指標的對應改用 rules/fact-words.json（design §5.2）：mismatched_numbers 取代舊的 unsourced_numbers

匯入關係：本模組不匯入 tools.plain_text（plain_text 會匯入本模組）；tools.orchestration 在函式內延遲匯入。
"""
from __future__ import annotations

import json
import re

from tools.common import RULES_DIR

OWNER_BY_ASSET_TYPE = {"internal_tool": "devops-team", "datastore": "dba-team", "device": "it-team", "app": "mobile-team",
                       "token": "security-team", "saas": "it-team", "api": "platform-team"}

# CEO 摘要用白話描述「可能碰到什麼」，不寫版本號、CVE、元件名稱（ceo-brief skill）
DATA_CLASS_TEXT = {"order": "訂單資料", "pii": "會員個資", "payment": "金流資料", "source_code": "原始碼", "session": "登入狀態"}

UNNAMED_SYSTEM = "未命名系統"
LABEL_LIMIT = 60                 # 系統白話名稱的上限（digest.LABEL_LIMIT 相同）
ID_NAME_LIMIT = 40               # 沒有白話名稱時，系統 ID 備援的上限（R3.2）
NEED_CHECK_TITLE = "需要確認："
NEED_CHECK_IGNORED = "如果確認屬實，"
DECISION_SEP = "——不決定的話："   # 決策「問題——不決定的話：後果」（R4.2）；網站 lib/brief.ts 有同名常數
SHADOW_IF_NOT = "負責人沒確認前，更新與監控可能沒人做，出事時也可能沒人發現。"


def owner_for(risk: dict, graph_nodes: dict) -> str:
    node = graph_nodes.get(risk["asset_id"], {})
    return node.get("owner") or OWNER_BY_ASSET_TYPE.get(node.get("type", ""), "security-team")


def _has_factor(risk: dict, factor: str) -> bool:
    return any(b["factor"] == factor for b in risk.get("breakdown") or [])


def _public_id(asset_id) -> bool:
    """系統 ID 能不能直接當名稱用（R3.2、R8.2）：safe_id、40 字內，且公開文字過濾後與原文完全相同。

    與 plain_text.exact_public 同一條規則（本模組不能匯入 plain_text，所以在這裡直接呼叫 public_safe）。
    """
    if not isinstance(asset_id, str) or not asset_id or len(asset_id) > ID_NAME_LIMIT:
        return False
    from tools.orchestration import public_safe, safe_id   # 延遲匯入：orchestration 會間接匯入 llm
    return safe_id(asset_id) and public_safe(asset_id, ID_NAME_LIMIT) == asset_id.strip()


def asset_name(asset_id, labels: dict | None = None) -> str:
    """系統白話名稱（design §2.3 的 name_for）：labels 已經過 R8 過濾；沒有名稱時 ID 通過檢查才用 ID，否則「未命名系統」。"""
    if labels and isinstance(asset_id, str) and asset_id in labels:
        return labels[asset_id]
    return asset_id if _public_id(asset_id) else UNNAMED_SYSTEM


_CJK = "㐀-鿿"
_LATIN_CJK_RE = re.compile(rf"(?<=[A-Za-z0-9])(?=[{_CJK}])|(?<=[{_CJK}])(?=[A-Za-z0-9])")


def spaced(text: str) -> str:
    """範本文字中，英數字與中文之間補一個半形空格（「品牌 App的密碼」→「品牌 App 的密碼」）。只用於程式範本，不改 AI 文字。"""
    return _LATIN_CJK_RE.sub(" ", text)


def risk_reach(risk: dict, nodes: dict) -> list[str]:
    """可能碰到的資料（design §3.5）：攻擊路徑長度 > 1 取終點的 data_classes，否則取風險資產本身的；轉白話、去重保序。"""
    path = risk.get("attack_path") or []
    target = path[-1] if len(path) > 1 else risk.get("asset_id")
    out: list[str] = []
    for c in (nodes.get(target) or {}).get("data_classes") or []:
        text = DATA_CLASS_TEXT.get(c)
        if text and text not in out:
            out.append(text)
    return out


def _plain(risk: dict, name: str, reach: list[str]) -> tuple[str, str, str]:
    """（plain_title, if_ignored, temporary）：design §4 的表格，依序比對。範本措辭不超出程式判定（R3.4）。"""
    cat, ctrl = risk["category"], risk.get("control_id")
    joined = "、".join(reach)

    def opt(fmt: str) -> str:            # reach 為空時整段省略
        return fmt.format(reach=joined) if reach else ""

    if cat == "vuln" and _has_factor(risk, "已停止支援"):
        return (f"{name}的軟體原廠已不再修補，有可被入侵的漏洞",
                f"漏洞不會再有官方修補，外人可能藉此控制{name}或竄改內容{opt('，進一步碰到{reach}')}。",
                f"先限制外人連到{name}並加強監看，同時評估是否暫時關掉")
    if cat == "vuln" and _has_factor(risk, "已遭實際利用"):
        return (f"{name}有已經被用來攻擊的漏洞{opt('，可能造成{reach}外洩')}",
                f"外人可能利用這個漏洞入侵{name}{opt('，一路碰到{reach}')}；這個漏洞已經有人在用。",
                f"先確認{name}有哪些地方外人連得到，能關的先關，並盡快安排更新")
    if cat == "vuln":
        return (f"{name}有已知漏洞{opt('，可能造成{reach}外洩')}",
                f"外人可能利用這個漏洞讓{name}停擺或被入侵{opt('，進一步碰到{reach}')}。",
                f"先確認{name}有哪些地方外人連得到，並安排更新")
    if ctrl == "C-DEV-DEVICE-TOKEN":
        return (f"{name}存著能直接改正式系統的權限",
                "這台電腦一旦中毒或遺失，對方就可能改動正式網站或 App。",
                "馬上把這個權限作廢，改用短期有效的權限")
    if ctrl in ("C-SECRET-IN-GIT", "C-THIRD-PARTY-KEY-ROTATION") or cat in ("secret", "identity"):
        return (f"{name}的密碼或金鑰保管不當{opt('，可能造成{reach}外洩')}",
                f"拿到這組密碼或金鑰的人，可能直接登入相關系統{opt('，讀走{reach}')}；不換掉，這個破口就一直在。",
                "馬上把這組密碼或金鑰作廢換新，並檢查最近有沒有被別人用過")
    if ctrl == "C-INTERNAL-TOOL-EXPOSED":
        return (f"只給員工用的{name}，外人也連得到",
                f"任何人都能從網路找到它的登入頁，外人可能藉此進到公司內部{opt('，最後碰到{reach}')}。",
                f"先讓{name}只有公司內部連得到")
    if ctrl == "C-NET-SEGMENT":
        return ("測試或辦公室網路可以直接連到正式資料庫",
                "這些網路裡的電腦一旦被入侵，外人就可能直接碰到正式資料。",
                "先擋住測試與辦公室網路連到正式資料庫")
    if ctrl == "C-CLOUD-STORAGE-PUBLIC":
        return (f"{name}設成任何人都能下載",
                "只要知道網址，任何人都能下載裡面的檔案；如果有個資外洩，可能要通報主管機關並通知受影響的人。",
                f"先把{name}改成不公開，並檢查有沒有被下載過")
    if ctrl == "C-BACKUP-ISOLATION" or cat == "backup":
        return (f"{name}的備份沒有分開保存",
                "遇到勒索軟體時，備份可能跟著一起被加密，資料救不回來。",
                "先另外做一份分開保存的備份")
    if cat == "shadow_it":
        return (f"{name}沒有登記，負責人尚未確認",
                "負責人沒確認前，更新與監控可能沒人做，漏洞會一直留著；出事時也可能沒人發現。",
                f"先找出{name}的負責人與用途，沒人用的話先停止對外開放")
    if cat == "clone_app":
        return ("有人冒用品牌上架假 App",
                "會員可能下載到假 App，被騙走帳號或個資，品牌信譽受損。",
                "通知受影響品牌商並向商店檢舉下架")
    if cat == "mobile":
        return (f"{name}的設定有安全問題",
                "外人可能利用 App 的設定問題取得會員資料或冒用 App。",
                "先在伺服器端限制舊版 App 能用的功能")
    return (f"{name}有安全設定問題",
            "問題會一直存在，增加被入侵的機會。",
            f"先確認{name}的狀況並限制誰能使用")


def solution_for(risk: dict, graph_nodes: dict, labels: dict | None = None) -> dict:
    """程式範本解法：permanent、options、verify、suggested_owner 是工程細節（不變）；temporary 與兩個白話欄位給 CEO 看。"""
    cat, ctrl = risk["category"], risk.get("control_id")
    asset = risk["asset_id"]
    owner = owner_for(risk, graph_nodes)
    eol_no_fix = _has_factor(risk, "已停止支援")
    if cat == "vuln" and eol_no_fix:
        permanent = f"將 {asset} 升級到仍受支援且已修補的版本，完成回歸測試後上線"
        options = [
            {"name": "緩解", "action": "WAF 限制異常請求、關閉不必要的功能", "cost": "需驗證不影響現有功能", "timing": "今天"},
            {"name": "下架", "action": f"暫停 {asset}，改導向其他服務", "cost": "相關流量中斷", "timing": "今天"},
            {"name": "修補", "action": "升級到受支援的修補版本", "cost": "需回歸測試", "timing": "7 天內"},
        ]
    elif cat == "vuln":
        permanent = f"將 {asset} 的受影響元件升級到修補版本"
        options = [
            {"name": "修補", "action": "升級到修補版本", "cost": "需回歸測試", "timing": f"{risk['deadline_hours']} 小時內"},
            {"name": "緩解", "action": "限制來源、關閉受影響功能", "cost": "部分功能受限", "timing": "今天"},
        ]
    elif ctrl in ("C-SECRET-IN-GIT", "C-THIRD-PARTY-KEY-ROTATION", "C-DEV-DEVICE-TOKEN") or cat in ("secret", "identity"):
        permanent = "金鑰改存 Secrets Manager、設定 IP 白名單與短效憑證，並從 Git 歷史稽核舊值的使用紀錄"
        options = [{"name": "緩解", "action": "撤銷並輪替金鑰", "cost": "使用該金鑰的服務需同步更新", "timing": "今天"}]
    elif ctrl == "C-INTERNAL-TOOL-EXPOSED":
        permanent = "內部工具一律放在內網並經 SSO，納入清冊與修補流程"
        options = [{"name": "緩解", "action": "關閉對外入口", "cost": "遠端使用者需改用 VPN", "timing": "今天"}]
    elif ctrl == "C-NET-SEGMENT":
        permanent = "正式與測試環境分開網段與帳號，正式資料庫只接受核准的服務連線"
        options = [{"name": "緩解", "action": "調整安全群組", "cost": "需確認測試流程不依賴正式資料", "timing": "7 天內"}]
    elif ctrl == "C-CLOUD-STORAGE-PUBLIC":
        permanent = "儲存空間預設私有，以簽章網址分享；加入設定漂移檢查"
        options = [{"name": "緩解", "action": "關閉公開讀取", "cost": "使用公開網址的功能需改為簽章網址", "timing": "今天"}]
    elif ctrl == "C-BACKUP-ISOLATION" or cat == "backup":
        permanent = "備份與來源隔離（不同帳號或離線），每 90 天做一次還原測試"
        options = [{"name": "緩解", "action": "建立隔離備份", "cost": "儲存費用", "timing": "7 天內"}]
    elif cat == "shadow_it":
        permanent = "納入清冊，指定負責人，改走 CI/CD 與修補流程，或正式除役"
        options = [{"name": "緩解", "action": "指定負責人並納管", "cost": "人力", "timing": "24 小時內"},
                   {"name": "下架", "action": "確認無人使用後除役", "cost": "可能影響未知的使用者", "timing": "7 天內"}]
    elif cat == "clone_app":
        permanent = "定期監控商店上的冒用 App，提供會員辨識官方 App 的方式"
        options = [{"name": "緩解", "action": "檢舉下架、發布防詐提醒", "cost": "客服人力", "timing": "今天"}]
    elif cat == "mobile":
        permanent = "修正 App 設定後發版，提高最低支援版本並強制更新"
        options = [{"name": "修補", "action": "修正設定並分批發版", "cost": "各品牌需重新上架", "timing": "數天"}]
    else:
        permanent = "依控制項要求修正，並在下次掃描確認"
        options = [{"name": "緩解", "action": "依控制項修正", "cost": "依項目而定", "timing": f"{risk['deadline_hours']} 小時內"}]
    title, ignored, temporary = (spaced(t) for t in _plain(risk, asset_name(asset, labels), risk_reach(risk, graph_nodes)))
    if risk.get("status") == "need_check":            # 需要確認的風險用條件語氣（R3.4）
        title, ignored = NEED_CHECK_TITLE + title, NEED_CHECK_IGNORED + ignored
    return {"risk_id": risk["id"], "temporary": temporary, "permanent": permanent, "options": options,
            "suggested_owner": owner, "verify": "工程團隊修正後，下次完整掃描不再命中才標示已修復", "source": "template",
            "plain_title": title, "if_ignored": ignored, "plain_source": "template"}


def _reach_text(highs: list[dict], nodes: dict, labels: dict | None = None) -> list[str]:
    """攻擊路徑終點轉白話（依節點 data_classes），去重保序；沒有資料類別的終點寫成「核心系統（名稱）」。"""
    out: list[str] = []
    for r in highs:
        path = r.get("attack_path") or []
        if len(path) < 2:
            continue
        target = path[-1]
        classes = (nodes.get(target) or {}).get("data_classes") or []
        texts = [DATA_CLASS_TEXT[c] for c in classes if c in DATA_CLASS_TEXT] or [f"核心系統（{asset_name(target, labels)}）"]
        for text in texts:
            if text not in out:
                out.append(text)
    return out


def ceo_summary(light: str, risks: list[dict], intel: dict, nodes: dict | None = None, labels: dict | None = None) -> list[str]:
    """三句白話摘要（design §5.1）：數字一律由程式計算，每個數字後面都有對應指標的詞（§5.2）。"""
    nodes = nodes or {}
    highs = [r for r in risks if r["level"] == "high" and r["status"] != "fixed"]
    meds = [r for r in risks if r["level"] == "medium" and r["status"] != "fixed"]
    first = {"red": "今天是紅燈", "yellow": "今天是黃燈", "green": "今天是綠燈"}[light]
    chained = [r for r in highs if len(r.get("attack_path") or []) > 1]
    eol = [r for r in highs if _has_factor(r, "已停止支援")]
    if chained:
        reach = _reach_text(chained, nodes, labels)
        second = (f"最急的是 {len(chained)} 個問題可以被駭客串起來一路闖進去"
                  + (f"，最後可能拿到{'、'.join(reach)}" if reach else "")
                  + (f"；另有 {len(eol)} 個對外系統的軟體原廠已不再修補" if eol else "") + "。")
    elif eol:
        second = f"最急的是 {len(eol)} 個對外系統的軟體原廠已不再修補。"
    elif highs:
        second = f"最急的是 {len(highs)} 個高風險要在 24 小時內處理。"
    else:
        second = "目前沒有高風險。"
    return [
        f"{first}：有 {len(highs)} 個高風險、{len(meds)} 個中風險的問題還沒處理。",
        second,
        f"今天看了 {intel.get('checked', 0)} 件外面發生的資安事件，其中 {intel.get('affected', 0)} 件的問題我們也有。",
    ]


def decisions(risks: list[dict], labels: dict | None = None) -> list[str]:
    """「問題？——不決定的話：後果」（R4.2）。停止支援在前；未登記的系統合併成一條；最多 5 條。"""
    takedown, shadow = [], []
    for r in risks:
        if r["status"] == "fixed" or r["level"] != "high":
            continue
        if _has_factor(r, "已停止支援"):
            name = asset_name(r["asset_id"], labels)
            d = (f"是否先把{name}暫時關掉？{DECISION_SEP}{name}的軟體原廠已不再修補，漏洞會一直開著，"
                 "外人可能藉此入侵或竄改內容。")
            if d not in takedown:
                takedown.append(d)
        if r["category"] == "shadow_it" and r["asset_id"] not in shadow:
            shadow.append(r["asset_id"])
    out = list(takedown)
    ask = "要正式列管（指定負責人、定期更新），還是確認沒人用後關掉？"
    if len(shadow) == 1:
        out.append(f"{asset_name(shadow[0], labels)}沒有登記，{ask}{DECISION_SEP}{SHADOW_IF_NOT}")
    elif shadow:
        names = "、".join(asset_name(a, labels) for a in shadow)
        out.append(f"這 {len(shadow)} 個沒登記的系統（{names}），{ask}{DECISION_SEP}{SHADOW_IF_NOT}")
    return [spaced(d) for d in out[:5]]


def decision_ok(text) -> bool:
    """AI 寫的每條決策：剛好一個「——不決定的話：」且前後非空（R4.6）。"""
    if not isinstance(text, str) or text.count(DECISION_SEP) != 1:
        return False
    question, if_not = text.split(DECISION_SEP)
    return bool(question.strip()) and bool(if_not.strip())


def summary_facts(risks: list[dict], intel: dict) -> dict:
    """CEO 摘要與決策可以出現的數字（全部由程式計算）；網站 lib/brief.ts 的 summaryFacts 用同一套定義帶出來源。"""
    live = [r for r in risks if r["status"] != "fixed"]
    highs = [r for r in live if r["level"] == "high"]
    return {
        "high": len(highs), "medium": sum(1 for r in live if r["level"] == "medium"), "low": sum(1 for r in live if r["level"] == "low"),
        "chained": sum(1 for r in highs if len(r.get("attack_path") or []) > 1),
        "eol": sum(1 for r in highs if _has_factor(r, "已停止支援")),
        "shadow_it": len({r["asset_id"] for r in highs if r["category"] == "shadow_it"}),
        "checked": int(intel.get("checked", 0)), "affected": int(intel.get("affected", 0)),
        "real_checked": int(intel.get("real_checked", intel.get("checked", 0))),
        "real_affected": int(intel.get("real_affected", intel.get("affected", 0))),
    }


# ---------------------------------------------------------------- 數字與指標（design §5.2）
_COUNT_RE = re.compile(r"(\d+)\s*(?:個|件|項|則|筆)")
_PUNCT_RE = re.compile(r"[，。；、,;]")
FACT_WORDS_FILE = RULES_DIR / "fact-words.json"


def _load_fact_words(path=FACT_WORDS_FILE) -> list[tuple[str, re.Pattern]]:
    """rules/fact-words.json：[[指標, 正規式], …]，順序是比對優先序（具體在前）。網站 lib/fact-words.json 是同一份的副本。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("words"), list):
        raise ValueError("rules/fact-words.json 格式無效")
    out = []
    for item in data["words"]:
        if not (isinstance(item, list) and len(item) == 2 and all(isinstance(x, str) and x for x in item)):
            raise ValueError("rules/fact-words.json 的每一項必須是 [指標, 正規式]")
        out.append((item[0], re.compile(item[1])))
    return out


FACT_WORDS = _load_fact_words()


def _load_refines(path=FACT_WORDS_FILE) -> dict[str, str]:
    """rules/fact-words.json 的 refines：{限定指標: 一般指標}（例如 real_checked 是 checked 的「真實事件」限定）。
    前後兩段分別對到一般與限定的同一類指標時不算歧義，取限定的那個（「今天檢查 13 件真實事件」）。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    refines = data.get("refines") or {}
    keys = {k for k, _ in FACT_WORDS}
    if not isinstance(refines, dict) or not all(k in keys and v in keys for k, v in refines.items()):
        raise ValueError("rules/fact-words.json 的 refines 格式無效")
    return dict(refines)


FACT_REFINES = _load_refines()


def _combine_keys(after_key: str | None, before_key: str | None) -> str | None:
    """前後兩段的指標合併：只有一段有就用它；相同或互為限定關係時取較精確的；其他不同為歧義（None）。"""
    if not (after_key and before_key) or after_key == before_key:
        return after_key or before_key
    if FACT_REFINES.get(after_key) == before_key:
        return after_key
    if FACT_REFINES.get(before_key) == after_key:
        return before_key
    return None


def _segment_key(segment: str) -> str | None:
    for key, pattern in FACT_WORDS:
        if pattern.search(segment):
            return key
    return None


def fact_key(text: str, matches: list[re.Match], i: int) -> str | None:
    """第 i 個「N 個／件／項／則／筆」對應的指標：只看數字前後、到標點或相鄰數字為止的文字；前後對到不同指標為歧義（None）。"""
    m = matches[i]
    stop = len(text)
    p = _PUNCT_RE.search(text, m.end())
    if p:
        stop = p.start()
    if i + 1 < len(matches):
        stop = min(stop, matches[i + 1].start())
    after_key = _segment_key(text[m.end():stop])
    start = 0
    for p in _PUNCT_RE.finditer(text, 0, m.start()):
        start = p.end()
    if i > 0:
        start = max(start, matches[i - 1].end())
    before_key = _segment_key(text[start:m.start()])
    return _combine_keys(after_key, before_key)


def mismatched_numbers(texts: list[str], facts: dict) -> list[int]:
    """文字中每個「N 個／件／項…」：找不到指標、指標歧義或數值不等於該指標，就列入（LLM 不能自行增減或錯置數字）。"""
    out = []
    for t in texts:
        if not isinstance(t, str):
            continue
        ms = list(_COUNT_RE.finditer(t))
        for i, m in enumerate(ms):
            n = int(m.group(1))
            key = fact_key(t, ms, i)
            if key is None or facts.get(key) != n:
                out.append(n)
    return out


def notice_draft(event_title: str, brands: list[str] | None = None) -> str:
    target = "、".join(brands) if brands else "各品牌商"
    return (f"致{target}：我們發現與「{event_title}」相關的風險，正在處理中。請提醒會員：官方不會以電話或簡訊要求轉帳或提供驗證碼，"
            "也請只從官方商店下載品牌 App。有疑問請聯繫平台客服。（自動範本，發送前請人工確認）")
