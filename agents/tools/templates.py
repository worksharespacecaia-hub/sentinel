"""程式範本：LLM 失敗、超出預算或 replay 未錄製時的降級文字。只建議，不執行任何修改。"""
from __future__ import annotations

OWNER_BY_ASSET_TYPE = {"internal_tool": "devops-team", "datastore": "dba-team", "device": "it-team", "app": "mobile-team",
                       "token": "security-team", "saas": "it-team", "api": "platform-team"}


def owner_for(risk: dict, graph_nodes: dict) -> str:
    node = graph_nodes.get(risk["asset_id"], {})
    return node.get("owner") or OWNER_BY_ASSET_TYPE.get(node.get("type", ""), "security-team")


def solution_for(risk: dict, graph_nodes: dict) -> dict:
    cat, ctrl = risk["category"], risk.get("control_id")
    asset = risk["asset_id"]
    owner = owner_for(risk, graph_nodes)
    eol_no_fix = any(b["factor"] == "已停止支援" for b in risk["breakdown"])
    if cat == "vuln" and eol_no_fix:
        temporary = f"立即限制 {asset} 的對外存取（WAF 規則、關閉高風險功能），並加強監控"
        permanent = f"將 {asset} 升級到仍受支援且已修補的版本，完成回歸測試後上線"
        options = [
            {"name": "緩解", "action": "WAF 限制異常請求、關閉不必要的功能", "cost": "需驗證不影響現有功能", "timing": "今天"},
            {"name": "下架", "action": f"暫停 {asset}，改導向其他服務", "cost": "相關流量中斷", "timing": "今天"},
            {"name": "修補", "action": "升級到受支援的修補版本", "cost": "需回歸測試", "timing": "7 天內"},
        ]
    elif cat == "vuln":
        temporary = f"確認 {asset} 的暴露範圍，先以 WAF 或存取限制降低風險"
        permanent = f"將 {asset} 的受影響元件升級到修補版本"
        options = [
            {"name": "修補", "action": "升級到修補版本", "cost": "需回歸測試", "timing": f"{risk['deadline_hours']} 小時內"},
            {"name": "緩解", "action": "限制來源、關閉受影響功能", "cost": "部分功能受限", "timing": "今天"},
        ]
    elif ctrl in ("C-SECRET-IN-GIT", "C-THIRD-PARTY-KEY-ROTATION", "C-DEV-DEVICE-TOKEN") or cat in ("secret", "identity"):
        temporary = f"撤銷並輪替 {risk.get('credential_id') or asset}，確認撤銷後舊值無法使用"
        permanent = "金鑰改存 Secrets Manager、設定 IP 白名單與短效憑證，並從 Git 歷史稽核舊值的使用紀錄"
        options = [{"name": "緩解", "action": "撤銷並輪替金鑰", "cost": "使用該金鑰的服務需同步更新", "timing": "今天"}]
    elif ctrl == "C-INTERNAL-TOOL-EXPOSED":
        temporary = f"立即關閉 {asset} 的對外入口，改為只允許 VPN 連入"
        permanent = "內部工具一律放在內網並經 SSO，納入清冊與修補流程"
        options = [{"name": "緩解", "action": "關閉對外入口", "cost": "遠端使用者需改用 VPN", "timing": "今天"}]
    elif ctrl == "C-NET-SEGMENT":
        temporary = "封鎖非正式環境到正式資料庫的連線"
        permanent = "正式與測試環境分開網段與帳號，正式資料庫只接受核准的服務連線"
        options = [{"name": "緩解", "action": "調整安全群組", "cost": "需確認測試流程不依賴正式資料", "timing": "7 天內"}]
    elif ctrl == "C-CLOUD-STORAGE-PUBLIC":
        temporary = f"關閉 {asset} 的公開讀取，檢查存取紀錄是否已被下載"
        permanent = "儲存空間預設私有，以簽章網址分享；加入設定漂移檢查"
        options = [{"name": "緩解", "action": "關閉公開讀取", "cost": "使用公開網址的功能需改為簽章網址", "timing": "今天"}]
    elif ctrl == "C-BACKUP-ISOLATION" or cat == "backup":
        temporary = "建立一份離線或不同帳號的備份"
        permanent = "備份與來源隔離（不同帳號或離線），每 90 天做一次還原測試"
        options = [{"name": "緩解", "action": "建立隔離備份", "cost": "儲存費用", "timing": "7 天內"}]
    elif cat == "shadow_it":
        temporary = f"確認 {asset} 的負責人與用途，必要時先關閉對外存取"
        permanent = "納入清冊，指定負責人，改走 CI/CD 與修補流程，或正式除役"
        options = [{"name": "緩解", "action": "指定負責人並納管", "cost": "人力", "timing": "24 小時內"},
                   {"name": "下架", "action": "確認無人使用後除役", "cost": "可能影響未知的使用者", "timing": "7 天內"}]
    elif cat == "clone_app":
        temporary = "通知受影響品牌商並向商店檢舉下架"
        permanent = "定期監控商店上的冒用 App，提供會員辨識官方 App 的方式"
        options = [{"name": "緩解", "action": "檢舉下架、發布防詐提醒", "cost": "客服人力", "timing": "今天"}]
    elif cat == "mobile":
        temporary = "伺服器端先限制舊版 App 可呼叫的 API"
        permanent = "修正 App 設定後發版，提高最低支援版本並強制更新"
        options = [{"name": "修補", "action": "修正設定並分批發版", "cost": "各品牌需重新上架", "timing": "數天"}]
    else:
        temporary = f"確認 {asset} 的狀況並限制存取"
        permanent = "依控制項要求修正，並在下次掃描確認"
        options = [{"name": "緩解", "action": "依控制項修正", "cost": "依項目而定", "timing": f"{risk['deadline_hours']} 小時內"}]
    return {"risk_id": risk["id"], "temporary": temporary, "permanent": permanent, "options": options,
            "suggested_owner": owner, "verify": "工程團隊修正後，下次完整掃描不再命中才標示已修復", "source": "template"}


# CEO 摘要用白話描述「可能碰到什麼」，不寫版本號、CVE、元件名稱（ceo-brief skill）
DATA_CLASS_TEXT = {"order": "訂單資料", "pii": "會員個資", "payment": "金流資料", "source_code": "原始碼", "session": "登入狀態"}


def _has_factor(risk: dict, factor: str) -> bool:
    return any(b["factor"] == factor for b in risk.get("breakdown") or [])


def _reach_text(highs: list[dict], nodes: dict) -> list[str]:
    """攻擊路徑終點轉白話（依節點 data_classes），去重保序；沒有資料類別的終點寫成「核心系統（id）」。"""
    out: list[str] = []
    for r in highs:
        path = r.get("attack_path") or []
        if len(path) < 2:
            continue
        target = path[-1]
        classes = (nodes.get(target) or {}).get("data_classes") or []
        labels = [DATA_CLASS_TEXT[c] for c in classes if c in DATA_CLASS_TEXT] or [f"核心系統（{target}）"]
        for label in labels:
            if label not in out:
                out.append(label)
    return out


def ceo_summary(light: str, risks: list[dict], intel: dict, nodes: dict | None = None) -> list[str]:
    nodes = nodes or {}
    highs = [r for r in risks if r["level"] == "high" and r["status"] != "fixed"]
    meds = [r for r in risks if r["level"] == "medium" and r["status"] != "fixed"]
    first = {"red": "今天是紅燈", "yellow": "今天是黃燈", "green": "今天是綠燈"}[light]
    chained = [r for r in highs if len(r.get("attack_path") or []) > 1]
    eol = [r for r in highs if _has_factor(r, "已停止支援")]
    parts = []
    if chained:
        reach = _reach_text(chained, nodes)
        parts.append(f"{len(chained)} 個問題可被串成入侵路徑" + (f"，可能一路碰到{'、'.join(reach)}" if reach else ""))
    if eol:
        parts.append(f"{len(eol)} 個對外系統已停止支援、沒有修補版本")
    if not parts and highs:
        parts.append(f"{len(highs)} 個高風險要在 24 小時內處理")
    second = f"最需要處理的是：{'；'.join(parts)}。" if parts else "目前沒有高風險。"
    return [
        f"{first}：{len(highs)} 個高風險、{len(meds)} 個中風險。",
        second,
        f"今天檢查 {intel.get('checked', 0)} 件外部資安事件，其中 {intel.get('affected', 0)} 件與我們有關。",
    ]


def decisions(risks: list[dict]) -> list[str]:
    """下架問題在前；未登記的系統合併成一條（格式與網站 lib/brief.ts 的 groupDecisions 一致）。"""
    takedown, shadow = [], []
    for r in risks:
        if r["status"] == "fixed" or r["level"] != "high":
            continue
        if _has_factor(r, "已停止支援"):
            d = f"是否暫時下架 {r['asset_id']}（已停止支援且沒有修補版本）"
            if d not in takedown:
                takedown.append(d)
        if r["category"] == "shadow_it" and r["asset_id"] not in shadow:
            shadow.append(r["asset_id"])
    out = list(takedown)
    if len(shadow) == 1:
        out.append(f"{shadow[0]} 要納管還是除役")
    elif shadow:
        out.append(f"{len(shadow)} 個未登記的系統要納管還是除役：{'、'.join(shadow)}")
    return out[:5]


def notice_draft(event_title: str, brands: list[str] | None = None) -> str:
    target = "、".join(brands) if brands else "各品牌商"
    return (f"致{target}：我們發現與「{event_title}」相關的風險，正在處理中。請提醒會員：官方不會以電話或簡訊要求轉帳或提供驗證碼，"
            "也請只從官方商店下載品牌 App。有疑問請聯繫平台客服。（自動範本，發送前請人工確認）")
