---
name: remediation-playbooks
description: 建議解法劇本索引；只讀命中的那一份，只寫建議方向與驗證方式
---

# 建議解法劇本
依風險類型只讀一份 `references/`：key-rotation、internal-tool-exposure、php2shell、nas-ransomware、identity-token、takedown-decision、mobile-sdk、incident-containment。

規則：
- 只寫建議方向、建議負責團隊、建議期限與驗證方式，由工程團隊決定是否執行。
- 沒有修補版本時，提供「修補／緩解／暫時下架」三個選項與影響，交給 CEO 決策。

## 白話標題與不處理的話（給 CEO 看）
- plain_title（40 字內）：系統白話名稱＋問題＋可能後果。例：「內部營運工具有帳號被盜用的漏洞，可能造成訂單與會員資料外洩」
- if_ignored（100 字內）：不處理時可能發生什麼，用任務內容的 path_names、may_reach、events。
  例：「外人可以從網路冒用帳號登入，再一路拿到正式訂單資料庫的帳密，把訂單和會員個資整批帶走。」
- status 為 need_check：用「可能」「需要確認」的語氣，不寫成已確定。
- events 有 brand 時可以提到該品牌（例：「同業 91APP 就是這樣被入侵」）；沒有 brand 的事件不得寫成某公司出事。
- 不得出現：CVE 編號、版本號、元件或套件名稱、系統代號（用 asset_name、path_names）、入侵路徑、納管、除役、WAF、VPN、Token。
- temporary 也用白話寫（CEO 頁顯示為「今天先做」）；技術做法寫在 permanent 與 options。
- 只用任務內容的事實，不誇大、不自行推測金額或人數。

範例（任務內容的事實不同時，照實改寫，不要照抄）：

| 情況 | plain_title | if_ignored |
|---|---|---|
| 已有人在用的漏洞，events 有 brand「91APP」 | 內部營運工具有帳號被盜用的漏洞，可能造成訂單與會員資料外洩 | 外人可以從網路冒用帳號登入，再一路拿到正式訂單資料庫的帳密，把訂單和會員個資整批帶走。這個漏洞已經有人在用，同業 91APP 就是這樣被入侵。 |
| 密碼寫在程式碼裡 | 品牌 App 的系統密碼寫在程式碼裡，可能造成會員個資外洩 | 拿到程式碼或 App 安裝檔的人，就能用這組密碼讀走正式會員資料庫的個資。密碼不換，這個破口就一直在。 |
| 管理頁對外開放的 NAS 漏洞 | 辦公室 NAS 有漏洞且管理頁對外開放，可能被勒索軟體加密 | 同型號 NAS 已被勒索集團大量攻擊。檔案被加密後要付贖金才拿得回來，接在上面的備份也可能一起被加密。 |
| 雲端檔案公開 | App 的雲端檔案設成任何人都能下載，可能造成會員與訂單資料外洩 | 只要知道網址，任何人都能下載裡面的檔案；外洩後要通報、通知會員，也可能要負個資法責任。 |

輸出：`[{"risk_id", "temporary", "permanent", "options": [{"name", "action", "cost", "timing"}], "suggested_owner", "verify", "plain_title", "if_ignored"}]`
