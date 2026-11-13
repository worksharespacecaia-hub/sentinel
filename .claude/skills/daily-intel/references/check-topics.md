# 可能破口的 topic（由 scripts/build-check-topics-reference.py 依 rules/check-hints.json 產生，請勿手改）

事件的 `possible_entry_points[].topic` 只能填下表的 ID；對不到任何一項時省略 `topic`（或填 `null`）。
不在下表的 ID 會被程式移除（項目本身保留）。關鍵字只是說明這一類「被打到的地方」的範例，不必出現在事件文字中。

| ID | 名稱 | 關鍵字範例 |
|---|---|---|
| `vendor` | 委外服務商 | 委外、服務商、廠商、供應商、外包、SaaS、vendor、supplier |
| `mail` | 寄信或電子報服務 | 郵件發送、郵件服務、電子報、寄信、寄送、Mailgun、SendGrid |
| `database` | 資料庫 | 資料庫、database、訂單資料、個資、伺服器上保存 |
| `member-portal` | 會員中心與訂單查詢 | 會員中心、會員系統、會員帳號、會員登入、訂單查詢、歷史訂單 |
| `admin` | 管理後台 | 管理系統、管理後台、後台、管理介面、管理者、admin |
| `code-repo` | 程式碼管理平台 | 程式碼管理、GitLab、GitHub、原始碼 |
| `endpoint` | 員工電腦與帳號 | 員工電腦、釣魚、惡意程式、筆電、帳號密碼、帳密 |
| `server` | 伺服器與對外系統 | 伺服器、主機、漏洞、server |
