# PostgreSQL 修補 52 個漏洞，含已有公開寫法的認證後遠端程式碼執行 CVE-2026-6460
`真實` `已確認` `CVE-2026-6460` `CVE-2026-6467`

**結論：3 項受影響，最高風險為高。order-db-prod：postgresql 15.6。**

## 事件摘要
postgresql 15.6 影響 3 個資料庫：order-db-prod 為高風險（8 分，位於攻擊路徑上）、member-db-prod 為中風險（5 分）、order-db-test 為低風險（3 分）。建議優先升級訂單正式資料庫。

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| order-db-prod | postgresql 15.6 | version | 受影響 | 高（8 分） |
| member-db-prod | postgresql 15.6 | version | 受影響 | 中（5 分） |
| order-db-test | postgresql 15.6 | version | 受影響 | 低（3 分） |

## 可能的解法：order-db-prod:postgresql:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 修補 | 升級到修補版本 | 需回歸測試 | 24 小時內 |
| 緩解 | 限制來源、關閉受影響功能 | 部分功能受限 | 今天 |
建議負責團隊：dba-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 可能的解法：member-db-prod:postgresql:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 修補 | 升級到修補版本 | 需回歸測試 | 168 小時內 |
| 緩解 | 限制來源、關閉受影響功能 | 部分功能受限 | 今天 |
建議負責團隊：dba-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 可能的解法：order-db-test:postgresql:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 修補 | 升級到修補版本 | 需回歸測試 | 720 小時內 |
| 緩解 | 限制來源、關閉受影響功能 | 部分功能受限 | 今天 |
建議負責團隊：dba-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 建議通知
致各品牌商：我們發現與「PostgreSQL 修補 52 個漏洞，含已有公開寫法的認證後遠端程式碼執行 CVE-2026-6460」相關的風險，正在處理中。請提醒會員：官方不會以電話或簡訊要求轉帳或提供驗證碼，也請只從官方商店下載品牌 App。有疑問請聯繫平台客服。（自動範本，發送前請人工確認）

## 處理狀態
待處理

## 來源
- PostgreSQL Patches 52 Flaws, Including 22-Year-Old Bug Enabling Authenticated RCE：https://thehackernews.com/2026/11/postgresql-patches-52-flaws-including.html
- PostgreSQL 一口氣修補 52 個漏洞，20 年歷史的程式碼執行缺陷成焦點：https://cyberq.tw/2026/11/14/postgresql-patched-52-vulnerabilities/
