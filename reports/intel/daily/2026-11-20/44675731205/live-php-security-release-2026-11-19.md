# PHP 發布 8.5.13、8.4.28、8.3.37、8.2.36，修補 7 個 Critical 漏洞
`真實` `已確認` `CVE-2026-109618` `CVE-2026-109619` `CVE-2026-115560` `CVE-2026-126714` `CVE-2026-129289` `CVE-2026-129496` `CVE-2026-129481` `CVE-2026-129474` `CVE-2026-129182` `CVE-2026-129291`

**結論：3 項受影響，最高風險為高。marketing-site：php 8.1.27（apache2handler），對外，session.upload_progress.enabled=On。**

## 事件摘要
行銷官網的 PHP 8.1.27 已停止支援且無修補，為高風險（9 分）；報表服務（5 分）與 phpmyadmin（4 分）為中風險。

> 這是「PHP2Shell：PHP 核心兩個免驗證遠端程式碼執行漏洞（CVE-2026-109618、CVE-2026-109619）」（evt-php2shell-2026-10）的新進度；比對時沿用原事件的產品、利用條件與控制項。

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| marketing-site | php 8.1.27（apache2handler），對外，session.upload_progress.enabled=On | condition | 受影響 | 高（9 分） |
| report-svc | php 8.4.27（fpm-fcgi），session.upload_progress.enabled=On | condition | 受影響 | 中（5 分） |
| phpmyadmin | php 8.3.20（fpm-fcgi），session.upload_progress.enabled=On | condition | 受影響 | 中（4 分） |

## Orchestrator 追加結果
- 派工・依事件解讀套件漏洞（AI 撰寫）：php 8.1.27：php 8.1.27 依 NVD 本地比對有 27 個確定漏洞（最高 CVSS 9.8，CVE-2024-11236），修補版本為 8.2.35，且 CVE-2026-109618、CVE-2026-109619 已列入 CISA KEV 遭實際利用。建議優先升級，並確認 3 個需確認漏洞與 8.2.35 是否符合現行分支政策。；php 8.3.20：php 8.3.20 依 NVD 本地比對有 28 個確定漏洞（最高 CVSS 9.8，CVE-2025-14179），資料列出的修補版本為 8.3.36，且 CVE-2026-109618、CVE-2026-109619 已列入 CISA KEV。事件公告另有 8.3.37 與 CVE-2026-126714（phpAfterShell），建議升級至 8.3.37 並在確認前暫時設定 session.upload_progress.enabled=0 作為緩解；3 個需確認漏洞仍待確認。；php 8.4.27：php 8.4.27 目前 0 個確定漏洞，僅 1 個需確認的 CVE-2007-3205，因 NVD 版本範圍無法判斷，資料未提供確定修補版本，也未見已遭實際利用的紀錄。建議先確認 CVE-2007-3205 是否適用此執行環境，並評估升級至事件公告的 8.4.28；在確認前結論不完整，需人工複核。
- 派工・依事件解讀執行環境與支援期限（AI 撰寫）：依 eol.json 記載，PHP 8.1 支援已於 2025-12-31 結束，今日（2026-11-20）為已停止支援狀態，runtime.json 顯示執行版本為 8.1.27，故此環境目前無安全修補。此為支援期限狀態，與是否已修補漏洞分開判斷。本次事件（8.1 未列於 11/19 發布的 8.5.13、8.4.28、8.3.37、8.2.36 修補範圍）顯示 8.1 分支不在本次修補內，需確認 8.1 分支是否有其他途徑取得修補，否則 CVE-2026-126714（phpAfterShell）的利用前提是否成立無法排除。利用條件需確認：是否使用預設檔案型 session handler、session.upload_progress.enabled 是否為 1（預設值）、是否存在可被利用的 gadget chain、寫入是否可被攻擊者中斷。在上述條件未確認前，不應視為安全。建議：優先升級至仍受支援的 PHP 分支（8.2 以上且對應已修補版本），若暫時無法升級，先將 session.upload_progress.enabled 設為 0 作為緩解，並確認 session handler 設定與應用程式 gadget 情況。

## 可能的解法：marketing-site:php:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | WAF 限制異常請求、關閉不必要的功能 | 需驗證不影響現有功能 | 今天 |
| 下架 | 暫停 marketing-site，改導向其他服務 | 相關流量中斷 | 今天 |
| 修補 | 升級到受支援的修補版本 | 需回歸測試 | 7 天內 |
建議負責團隊：security-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 可能的解法：report-svc:php:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 修補 | 升級到修補版本 | 需回歸測試 | 168 小時內 |
| 緩解 | 限制來源、關閉受影響功能 | 部分功能受限 | 今天 |
建議負責團隊：data-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 可能的解法：phpmyadmin:php:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 修補 | 升級到修補版本 | 需回歸測試 | 168 小時內 |
| 緩解 | 限制來源、關閉受影響功能 | 部分功能受限 | 今天 |
建議負責團隊：dba-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## AI 建議的通知草稿（程式未要求）
建議通知品牌商：PHP 發布修補重大漏洞的更新，我們的行銷官網使用的版本已不再受原廠支援，正在評估升級；目前沒有資料顯示已有外洩。
_（AI 撰寫；程式沒有要求通知，發送前請人工確認）_

## 處理狀態
待處理

## 來源
- PHP Patches Seven Critical RCE Vulnerabilities：https://www.securityweek.com/php-patches-seven-critical-rce-vulnerabilities/
- PHP Fixes 7 Critical Flaws, Including Bugs That Could Allow Remote Code Execution：https://thehackernews.com/2026/11/php-fixes-7-critical-flaws-including.html
- 實測 PHP 8.5.13、8.4.28、8.3.37、8.2.36 資安更新：7 項 Critical 的觸發條件與主機升級驗證：https://cyberq.tw/2026/11/19/php-security-release-2026-11-19-hands-on/
