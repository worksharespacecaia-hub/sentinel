# PHP 11/19 安全更新修補 7 個 Critical RCE 漏洞，含 PHP2Shell 的不完整修補
`真實` `已確認` `CVE-2026-109618` `CVE-2026-109619` `CVE-2026-115560` `CVE-2026-126714` `CVE-2026-129289` `CVE-2026-129496` `CVE-2026-129481` `CVE-2026-129474` `CVE-2026-129182` `CVE-2026-129291`

**結論：3 項受影響，最高風險為高。marketing-site：php 8.1.27（apache2handler），對外，session.upload_progress.enabled=On。**

## 事件摘要
3 項受影響：行銷官網 marketing-site 已停止支援且無修補，為高風險（9 分）；報表服務 report-svc（5 分）與 phpmyadmin（4 分，只允許公司連線通道連入）為中風險。

> 這是「PHP2Shell：PHP 核心兩個免驗證遠端程式碼執行漏洞（CVE-2026-109618、CVE-2026-109619）」（evt-php2shell-2026-10）的新進度；比對時沿用原事件的產品、利用條件與控制項。

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| marketing-site | php 8.1.27（apache2handler），對外，session.upload_progress.enabled=On | condition | 受影響 | 高（9 分） |
| report-svc | php 8.4.27（fpm-fcgi），session.upload_progress.enabled=On | condition | 受影響 | 中（5 分） |
| phpmyadmin | php 8.3.20（fpm-fcgi），session.upload_progress.enabled=On | condition | 受影響 | 中（4 分） |

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

## 處理狀態
待處理

## 來源
- PHP Patches Seven Critical RCE Vulnerabilities：https://www.securityweek.com/php-patches-seven-critical-rce-vulnerabilities/
- PHP Fixes 7 Critical Flaws, Including Bugs That Could Allow Remote Code Execution：https://thehackernews.com/2026/11/php-fixes-7-critical-flaws-including.html
- PHP釋出安全更新修補18個漏洞，7個為重大等級：https://www.ithome.com.tw/news/180678
- phpAfterShell Explained: How Hackers Could Turn a PHP Session Flaw Into Code Execution：https://thehackernews.com/2026/11/phpaftershell-explained-how-hackers.html
