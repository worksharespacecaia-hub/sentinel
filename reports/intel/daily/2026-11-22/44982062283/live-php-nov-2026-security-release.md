# PHP 11/19 安全更新修補 18 個漏洞，7 個為重大等級
`真實` `暫定` `CVE-2026-115560` `CVE-2026-126714` `CVE-2026-129289` `CVE-2026-129496` `CVE-2026-129291` `CVE-2026-129182` `CVE-2026-129474` `CVE-2026-129481`

**結論：2 項受影響，最高風險為中。report-svc：php 8.4.27（fpm-fcgi）。**

## 事件摘要
2 項受影響：報表服務為低風險（3 分），phpmyadmin 為中風險（4 分，已因只允許公司 VPN 連入扣 3 分）。建議依 11/19 安全更新升級。

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| report-svc | php 8.4.27（fpm-fcgi） | version | 受影響 | 低（3 分） |
| phpmyadmin | php 8.3.20（fpm-fcgi） | version | 受影響 | 中（4 分） |

## 不受影響與需確認
- marketing-site：php 8.1.27（apache2handler），8.1.27 不在受影響範圍（已是修補版本或不同分支）

## Orchestrator 追加結果
- 派工・依事件解讀套件漏洞（AI 撰寫）：php 8.3.20：php 8.3.20 經程式比對有 28 個確定漏洞，最高 CVSS 9.8（CVE-2025-14179），事件描述的攻擊鏈包含記憶體釋放後再存取、輸入驗證不當、TOCTOU 與 HTTP 解析不一致，可能達成遠端程式碼執行或工作階段資料竄改。CVE-2026-109618 與 CVE-2026-109619 已列入 CISA KEV，代表有實際利用紀錄。利用前提需依各 CVE 個別確認，例如是否需要特定 SAPI、功能啟用或網路可達性，目前資料未提供。修補版本為 8.3.36，建議優先升級至此版本，並先盤點對外暴露的 PHP 服務，檢查是否有入侵跡象，再依 KEV 清單排序處理。；php 8.4.27：php 8.4.27 經程式比對為 0 個確定漏洞、1 個待確認項目 CVE-2007-3205，因 NVD 版本範圍無法判斷，是否受影響不明。目前無法確定修補版本，因部分漏洞沒有明確修補版本或範圍。建議人工核對 CVE-2007-3205 的適用版本與執行環境，確認是否為此服務的實際風險；在確認前可先將 PHP 8.4.x 升級至官方最新穩定版作為預防措施，並持續追蹤 NVD 與 PHP 官方公告。

## 可能的解法：report-svc:php:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 修補 | 升級到修補版本 | 需回歸測試 | 720 小時內 |
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
- PHP Fixes 7 Critical Flaws, Including Bugs That Could Allow Remote Code Execution：https://thehackernews.com/2026/11/php-fixes-7-critical-flaws-including.html
- phpAfterShell Explained: How Hackers Could Turn a PHP Session Flaw Into Code Execution：https://thehackernews.com/2026/11/phpaftershell-explained-how-hackers.html
