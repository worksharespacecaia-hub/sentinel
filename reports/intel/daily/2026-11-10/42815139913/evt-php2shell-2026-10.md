# PHP2Shell：PHP 核心兩個免驗證遠端程式碼執行漏洞（CVE-2026-109618、CVE-2026-109619）
`真實・已收錄` `已確認` `CVE-2026-109618` `CVE-2026-109619`

**結論：2 項受影響，最高風險為高。marketing-site：php 8.1.27（apache2handler），對外，session.upload_progress.enabled=On。**

## 事件摘要
事件：PHP2Shell，PHP 核心兩個免驗證遠端程式碼執行漏洞。比對結果 2 項受影響、最高為高風險：marketing-site（php 8.1.27，對外，9 分，已停止支援且無修補）；phpmyadmin 為中風險（4 分），因只允許 corp-vpn 連入而扣 3 分。

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| marketing-site | php 8.1.27（apache2handler），對外，session.upload_progress.enabled=On | condition | 受影響 | 高（9 分） |
| phpmyadmin | php 8.3.20（fpm-fcgi），session.upload_progress.enabled=On | condition | 受影響 | 中（4 分） |

## 不受影響與需確認
- report-svc：php 8.4.27（fpm-fcgi），8.4.27 不在受影響範圍（已是修補版本或不同分支）

## 可能的解法：marketing-site:php:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | WAF 限制異常請求、關閉不必要的功能 | 需驗證不影響現有功能 | 今天 |
| 下架 | 暫停 marketing-site，改導向其他服務 | 相關流量中斷 | 今天 |
| 修補 | 升級到受支援的修補版本 | 需回歸測試 | 7 天內 |
建議負責團隊：security-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 可能的解法：phpmyadmin:php:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 修補 | 升級到修補版本 | 需回歸測試 | 168 小時內 |
| 緩解 | 限制來源、關閉受影響功能 | 部分功能受限 | 今天 |
建議負責團隊：dba-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 處理狀態
待處理

## 來源
- CVE-2026-109618 and CVE-2026-109619: Critical Unauthenticated Remote Code Execution in PHP：https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/
- 十月PHP風暴全紀錄：AI撬開潛伏十四年的漏洞 全球政府連夜「拔網線」的48小時 | 閒聊：https://www.heatalk.com/20261104/17170/
- Synology NAS 接連遭勒索、PHP2Shell 漏洞波及套件，用戶自保與各家 NAS 因應之道 – CyberQ 賽博客：https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/
