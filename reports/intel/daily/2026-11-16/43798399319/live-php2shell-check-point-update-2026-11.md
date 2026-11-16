# PHP2Shell 事件新進度：Check Point 閘道遭鏈式攻擊，ESXi 主機資料被抹除
`真實` `暫定` `CVE-2026-109618` `CVE-2026-109619` `CVE-2026-123039`

**結論：2 項受影響，最高風險為高。marketing-site：php 8.1.27（apache2handler），對外，session.upload_progress.enabled=On。**

## 事件摘要
此為 PHP2Shell 事件的新進度，marketing-site 仍為高風險（9 分），phpmyadmin 為中風險（4 分）；處置建議與先前相同，需優先決定 marketing-site 的處理方式。

> 這是「PHP2Shell：PHP 核心兩個免驗證遠端程式碼執行漏洞（CVE-2026-109618、CVE-2026-109619）」（evt-php2shell-2026-10）的新進度；比對時沿用原事件的產品、利用條件與控制項。

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
- Check Point 閘道遭 PHP2Shell 鏈式攻擊，VMware ESXi 主機資料被抹除：https://cyberq.tw/2026/11/15/check-point-gateway-was-compromised/
