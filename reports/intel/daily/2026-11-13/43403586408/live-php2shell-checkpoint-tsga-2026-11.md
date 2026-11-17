# PHP2Shell 漏洞被用於攻擊 Check Point 閘道，部署 TSGA 後門並清除 ESXi 檔案
`真實` `暫定` `CVE-2026-109618` `CVE-2026-109619` `CVE-2026-123039`

**結論：2 項受影響，最高風險為高。marketing-site：php 8.1.27（apache2handler），對外，session.upload_progress.enabled=On。**

## 事件摘要
Check Point 指出，未知攻擊者自 10 月 30 日起，利用 PHP2Shell 取得 Check Point 閘道初始存取，再以 CVE-2026-123039 提權到 root，部署 PHP web shell 與 TSGA 後門，並經 SSH 轉入 VMware ESXi 部署 wiper。

_自動摘要未產生_

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
- Hackers Exploit PHP2Shell Flaws in Check Point Gateways to Deploy TSGA Backdoor and Wipe ESXi Files：https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html
