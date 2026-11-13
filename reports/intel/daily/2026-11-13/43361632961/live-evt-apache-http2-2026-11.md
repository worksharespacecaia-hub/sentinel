# Apache HTTP Server mod_http2 重大 RCE 漏洞 CVE-2026-119618
`真實` `已確認` `CVE-2026-119618`

**結論：1 項受影響，最高風險為中。marketing-site：apache-httpd 2.4.57，對外。**

## 事件摘要
marketing-site 的 apache-httpd 2.4.57 落在受影響範圍且對外，程式評為中風險（6 分）。建議升級至官方修補版本。

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| marketing-site | apache-httpd 2.4.57，對外 | version | 受影響 | 中（6 分） |

## 可能的解法：marketing-site:apache-httpd:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 修補 | 升級到修補版本 | 需回歸測試 | 168 小時內 |
| 緩解 | 限制來源、關閉受影響功能 | 部分功能受限 | 今天 |
建議負責團隊：security-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 處理狀態
待處理

## 來源
- Critical Apache HTTP/2 Flaw Could Let Unauthenticated Attackers Execute Code Remotely：https://thehackernews.com/2026/11/critical-apache-http2-flaw-could-let.html
- Apache mod_http2 爆重大 RCE 漏洞：CVSS 9.8，實測修補與緩解效果：https://cyberq.tw/2026/11/12/apache-mod-http2-cve-2026-119618-hands-on/
