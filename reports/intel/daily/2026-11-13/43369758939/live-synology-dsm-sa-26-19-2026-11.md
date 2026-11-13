# Synology DSM 登入驗證介面 SQL 注入漏洞（SA-26:19，CVSS 9.8）
`真實` `暫定` `CVE-2026-76954` `CVE-2026-85101`

**結論：1 項受影響，最高風險為高。nas-office-01：synology-dsm 7.2.1-69057 Update 5，對外。**

## 事件摘要
Synology DSM 登入介面的 SQL 注入漏洞（SA-26:19，CVSS 9.8）命中 nas-office-01（對外，高風險，分數 8）；建議關閉對外開放並升級 DSM。

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| nas-office-01 | synology-dsm 7.2.1-69057 Update 5，對外 | version | 受影響 | 高（8 分） |

## 可能的解法：nas-office-01:synology-dsm:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 修補 | 升級到修補版本 | 需回歸測試 | 24 小時內 |
| 緩解 | 限制來源、關閉受影響功能 | 部分功能受限 | 今天 |
建議負責團隊：it-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 處理狀態
待處理

## 來源
- Synology DSM 登入介面 SQL 注入漏洞 9.8 分：不必登入就能讀寫 NAS 檔案，官方表示只能更新：https://cyberq.tw/2026/11/12/synology-sa-26-19-dsm-auth-api-sql-injection/
