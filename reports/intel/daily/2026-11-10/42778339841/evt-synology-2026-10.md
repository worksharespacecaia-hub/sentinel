# Synology NAS 遭 C3RB3R 勒索軟體加密：DSM 登入頁對外暴露，常駐連接的備份碟一併被加密
`真實・已收錄` `暫定` `CVE-2026-13639` `CVE-2026-13684` `CVE-2024-10441`

**結論：3 項受影響，最高風險為中。nas-office-01：synology-dsm 7.2.1-69057 Update 5，對外。**

## 事件摘要
DSM 登入頁經 UPnP、連接埠轉發、QuickConnect 或反向代理暴露於網際網路；疑利用 DSM 舊漏洞（360 歸因 CVE-2026-13639、CVE-2026-13684，9/18 已修補）免帳密遠端讀寫任意檔案；刪除快照；加密檔案（副檔名 .L0CK3D），常駐連接的 Hyper Backup USB 硬碟／備份碟一併被加密；每個資料夾留下 read-me3.txt 勒索信，要求透過 Tor 網站購買解密器

_自動摘要未產生_

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| nas-office-01 | synology-dsm 7.2.1-69057 Update 5，對外 | condition | 受影響 | 中（8 分） |
| nas-office-01 | backups.json: nas-office-01：備份與來源未隔離（usb:attached-to-nas-office-01）、從未做過還原測試 | control | 受影響 | 中（5 分） |
| nas-office-01 | network.json: internet → nas-office-01:5001 | control | 受影響 | 中（5 分） |

## 可能的解法：nas-office-01:synology-dsm:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 修補 | 升級到修補版本 | 需回歸測試 | 168 小時內 |
| 緩解 | 限制來源、關閉受影響功能 | 部分功能受限 | 今天 |
建議負責團隊：it-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 可能的解法：nas-office-01:C-BACKUP-ISOLATION
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | 建立隔離備份 | 儲存費用 | 7 天內 |
建議負責團隊：it-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 可能的解法：nas-office-01:C-INTERNAL-TOOL-EXPOSED
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | 依控制項修正 | 依項目而定 | 168 小時內 |
建議負責團隊：it-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 處理狀態
待處理

## 來源
- Synology NAS 接連遭勒索、PHP2Shell 漏洞波及套件，用戶自保與各家 NAS 因應之道 – CyberQ 賽博客：https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/
