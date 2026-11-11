# Synology NAS 遭 C3RB3R 勒索軟體加密：DSM 登入頁對外暴露，常駐連接的備份碟一併被加密
`真實・已收錄` `暫定` `CVE-2026-13639` `CVE-2026-13684` `CVE-2024-10441`

**結論：3 項受影響，最高風險為高。nas-office-01：synology-dsm 7.2.1-69057 Update 5，對外。**

## 事件摘要
Synology NAS 遭 C3RB3R 勒索軟體加密，DSM 登入頁對外暴露，常駐連接的備份碟一併被加密。本次比對共 3 項受影響，最高風險為高，對應 nas-office-01 的 synology-dsm 7.2.1-69057 Update 5（對外）。

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| nas-office-01 | synology-dsm 7.2.1-69057 Update 5，對外 | condition | 受影響 | 高（8 分） |
| nas-office-01 | backups.json: nas-office-01：備份與來源未隔離（usb:attached-to-nas-office-01）、從未做過還原測試 | control | 受影響 | 中（5 分） |
| nas-office-01 | network.json: internet → nas-office-01:5001 | control | 受影響 | 中（5 分） |

## 可能的解法：nas-office-01:synology-dsm:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 修補 | 升級到修補版本 | 需回歸測試 | 24 小時內 |
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
