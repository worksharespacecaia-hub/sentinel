# nginx2root：nginx 1.31.9 與 1.30.7 修補 10 個漏洞，5 個可遠端執行程式碼
`真實` `已確認` `CVE-2026-123007` `CVE-2026-123633` `CVE-2026-121810` `CVE-2026-123634` `CVE-2026-113425`

**結論：1 項受影響，最高風險為高。api-gateway：nginx 1.27.2，對外。**

## 事件摘要
API 閘道使用 nginx 1.27.2，對外且落在受影響範圍，可能碰到會員個資，程式判定為高風險（8 分）。

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| api-gateway | nginx 1.27.2，對外 | version | 受影響 | 高（8 分） |

## 可能的解法：api-gateway:nginx:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 修補 | 升級到修補版本 | 需回歸測試 | 24 小時內 |
| 緩解 | 限制來源、關閉受影響功能 | 部分功能受限 | 今天 |
建議負責團隊：platform-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 建議通知
致各品牌商：我們發現與「nginx2root：nginx 1.31.9 與 1.30.7 修補 10 個漏洞，5 個可遠端執行程式碼」相關的風險，正在處理中。請提醒會員：官方不會以電話或簡訊要求轉帳或提供驗證碼，也請只從官方商店下載品牌 App。有疑問請聯繫平台客服。（自動範本，發送前請人工確認）

## 處理狀態
待處理

## 來源
- 10-Year-Old NGINX HTTP/2 Flaw Lets Unauthenticated Attackers Execute Code on Servers：https://thehackernews.com/2026/11/10-year-old-nginx-http2-flaw-lets.html
- Nginx緊急修補10個漏洞，其中5個恐遭遠端執行程式碼：https://www.ithome.com.tw/news/180651
- 實測 NGINX2Root：CVSS 9.2 分 nginx 漏洞影響上千萬台主機，從升級修補到重啟驗證：https://cyberq.tw/2026/11/19/nginx2root-cve-2026-123007-hands-on/
