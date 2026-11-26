# F5 修補 NGINX2Root 重大漏洞，PoC 已公開
`真實` `已確認` `CVE-2026-113425` `CVE-2026-121810` `CVE-2026-123007` `CVE-2026-123633` `CVE-2026-123634`

**結論：1 項受影響，最高風險為高。api-gateway：nginx 1.27.2，對外。**

## 事件摘要
API 閘道使用的 nginx 1.27.2 落在受影響範圍且對外，攻擊程式碼已公開，程式判定為高風險（8 分），建議升級至修補版本。

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| api-gateway | nginx 1.27.2，對外 | version | 受影響 | 高（8 分） |

## Orchestrator 追加結果
- 派工・依事件解讀套件漏洞（AI 撰寫）：nginx 1.27.2 落在 live 範圍 [1.9.5, 1.30.7) 內，依程式比對為受影響，最高 CVSS 9.8 (CVE-2026-97205)，且事件已有公開 PoC。可確定的最低修補版本為 1.30.7（1.31.x 分支為 1.31.9），但 31 個漏洞中部分沒有修補版本或範圍不明，整體修補版本無法完全確定，需人工逐一核對官方公告並確認 1.27.x 是否有後移修補。

## 可能的解法：api-gateway:nginx:vuln
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 修補 | 升級到修補版本 | 需回歸測試 | 24 小時內 |
| 緩解 | 限制來源、關閉受影響功能 | 部分功能受限 | 今天 |
建議負責團隊：platform-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 建議通知
致各品牌商：我們發現與「F5 修補 NGINX2Root 重大漏洞，PoC 已公開」相關的風險，正在處理中。請提醒會員：官方不會以電話或簡訊要求轉帳或提供驗證碼，也請只從官方商店下載品牌 App。有疑問請聯繫平台客服。（自動範本，發送前請人工確認）

## 處理狀態
待處理

## 來源
- F5 Patches Critical NGINX2Root Flaws as PoC Exploits Go Public - SecurityWeek：https://www.securityweek.com/f5-patches-critical-nginx2root-flaws-as-poc-exploits-go-public/
- 10-Year-Old NGINX HTTP/2 Flaw Lets Unauthenticated Attackers Execute Code on Servers：https://thehackernews.com/2026/11/10-year-old-nginx-http2-flaw-lets.html
