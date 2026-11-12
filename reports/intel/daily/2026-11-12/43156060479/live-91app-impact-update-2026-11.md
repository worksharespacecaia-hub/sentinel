# 91APP 公布調查結果：最大影響範圍 1,329 個品牌、約 480 萬名消費者
`真實` `暫定`

**結論：5 項受影響，最高風險為高。internal-tool：network.json: internet → internal-tool:443。**

## 事件摘要
91APP 公布最大影響範圍為 1,329 個品牌、約 480 萬名消費者；我們與該事件同樣有 5 項命中，最高為高風險（brand-app 10 分），建議優先處理對外開放的內部工具與程式庫內的金鑰。

> 這是「91APP 訂單資料庫遭入侵：未更新的內部工具 Appsmith 成破口，自內部 GitLab 取得資料庫金鑰」（evt-91app-2026-10）的新進度；比對時沿用原事件的產品、利用條件與控制項。

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| internal-tool | network.json: internet → internal-tool:443 | control | 受影響 | 高（8 分） |
| nas-office-01 | network.json: internet → nas-office-01:5001 | control | 受影響 | 中（5 分） |
| gitlab | config/db.yml:4 | control | 受影響 | 高（8 分） |
| brand-app | services/brand-app/src/config.ts:3 | control | 受影響 | 高（10 分） |
| order-db-prod | network.json: order-db-test（test）→ order-db-prod:5432 | control | 受影響 | 中（5 分） |

## 可能的解法：internal-tool:C-INTERNAL-TOOL-EXPOSED
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | 依控制項修正 | 依項目而定 | 24 小時內 |
建議負責團隊：devops-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 可能的解法：nas-office-01:C-INTERNAL-TOOL-EXPOSED
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | 依控制項修正 | 依項目而定 | 168 小時內 |
建議負責團隊：it-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 可能的解法：gitlab:C-SECRET-IN-GIT
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | 撤銷並輪替金鑰 | 使用該金鑰的服務需同步更新 | 今天 |
建議負責團隊：devops-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 可能的解法：brand-app:C-SECRET-IN-GIT
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | 撤銷並輪替金鑰 | 使用該金鑰的服務需同步更新 | 今天 |
建議負責團隊：mobile-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 可能的解法：order-db-prod:C-NET-SEGMENT
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | 依控制項修正 | 依項目而定 | 168 小時內 |
建議負責團隊：dba-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 建議通知
致各品牌商：我們發現與「91APP 公布調查結果：最大影響範圍 1,329 個品牌、約 480 萬名消費者」相關的風險，正在處理中。請提醒會員：官方不會以電話或簡訊要求轉帳或提供驗證碼，也請只從官方商店下載品牌 App。有疑問請聯繫平台客服。（自動範本，發送前請人工確認）

## 處理狀態
待處理

## 來源
- 收集會員資料愈多愈好？電商個資外洩突顯資料治理盲點：https://infosecu.technews.tw/2026/11/12/membership-information-data-governance/
