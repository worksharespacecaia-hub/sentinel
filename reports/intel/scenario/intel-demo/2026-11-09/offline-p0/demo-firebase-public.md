# 示範：電商平台 Firebase 儲存空間公開，訂單匯出檔外洩
`示範` `已確認`

**結論：2 項受影響，最高風險為高。firebase-brand-app-storage：firebase-config.json: /user-uploads/{allPaths=**} read if true；external-scan.json: storage.shopsaas-demo.example 可匿名列出內容。**

## 事件摘要
搜尋公開的雲端儲存空間；匿名列出並下載訂單匯出檔

_自動摘要未產生_

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| firebase-brand-app-storage | firebase-config.json: /user-uploads/{allPaths=**} read if true；external-scan.json: storage.shopsaas-demo.example 可匿名列出內容 | control | 受影響 | 高（7 分） |
| order-exports-bucket | external-scan.json: shopsaas-demo-order-exports.s3.example 可匿名列出內容；infra/terraform/main.tf: aws_s3_bucket_acl acl = "public-read" | control | 受影響 | 高（7 分） |

## 可能的解法：firebase-brand-app-storage:C-CLOUD-STORAGE-PUBLIC
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | 依控制項修正 | 依項目而定 | 24 小時內 |
建議負責團隊：mobile-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 可能的解法：order-exports-bucket:C-CLOUD-STORAGE-PUBLIC
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | 依控制項修正 | 依項目而定 | 24 小時內 |
建議負責團隊：data-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 建議通知
致各品牌商：我們發現與「示範：電商平台 Firebase 儲存空間公開，訂單匯出檔外洩」相關的風險，正在處理中。請提醒會員：官方不會以電話或簡訊要求轉帳或提供驗證碼，也請只從官方商店下載品牌 App。有疑問請聯繫平台客服。（自動範本，發送前請人工確認）

## 處理狀態
待處理

## 來源
- 虛構示範事件，非真實報導
