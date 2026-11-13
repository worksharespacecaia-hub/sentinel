# FBI：美國查扣遭竊自 Binance 的 12 億美元加密貨幣
`真實` `暫定`

**結論：2 項受影響，最高風險為高。laptop-eng-07：mdm.json: laptop-eng-07 有 ~/.config/pipeline/token；secrets.json: deploy-token-eng07 → deploy-pipeline。**

## 事件摘要
此事件與先前幣安事件相關：laptop-eng-07 持有正式部署權杖（高風險 7 分），ai-code-assistant 可繞過 Pipeline 直接部署（中風險 4 分）。建議撤銷權杖並限制部署只經由 Pipeline。

> 這是「幣安 63.4 億美元駭案：假面試惡意程式入侵開發者電腦，取得容器部署憑證後攻陷錢包簽章服務」（evt-binance-2026-10）的新進度；比對時沿用原事件的產品、利用條件與控制項。

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| laptop-eng-07 | mdm.json: laptop-eng-07 有 ~/.config/pipeline/token；secrets.json: deploy-token-eng07 → deploy-pipeline | control | 受影響 | 高（7 分） |
| ai-code-assistant | secrets.json: ai-assistant-token 存放於 ai-code-assistant，可直接觸發 deploy-pipeline（繞過 Pipeline 審核） | control | 受影響 | 中（4 分） |

## 可能的解法：laptop-eng-07:C-DEV-DEVICE-TOKEN
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | 撤銷並輪替金鑰 | 使用該金鑰的服務需同步更新 | 今天 |
建議負責團隊：eng-07；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 可能的解法：ai-code-assistant:C-NON-CI-DEPLOY
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | 依控制項修正 | 依項目而定 | 168 小時內 |
建議負責團隊：devops-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 處理狀態
待處理

## 來源
- FBI Says US Seized $1.2 Billion Worth of Cryptocurrency Stolen From Binance：https://www.securityweek.com/fbi-says-us-seized-1-2-billion-worth-of-cryptocurrency-stolen-from-binance/
