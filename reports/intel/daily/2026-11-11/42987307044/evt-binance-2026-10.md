# 幣安 63.4 億美元駭案：假面試惡意程式入侵開發者電腦，取得容器部署憑證後攻陷錢包簽章服務
`真實・已收錄` `已確認`

**結論：2 項受影響，最高風險為高。laptop-eng-07：mdm.json: laptop-eng-07 有 ~/.config/pipeline/token；secrets.json: deploy-token-eng07 → deploy-pipeline。**

## 事件摘要
幣安事件是開發者電腦被入侵後取得部署憑證；我們的 laptop-eng-07 存有可連到 deploy-pipeline 的部署權杖（高風險，7 分），ai-code-assistant 也能繞過審核直接部署（中風險，4 分），共 2 項受影響。

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
- 幣安63.4億美元資安案調查出爐：北韓駭客如何用「假面試、內部AI」層層攻陷錢包？|數位時代 BusinessNext：https://www.bnext.com.tw/article/92910/binance-hack-initial-findings-north-korea
- Binance’s $6.34 Billion Hack: Developer Machines, AI Tooling, and Wallet Signing - StepSecurity：https://www.stepsecurity.io/blog/binance-hack-developer-machine-security
