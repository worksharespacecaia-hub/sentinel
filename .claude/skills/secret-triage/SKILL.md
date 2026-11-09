---
name: secret-triage
description: 判斷金鑰掃描結果的類型、環境與風險
---

# 金鑰判讀
- 類型：資料庫連線字串、第三方 API 金鑰、部署權杖、簽章或推播金鑰。
- 環境依檔案區段（production／test）與清冊判斷，不確定填 unknown。
- `DEMO-FAKE-` 只代表 Demo 假資料，不代表可以忽略。
- 刪除檔案不等於修復，要有撤銷或輪替證據。
- 只回報位置與類型，不輸出金鑰內容。

輸出：`[{"id", "explanation", "confidence"}]`
