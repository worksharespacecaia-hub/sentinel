---
name: mobile-check
description: App 風險判斷與處置分層原則
---

# App 風險
- App 內寫死的金鑰視為已外洩。
- 影響範圍以程式算出的逐品牌、逐版本安裝數為準。
- 處置分層：伺服器端緩解 → 遠端關閉功能 → 強制更新 → 分批發版 → 通知品牌商。

輸出：`[{"id", "explanation", "confidence"}]`
