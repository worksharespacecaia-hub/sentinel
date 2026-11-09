# Changelog

## 0.1.0 — 2026-11-09（P0）

可展示的 Demo：Agent 流程以 replay／範本執行（不呼叫 LLM API），確定性計算全部真實執行。

- **工具層**：資產對帳、圖譜、版本比對、攻擊路徑、評分、燈號、情資驗證與比對、報告（不使用 LLM）
- **Agent 層**：Orchestrator、A0～A5、圍堵建議；14 個精簡 Skill；replay／record／live 三種模式與工具權限白名單
- **Workflow**：`sentinel.yml`（每日／公告／情境）、`intel-watch.yml`（公告輪詢）、`incident.yml`（圍堵建議）；發布採 push-with-retry 合併
- **Dashboard**（Next.js 16.4.5）：總覽、情資比對、Agent 執行、攻擊鏈、風險、資產、App、觸發紀錄、架構說明、即時監控
- **即時規則層**：RT-001～003、GitHub Deployments Webhook、攻擊模擬器、告警交付（Issue → incident）與管理者結案／重試
- 未包含：LINE 通知（P2）、預算 API（live 模式缺少時以範本降級）、Neon（選配）
