# Changelog

## 0.2.2 — 2026-11-10（hotfix：首次部署發現的問題）

- 所有 `.sh` 標記為可執行：在 Windows 上 commit 時沒有執行位元，Actions 發布結果時 exit 126；新增測試防止再發生
- Redis 設定接受 Vercel Marketplace 的 Upstash 整合實際注入的 `KV_REST_API_URL`／`KV_REST_API_TOKEN`（仍接受 `UPSTASH_REDIS_REST_*`，不使用唯讀 Token）

## 0.2.1 — 2026-11-10（hotfix：作者身分與 baseline SHA）

- 兩個 Repo 的 commit 與 tag 作者身分改寫後，shopsaas-demo-platform 的 baseline commit 改為 `a0d8611612c2f2631a687271de528a0d7a806245`；更新 fixture（`.fixture.json`、`deployments.json`、`gitleaks.json`）、測試、README 與網站資料
- 重新產生網站資料（`offline-p0`）：只有 SHA 改變，manifest 檢查碼改為與檔案內容相符（先前記錄的檢查碼已過期）
- Actions 發布結果的 commit 改用官方 `github-actions[bot]` 身分，避免歸屬到陌生帳號

## 0.2.0 — 2026-11-09（P1 情境驗收與文件）

- **修復後情境**：新增 `fixtures/after-fix/{partial,full}` 疊加資料。部分修復只解除對應的 3 個風險、維持紅燈；完整修復降為黃燈，但仍有未結案的真實高風險告警時維持紅燈
- **撤銷需要證據**：`secrets.json` 標成 revoked 但沒有 `revocation_evidence` 時仍視為有效金鑰，並記一筆未驗證的資料問題（第 10 節）
- **修正**：SaaS 補登第三方清冊後，舊的影子 IT 風險會停在「需確認」，紅燈無法解除
- **P2 情境明確停用**：`nas`、`insider-path`、`mobile-sdk` 在 CLI 回傳 2、網站 API 回傳 409，按鈕標示「P2 未啟用」
- **測試**：P1 各情境驗收、RT-002 白天排練、RT-003 反向案例、有效燈號合併規則（`lib/light.ts`）
- **README**：架構、觸發時機、本機開發、部署步驟、情境、重設 Demo（含可信的 baseline SHA）、成本
- 仍未包含：預算 API、LINE 通知（P2）、P2 情境的輸入資料；實際成本與各情境實跑紀錄待部署後補上

## 0.1.0 — 2026-11-09（P0）

可展示的 Demo：Agent 流程以 replay／範本執行（不呼叫 LLM API），確定性計算全部真實執行。

- **工具層**：資產對帳、圖譜、版本比對、攻擊路徑、評分、燈號、情資驗證與比對、報告（不使用 LLM）
- **Agent 層**：Orchestrator、A0～A5、圍堵建議；14 個精簡 Skill；replay／record／live 三種模式與工具權限白名單
- **Workflow**：`sentinel.yml`（每日／公告／情境）、`intel-watch.yml`（公告輪詢）、`incident.yml`（圍堵建議）；發布採 push-with-retry 合併
- **Dashboard**（Next.js 16.4.5）：總覽、情資比對、Agent 執行、攻擊鏈、風險、資產、App、觸發紀錄、架構說明、即時監控
- **即時規則層**：RT-001～003、GitHub Deployments Webhook、攻擊模擬器、告警交付（Issue → incident）與管理者結案／重試
- 未包含：LINE 通知（P2）、預算 API（live 模式缺少時以範本降級）、Neon（選配）
