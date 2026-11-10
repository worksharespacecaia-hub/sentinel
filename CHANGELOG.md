# Changelog

## 0.3.1 — 2026-11-10（hotfix：每日情資失敗診斷）

- 首次啟用的 daily-intel 在第一個 API 請求就結束（0 回合用量），但 claude-code-action 隱藏了錯誤訊息，無法判斷原因
- 執行前檢查 `CLAUDE_CODE_OAUTH_TOKEN` 格式：未設定或含空白／換行（複製時被折行）就直接失敗並說明；不印出 Token
- 失敗時以 `scripts/claude-error-summary.py` 只列出模型、驗證來源、錯誤代碼與錯誤訊息（截斷、遮蔽疑似金鑰），不列對話內容（公開 Repo 的 log 是公開的）
- 驗證：0.3.0 後的 daily 完整度為 complete，GitHub Deployments 由 API 讀取成功（不再有 `github/deployments` 資料問題）

## 0.3.0 — 2026-11-10（每日情資串接訂閱方案、讀取 GitHub Deployments）

- **每日情資**：`daily-intel` 不再要求 live 模式，每日排程與手動 `daily` 都會執行（A1～A5 維持 replay，不花 API 費用）。原本綁 live 是實作時多加、規格沒有的條件，導致從未執行
- **最小權限**：`daily-intel` 改用本 Job 的唯讀 `github.token`，不需安裝 Claude GitHub App，移除 `id-token: write`
- **修正**：「Claude 只寫了 out/」檢查失敗時，結果仍會上傳並被 A1 採用；改為檢查通過才上傳，失敗時列出被改動的檔案
- **不信任 LLM 輸出**：`out/intel-daily.json` 先清理再使用——強制為新事件（`live-` 前綴，不能冒充或覆蓋收錄事件）、清空自稱的驗證狀態、不採用「已遭利用」「已確認」與觸發條件、控制項只接受既有 ID、限制數量與長度；格式不符的事件略過並在報告標示
- **引用驗證**：每日情資的新事件不論執行模式都實際抓來源頁面確認引用（抓網頁不是 LLM 呼叫）
- 每日情資狀態依實際執行結果顯示（正常／今日新聞情資未更新），本機 replay 仍顯示重播模式
- Skill 寫明 `intel-daily.json` 的輸出格式（Job 中 Claude 讀不到 `agents/schemas.py`）
- **GitHub Deployments**：A0 Job 以 `TARGET_READ_TOKEN` 讀取 Repo ① 的 production Deployments 與最新狀態（`scripts/fetch-deployments.py`，只用 GET），以獨立 artifact 給 A2～A5 共用；讀取失敗時改用離線 fixture 並在報告標示原因。payload 的 service_id 驗證格式
- 測試：daily-intel 觸發條件、輸出清理、報告狀態、Workflow 權限與上傳順序、Deployments 讀取與 Token 不外洩

## 0.2.3 — 2026-11-10（hotfix：gitleaks 設定檔）

- 補上 sentinel 自己保存的 `.gitleaks.toml`（規格 5.5，與 Repo ① 相同、不讀受掃描 Repo 的設定）：先前檔案不存在，Docker 掛載時建立空目錄，首次 daily 的 gitleaks 掃描失敗
- 新增測試：workflow 以 docker 掛載的 sentinel 檔案必須在 repo 中；`.gitleaks.toml` 必須與 baseline 副本一致

## 0.2.2 — 2026-11-10（hotfix：首次部署發現的問題）

- 所有 `.sh` 標記為可執行：在 Windows 上 commit 時沒有執行位元，Actions 發布結果時 exit 126；新增測試防止再發生
- Redis 設定接受 Vercel Marketplace 的 Upstash 整合實際注入的 `KV_REST_API_URL`／`KV_REST_API_TOKEN`（仍接受 `UPSTASH_REDIS_REST_*`，不使用唯讀 Token）
- shopsaas-demo-platform 1.0.1 修正 CI 後 `baseline` tag 移到 `9a36cf036c436295c08a54d38789029e29d0f9ea`；更新 fixture、測試、README 與網站資料（只有 SHA 改變）

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
