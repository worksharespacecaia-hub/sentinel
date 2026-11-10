# Changelog

## 0.9.3 — 2026-11-10（沒有比對依據的事件不再顯示「不受影響」）

- 新聞事件沒有產品、CVE，也對應不到有檢查結果的控制項時，程式等於沒有比對任何資產；原本只要資產清單完整就判為不受影響（例如 2026-11-10 易遊網等 4 則新聞），改為「需確認」，結論寫明「無法自動判定」與原因
- 待確認事項列出要人工判斷的內容與建議新增的控制項；daily-intel 保留 LLM 輸出的 `proposed_controls`（只留標題與理由文字，不能帶入既有控制項 ID），技能說明要求對應不到控制項時填寫
- 已發布的報告不回溯修改，下一次每日評估起套用

## 0.9.2 — 2026-11-10（摘要數字可帶出來源）

- 今日重點與行動報告的 CEO 摘要、決策中「N 個／件」可點，跳到行動報告「數字從哪來」並展開對應的風險或事件清單；對不上程式結果的數字標示警告
- 今日重點的高風險卡片可看是哪些；未登記對外系統直接列出名稱
- A5：Claude 撰寫的摘要與決策中帶單位的數字必須是程式算出的數字之一，否則改用程式範本並記錄在執行紀錄
- 限制：寫錯的數字若剛好等於另一項數字，檢查無法發現

## 0.9.1 — 2026-11-10（行動報告的外部事件附上來源）

- 行動報告「與我們有關的外部事件」：每件事件列出事件日期、可信度與來源（報導標題、媒體網域、驗證狀態、原文引用）；匯出 PDF 時印出來源網址
- 行動項目列出相關事件名稱，可跳到該事件的來源；今日重點的外部事件數字連到行動報告的事件與來源
- 示範事件標示「示範，非真實報導」；來源網址只接受 http(s)

## 0.9.0 — 2026-11-10（給 CEO 看的 Demo：精簡導覽、今日重點、行動報告、LINE、燈號權重）

- **導覽列精簡**：只留 3 個主項（今日重點、行動報告、即時告警），其他頁收進「工程細節」下拉並標示目前頁。頁名改白話：總覽→詳細總覽、風險清單→風險明細、情資比對→外部事件、攻擊鏈→入侵路徑、資產→系統盤點、App→App 風險、Agent 執行→AI 分析過程、架構說明→運作原理、即時監控→即時告警（名稱集中在 `dashboard/lib/nav.ts`）
- **今日重點 `/brief`**：紅黃綠三顆燈（亮目前燈號並附文字）、三句摘要、3 個數字、今天要決定的事、最需要處理的 3 件事
- **行動報告 `/report`**：彙整決策、全部未修復的高中風險與建議做法、受影響的外部事件、通知草稿；「匯出 PDF」使用瀏覽器列印（A4 版面、保留免責橫幅）
- **處理中追蹤**：管理者可把風險設為處理中（負責人、期限必填、最多 30 天）；`reminders.yml` 每小時檢查，期限前 24 小時與逾期各以 LINE 提醒一次。已修復仍只由重新評估判定
- **LINE Bot（規格 7.7）**：`/api/webhooks/line`（簽章驗證、綁定碼、最多 3 位管理者、今日燈號／最新告警／行動報告查詢）、高風險告警推播、`/api/notify/light` 燈號變化推播、`/api/report/send` 手動傳送、額度分級（150／190 則）。未設定 LINE 時一律 skipped
- **燈號權重 `/weights`**：加分因子與高／中門檻改由 `rules/scoring.json` 設定（預設值不變）；網站可試算並以管理者密碼儲存（寫回 GitHub 一個 commit），下一次評估起生效；設定無效時改用預設並列入資料狀態。報告新增 `scoring`、風險新增 `level_floor`、`provisional_basis`
- **CEO 摘要白話化**：範本第二句改寫影響（可能碰到訂單資料、會員個資…），不寫版本號與 CVE；未登記系統的決策合併成一條；`ceo-brief` skill 與 Claude 撰寫任務同步
- 驗證：本機以 Chrome 無頭模式檢查 /brief、/report 桌面、深色與 390px 手機寬度（無橫向捲動），列印 PDF 為 A4 10 頁、卡片不跨頁、表頭跨頁重複
- 尚未驗證：需要 Redis、LINE 帳號與 GitHub Token 的流程（追蹤寫入、綁定與推播、權重寫回）只有單元測試與型別檢查，未做整合與實機測試

## 0.8.0 — 2026-11-10（A2、A4、A5 的說明文字改由 Claude 訂閱方案撰寫）

- 使用者決定用訂閱方案而不是 API Key。官方文件：Agent SDK 產品應使用 API Key 認證；claude-code-action 支援以 `CLAUDE_CODE_OAUTH_TOKEN` 使用訂閱方案。因此改為比照每日情資，以 claude-code-action 撰寫，不在 Agent SDK 中使用訂閱 Token（另查證 GitHub Models 已於 2026-07-30 停止服務）
- 新增 `claude-analysis` Job（A4 之後、A5 之前，只在預設分支的排程與手動 daily）：
  - A2、A4 改用範本的任務存成 `llm-tasks.json`；`run_agent.py llm-plan` 再依 A5 的流程算出 A5 的任務，寫成 `out/llm/tasks.json`
  - Claude（`/analysis-writer` Skill）只讀 `out/`、`.claude/`，只寫 `out/llm/results.json`；不上網、不派發 Subagent（hook 參數化）
  - 程式確認只寫了 `out/`、任務檔雜湊不變，`llm-validate` 以各 Subagent 原本的範圍與格式驗證（分數、等級、狀態不得改動，不得含金鑰）
  - A5 採用通過驗證的結果，A2、A4 的說明再以原任務驗證一次；其餘用範本。執行樹新增「Claude 撰寫說明（訂閱方案）」節點
- 同一次執行的所有 Job 使用 Orchestrator 決定的同一個邏輯時間（`AS_OF`）：修正各 Job 各自取現在時間，造成規劃與 A5 的任務鍵不同（情資摘要的 `observed_at`）
- 本機端到端驗證：29 個任務（A2 5、A4 10、A5 14）由 Claude 撰寫，程式驗證 29／29 通過；A5 的 20 筆執行紀錄全部為即時呼叫，37 項風險說明、12 項修補建議、CEO 摘要與 7 份情資摘要採用 Claude 的文字
- `dl/` 加入 .gitignore（`claude-analysis` Job 的「只寫了 out/」檢查不會被下載的掃描結果誤判）

## 0.7.0 — 2026-11-10（Agent 執行頁顯示真實的 Claude 判讀；A1～A5 可啟用 live）

- 使用者回報「Agent 執行」頁全是程式範本：A0～A5 在 replay 模式下沒有任何錄製檔（29 筆 Subagent 結果都是範本），而真的有呼叫 Claude 的每日情資沒有出現在執行樹
- **每日情資放進執行樹**：daily-intel Job 以程式把 Claude 的執行紀錄整理成 `trace.jsonl`（抓了幾篇、派了哪些 Subagent、各用了哪些工具、寫出幾件事件；不含網頁與對話內容），Claude 失敗也會留下紀錄；A5 合併進執行樹，網站標示「即時呼叫・訂閱方案，不計 API 費用」
- **月預算 API（`/api/budget`，規格 v2 第 11.2 節）**：live 模式的 Agent 呼叫 Claude API 前先預留、完成後依實際用量結算
  - `NOTIFY_TOKEN` 保護；金額以微美元整數計算；每月額度（預設 US$15、保留 10% 超支緩衝）與單筆上限（US$0.5）由伺服器設定
  - 冪等鍵 `<run>-<attempt>/<agent>/<agent>/<序號>`：同一筆重送不重複扣額，已結算的鍵不能再預留
  - 未結算的預留保守地一直佔用額度（由用量對帳釋放）；並行租約 30 分鐘逾時，避免中斷的 Job 永久卡住
  - 月份依帳務時區（`BUDGET_TZ`，預設 UTC）；跨月結算計入預留當月
  - 整合測試（本機 Redis）：預留與結算、冪等、額度不足、單筆上限、租約逾時、跨月、30 筆同時預留不超額
- 修正：結算原本用 Agent 的累計花費，同一個 Agent 呼叫多次時會重複計入；改為只結算本次用量
- Workflow：live 時 A1～A5 才取得 `NOTIFY_TOKEN` 與 `SENTINEL_BASE_URL`（SDK 子行程仍由 `scrubbed_environ` 清除）
- README：啟用 live 的步驟（Anthropic API Key、`SENTINEL_SCHEDULE_MODE=live`、預算設定）

## 0.6.0 — 2026-11-10（每日情資改為程式抓新聞、Claude 判讀）

- **架構調整**（使用者決定）：資安新聞改由程式從可信網站的 RSS 與 CISA KEV 抓取（`agents/tools/news_collect.py`、`agents/intel/news_feeds.yaml`），Claude 只做判讀；不再使用 WebFetch，WebSearch 只用來補充 RSS 沒涵蓋的事件
  - 來源：iThome、TechNews、INSIDE、CyberQ、中央社（科技、社會）、Taipei Times、The Hacker News、SecurityWeek、The Record、CISA KEV
  - 近 72 小時（原 48 小時；GitHub 排程常延遲數小時）；一般新聞來源只保留含資安關鍵字的文章，依技術棧產品、產業、地區排序取前 30 篇；內文切成句子（每句一行），`news.json` 限制在 80 KB 內
  - safe_fetch：只接受 HTTPS 與允許的網域、限制大小與型態；XML 以 defusedxml 解析；文章網域必須在可信清單中
  - A1 以同一次執行抓到的原文確認引用（不需再抓一次）；WebSearch 補充的事件仍實際抓頁面確認
  - Job 在抓取後記錄 `news.json` 雜湊，Claude 執行後核對；hook 拒絕 WebFetch
- 本機端到端驗證（11/10）：抓到 40 篇相關文章；Claude 判讀出 4 件事件，引用全部比對通過——易遊網會員資料外洩（iThome、INSIDE、Taipei Times 三家一致 → 確認）、順立智慧（Cyberbiz）資料庫遭異常存取波及櫻花／曜亞／崇越安永生活、美吾華購物網站、SEGA（Arara）
- 修正：沒有時區的發布時間（iThome）被當成 UTC；safe_fetch 接受 `text/xml`、`application/atom+xml`
- 併入未單獨發布的 0.5.1：Subagent 搜尋步驟、`advisory-scout` 讀正確路徑 `out/stack.json`、Skill 參考檔使用完整路徑；每次執行的 log 逐筆列出工具呼叫（工具、查詢字詞或網站、結果）與 Claude 最後的說明，不含網頁內容
- 網站：「Agent 執行」頁的每日情資節點與說明改為「程式抓新聞＋Claude 判讀」

## 0.5.0 — 2026-11-10（每日情資信任來源擴充）

- 0.4.2 後每日情資全流程跑通（狀態正常、報告完整、無資料問題），但新事件 0 件：信任網站清單只有 15 個網域，多數台灣新聞網站抓不到原文，依「每項判斷必附原文引用」的規則不列入
- 新增 11 個信任網域（使用者選定）：TWCERT/CC、國家資通安全研究院（advisory）；中央社、Focus Taiwan、Taipei Times、INSIDE、資安人、BleepingComputer、The Hacker News、SecurityWeek、The Record（media，需兩家一致才確認）
- Job 中 Claude 只能讀 `.claude/`，讀不到 `agents/intel/sources.yaml`：可抓取網域改寫進 Skill 參考檔，測試檢查 hook 解析結果、YAML 與參考檔三者一致
- news-scout、advisory-scout 可讀參考檔；每個事件至少要有一個清單內來源，清單外網站的新聞改找清單內網站的報導
- 每次執行在 log 印出事件數、各工具呼叫次數與被擋的網站（調整清單的依據），不含對話內容
- 「Agent 執行」頁的重播說明分開說明：A0～A5 是重播（不花 API 費用），每日情資由訂閱方案實際搜尋

## 0.4.2 — 2026-11-10（hotfix：每日情資的 Subagent 在背景被中斷）

- 0.4.1 的診斷找到原因：Claude 把 news-scout、advisory-scout 放到背景執行後結束回合；GitHub 上是無人值守的單次執行，主 Agent 結束回合就整個結束，背景 Subagent 被中斷，沒有寫出結果
- 三層防護，Subagent 一律在前景執行：daily-intel 設定 `CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=1`（Agent 工具不再提供背景參數）；hook 拒絕 `run_in_background`；Skill 寫明等全部回報、寫出結果後才結束
- 本機以相同參數驗證：明確要求背景派發時，Agent 工具沒有背景參數，改為前景執行並等到回覆
- 新增 hook 測試（允許與拒絕的工具、背景 Subagent、設定檔）

## 0.4.1 — 2026-11-10（hotfix：每日情資診斷補完整）

- 0.3.2 後 daily-intel 不再被權限擋下，但 Claude 7 個回合、9 秒就結束且沒有寫出結果；當時的診斷只列權限拒絕，看不出原因
- Claude 沒寫出 `out/intel-daily.json` 時，另外列出：`out/` 中的檔案名稱與大小、主 Agent／Subagent 各工具呼叫次數、工具錯誤（截斷）與 Claude 最後的說明（截斷、遮蔽疑似金鑰）；仍不印工具輸入內容與網頁內容

## 0.4.0 — 2026-11-10（Agent 執行頁可操作執行）

- 「Agent 執行」頁新增操作面板：選情境、輸入示範密碼後送出，即時顯示 6 個階段、11 個 Job（Orchestrator、A0、三種掃描、每日情資、A1～A5）的狀態與耗時，點 Agent 開啟該 Job 的 GitHub 執行紀錄（規格第 11 節驗收「Agent 執行頁可看到即時進度」）
- 執行結束後輪詢 `index.json`，新結果隨 Vercel 重新部署上線才提示「查看這次的 Agent 執行結果」；超過 15 分鐘未上線時提示檢查 A5 與 Vercel
- 重新整理或換頁回來會繼續追蹤（瀏覽器本機保存請求 ID，3 小時後失效）；可停止追蹤（不會取消 GitHub 上的執行）
- `/api/status` 的 Job 資料加上開始／結束時間與 Job 網址（只接受 GitHub Job 網址）
- 總覽頁的執行表單改為連到「Agent 執行」頁；權限、冷卻、執行模式等限制不變（伺服器端決定）

## 0.3.2 — 2026-11-10（hotfix：每日情資寫不出結果）

- `--allowedTools` 的 `Write(./out/**)` 不是有效的權限規則，dontAsk 模式下 Write 一律被拒：Claude 完成搜尋卻寫不出 `out/intel-daily.json`，Job 仍顯示成功。改為 `Edit(./out/**)`（涵蓋所有寫檔工具），PreToolUse hook 仍只允許寫 `out/intel-daily.json`（本機以相同參數驗證：intel-daily.json 可寫，out/other.json、notes.txt 被 hook 擋下）
- Claude 執行結束但沒有寫出 `out/intel-daily.json` 時 Job 明確失敗，並列出被拒絕的工具（只列工具名稱、相對路徑或網址主機）
- 0.3.1 的診斷已找出前一個問題：Secret 中的 Token 含換行與多餘字元（401 OAuth access token is invalid），重新貼上後驗證通過

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
