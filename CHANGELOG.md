# Changelog

## 0.11.2 — 2026-11-12（運作原理頁加入各 Agent 的 Subagent）

- **運作原理頁**：整體架構圖下方新增「每個 Agent 底下的 Subagent」（`components/SubagentMap.tsx`）
  - 依流程順序：派工（純程式，不派 Subagent）→ A0 → A1～A3（同時進行）→ A4 → A5，每個 Agent 列出 Subagent 的白話名稱與程式名稱
  - 另列每日情資（Claude Code・訂閱方案，4 個 Subagent，結果交給 A1）與告警調查（由即時告警觸發，1 個 Subagent）
  - A0～A5 與告警調查共 21 個 Subagent（Agent SDK 派發），數量由清單計算；清單對應 `agents/registry.py` 與 `.claude/agents/`，兩處增減時需一併更新
- **RWD**：桌機橫向流程，900px 以下改直式；平板寬度時 A1～A3 並排
- **驗證**：`tsc --noEmit`、`npm test`、`next build` 通過；本機以 Chrome（DevTools 模擬）檢查 1280px、768px、390px（深色），頁面無橫向捲動。未呼叫任何付費 API

## 0.11.1 — 2026-11-12（運作原理頁加入整體架構圖）

- **運作原理頁**：最上方新增「整體架構」圖（`components/ArchitectureDiagram.tsx`，內嵌 SVG），原本的「流程」與「設計理由」不變
  - 三個區塊：外部資安情資與電商平台（被評估的系統）→ Sentinel 分析流程（派工 → 盤點系統 → 外部情資／弱點掃描／早期訊號 → 入侵路徑與評分 → 報告與建議）→ 網站（今日重點、行動報告、即時告警）
  - 以 ①～④ 標出四種觸發時機；藍色箭頭標示分析流程只「唯讀讀取」電商平台；Claude AI 以虛線框標示只判讀新聞、撰寫說明，分數與燈號由程式計算
  - 即時告警路線：部署通知 → 網站規則判斷 → 觸發告警調查 → 圍堵建議（留言到 Issue）
- **RWD**：960px 以上顯示橫向圖，以下改為直式圖（內容相同）；顏色使用主題變數，支援深色模式
- **驗證**：`tsc --noEmit` 通過；本機以 Chrome（DevTools 模擬）檢查 1280px（淺色、深色）、390px、360px，頁面無橫向捲動。未呼叫任何付費 API

## 0.11.0 — 2026-11-12（動態派工：AI 建議、程式核准）

規格文件（requirements／design／tasks）保存在 Repo 之外（專案資料夾的 `specs/dynamic-planner/`），未納入版本控制。

- **動態派工**：Orchestrator 維持純程式（它在 A0 之前，看不到當天情資）；A1 驗證完情資後，依新同業事件（live／demo，最多 5 件）取得 AI 建議，由程式逐項核准後執行。建議只有兩種：加查控制項、請 A4 說明相關風險；只能追加，不能跳過任何評估
- **建議來源**：daily（排程、手動）優先採用 `daily-intel`（訂閱方案）在 `intel-daily.json` 寫的 `agent_plan`，不呼叫 API；每日情資沒有可用建議、情境與公告調查改用 A1 的 `planner` Subagent（從 orchestrator 搬到 a1），live 呼叫 API、replay 只查錄製／快取，沒有就用範本。合法的 `{}` 或全部被拒絕不會改呼叫 API
- **程式核准**：控制項須在 `controls.yaml`、事件須在本次範圍、每件最多 3 個控制項（總共 8 個）、追加工作最多 3 項且只開放 A4 `impact-analyst`；多寫的欄位、重複、空白理由都拒絕並記錄原因。事件 ID 用同一份 `intel-daily.json` 快照對應，歧義 ID 一律拒絕
- **不影響判定**：加查只列出本次已算好的控制項檢查結果（情資報告新區塊 `8_extra_checks`），不進事件的控制項對應、impacts 與評分；分數、等級、燈號、結論與沒有建議時完全相同（測試逐欄比較）
- **A4 追加說明**：依核准的工作挑出這件事件命中、且不在原本前 10 個的風險（每件最多 3 個），以原本的任務格式追加；replay 時會一併交給 `claude-analysis` 撰寫
- **計畫檔**：`out/a1/agent-plan.json` 開始時先寫「處理未完成」，完成後原子替換；綁定執行識別與 `verified.json` 雜湊，A4、A5／llm-plan 讀到舊檔、壞檔或不符就停用並記錄原因，原有評估不受影響
- **預算**：A1 上限 $0.05 → $0.10（公告抽取與 planner 共用）；所有 Agent 的呼叫與重試改為只用「上限扣掉本次已花費」的餘額，用完就改用範本；planner 每次嘗試 60 秒
- **快取**：錄製結果無效時改查同鍵快取，兩者都無效才用範本
- **網站**：「AI 分析過程」頁顯示一行摘要（AI 建議 N 項、核准 M 項、拒絕 K 項與來源），可展開核准與拒絕明細；事件頁新增「AI 建議加查（程式檢查結果，不影響結論與分數）」。今日重點與行動報告頁不變；舊報告沒有這個欄位時照常顯示
- **daily-intel Skill**：輸出格式加上 `agent_plan`，規則與上限在 `references/agent-plan.md`（由 `scripts/build-agent-plan-reference.py` 產生，`--check` 檢查過期）。不新增 Subagent，guard hook、工具設定與 workflow 都沒有變更
- **新事件判斷**：以 checkout 進來的 `dashboard/public/data/daily/state/intel.json`（上一次發布的 daily）比對事件 ID；這個檔案缺失或損壞時，當天所有 live／demo 事件都視為新事件（最多 5 件），執行紀錄註明「讀不到上次清單」（使用者 2026-11-12 接受此降級）
- **驗證**（本機，只用 replay 與 fixture，未呼叫任何付費 API）：
  - pytest 全部通過（新增 `test_agent_plan.py`、`test_dynamic_planner_flow.py`、`test_dynamic_planner_rules.py` 與 `test_daily_intel.py` 的快照／ID 對應測試）；dashboard `npm test`、`tsc --noEmit` 通過
  - peer-incident 隔離空快取：planner 走範本，0 項建議；注入快取建議（1 個合法控制項、1 個未知控制項、1 個 A4 追加工作）：核准 2、拒絕 1，A4 追加 1 個風險說明，風險分數、等級、燈號與事件結論與基準相同
  - daily fixture：合法建議 → 採用訂閱方案、不建立 planner 任務；`{}`、全部拒絕不退回；缺欄位、null、錯結構 → 退回 A1 planner；沒有新事件 → 未觸發
  - 計畫檔被改壞、狀態未完成、不同執行、雜湊不符、核准值非法、verified 損壞時，A4、A5 都停用計畫並照常產出報告
  - 網站：以 Chrome（DevTools 精確模擬 390px）檢查事件頁與執行紀錄頁無橫向捲動，桌面與深色模式正常
  - **尚未在 GitHub 實跑**：訂閱方案的 Claude 是否實際寫出合格的 `agent_plan`，要等下一次每日排程確認

## 0.10.2 — 2026-11-11（摘要數字滑過顯示包含哪幾項）

- **今日重點、行動報告**：摘要與決策裡有底線的數字，滑鼠移上去（或用鍵盤聚焦）會顯示小卡，列出前 5 項與「還有幾項」；點數字仍跳到「數字從哪來」
- **RWD**：小卡寬度不超過畫面寬度減左右 16px，位置依畫面計算，手機 360／414、平板、桌機都不超出畫面；觸控裝置不顯示（點數字直接跳到清單），列印不顯示
- **驗證**：本機以 Chrome 在 360、414、768、1280、1920 五種寬度逐一滑過兩頁所有數字（80 次），小卡皆在畫面內、頁面無橫向捲軸

## 0.10.1 — 2026-11-11（Subagent 全部改用 Haiku；成本量測）

- **模型**：原本用 Sonnet 的 6 個撰寫型 Subagent（planner、remediation-advisor、brand-notice-writer、ceo-briefer、intel-report-writer、containment-advisor）改用 Haiku 5.5，設定 effort medium、未用圖譜時最多 3 回合；其他 Subagent 不變（effort low、最多 2 回合）。快取鍵含模型 ID，這 6 個的舊快取不再命中，第一次 live 會重新撰寫
- **修正**：remediation-advisor 回傳 Solution 時多出的欄位（例如 `confidence`）會讓 Report schema 驗證失敗、A5 整份報告產不出來；改為只保留 Solution 允許的欄位
- **用量記錄**：每次呼叫另記 token 用量（input、output、cache 寫入／讀取，含 Subagent，依模型拆分），寫進 `out/<agent>/cost.json` 的 `usage`；trace 的 result 事件附 token 數
- **成本量測**：新增 `scripts/cost_probe.py`（本機 record，冷啟動與有快取各跑一次，執行前備份、結束後還原，報告寫在 `.cost-test/`）；`SENTINEL_MODEL_OVERRIDE` 可強制所有 Subagent 用指定模型以便比較
- **實測**（2026-11-11 本機，全 Haiku）：daily 無快取 US$0.0725（A2 0.015、A4 0.016、A5 0.042）、全部命中快取 US$0；README「實際成本」已更新

## 0.10.0 — 2026-11-11（資安事件整理）

規格文件（requirements／design／tasks）保存在 Repo 之外（專案資料夾的 `specs/security-digest/`），未納入版本控制。

- **新頁面 `/digest`（資安事件整理）**：主導覽由 3 項改為 4 項（今日重點、行動報告、資安事件整理、異常行為偵測）；「外部事件」`/intel` 仍在「工程細節」，行為不變
  - 近 30 天外部事件依收錄日期分組（新到舊），同日依與我們的關係、最高等級排序；收錄事件與其他事件同樣放在收錄日期底下
  - 每件顯示標題、類型（真實報導／收錄事件／公告）、可信度、事件日期（缺少時「未提供」）、來源（標題、網域、驗證狀態）、摘要、關係、受影響系統數與最高等級；來源連結只接受 http(s)
  - 「與我們的關係」篩選（全部／受影響／需確認／不受影響）；新進度縮排在原事件底下，原事件不符合篩選時仍顯示符合的新進度與群組標示；原事件已過期時新進度單獨顯示「較早事件的新進度」
  - 頁首：最後更新、每天一次、下次預定更新（GitHub 排程可能延遲）；超過下次預定更新 12 小時標示「資料已過期」；最新 daily 的新聞情資 failed／skipped／重播／讀不到時分別提示；容量省略提示
  - 讀取時查驗目前 daily 的 intel index 與明細檔：存在才給「查看比對明細」，與保存結論不同次評估時註明「明細為另一份每日評估」；否則展開保存的受影響系統與結論（同名系統合併、超過 20 項時顯示原始總數）
  - 歷史事件顯示「上次評估於」，結論改變時顯示「結論更新於」；不顯示事件或系統的內部 ID
- **資料保留 30 天**：`dashboard/public/data/digest/` 的 `store.json`、`seen.json`、`latest.json`（不在 `daily/` 底下，不會被每日發布覆蓋）
  - 保留窗口為台灣日期當日與前 29 日；過期事件由發布端每次 daily 發布時移除（包含資料不完整、網站觸發與整理產生失敗），網站讀取時也依當天日期再過濾；清理不改最後更新與評估時間
  - `seen.json` 只有事件 ID 的 sha256 與首次收錄日期，過期後再次出現不會重新列為新事件
  - 每個收錄日期最多 50 件、各檔 1 MiB，超過時記錄省略件數
- **產生方式**：A5 在報告寫出前以程式產生（不新增 LLM 呼叫、不新增排程、不改 workflow）；只有 daily 的排程與手動來源會更新，網站觸發的 daily 不重建；資料不完整時只更新收錄紀錄，不發布新結論；產生或寫入失敗時保留前一版整組檔案，原因寫進 daily 報告與執行紀錄
- **發布合併**：`publish_merge` 只在 daily 合併 digest；seen 聯集取最早日期，store 依收錄時間與評估時間整組合併，latest 依 as_of → updated_at → run_id 選取，重試不倒退
- 排除示範事件與示範 fixture（`demo_fixture`），情境與公告調查不寫 digest；系統白話名稱新增 `rules/asset-labels.json`（Repo ① 清冊沒有名稱欄位）
- **v2 規格待同步**（本版不修改 `SENTINEL_SPEC.v2.md`，是否另發 v2.1 由使用者決定）：
  - 第 0 節規則 6：受信任程式可寫入的內容加上 `dashboard/public/data/digest/`
  - 第 10、10.1 節：新增 digest 三份資料與發布合併規則（seen 聯集、store 整組合併、latest 選取與到期清理）
  - 第 11.1 節：新增 `/digest` 頁面，主導覽由 3 項改為 4 項
- 驗證（本機，2026-11-11）：
  - 自動測試：Python 456 passed；dashboard `npm test` 71 pass（新增 `lib/digest.test.ts` 13 項，凍結 now）、`tsc --noEmit` 與 `next build` 通過
  - 以 `python agents/run_agent.py all --replay` 產生 digest 三檔（6 件收錄事件都在上線當天分組、皆受影響）；`next start` 後以 Chrome 無頭模式截圖 `/digest` 桌面、深色、390px（含展開明細），`scrollWidth <= innerWidth` 皆成立；「查看比對明細」連結正常（審查修正：與保存結論同一次評估時不再另附評估時間，只有另一次評估才附註），「辦公室 NAS（3 項）」同名合併且受影響數不變
  - 本機暫存假資料逐一驗證畫面：整理不存在（「整理尚未產生，將於下次每日評估後出現」）、沒有事件（「近 30 天沒有收錄的外部資安事件」）、過期（「資料已過期：上次更新於…」與「上次評估於」）、最新 daily 的新聞情資 failed／skipped／重播、父子事件篩選（原事件不符合時仍顯示受影響新進度與群組標示；讀取時原事件過期的新進度提升為「較早事件的新進度」；自我參照獨立顯示並列入資料狀態）、容量省略（只加總窗口內日期）與 20 項截斷提示、daily 被取代且明細檔消失時退回保存的評估結果、明細屬另一次評估時註明「明細為另一份每日評估」；`javascript:` 來源不產生連結；`/report` 標題日期、`/brief`、`/intel` 正常且保留 noindex
  - 驗證後已還原本機產生與假資料（`dashboard/public/data`、history 當日檔、`reports/intel` 當日目錄、`out/`）
  - 驗證中修正：卡片的「評估於／上次評估於」改與目前已發布的 daily 比較（daily 被取代或讀不到時一律「上次評估於」）；數字列多餘空白
- 尚未驗證（只在本機驗證）：GitHub Actions 上的排程與手動 daily 實際產生並發布 digest、`push-with-retry.sh` 在 main 上的重試合併、Vercel 部署後的 `/digest`；第一次排程 daily 之前，正式網站會顯示「整理尚未產生」
  - tasks.md T9 第 1、2、4 項（凍結時間連續多日與同日重跑的 daily、D+30／D+31 實體清理、不完整快照、注入 digest 準備／提交失敗再做發布重試）只由 T2～T5 的 Python 自動測試涵蓋，未以完整流程逐日實跑

## 0.9.5 — 2026-11-10（異常行為偵測與偵測規則設定）

- 「即時告警」頁改名「異常行為偵測」（網址 `/live` 不變；單則「告警」名詞不變）
- 新增「偵測規則」頁 `/rules`（在「工程細節」）：管理者可調整啟用／停用、等級、燈號、去重時間、偵測時段、時間窗、倍數、門檻、允許的部署者；需管理者密碼、操作人與理由
- 儲存寫回 `rules/realtime-settings.json` 一個 commit（base_sha 併發檢查）並同步 Redis，數秒內生效、不必重新部署；Redis 沒有設定時先用預設規則，並自動從 GitHub 修復
- 正規表示式、資料表、資料來源與新的規則類型仍需改 `rules/realtime.yaml` 並經過審查
- 尚未驗證：線上寫入 GitHub 與 Redis 的流程只有整合測試（本機 Docker Redis、假 GitHub API）

## 0.9.4 — 2026-11-10（CVE 改由程式直接比對：CISA KEV、NVD、事件新進度、自動公告）

- **KEV**：每日掃描新增 `kev`（CISA KEV 全集）；Trivy、NVD 與情資事件的 CVE 列入 KEV 即標為已遭實際利用並加分（daily-intel 的 LLM 宣稱仍不採用）
- **NVD**：每日掃描新增 `nvd`；執行環境與設備（PHP、Node、nginx、Apache、PostgreSQL、Redis、GitLab、phpMyAdmin、WordPress、OpenJDK、Synology DSM）依 CPE 取候選 CVE，一律在本地重新比對版本（實測 NVD 會忽略 DSM 的 Update 編號，9 個候選中 4 個其實已修補）；只影響特定平台（例如 Windows）或「所有版本」的列為暫定、需確認
- **事件新進度**：`is_update_of` 沿用原事件的產品、利用條件與控制項，版本範圍取聯集，原事件不改；原事件報告列出「事件進度」，網站與 Markdown 互相連結
- **intel-watch**：每小時由 KEV 近 30 天新列入的 CVE 查 NVD，涉及我們產品的才產生公告（存在 `intel-watch.json`）；每 24 小時重查，NVD 更新就重新比對；命中先排入 queued，發布狀態後才派工，被派工的執行才讀得到公告
- KEV／NVD 失敗或未涵蓋只是註記（`required=False`），不影響完整性、燈號與其他掃描結果的沿用；manifest 失敗或過期的掃描結果不再被載入；資產清單缺失時 NVD 不輸出零結果
- intel-watch 第一次產生 `intel-watch.json` 時也會發布：原本以 `git diff` 判斷，看不到尚未追蹤的新檔案，狀態永遠不會 commit，自動公告也到不了 main
- 選用 Secret：`NVD_API_KEY`（沒有時每 30 秒 5 次，daily 的 NVD 掃描約 2 分鐘）
- 影響：以 demo 技術棧與真實 NVD 資料實測，每日報告新增 5 個高風險（3 個 Node 22.11.0、nginx、Apache）、NAS 由中升高，另新增 5 個中風險、3 個低風險；實際數字依當天 NVD 資料而定
- 尚未驗證：新的 workflow 步驟（scanners 的 kev／nvd、intel-watch 發布後派工）還沒在 GitHub Actions 上實際執行

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
