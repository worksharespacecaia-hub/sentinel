> **虛構環境，非 91APP 或任何公司的實際系統。所有金鑰皆為 DEMO-FAKE 假值。**

# Sentinel

電商 SaaS 資安哨兵系統（多 Agent Demo）：每天回答 CEO「外面發生什麼、我們有沒有事、要做什麼」。

系統只產出報告與建議，**不修改受評估的系統、不開 PR**。原則是：工具負責找、程式負責算、LLM 負責理解與說明。版本、分數、結論與燈號都以程式結果為準；LLM 失敗或超出預算時退回程式範本，報告一定會產生。

## 架構

```
Repo ① shopsaas-demo-platform（被評估的虛構系統）
   pr-gate.yml：PR 掃描把關（觸發 ①）
   ci.yml：SBOM、部署紀錄
   Webhook（Deployments）─────────────────────────────┐
        ▲ 唯讀 Token                                   │
Repo ② sentinel（本 Repo）                             │
   intel-watch.yml：每小時比對公告（觸發 ②）           │
   sentinel.yml：Orchestrator → A0 → A1/A2/A3 → A4 → A5（觸發 ②③）
   incident.yml：從告警資產推演攻擊路徑 → 圍堵建議 → Issue 留言（觸發 ④）
   A5 commit 到 dashboard/public/data/ → Vercel 自動重新部署
        ▼                                              ▼
Vercel：Dashboard、/api/run、/api/status、/api/webhooks/github、/api/events、/api/alerts
   即時規則（觸發 ④，不用 LLM）→ Upstash Redis、GitHub Issues、repository_dispatch → incident.yml
```

| 層級 | 內容 |
|------|------|
| Agent 層 | 每個 Agent 是一個 GitHub Actions Job，以 `needs:` 串接；Actions 的 Job 圖就是多 Agent 流程圖 |
| Subagent 層 | Job 內以 Claude Agent SDK 定義 Subagents 與 Skills（主 Agent 用 Haiku，撰寫用 Sonnet）；每日排程與手動 daily 時，A2、A4、A5 的說明文字由 `claude-analysis` Job（claude-code-action，訂閱方案）撰寫 |
| 每日情資層 | `daily-intel` Job：程式先從可信資安網站的 RSS 與 CISA KEV 抓近 72 小時文章（`news_collect.py`），再由 claude-code-action（訂閱方案）判讀；只在預設分支的每日排程與手動 `daily` 執行 |
| 工具層 | Trivy、Gitleaks、Checkov、CISA KEV 全集、NVD（依 CPE 查執行環境與設備的 CVE，本地重新比對版本）與確定性 Python：圖譜、對帳、控制項、評分、攻擊路徑、燈號、報告 |
| 網站與即時層 | Next.js（Vercel）＋ Upstash Redis：Dashboard、即時規則、告警交付與結案 |

## 四種觸發時機

| 觸發 | 時機 | 做什麼 | 是否用 LLM |
|------|------|-------|-----------|
| ① CI/CD 把關 | 每次 PR、每次部署（Repo ①） | 掃描變更，新增金鑰等高風險擋下 PR；部署時產出 SBOM | 否 |
| ② 事件觸發 | 每小時輪詢公告（`intel-watch.yml`） | 手寫公告，以及 CISA KEV 近 30 天新列入、經 NVD 查到涉及我們產品的 CVE（程式自動產生公告）；比對已存的 SBOM 與圖譜，命中才觸發 `sentinel.yml`（`scenario=advisory`）只調查受影響資產 | 第 1 層否；命中後才用 |
| ③ 每日例行 | 每天台灣時間 08:00（`sentinel.yml`） | 全部資產重新評估：影子 IT、金鑰輪替、設定漂移、備份、App 版本分布 | 只處理差異 |
| ④ 即時規則 | 事件一出現（Vercel） | 非 Pipeline 部署（RT-001）、凌晨大量讀取（RT-002）、多品牌詐騙回報（RT-003）→ 告警、建立 Issue、觸發 `incident.yml` | 規則判斷不用；告警後才產生圍堵建議 |

只靠任一種都會漏：CI/CD 看不到「程式沒變但今天公布新漏洞」；事件觸發看不到金鑰太久沒換；每日排程對幾十分鐘就爆量的攻擊太慢。

## 目錄

```
agents/                 Python：Agent（agents/）、確定性工具（tools/）、情境（scenarios/）、測試（tests/）
  fixtures/             Repo ① baseline 的凍結副本（金鑰值已遮蔽）、掃描結果、修復後 overlay（after-fix/）
  intel/                預先收錄的真實事件、已知公告、示範事件、控制項
rules/                  即時規則 realtime.yaml 與帳號基準 baselines.json
dashboard/              Next.js 網站與 API（Vercel 只部署這個目錄）
  public/data/          A5 發布的評估結果（daily、scenarios、advisories）
reports/                情資比對報告（Markdown）
scripts/                build-rules.py、push-with-retry.sh、sync-target-fixture.sh、lint-workflows.sh
.github/workflows/      sentinel.yml、intel-watch.yml、incident.yml
```

## 本機開發（不花 API 費用）

需要 Python 3.12、Node.js 24、Docker（掃描工具與整合測試）。預設執行模式是 replay，不呼叫任何 LLM。

```bash
pip install -r agents/requirements.txt
pytest                                             # 確定性流程、情境驗收、Workflow 結構

python agents/run_agent.py all --replay --scenario php2shell
# 依序執行 orchestrator → a5；結果寫到 out/ 與 dashboard/public/data/scenarios/php2shell/（會覆蓋已提交的結果）

python scripts/build-rules.py                      # 修改 rules/ 後重新產生 dashboard/lib/realtime-rules.json
scripts/lint-workflows.sh                          # 以 Docker 執行 actionlint

cd dashboard
npm ci
npm test                                           # 單元測試
npm run test:integration                           # 啟動本機 Redis＋Upstash REST 相容代理（只綁 127.0.0.1），結束後自動移除容器
npx tsc --noEmit && npx next build
npm run dev
```

本機沒有 `target/`（Repo ① 的 checkout）時，自動使用 `agents/fixtures/target-baseline/`。Repo ① 的 `baseline` tag 有變動時，以 `scripts/sync-target-fixture.sh <Repo ① 路徑>` 重新匯出。

本機試跑每日情資（用訂閱方案，不花 API 費用）：

```bash
python agents/run_agent.py a0 --replay            # 產生 out/stack.json、out/seen.json
python agents/tools/news_collect.py --out out/news.json --stack out/stack.json   # 程式抓資安新聞（RSS、CISA KEV）
# 與 Actions 相同的限制：Claude 只讀 out/ 與 .claude/、只寫 out/intel-daily.json，不抓網頁（WebSearch 只用來補充）
claude -p "/daily-intel" --model sonnet --max-turns 40 --settings .claude/daily-intel-settings.json \
  --tools "Read,Write,Agent,Skill,WebSearch" --disallowedTools "Bash,Edit,NotebookEdit,WebFetch" \
  --allowedTools "Read(./out/**),Read(./.claude/**),Edit(./out/**),Agent,WebSearch" \
  --permission-mode dontAsk --strict-mcp-config
python agents/run_agent.py all --replay           # A1 清理格式，引用比對同一份原文（news.json）
```

`--record`（本機實際呼叫 API 並錄製）會花錢，需以 `LOCAL_RECORD_CAP_USD` 設定單次上限；執行前請先確認預估成本（見[成本](#成本)）。

## 部署

以下步驟需要你自己的 GitHub、Vercel 帳號。隨機字串可用 `openssl rand -hex 24` 產生；所有 PAT 請設定到期日（例如 90 天）。

### 1. 建立兩個 GitHub Repo 並推送

建立兩個空的公開 Repo：`shopsaas-demo-platform`（Repo ①）與 `sentinel`（Repo ②），不要勾選 README。推送 `main`、`develop` 與 tag（Repo ①：`baseline`、`v1.0.0`；Repo ②：版本 tag）。

### 2. Repo ① 設定

- Settings → Code security：開啟 Dependabot alerts、Secret scanning、Code scanning（CodeQL Default setup）
- Settings → Branches：`main` 設定分支保護，要求 `pr-gate` 通過才能合併

### 3. 建立 Fine-grained PAT

| 名稱 | 範圍 | 權限 | 放在 |
|------|------|------|------|
| `TARGET_READ_TOKEN` | 只限 Repo ① | Contents、Deployments、Dependabot alerts、Secret scanning alerts、Code scanning alerts：Read | Repo ② Actions Secrets |
| `GH_DISPATCH_TOKEN` | 只限 Repo ② | Actions：Read and write；Contents：Read and write | Vercel 環境變數 |
| `ALERT_ISSUE_TOKEN` | 只限 Repo ② | Issues：Read and write | Vercel 環境變數 |

### 4. Repo ② Actions 設定

- Secrets：`TARGET_READ_TOKEN`、`NOTIFY_TOKEN`（隨機字串，與 Vercel 相同）、`CLAUDE_CODE_OAUTH_TOKEN`（每日情資；在本機以要負擔用量的 Claude 訂閱帳號執行 `claude setup-token` 產生，到期需重新產生）
- Variables：`SENTINEL_SCHEDULE_MODE=replay`、`INCIDENT_EXECUTION_MODE=replay`；Vercel 網域確定後加上 `SENTINEL_BASE_URL=https://<網域>`
- 選用：`TARGET_REPO`（預設 `<owner>/shopsaas-demo-platform`）；`NVD_API_KEY`（NVD 免費申請；沒有時查詢放慢為每 30 秒 5 次，daily 的 NVD 掃描約 2 分鐘）
- replay 模式不需要 `ANTHROPIC_API_KEY`；要讓 A1～A5 實際呼叫 Claude，見下方「啟用 live」
- 每日情資不論 replay 或 live 都會執行；沒有 `CLAUDE_CODE_OAUTH_TOKEN` 時 daily 照常完成，報告標示「今日新聞情資未更新」
- 不需要安裝 Claude GitHub App：`daily-intel` 以本 Job 的唯讀 `github.token` 執行
- A0 以 `TARGET_READ_TOKEN`（Deployments：Read）讀取 Repo ① 的 production Deployments，同一次執行的 A0～A5 共用；讀取失敗時改用離線 fixture，報告標示原因
- `main` 不要設定會阻擋 `github-actions[bot]` 推送的分支保護：A5 以 `scripts/push-with-retry.sh` 把結果 commit 到 `dashboard/public/data/`

#### 說明文字由 Claude 撰寫（訂閱方案，預設）

每日排程與 GitHub 手動 `daily` 時，A4 之後的 `claude-analysis` Job 會讓 Claude（claude-code-action、訂閱方案）撰寫 A2、A4、A5 的說明文字：

1. 程式整理要撰寫的任務（`out/llm/tasks.json`：風險說明、修補建議、CEO 摘要、情資摘要、品牌商通知；分數、等級與燈號已由程式算好）
2. Claude 只讀 `out/`、`.claude/`，只寫 `out/llm/results.json`（不上網、不派發 Subagent；hook 參數見 `.claude/analysis-settings.json`）
3. 程式確認 Claude 只寫了 `out/`、任務檔沒被改動，再以各 Subagent 原本的範圍與格式驗證（不得改動分數、等級、狀態，不得含金鑰）
4. A5 採用通過驗證的結果，其餘用程式範本；「AI 分析過程」頁標示「即時呼叫・訂閱方案」

不需要額外設定（使用每日情資的 `CLAUDE_CODE_OAUTH_TOKEN`），不產生 API 費用，會使用訂閱額度。同一次執行的所有 Job 使用 Orchestrator 決定的同一個邏輯時間（`AS_OF`），任務鍵才會一致。A1（公告抽取）與 A3（客訴分類）的結果在各自的 Job 內使用，仍是範本；網站觸發與情境不使用訂閱方案。

#### 啟用 live（A1～A5 改用 Claude API，選用）

不用訂閱方案、或要讓網站觸發與情境也由 Claude 撰寫時，可改用 Claude API（按量計費）：

1. 在 Anthropic Console 建立 API Key（按量計費，與 Claude 訂閱方案分開），並設定每月 spend limit（建議 US$15）
2. Repo ② Actions Secrets 新增 `ANTHROPIC_API_KEY`
3. Repo ② Actions Variables 把 `SENTINEL_SCHEDULE_MODE` 改為 `live`（排程與 GitHub 手動 daily）；`SENTINEL_BASE_URL` 必須已設定
4. 選用（Vercel）：`BUDGET_MONTHLY_USD`（預設 15）、`BUDGET_BUFFER`（超支緩衝比例，預設 0.1）、`BUDGET_TZ`（帳務時區，預設 UTC）、`BUDGET_MAX_RESERVATION_USD`（單筆上限，預設 0.5）

每個 Agent 呼叫 API 前先向 `/api/budget` 預留（以 `NOTIFY_TOKEN` 保護、冪等鍵含 run／attempt／agent／序號），完成後依實際用量結算；本月額度不足或服務無法連線時改用程式範本，報告照常產出。網站觸發（`WEB_EXECUTION_MODE`）與圍堵建議（`INCIDENT_EXECUTION_MODE`）維持 replay，需要時另外設定。

### 5. Vercel

1. 匯入 `sentinel`，Root Directory 設為 `dashboard`，Production Branch 為 `main`
2. 從 Vercel Marketplace 加入 Upstash Redis（會自動注入 `KV_REST_API_URL`、`KV_REST_API_TOKEN` 等變數，程式直接使用；也接受 `UPSTASH_REDIS_REST_URL`、`UPSTASH_REDIS_REST_TOKEN`，不使用唯讀 Token）
3. 設定環境變數：

| 變數 | 值 |
|------|----|
| `DEMO_PASSCODE` | 隨機字串（網站觸發與模擬器） |
| `ADMIN_PASSCODE` | 隨機字串（略過網站冷卻、告警結案與重試） |
| `GITHUB_WEBHOOK_SECRET` | 隨機字串（與 Repo ① Webhook 相同） |
| `NOTIFY_TOKEN` | 與 Repo ② Secret 相同 |
| `GH_OWNER`、`GH_REPO` | 你的帳號、`sentinel` |
| `GH_DISPATCH_TOKEN`、`ALERT_ISSUE_TOKEN` | 步驟 3 建立的 PAT |
| `GITHUB_TARGET_REPO_ID` | `gh api repos/<owner>/shopsaas-demo-platform --jq .id` 的數字 |
| `WEB_EXECUTION_MODE` | `replay` |
| `SENTINEL_BASE_URL` | `https://<網域>`（Issue 內的連結） |

LINE 相關變數為選用（見「給 CEO 看的頁面」）。缺少 `DEMO_PASSCODE`、`GITHUB_WEBHOOK_SECRET` 或 Redis 時，對應的 API 會回 503 停用，不會以空值放行。

### 6. Repo ① Webhook

Settings → Webhooks：Payload URL `https://<網域>/api/webhooks/github`、Content type `application/json`、Secret 與 `GITHUB_WEBHOOK_SECRET` 相同、事件只勾選 **Deployments**。

### 7. 上線驗證

1. Repo ① 推送一次，確認 Release 有 SBOM、Deployments 有紀錄
2. Repo ② 手動執行 `sentinel`（`scenario=daily`），確認 Job 圖與結果；Vercel 自動重新部署後，網站總覽顯示紅燈與免責橫幅
   - 網站總覽的「每日情資」顯示「正常」；新事件出現在情資頁（標示「真實」），引用未通過驗證的事件只到暫定
   - 資料問題中不再出現 `github/deployments`（代表已讀到 Repo ① 的實際部署紀錄）
3. 手動執行 `intel-watch`：沒有命中時不觸發；有命中時觸發 `advisory`
4. 在筆電建立一次正式部署（即時告警頁也有這段指令）：

   ```bash
   gh api -X POST repos/<owner>/shopsaas-demo-platform/deployments --input - <<'EOF'
   {"ref":"main","environment":"production","auto_merge":false,"required_contexts":[],"description":"manual deploy (demo)"}
   EOF
   ```

   目標：10 秒內網站出現 RT-001 紅色告警並建立 Issue；約 3 分鐘內 Issue 出現圍堵建議留言（取決於 Actions 排隊，超過 5 分鐘網站會標示延遲）
5. 依序執行下方情境並記錄成本
6. 重設 Demo，再跑一次 `daily`，確認回到基準狀態

## 給 CEO 看的頁面

- Demo 請從 `/brief`（今日重點）開始：三顆燈、三句摘要、今天要決定的事、最需要處理的 3 件事；可加 `?source=<情境>`
- `/report`（行動報告）：按「匯出 PDF」後在列印視窗選「另存為 PDF」；管理者可把項目設為處理中（期限必填），到期前 24 小時與逾期時以 LINE 提醒（`reminders.yml` 每小時執行，GitHub 排程可能延遲）
- `/weights`（燈號權重，在「工程細節」）：調整加分因子與高／中門檻，需 `ADMIN_PASSCODE`；以 `GH_DISPATCH_TOKEN`（Contents 讀寫）把 `rules/scoring.json` 寫回預設分支，下一次評估起生效
- LINE：依規格 14.2 建立官方帳號後，Webhook URL 設為 `https://<網域>/api/webhooks/line`，Vercel 設定 `LINE_CHANNEL_SECRET`、`LINE_CHANNEL_ACCESS_TOKEN`、`LINE_BIND_CODE`、`LINE_MAX_ADMINS`、`LINE_PUSH_SIMULATED`；圖文選單三個按鈕送出文字「今日燈號」「最新告警」「行動報告」。未設定時 LINE 功能略過，不影響其他功能

## 執行情境

情境把額外輸入疊加到基準資料上，結果寫到 `dashboard/public/data/scenarios/<name>/`，**不影響正式總覽燈號**。可以從網站的「AI 分析過程」頁（需示範密碼，每小時一次）或 GitHub Actions 的 `sentinel` workflow 手動執行。

「AI 分析過程」頁送出後會即時顯示每個 Agent（Job）的狀態與耗時，點 Agent 可開啟該 Job 的執行紀錄；執行結束後偵測到新結果隨 Vercel 重新部署上線，就提供「查看這次的 Agent 執行結果」。重新整理頁面會繼續追蹤（只存在瀏覽器本機）。網站觸發使用伺服器設定的執行模式（預設 replay），不使用訂閱方案：網站觸發的 `daily` 不會搜尋新聞。

| 情境 | 怎麼觸發 | 預期結果 |
|------|---------|---------|
| `daily` | 排程、手動、網站 | 內部工具漏洞、Git 中的資料庫金鑰、網路未分段 → 攻擊鏈 internet → internal-tool → order-db-prod → 紅燈；6 個真實事件命中 |
| `php2shell` | 網站／手動 | PHP 官方公告：marketing-site 高 9 分、phpMyAdmin 中 4 分（只允許 VPN），附修補／緩解／下架選項 |
| `peer-incident` | 網站／手動 | 同業寄信金鑰外洩 → 檢查第三方金鑰 → 寄信金鑰超過一年未輪替，附輪替建議與品牌商通知草稿 |
| `early-signal` | 網站／手動 | 同日 3 個品牌詐騙回報＋凌晨大量讀取 → 早期訊號直接紅燈，標示「疑似已發生外洩」 |
| `intel-demo` | 網站／手動 | 5 份示範比對報告：2 高、1 中（含通知草稿）、1 不受影響、1 需確認 |
| `advisory` | `intel-watch` 自動 | 只調查公告影響的資產；版本或條件未知為需確認，只有確認高風險才提高有效燈號 |
| 即時：非 Pipeline 部署 | 筆電執行上方 `gh api` 指令 | RT-001 告警、Issue、圍堵建議 |
| 即時：凌晨大量讀取 | 即時告警頁模擬器 | RT-002 告警（白天排練也能命中；模擬告警與真實告警完全隔離） |
| 即時：多品牌詐騙 | 即時告警頁模擬器 | RT-003 告警，對應 91APP 事件 |
| 修復後 | 依建議修正 Repo ①，再跑 `daily` | 對應攻擊鏈斷開、風險標為已修復；只修部分時其他高風險仍紅 |

`nas`、`insider-path`、`mobile-sdk` 屬 P2，尚未提供輸入資料：網站按鈕標示「P2 未啟用」，手動執行會明確失敗，不會產出看似完成的報告。

### 修復後情境

實際流程：依報告建議在 Repo ① 開 PR 修正（撤銷外洩金鑰、升級或隔離服務、更新快照）→ `pr-gate` 通過後合併 → `ci.yml` 重產 SBOM 與部署紀錄 → 執行 `daily`。判定規則：

- 只有本次資料完整、新鮮且重新評估未再命中，才標為已修復；資料缺失時保留為「需確認」
- Git 歷史仍保留舊金鑰，所以只改 HEAD 不夠：`secrets.json` 必須標記 `revoked` 並附 `revocation_evidence`，否則仍視為有效金鑰
- 有效燈號另外取未結案（open／contained）的真實高風險告警，告警須由管理者附證據結案

`agents/fixtures/after-fix/` 有兩組 overlay 供測試與排練對照：`partial` 只斷開 internal-tool 攻擊鏈（預期仍紅燈），`full` 處理全部高風險與可見度缺口（預期黃燈，中低風險保留）。各自的 `fix.yaml` 說明改了什麼與預期結果。

## 重設 Demo

排練「修復後」之後，以 Repo ① 的 `scripts/reset-demo.sh` 還原（只供手動執行）：

```bash
cd shopsaas-demo-platform
BASELINE_SHA=9a36cf036c436295c08a54d38789029e29d0f9ea scripts/reset-demo.sh
```

`BASELINE_SHA` 是受信任的 baseline commit（與 `agents/fixtures/target-baseline/.fixture.json` 相同）；與 `baseline` tag 不一致時腳本會停止。腳本從最新 `main` 開 `demo-reset-<時間>` 分支、還原受追蹤檔案、顯示 diff，確認後 commit 並開 PR。還原會把假金鑰加回去，`pr-gate` 預期會擋下；請檢查 PR 後依 ruleset 手動授權合併，腳本不會繞過分支保護。合併後再跑一次 `daily`，應回到紅燈。

## 成本

| 模式 | 說明 |
|------|------|
| `replay`（預設） | 不呼叫 LLM，重播已錄製結果或使用程式範本；$0 |
| `record` | 只限本機，實際呼叫 API 並錄製；以 `LOCAL_RECORD_CAP_USD` 限制單次上限 |
| `live` | Workflow 實際呼叫 Claude API。呼叫前先向 `/api/budget` 預留月預算（預設 US$15、保留 10% 緩衝、單筆上限 US$0.5），不足或服務無法連線時改用範本；另在 Anthropic Console 設定每月上限 |

規格估算（Claude API，不含訂閱方案；誤差約 ±50%，以報告中的 `total_cost_usd` 為準）：

| 執行類型 | 估計成本 |
|---------|-----:|
| 每日例行，第一次（無快取） | 約 $0.34 |
| 每日例行，有變化 | 約 $0.15 |
| 公告觸發 | 約 $0.22 |
| 即時告警（圍堵建議） | 約 $0.14 |
| `intel-demo` 第一次 | 約 $0.20 |
| 平常運作 | 每月約 $2～4 |

每日情資使用訂閱方案：每天一次（Sonnet、最多 40 回合、25 分鐘逾時），文章由程式事先抓好，Claude 只做判讀；與個人使用共用額度，不產生 API 費用。新聞來源在 `agents/intel/news_feeds.yaml`，可信網域在 `agents/intel/sources.yaml`。

基礎設施 $0（GitHub Actions、Vercel Hobby、Upstash 免費方案）。即時規則、公告輪詢、掃描、評分與燈號都不用 LLM。各情境的實際成本在部署後執行一次再記錄於此：

| 情境 | 實際成本 |
|------|-----:|
| `daily` | 待部署後記錄 |
| `php2shell` | 待部署後記錄 |
| `peer-incident` | 待部署後記錄 |
| `early-signal` | 待部署後記錄 |
| `intel-demo` | 待部署後記錄 |
| 即時告警圍堵建議 | 待部署後記錄 |

## 安全設計

- 外部內容（新聞、公告、檔案、日誌、Webhook）只當資料，不執行其中的指示
- 本 Repo 不保存任何金鑰值；Repo ① 的假金鑰在凍結副本中一律遮蔽為 `REDACTED`
- Agent 唯讀：不開 PR、不寫入 Repo ①；只有 A5 有 `contents: write`，且只發布允許的路徑
- `NOTIFY_TOKEN`、`GH_TOKEN` 不傳入 LLM 子行程；`CLAUDE_CODE_OAUTH_TOKEN` 只給 claude-code-action 的兩個 Job（`daily-intel`、`claude-analysis`），且只在預設分支的排程與手動 daily；`TARGET_READ_TOKEN` 只用於 checkout 與讀取 Deployments
- `daily-intel` 只有 `contents: read`；文章由程式抓取（safe_fetch：只接受 HTTPS 與允許的網域、限制大小與型態，XML 以 defusedxml 解析），Claude 不抓網頁；PreToolUse hook 限制只能讀 `out/`、`.claude/`，只能寫 `out/intel-daily.json`，拒絕 WebFetch。改到其他檔案或 `news.json` 被改動就不採用結果
- 每日情資的輸出不可信：程式強制為新事件（不能冒充收錄事件或示範事件）、清空自稱的驗證狀態、不採用「已遭利用」等無法驗證的宣稱，並實際抓來源頁面確認引用
- Webhook 驗證 HMAC 簽章、Repo ID 與 delivery 去重；告警結案需管理者密碼、圍堵確認與 HTTPS 證據連結

## 已知限制

- 系統只產出建議，不自動修補；處理狀態以重新評估為準
- 只有「非 Pipeline 部署」接真實 Webhook，其他即時事件以模擬器代替
- 圍堵建議的完成時間取決於 GitHub Actions 排隊，目標約 3 分鐘；GitHub 排程也可能延遲
- 執行層資料是快照；正式導入需串接雲端 API、裝置管理與 SIEM
- 尚未實作：LINE 通知與 App 頁（P2）、`nas`／`insider-path`／`mobile-sdk` 情境（P2）、Neon 趨勢圖（選配）
