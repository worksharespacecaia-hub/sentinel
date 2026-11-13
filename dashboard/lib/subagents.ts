// 運作原理頁用：每個 Agent（GitHub Actions Job）底下派發的 Subagent。
// 名稱對應 agents/registry.py 的 AGENTS 與 .claude/agents/（每日情資）；subagents.test.ts 會比對兩邊是否一致。
// dispatch、review 是 Orchestrator 的派工與驗收（registry 的 orchestrator-dispatch、orchestrator-review）；
// 開工路由（router）是純程式，不在 registry、不派 Subagent。
// planned：已在 registry 登錄、規格有定義，但還沒有 Agent 派發（尚未實作）；測試會確認標示與程式一致。

export type Sub = { label: string; name: string; planned?: boolean };
export type AgentKey = "dispatch" | "review" | "a0" | "a1" | "a2" | "a3" | "a4" | "a5" | "incident" | "daily";
export type AgentInfo = { id: string; title: string; subs: Sub[]; note?: string; side?: boolean };

export const AGENT_SUBAGENTS: Record<AgentKey, AgentInfo> = {
  dispatch: {
    id: "Orchestrator 派工", title: "AI 提案＋程式核准",
    note: "讀完當天情資與掃描結果後，追加 A2～A4 的任務、排優先；每一項經程式核准，必要任務一定照跑",
    subs: [{ label: "建議追加任務與排優先（程式核准）", name: "planner" }],
  },
  review: {
    id: "Orchestrator 驗收", title: "AI 提案＋程式核准",
    note: "看完 A1～A4 的結果後，追加 A5 的後續任務、寫執行摘要；每一項經程式核准",
    subs: [{ label: "建議後續任務並寫執行摘要（程式核准）", name: "reviewer" }],
  },
  a0: { id: "A0", title: "盤點系統", subs: [{ label: "辨識不明設備", name: "device-identifier" }] },
  a1: {
    id: "A1", title: "外部情資", subs: [
      { label: "抽取公告重點", name: "advisory-extractor" },
      { label: "SDK 公告關聯", name: "sdk-advisory", planned: true },
      { label: "冒用 App 偵測", name: "app-store-monitor", planned: true },
    ],
  },
  a2: {
    id: "A2", title: "弱點掃描", subs: [
      { label: "金鑰外洩判斷", name: "secret-analyst" },
      { label: "套件漏洞", name: "dependency-analyst" },
      { label: "執行環境與支援期限", name: "runtime-analyst" },
      { label: "身分與權杖", name: "identity-analyst" },
      { label: "備份韌性", name: "backup-analyst" },
      { label: "部署合規", name: "compliance-checker" },
      { label: "App 設定檢查", name: "mobile-analyst" },
    ],
  },
  a3: {
    id: "A3", title: "早期訊號", subs: [
      { label: "客訴詐騙判斷", name: "complaint-classifier" },
      { label: "回溯搜查可疑紀錄", name: "retro-hunter" },
    ],
  },
  a4: { id: "A4", title: "入侵路徑與評分", subs: [{ label: "影響說明（不計分）", name: "impact-analyst" }] },
  a5: {
    id: "A5", title: "報告與建議", subs: [
      { label: "修補建議", name: "remediation-advisor" },
      { label: "金鑰輪替順序", name: "key-rotation-advisor" },
      { label: "品牌商通知", name: "brand-notice-writer" },
      { label: "CEO 摘要", name: "ceo-briefer" },
      { label: "情資比對報告", name: "intel-report-writer" },
    ],
  },
  incident: {
    id: "告警調查", title: "由即時告警觸發", side: true, subs: [{ label: "圍堵建議（只建議）", name: "containment-advisor" }],
  },
  daily: {
    id: "每日情資", title: "Claude Code・訂閱方案", side: true, note: "結果交給 A1：判讀當天新聞、推測破口", subs: [
      { label: "找同業資安事件", name: "news-scout" },
      { label: "找相關公告與已遭利用漏洞", name: "advisory-scout" },
      { label: "整理攻擊步驟", name: "incident-analyst" },
      { label: "比對我們的技術棧", name: "stack-impact-analyst" },
    ],
  },
};

/** Agent SDK 派發的 Subagent 數（Orchestrator、A0～A5 與告警調查；不含每日情資） */
export const SDK_SUBAGENT_COUNT = (Object.keys(AGENT_SUBAGENTS) as AgentKey[])
  .filter((k) => k !== "daily")
  .reduce((n, k) => n + AGENT_SUBAGENTS[k].subs.length, 0);

/** 其中尚未實作（planned）的數量 */
export const PLANNED_SUBAGENT_COUNT = Object.values(AGENT_SUBAGENTS)
  .reduce((n, a) => n + a.subs.filter((s) => s.planned).length, 0);
