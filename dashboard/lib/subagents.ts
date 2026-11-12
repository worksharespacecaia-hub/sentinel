// 運作原理頁用：每個 Agent（GitHub Actions Job）底下派發的 Subagent。
// 名稱對應 agents/registry.py 的 AGENTS 與 .claude/agents/（每日情資）；subagents.test.ts 會比對兩邊是否一致。

export type Sub = { label: string; name: string };
export type AgentKey = "a0" | "a1" | "a2" | "a3" | "a4" | "a5" | "incident" | "daily";
export type AgentInfo = { id: string; title: string; subs: Sub[]; note?: string; side?: boolean };

export const AGENT_SUBAGENTS: Record<AgentKey, AgentInfo> = {
  a0: { id: "A0", title: "盤點系統", subs: [{ label: "辨識不明設備", name: "device-identifier" }] },
  a1: {
    id: "A1", title: "外部情資", subs: [
      { label: "抽取公告重點", name: "advisory-extractor" },
      { label: "SDK 公告關聯", name: "sdk-advisory" },
      { label: "冒用 App 偵測", name: "app-store-monitor" },
      { label: "建議加查（程式核准）", name: "planner" },
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
      { label: "回溯可疑請求", name: "retro-hunter" },
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
    id: "每日情資", title: "Claude Code・訂閱方案", side: true, note: "結果交給 A1：新聞判讀與派工建議", subs: [
      { label: "找同業資安事件", name: "news-scout" },
      { label: "找相關公告與已遭利用漏洞", name: "advisory-scout" },
      { label: "整理攻擊步驟", name: "incident-analyst" },
      { label: "比對我們的技術棧", name: "stack-impact-analyst" },
    ],
  },
};

/** Agent SDK 派發的 Subagent 數（A0～A5 與告警調查；不含每日情資） */
export const SDK_SUBAGENT_COUNT = (Object.keys(AGENT_SUBAGENTS) as AgentKey[])
  .filter((k) => k !== "daily")
  .reduce((n, k) => n + AGENT_SUBAGENTS[k].subs.length, 0);
