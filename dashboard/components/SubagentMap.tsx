// 運作原理頁：每個 Agent（GitHub Actions Job）底下派發的 Subagent。
// 名稱對應 agents/registry.py 的 AGENTS 與 .claude/agents/（每日情資）；改動那兩處時請一併更新這裡。

type Sub = { label: string; name: string };
type AgentCard = { id: string; title: string; subs: Sub[]; note?: string; variant?: "side" };

const ORCHESTRATOR: AgentCard = { id: "派工", title: "Orchestrator", subs: [], note: "純程式決定要跑哪些 Job，不派 Subagent" };

const A0: AgentCard = { id: "A0", title: "盤點系統", subs: [{ label: "辨識不明設備", name: "device-identifier" }] };

const PARALLEL: AgentCard[] = [
  {
    id: "A1", title: "外部情資", subs: [
      { label: "抽取公告重點", name: "advisory-extractor" },
      { label: "SDK 公告關聯", name: "sdk-advisory" },
      { label: "冒用 App 偵測", name: "app-store-monitor" },
      { label: "建議加查（程式核准）", name: "planner" },
    ],
  },
  {
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
  {
    id: "A3", title: "早期訊號", subs: [
      { label: "客訴詐騙判斷", name: "complaint-classifier" },
      { label: "回溯可疑請求", name: "retro-hunter" },
    ],
  },
];

const A4: AgentCard = { id: "A4", title: "入侵路徑與評分", subs: [{ label: "影響說明（不計分）", name: "impact-analyst" }] };

const A5: AgentCard = {
  id: "A5", title: "報告與建議", subs: [
    { label: "修補建議", name: "remediation-advisor" },
    { label: "金鑰輪替順序", name: "key-rotation-advisor" },
    { label: "品牌商通知", name: "brand-notice-writer" },
    { label: "CEO 摘要", name: "ceo-briefer" },
    { label: "情資比對報告", name: "intel-report-writer" },
  ],
};

const DAILY_INTEL: AgentCard = {
  id: "每日情資", title: "Claude Code・訂閱方案", variant: "side", note: "結果交給 A1：新聞判讀與派工建議", subs: [
    { label: "找同業資安事件", name: "news-scout" },
    { label: "找相關公告與已遭利用漏洞", name: "advisory-scout" },
    { label: "整理攻擊步驟", name: "incident-analyst" },
    { label: "比對我們的技術棧", name: "stack-impact-analyst" },
  ],
};

const INCIDENT: AgentCard = {
  id: "告警調查", title: "由即時告警觸發", variant: "side", subs: [{ label: "圍堵建議（只建議）", name: "containment-advisor" }],
};

function Card({ a }: { a: AgentCard }) {
  return (
    <section className={`sa-card${a.variant ? ` ${a.variant}` : ""}`} aria-label={`${a.id} ${a.title}`}>
      <div className="sa-head">
        <span className="sa-id">{a.id}</span> <span>{a.title}</span>
      </div>
      <div className="sa-count">{a.subs.length ? `${a.subs.length} 個 Subagent` : "沒有 Subagent"}</div>
      {a.subs.length > 0 && (
        <ul className="sa-list">
          {a.subs.map((s) => (
            <li key={s.name}>
              <span>{s.label}</span>
              <code>{s.name}</code>
            </li>
          ))}
        </ul>
      )}
      {a.note && <div className="sa-note">{a.note}</div>}
    </section>
  );
}

export default function SubagentMap() {
  const total = [A0, ...PARALLEL, A4, A5, INCIDENT].reduce((n, a) => n + a.subs.length, 0);
  return (
    <figure className="sa-map">
      <div className="sa-flow">
        <div className="sa-stage"><Card a={ORCHESTRATOR} /></div>
        <div className="sa-stage"><Card a={A0} /></div>
        <div className="sa-stage parallel">
          <div className="sa-par-label">A1～A3 同時進行</div>
          {PARALLEL.map((a) => <Card key={a.id} a={a} />)}
        </div>
        <div className="sa-stage"><Card a={A4} /></div>
        <div className="sa-stage"><Card a={A5} /></div>
      </div>
      <div className="sa-side">
        <Card a={DAILY_INTEL} />
        <Card a={INCIDENT} />
      </div>
      <figcaption className="muted">
        每個 Agent 是一個 GitHub Actions Job，Job 內再派發 Subagent 分工（A0～A5 與告警調查共 {total} 個，由 Agent SDK 派發；
        每日情資的 {DAILY_INTEL.subs.length} 個由 Claude Code 派發）。Subagent 只負責判讀與撰寫說明，不計分、不定燈號。
      </figcaption>
    </figure>
  );
}
