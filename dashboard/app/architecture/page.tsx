import ArchitectureDiagram from "@/components/ArchitectureDiagram";
import { PAGES } from "@/lib/nav";

export default function Architecture() {
  return (
    <>
      <h1>{PAGES.architecture.label}</h1>
      <div className="panel">
        <h2 style={{ marginTop: 0 }}>整體架構</h2>
        <ArchitectureDiagram />
      </div>
      <div className="panel">
        <h2 style={{ marginTop: 0 }}>流程</h2>
        <ol>
          <li>觸發：公告與同業事件（每小時）／每日排程（CI/CD 把關在 PR 階段完成）</li>
          <li>Orchestrator（程式為主）：讀取情境與差異，決定派工</li>
          <li>A0 資產探索與對帳 → 資安知識圖譜</li>
          <li>平行：A1 外部情資（每日情資用訂閱方案）、A2 弱點掃描、A3 早期訊號</li>
          <li>A4 攻擊鏈與風險（圖搜尋＋規則評分）</li>
          <li>A5 報告與建議（燈號、建議解法、CEO 摘要、情資比對報告）→ 發布到網站</li>
        </ol>
        <p>異常行為偵測的告警走獨立的 incident 流程：規則命中 → GitHub Issue → A3 關聯 → A4 從告警資產出發的路徑 → 圍堵建議留言。</p>
      </div>
      <div className="panel">
        <h2 style={{ marginTop: 0 }}>設計理由</h2>
        <ul>
          <li><strong>工具找、程式算、LLM 說明</strong>：評分與攻擊路徑可重現、可稽核；LLM 不判斷版本大小、不自行計分。</li>
          <li><strong>多 Agent 與 Subagent</strong>：每個 Agent 是一個 GitHub Actions Job，Job 圖就是流程圖；每個 Job 內以 Agent SDK 派發 Subagents 與 Skills。</li>
          <li><strong>攻擊鏈推演</strong>：單一弱點可能只是中風險，串起來才是高風險。</li>
          <li><strong>四種觸發時機</strong>：掃描只在變動時做，比對隨時做，全面評估每天做，已出事的異常行為即時偵測、告警。</li>
          <li><strong>只讀、只建議</strong>：系統不持有能修改受評估系統的權杖，Agent 本身不能成為新破口。</li>
          <li><strong>多來源對帳與可見度指標</strong>：看不到的地方燈號再綠也沒意義。</li>
          <li><strong>不受影響也出報告</strong>：每天說明哪些事件與我們無關及原因。</li>
          <li><strong>示範事件明確標示</strong>：虛構事件一律以「示範：」開頭，不冒用真實公司。</li>
        </ul>
      </div>
    </>
  );
}
