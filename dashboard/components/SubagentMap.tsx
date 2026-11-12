// 運作原理頁：「列出全部 Subagent」展開後的總表（資料在 lib/subagents.ts）。

import { AGENT_SUBAGENTS, type AgentInfo } from "@/lib/subagents";

export function SubagentList({ a }: { a: AgentInfo }) {
  return (
    <>
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
    </>
  );
}

function Card({ a }: { a: AgentInfo }) {
  return (
    <section className={`sa-card${a.side ? " side" : ""}`} aria-label={`${a.id} ${a.title}`}>
      <div className="sa-head">
        <span className="sa-id">{a.id}</span> <span>{a.title}</span>
      </div>
      <SubagentList a={a} />
    </section>
  );
}

const ORCHESTRATOR: AgentInfo = { id: "派工", title: "Orchestrator", subs: [], note: "純程式決定要跑哪些 Job，不派 Subagent" };

export default function SubagentMap() {
  const s = AGENT_SUBAGENTS;
  return (
    <div className="sa-map">
      <div className="sa-flow">
        <div className="sa-stage"><Card a={ORCHESTRATOR} /></div>
        <div className="sa-stage"><Card a={s.a0} /></div>
        <div className="sa-stage parallel">
          <div className="sa-par-label">A1～A3 同時進行</div>
          <Card a={s.a1} />
          <Card a={s.a2} />
          <Card a={s.a3} />
        </div>
        <div className="sa-stage"><Card a={s.a4} /></div>
        <div className="sa-stage"><Card a={s.a5} /></div>
      </div>
      <div className="sa-side">
        <Card a={s.daily} />
        <Card a={s.incident} />
      </div>
    </div>
  );
}
