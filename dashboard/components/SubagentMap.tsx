// 運作原理頁：「列出全部 Subagent」展開後的總表（資料在 lib/subagents.ts）。

import { AGENT_SUBAGENTS, type AgentInfo } from "@/lib/subagents";

export function SubagentList({ a }: { a: AgentInfo }) {
  const planned = a.subs.filter((s) => s.planned).length;
  return (
    <>
      <div className="sa-count">
        {a.subs.length ? `${a.subs.length} 個 Subagent${planned ? `（${planned} 個尚未實作）` : ""}` : "沒有 Subagent"}
      </div>
      {a.subs.length > 0 && (
        <ul className="sa-list">
          {a.subs.map((s) => (
            <li key={s.name} className={s.planned ? "planned" : undefined}>
              <span>{s.label}</span>
              <code>{s.name}</code>
              {s.planned && <span className="sa-tag">尚未實作</span>}
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

const ORCHESTRATOR: AgentInfo = { id: "路由", title: "開工路由", subs: [], note: "純程式依觸發來源決定流程，不派 Subagent" };

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
