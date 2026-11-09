import { getReport, getTrace, listSources, resolveSource } from "@/lib/data";
import { AGENT_TEXT, SOURCE_TEXT, fmtTime } from "@/lib/labels";
import { SimNotice, SourceSwitcher } from "@/components/ui";

export const dynamic = "force-dynamic";

const ORDER = ["orchestrator", "a0", "a1", "a2", "a3", "a4", "a5", "incident"];

export default async function Runs({ searchParams }: { searchParams: Promise<Record<string, string | string[]>> }) {
  const source = await resolveSource((await searchParams).source);
  const [trace, report, sources] = await Promise.all([getTrace(source), getReport(source), listSources()]);
  const byAgent = new Map<string, typeof trace>();
  for (const e of trace) byAgent.set(e.agent, [...(byAgent.get(e.agent) ?? []), e]);
  const owner = process.env.GH_OWNER, repo = process.env.GH_REPO;
  const runUrl = owner && repo && report && /^\d+$/.test(report.run_id) ? `https://github.com/${owner}/${repo}/actions/runs/${report.run_id}` : null;
  const replayed = report?.execution_mode !== "live";
  return (
    <>
      <h1>Agent 執行</h1>
      <SourceSwitcher current={source.key} sources={sources} path="/runs" />
      <SimNotice source={source} />
      <p className="muted">執行 {report?.run_id}（{fmtTime(report?.generated_at)}，模式 {report?.execution_mode}）
        {runUrl && <> ｜ <a href={runUrl} target="_blank" rel="noreferrer">GitHub Actions 執行頁</a></>}</p>
      {replayed && <div className="panel sim">此次為{report?.execution_mode === "replay" ? "重播" : "範本"}模式：Subagent 結果來自錄製或程式範本，並未真的呼叫 Subagent。</div>}
      <div className="panel">
        <ul className="tree">
          {ORDER.filter((a) => byAgent.has(a)).map((agent) => {
            const events = byAgent.get(agent)!;
            const cost = report?.cost.per_agent[agent];
            const subs = events.filter((e) => e.kind === "subagent" || (e.kind === "skip" && e.subagent));
            const tools = events.filter((e) => e.kind === "tool" || e.kind === "skill");
            const result = events.filter((e) => e.kind === "result").at(-1);
            return (
              <li key={agent}>
                <details open>
                  <summary><strong>{AGENT_TEXT[agent] ?? agent}</strong>
                    <span className="muted">（成本 US${(cost ?? 0).toFixed(3)}）{result ? `｜${result.detail}` : ""}</span></summary>
                  <ul>
                    {tools.map((e, i) => <li key={`t${i}`}>{e.kind === "skill" ? "Skill" : "工具"}：{e.detail}</li>)}
                    {subs.map((e, i) => (
                      <li key={`s${i}`}>{e.kind === "skip" ? "跳過" : "Subagent"} {e.subagent}：{e.detail}
                        {e.source && <span className="tag">{SOURCE_TEXT[e.source] ?? e.source}</span>}</li>))}
                    {events.filter((e) => e.kind === "error").map((e, i) => <li key={`e${i}`} className="lv-high">錯誤：{e.detail}</li>)}
                  </ul>
                </details>
              </li>
            );
          })}
        </ul>
      </div>
    </>
  );
}
