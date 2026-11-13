import Link from "next/link";
import { getReport, getTrace, listSources, resolveSource } from "@/lib/data";
import { AGENT_TEXT, SOURCE_TEXT, TRACE_ORDER, fmtTime } from "@/lib/labels";
import { SimNotice, SourceSwitcher } from "@/components/ui";
import RunConsole from "@/components/RunConsole";
import { PAGES } from "@/lib/nav";
import {
  PLAN_SOURCE_TEXT, approvedLines, normalizePlans, planSummary, rejectedLines, resultRows,
  type AgentPlan, type Names, type ResultRow,
} from "@/lib/agentplan";

export const dynamic = "force-dynamic";

type Mode = "dispatch" | "review";

// Orchestrator 的兩份計畫（specs/orchestrator R5.8、R9.2）：AI 提案、程式核准；核准與拒絕明細都看得到（R10 第 5 頁）
const PLAN_TITLE: Record<Mode, string> = { dispatch: "Orchestrator 派工", review: "Orchestrator 驗收" };
const PLAN_INTRO: Record<Mode, string> = {
  dispatch: "讀完當天情資與掃描結果後，AI 只能建議追加的檢查、任務與說明順序，由程式逐項核准；必要任務一定照跑，不影響分數、燈號與結論。",
  review: "看完 A1～A4 的結果後，AI 只能建議 A5 追加的後續任務與說明順序，並寫執行摘要；每一項由程式核准，不影響分數、燈號與結論。",
};
const PLAN_MISSING: Record<Mode, string> = {
  dispatch: "本次沒有有效的派工單（AI 沒有提案、處理失敗或核對不符），A2～A4 只跑必要任務；原因見下方執行紀錄。",
  review: "本次沒有有效的驗收單（AI 沒有提案、處理失敗或核對不符），A5 只跑必要任務，報告照常產生；原因見下方執行紀錄。",
};
const LEGACY_NOTE = "這份報告產生於 Orchestrator 上線前：由每日情資提出追加建議、A1 以程式逐項核准。";

function PlanPanel({ mode, plan, legacy, names }: { mode: Mode; plan: AgentPlan | null; legacy: boolean; names: Names }) {
  const ok = plan ? approvedLines(plan, names.events ?? {}, names.risks) : [];
  const no = plan ? rejectedLines(plan, names.events ?? {}, names.risks) : [];
  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>{legacy ? "動態派工（舊版）" : PLAN_TITLE[mode]}</h3>
      {!plan ? <p className="muted" style={{ marginBottom: 0 }}>{PLAN_MISSING[mode]}</p> : <>
        <p><strong>{planSummary(plan)}</strong></p>
        <p className="muted">{legacy ? "AI 只能建議追加的檢查與說明，由程式逐項核准；不會跳過任何評估，也不影響分數、燈號與結論。" : PLAN_INTRO[mode]}</p>
        {legacy && <p className="muted">{LEGACY_NOTE}</p>}
        {mode === "review" && plan.summary && (
          <>
            <h4>執行摘要 <span className="tag">AI 撰寫（{PLAN_SOURCE_TEXT[plan.source] ?? "未知來源"}）</span></h4>
            <p>{plan.summary}</p>
            <p className="muted">給工程團隊的執行摘要，經程式檢查不含金鑰、個資、檔案路徑等內容；只是說明，不影響分數、燈號與結論。</p>
          </>
        )}
        {plan.note && <p className="muted">備註：{plan.note}</p>}
        {(ok.length > 0 || no.length > 0) && (
          <details>
            <summary>查看核准與拒絕明細（核准 {ok.length}、拒絕 {no.length}）</summary>
            {ok.length > 0 && <><h4>核准（{ok.length}）</h4><ul>{ok.map((t, i) => <li key={`a${i}`}>{t}</li>)}</ul></>}
            {no.length > 0 && <><h4>拒絕（{no.length}）</h4><ul>{no.map((t, i) => <li key={`r${i}`}>{t}</li>)}</ul></>}
          </details>
        )}
      </>}
    </div>
  );
}

/** 追加結果的對象：事件連到情資明細頁（只連本次報告有的事件），風險只顯示名稱。 */
function Target({ r, names, query }: { r: ResultRow; names: Names; query: string }) {
  if (r.targetType === "event" && names.events?.[r.targetId]) {
    return <Link href={`/intel/${encodeURIComponent(r.targetId)}${query}`}>{r.target}</Link>;
  }
  return <>{r.target}</>;
}

export default async function Runs({ searchParams }: { searchParams: Promise<Record<string, string | string[]>> }) {
  const source = await resolveSource((await searchParams).source);
  const [trace, report, sources] = await Promise.all([getTrace(source), getReport(source), listSources()]);
  const byAgent = new Map<string, typeof trace>();
  for (const e of trace) byAgent.set(e.agent, [...(byAgent.get(e.agent) ?? []), e]);
  const owner = process.env.GH_OWNER, repo = process.env.GH_REPO;
  const runUrl = owner && repo && report && /^\d+$/.test(report.run_id) ? `https://github.com/${owner}/${repo}/actions/runs/${report.run_id}` : null;
  const replayed = report?.execution_mode !== "live";
  const plans = normalizePlans(report?.agent_plan);
  const names: Names = {
    events: Object.fromEntries((report?.events ?? []).map((e) => [e.id, e.title])),
    risks: Object.fromEntries((report?.risks ?? []).map((r) => [r.id, r.title])),
  };
  const { extra, notices } = resultRows(report?.orchestrator_results, names);
  const query = source.simulated ? `?source=${encodeURIComponent(source.key)}` : "";
  // 計畫有效，或本次有派工／驗收的執行紀錄時才顯示面板（舊報告沒有這兩個 Job，不出現空框）
  const showDispatch = plans.dispatch !== null || byAgent.has("orchestrator-dispatch");
  const showReview = plans.review !== null || byAgent.has("orchestrator-review");
  const subscribed = (agent: string) => agent === "daily-intel" || agent === "claude-analysis"
    || (agent === "orchestrator-dispatch" && plans.dispatch?.source === "subscription")
    || (agent === "orchestrator-review" && plans.review?.source === "subscription");
  const orchSubscription = !plans.legacy && (plans.dispatch?.source === "subscription" || plans.review?.source === "subscription");
  return (
    <>
      <h1>{PAGES.runs.label}</h1>
      <div className="panel">
        <h2 style={{ marginTop: 0 }}>執行 Agent 流程</h2>
        <p className="muted">選擇情境後送出，網站會派發 GitHub Actions，並在這裡即時顯示每個 Agent 的進度；點 Agent 可開啟該 Job 的執行紀錄。
          網站觸發使用伺服器設定的執行模式（預設重播，不花 API 費用），不使用訂閱方案；每小時最多一次。</p>
        <RunConsole />
      </div>
      <h2>執行紀錄</h2>
      <SourceSwitcher current={source.key} sources={sources} path="/runs" />
      <SimNotice source={source} />
      <p className="muted">執行 {report?.run_id}（{fmtTime(report?.generated_at)}，模式 {report?.execution_mode}）
        {runUrl && <> ｜ <a href={runUrl} target="_blank" rel="noreferrer">GitHub Actions 執行頁</a></>}</p>
      {replayed && <div className="panel sim">
        A0～A5 為{report?.execution_mode === "replay" ? "重播" : "範本"}模式：分析 Agent 的 Subagent 結果來自錄製或程式範本，沒有呼叫 Claude API（不花 API 費用）；
        版本比對、評分、攻擊鏈與燈號仍由程式實際計算。
        {report?.daily_intel_status === "ok" && <> 每日情資則由程式抓取今日資安新聞、Claude（訂閱方案）實際判讀（狀態：正常）。</>}
        {report?.daily_intel_status === "failed" && <> 每日情資本次未成功（今日新聞情資未更新）。</>}
        {orchSubscription && <> Orchestrator 的派工與驗收由 Claude（訂閱方案）實際提案、程式核准。</>}
      </div>}
      {showDispatch && <PlanPanel mode="dispatch" plan={plans.dispatch} legacy={plans.legacy} names={names} />}
      {showReview && <PlanPanel mode="review" plan={plans.review} legacy={false} names={names} />}
      {(extra.length > 0 || notices.length > 0) && (
        <div className="panel">
          <h3 style={{ marginTop: 0 }}>Orchestrator 追加結果</h3>
          <p className="muted">派工與驗收核准的追加任務寫出的說明，只補充說明，不影響分數、燈號與結論。
            標「程式範本」的是 AI 沒有寫出時的通用文字，列在 AI 撰寫的項目之後。</p>
          {extra.length > 0 && (
            <ul>{extra.map((r, i) => (
              <li key={`x${i}`}><span className="tag">{r.stage}</span>{r.label}：<Target r={r} names={names} query={query} />
                <span className="tag">{r.source}</span>
                <div>{r.text}</div></li>))}</ul>
          )}
          {notices.length > 0 && (
            <>
              <h4>AI 建議的通知草稿（程式未要求）</h4>
              <p className="muted">程式沒有要求這些事件發通知，草稿另外列出、不改變是否需要通知；發送前請人工確認。</p>
              <ul>{notices.map((r, i) => (
                <li key={`n${i}`}><Target r={r} names={names} query={query} /> <span className="tag">{r.source}</span>
                  <div>{r.text}</div></li>))}</ul>
            </>
          )}
        </div>
      )}
      <div className="panel">
        <ul className="tree">
          {TRACE_ORDER.filter((a) => byAgent.has(a)).map((agent) => {
            const events = byAgent.get(agent)!;
            const cost = report?.cost.per_agent[agent];
            const subs = events.filter((e) => e.kind === "subagent" || (e.kind === "skip" && e.subagent));
            const tools = events.filter((e) => e.kind === "tool" || e.kind === "skill");
            const result = events.filter((e) => e.kind === "result").at(-1);
            return (
              <li key={agent}>
                <details open>
                  <summary><strong>{AGENT_TEXT[agent] ?? agent}</strong>
                    <span className="muted">{subscribed(agent) ? "（訂閱方案，不計 API 費用）" : `（成本 US$${(cost ?? 0).toFixed(3)}）`}
                      {result ? `｜${result.detail}` : ""}</span></summary>
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
