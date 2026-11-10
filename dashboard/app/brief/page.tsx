// 今日重點：給 CEO 的一頁。只呈現程式已算好的燈號、摘要、決策與前 3 項風險；技術細節留在「工程細節」各頁。
import Link from "next/link";
import { getReport, listSources, resolveSource, type Light } from "@/lib/data";
import { computeSummary } from "@/lib/summary";
import { openAlertsInfo } from "@/lib/alerts";
import { deadlineText, fmtTime } from "@/lib/labels";
import { groupDecisions, riskHeadline, riskTags, topRisks } from "@/lib/brief";
import { PAGES } from "@/lib/nav";
import { SimNotice, SourceSwitcher, TrafficLight } from "@/components/ui";
import ScoringNote from "@/components/ScoringNote";

export const dynamic = "force-dynamic";
export const metadata = { title: `${PAGES.brief.label}｜Sentinel` };

const RANK: Record<Light, number> = { green: 0, yellow: 1, red: 2 };

export default async function Brief({ searchParams }: { searchParams: Promise<Record<string, string | string[]>> }) {
  const source = await resolveSource((await searchParams).source);
  const [report, sources, summary] = await Promise.all([getReport(source), listSources(), computeSummary(await openAlertsInfo())]);
  const q = source.simulated ? `?source=${encodeURIComponent(source.key)}` : "";
  if (!report) return <><h1>{PAGES.brief.label}</h1><div className="panel">尚未有評估結果。</div></>;

  const light = source.simulated ? report.light : summary.light;
  const raised = !source.simulated && RANK[summary.light] > RANK[report.light];
  const unregistered = (report.coverage as Record<string, unknown>).unregistered_exposed;
  const decisions = groupDecisions(report.decisions);
  const top = topRisks(report);

  return (
    <div className="brief">
      <h1 className="sr-only">{PAGES.brief.label}</h1>
      <SimNotice source={source} />
      <section className="panel brief-hero" aria-label="今日燈號">
        <TrafficLight light={light} />
        {raised && <ul className="muted">{summary.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>}
        {!source.simulated && summary.degraded.length > 0 && <p className="warn">資料不足：{summary.degraded.join("；")}</p>}
        {report.daily_intel_status === "failed" && <p className="warn">今日新聞情資未更新，外部事件只含已收錄的事件。</p>}
        <ol className="brief-summary">{report.ceo_summary.map((s, i) => <li key={i}>{s}</li>)}</ol>
      </section>

      <section className="kpis" aria-label="三個重點數字">
        <div className="panel kpi"><div className="num lv-high">{report.counts.high}</div><div>個高風險</div><div className="muted">24 小時內要處理</div></div>
        <div className="panel kpi"><div className="num">{report.intel_summary.affected}<span className="of">／{report.intel_summary.checked}</span></div>
          <div>件外部事件與我們有關</div><div className="muted"><Link href={`${PAGES.report.href}${q}#events`}>看事件與來源 →</Link></div></div>
        <div className="panel kpi"><div className="num">{typeof unregistered === "number" ? unregistered : "—"}</div>
          <div>個系統沒登記就對外開放</div><div className="muted">{typeof unregistered === "number" ? "看不到就管不到" : "無法計算"}</div></div>
      </section>

      <section className="panel">
        <h2>今天要您決定的事</h2>
        {decisions.length ? <ol className="brief-decisions">{decisions.map((d, i) => <li key={i}>{d}</li>)}</ol>
          : <p>今天沒有需要您決定的事項。</p>}
      </section>

      <section className="panel">
        <h2>最需要處理的 {top.length} 件事</h2>
        {top.length === 0 ? <p>目前沒有未處理的高風險。</p> : (
          <ol className="brief-risks">
            {top.map((r) => {
              const h = riskHeadline(r);
              return (
                <li key={r.id} className={`brief-risk ${r.level}`}>
                  <Link href={`${PAGES.report.href}${q}#${encodeURIComponent(r.id)}`}>
                    <strong>{h.headline}</strong>
                    {h.detail && <div className="muted">{h.detail}</div>}
                    <div className="tags">{riskTags(r).map((t) => <span key={t} className="tag">{t}</span>)}</div>
                    {r.solution && <div>建議先做：{r.solution.temporary}</div>}
                    <div className="muted">負責：{r.solution?.suggested_owner ?? "待指派"}｜期限：{deadlineText(r.deadline_hours)}</div>
                  </Link>
                </li>
              );
            })}
          </ol>
        )}
        <p><Link className="button primary" href={`${PAGES.report.href}${q}`}>看完整{PAGES.report.label}／匯出 PDF →</Link></p>
      </section>

      <footer className="brief-footer muted">
        <p>評估時間 {fmtTime(report.generated_at)}｜<ScoringNote scoring={report.scoring} />｜系統只建議、不執行。
          <Link href={`${PAGES.overview.href}${q}`}>看{PAGES.overview.label}</Link></p>
        <SourceSwitcher current={source.key} sources={sources} path={PAGES.brief.href} />
      </footer>
    </div>
  );
}
