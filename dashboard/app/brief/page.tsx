// 今日重點：給 CEO 的一頁。只呈現程式已算好的燈號、摘要、前 3 項風險與決策；技術細節留在「工程細節」各頁。
// 順序：燈號與摘要 → 最需要處理的 3 件事 → 三個數字 → 今天要決定的事（最急的事放在第一屏）。
import Link from "next/link";
import { getReport, listSources, resolveSource, type Light } from "@/lib/data";
import { computeSummary } from "@/lib/summary";
import { openAlertsInfo } from "@/lib/alerts";
import { LEVEL_TEXT, deadlineText, fmtTime } from "@/lib/labels";
import { assetLabel, groupDecisions, ifIgnored, riskBrand, riskDetail, riskHeadline, riskTags, splitDecision, summaryFacts, topRisks } from "@/lib/brief";
import SummaryText from "@/components/SummaryText";
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
  const unregisteredIds = ((report.coverage as Record<string, unknown>).unregistered_exposed_ids as string[] | undefined) ?? [];
  const decisions = groupDecisions(report.decisions).map(splitDecision);    // 先合併舊句型，再切出「不決定的話」
  const top = topRisks(report);
  const facts = summaryFacts(report);
  const labels = report.asset_labels;                                     // 系統白話名稱；舊報告沒有時退回系統 ID
  const base = `${PAGES.report.href}${q}`;

  return (
    <div className="brief">
      <h1 className="sr-only">{PAGES.brief.label}</h1>
      <SimNotice source={source} />
      <section className="panel brief-hero" aria-label="今日燈號">
        <TrafficLight light={light} />
        {raised && <ul className="muted">{summary.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>}
        {!source.simulated && summary.degraded.length > 0 && <p className="warn">資料不足：{summary.degraded.join("；")}</p>}
        {report.daily_intel_status === "failed" && <p className="warn">今日新聞情資未更新，外部事件只含已收錄的事件。</p>}
        <ol className="brief-summary">{report.ceo_summary.map((s, i) => <li key={i}><SummaryText text={s} facts={facts} base={base} labels={labels} /></li>)}</ol>
        <p className="muted">點底線數字可看是哪幾項。</p>
      </section>

      <section className="panel">
        <h2>最需要處理的 {top.length} 件事</h2>
        {top.length === 0 ? <p>目前沒有未處理的高風險。</p> : (
          <ol className="brief-risks">
            {top.map((r) => {
              // 卡片本身不是連結（收合區塊不能放在連結裡）；到行動報告的連結放在收合區塊內
              const h = riskHeadline(r, labels);
              const brand = riskBrand(r, report.events);
              const tags = riskTags(r, { labels, events: report.events, brand });
              const ignored = ifIgnored(r);
              const d = riskDetail(r, report);
              return (
                <li key={r.id} className={`brief-risk ${r.level}`}>
                  <strong>{brand && <span className="brand">{brand} 事件同款破口</span>}{h.headline}</strong>
                  {tags.length > 0 && <div className="tags">{tags.map((t) => <span key={t} className="tag">{t}</span>)}</div>}
                  {ignored && <div className="if-ignored"><b>不處理的話：</b>{ignored}</div>}
                  {r.solution && <div>今天先做：{r.solution.temporary}</div>}
                  <div className="muted">負責：{r.solution?.suggested_owner ?? "待指派"}｜期限：{deadlineText(r.deadline_hours)}</div>
                  <details className="risk-more">
                    <summary>看細節與漏洞原因</summary>
                    <dl>
                      <dt>漏洞原因</dt>{d.cause.map((c, i) => <dd key={i}>{c}</dd>)}
                      <dt>會怎麼被入侵</dt><dd>{d.path ? d.path.join(" → ") : "系統沒有找到可以一路串到其他系統的路徑。"}</dd>
                      {d.events.length > 0 && <><dt>相關事件</dt><dd>{d.events.map((e, i) => (
                        <span key={i}>{i > 0 && "；"}{e.demo && <span className="tag">示範</span>}{e.title}</span>))}</dd></>}
                      {d.permanent && <><dt>根本解法</dt><dd>{d.permanent}</dd></>}
                      <dt>風險分數</dt>
                      <dd>{r.score} 分（{LEVEL_TEXT[r.level]}）｜<Link href={`${base}#${encodeURIComponent(r.id)}`}>到{PAGES.report.label}看完整內容與追蹤進度 →</Link></dd>
                    </dl>
                  </details>
                </li>
              );
            })}
          </ol>
        )}
        <p><Link className="button primary" href={base}>看完整{PAGES.report.label}／匯出 PDF →</Link></p>
      </section>

      <section className="kpis" aria-label="三個重點數字">
        <div className="panel kpi"><div className="num lv-high">{report.counts.high}</div><div>個高風險</div>
          <div className="muted">24 小時內要處理，拖越久越可能被入侵｜<Link href={`${base}#fact-high`}>看是哪些 →</Link></div></div>
        <div className="panel kpi"><div className="num">{report.intel_summary.affected}<span className="of">／{report.intel_summary.checked}</span></div>
          <div>件別人出的事，我們也有同樣的問題</div><div className="muted"><Link href={`${base}#events`}>看事件與來源 →</Link></div></div>
        <div className="panel kpi"><div className="num">{typeof unregistered === "number" ? unregistered : "—"}</div>
          <div>個系統沒登記就對外開放</div><div className="muted">{typeof unregistered === "number"
            ? (unregisteredIds.length ? `${unregisteredIds.map((id) => assetLabel(labels, id)).join("、")}。負責人尚未確認，出事可能沒人發現`
              : "看不到就管不到") : "無法計算"}</div></div>
      </section>

      <section className="panel">
        <h2>今天要您決定的事</h2>
        {decisions.length ? <ol className="brief-decisions">{decisions.map((d, i) => (
          <li key={i}><SummaryText text={d.question} facts={facts} base={base} labels={labels} />
            {d.ifNot && <div className="if-ignored"><b>不決定的話：</b><SummaryText text={d.ifNot} facts={facts} base={base} labels={labels} /></div>}</li>
        ))}</ol>
          : <p>今天沒有需要您決定的事項。</p>}
      </section>

      <footer className="brief-footer muted">
        <p>評估時間 {fmtTime(report.generated_at)}｜<ScoringNote scoring={report.scoring} />｜系統只建議、不執行。
          <Link href={`${PAGES.overview.href}${q}`}>看{PAGES.overview.label}</Link></p>
        <SourceSwitcher current={source.key} sources={sources} path={PAGES.brief.href} />
      </footer>
    </div>
  );
}
