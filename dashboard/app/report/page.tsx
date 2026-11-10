// 行動報告：彙整所有需要採取行動的結果（決策、風險與建議做法、受影響事件、通知草稿、處理中追蹤）。
// 「匯出 PDF」使用瀏覽器列印（globals.css 的 @media print）；daily 報告可傳送到 LINE、可設定處理中。
import type { Metadata } from "next";
import Link from "next/link";
import { getReport, listSources, resolveSource } from "@/lib/data";
import { KIND_TEXT, LEVEL_TEXT, fmtTime } from "@/lib/labels";
import { TRACK_TEXT } from "@/lib/actions";
import { PAGES } from "@/lib/nav";
import { loadActionReport } from "@/lib/report-data";
import { LevelText, SimNotice, SourceSwitcher, TrafficLight } from "@/components/ui";
import PrintButton from "@/components/PrintButton";
import ScoringNote from "@/components/ScoringNote";
import SendToLine from "@/components/SendToLine";
import TrackForm from "@/components/TrackForm";

export const dynamic = "force-dynamic";

type SP = { searchParams: Promise<Record<string, string | string[]>> };

const taipeiDate = (iso: string) => new Intl.DateTimeFormat("sv-SE", { timeZone: "Asia/Taipei" }).format(new Date(iso));

export async function generateMetadata({ searchParams }: SP): Promise<Metadata> {
  const source = await resolveSource((await searchParams).source);
  const report = await getReport(source);
  const suffix = source.simulated ? `（情境 ${source.key}）` : "";
  // 另存 PDF 時瀏覽器以標題當預設檔名
  return { title: `Sentinel ${PAGES.report.label} ${report ? taipeiDate(report.generated_at) : ""}${suffix}`.trim() };
}

export default async function ReportPage({ searchParams }: SP) {
  const source = await resolveSource((await searchParams).source);
  const [loaded, sources] = await Promise.all([loadActionReport(source), listSources()]);
  if (!loaded) return <><h1>{PAGES.report.label}</h1><div className="panel">尚未有評估結果。</div></>;
  const { report, action, trackingDegraded } = loaded;
  const c = action.counts;

  return (
    <div className="report">
      <div className="report-toolbar no-print">
        <PrintButton />
        {!source.simulated && <SendToLine />}
        <Link href={`${PAGES.brief.href}${source.simulated ? `?source=${encodeURIComponent(source.key)}` : ""}`}>← 回{PAGES.brief.label}</Link>
      </div>

      <header className="report-head">
        <h1>資安{PAGES.report.label}</h1>
        <p className="muted">評估時間 {fmtTime(report.generated_at)}｜資料來源：{source.label}｜列印時間以 PDF 頁首為準</p>
      </header>
      <SimNotice source={source} />

      <section className="panel report-section">
        <TrafficLight light={action.light} />
        <ol className="brief-summary">{action.summary.map((s, i) => <li key={i}>{s}</li>)}</ol>
      </section>

      <section className="panel report-section">
        <h2>今天要決定的事</h2>
        {action.decisions.length ? <ol>{action.decisions.map((d, i) => <li key={i}>{d}</li>)}</ol> : <p>今天沒有需要決定的事項。</p>}
      </section>

      <section className="panel report-section">
        <h2>行動清單：高風險 {c.high} 項、中風險 {c.medium} 項</h2>
        {!source.simulated && (
          <p className="track-summary">處理中 {c.in_progress}｜即將到期 <span className={c.due_soon ? "warn" : undefined}>{c.due_soon}</span>｜
            已逾期 <span className={c.overdue ? "lv-high" : undefined}>{c.overdue}</span>｜高風險尚未有人處理 {c.unassigned_high}</p>
        )}
        {source.simulated && <p className="muted">情境只供排練，不追蹤處理狀態。</p>}
        {trackingDegraded && <p className="warn">{trackingDegraded}：處理狀態無法確認，不代表沒有人在處理。</p>}
        {action.items.length === 0 ? <p>目前沒有未處理的高、中風險。</p> : (
          <ol className="action-list">
            {action.items.map((it) => (
              <li key={it.id} id={it.id} className={`action-item ${it.level} track-${it.track_state}`}>
                <div className="action-title">
                  <span className={`tag lv-${it.level}`}>{LEVEL_TEXT[it.level]}風險</span>
                  {it.need_check && <span className="tag">需確認</span>}
                  <strong>{it.headline}</strong>
                </div>
                {it.detail && <div className="muted">{it.detail}</div>}
                {it.tags.length > 0 && <div className="tags">{it.tags.map((t) => <span key={t} className="tag">{t}</span>)}</div>}
                <dl className="action-fields">
                  <dt>建議先做</dt><dd>{it.temporary ?? "—"}</dd>
                  <dt>根本修復</dt><dd>{it.permanent ?? "—"}</dd>
                  <dt>負責團隊</dt><dd>{it.owner ?? "待指派"}</dd>
                  <dt>建議期限</dt><dd>{it.suggested_due ? fmtTime(it.suggested_due) : "—"}</dd>
                  {!source.simulated && <>
                    <dt>處理狀態</dt>
                    <dd className={`track-state ${it.track_state}`}>
                      {TRACK_TEXT[it.track_state]}
                      {it.tracking && <>｜負責人 {it.tracking.owner}｜期限 {fmtTime(it.tracking.due_at)}{it.tracking.note ? `｜${it.tracking.note}` : ""}</>}
                      {it.beyond_suggested && <span className="warn">｜超過建議期限</span>}
                    </dd>
                  </>}
                </dl>
                {!source.simulated && <TrackForm riskId={it.id} version={it.tracking?.version ?? 0} inProgress={Boolean(it.tracking)}
                  owner={it.tracking?.owner ?? it.owner ?? ""} dueAt={it.tracking?.due_at ?? it.suggested_due} note={it.tracking?.note ?? ""} />}
              </li>
            ))}
          </ol>
        )}
      </section>

      <section className="panel report-section">
        <h2>與我們有關的外部事件：{action.events.length} 件</h2>
        {action.events.length === 0 ? <p>今天沒有與我們有關的外部事件。</p> : (
          <div className="table-wrap"><table>
            <thead><tr><th>事件</th><th>類型</th><th>受影響項目</th><th>最高等級</th></tr></thead>
            <tbody>{action.events.map((e) => (
              <tr key={e.id}>
                <td><Link href={`${PAGES.intel.href}/${encodeURIComponent(e.id)}${source.simulated ? `?source=${encodeURIComponent(source.key)}` : ""}`}>{e.title}</Link></td>
                <td>{KIND_TEXT[e.kind] ?? e.kind}</td><td>{e.affected_count}</td><td><LevelText level={e.max_level} /></td>
              </tr>))}</tbody>
          </table></div>
        )}
      </section>

      {action.notices.length > 0 && (
        <section className="panel report-section">
          <h2>建議通知草稿</h2>
          {action.notices.map((n) => <div key={n.event_id} className="notice"><h3>{n.title}</h3><p>{n.draft}</p></div>)}
        </section>
      )}

      <footer className="report-footer muted">
        <p>系統只產出建議、不執行任何修改；已修復需要下次完整評估確認不再命中。<ScoringNote scoring={report.scoring} /></p>
        {report.data_issues.length > 0 && <p>資料狀態：{report.data_issues.map((d) => `${d.source}：${d.status}${d.impact ? `（${d.impact}）` : ""}`).join("；")}</p>}
        <div className="no-print"><SourceSwitcher current={source.key} sources={sources} path={PAGES.report.href} /></div>
      </footer>
    </div>
  );
}
