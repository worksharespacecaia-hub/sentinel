import Link from "next/link";
import { getHistory, getReport, listSources, resolveSource } from "@/lib/data";
import { computeSummary } from "@/lib/summary";
import { openAlertsInfo } from "@/lib/alerts";
import { fmtTime, LIGHT_TEXT } from "@/lib/labels";
import { LightBadge, RiskRow, SimNotice, SourceSwitcher } from "@/components/ui";
import { PAGES } from "@/lib/nav";

export const dynamic = "force-dynamic";

const pct = (v: unknown) => (typeof v === "number" ? `${Math.round(v * 100)}%` : "無法計算");

export default async function Overview({ searchParams }: { searchParams: Promise<Record<string, string | string[]>> }) {
  const sp = await searchParams;
  const source = await resolveSource(sp.source);
  const [report, sources, history, summary] = await Promise.all([
    getReport(source), listSources(), getHistory(), computeSummary(await openAlertsInfo()),
  ]);
  if (!report) return <><h1>{PAGES.overview.label}</h1><div className="panel">尚未有評估結果。</div></>;
  const cov = report.coverage as Record<string, any>;
  const top = report.risks.filter((r) => r.status !== "fixed" && r.level === "high").slice(0, 8);
  const intel = report.intel_summary;
  return (
    <>
      <h1>{PAGES.overview.label}</h1>
      <SourceSwitcher current={source.key} sources={sources} path="/" />
      <SimNotice source={source} />
      {!source.simulated && (
        <div className="panel">
          <h2 style={{ marginTop: 0 }}>有效燈號</h2>
          <LightBadge light={summary.light} />
          <ul>{summary.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
          {summary.degraded.length > 0 && <p className="muted">資料狀態：{summary.degraded.join("；")}</p>}
        </div>
      )}
      <div className="grid">
        <div className="panel"><div className="muted">{source.simulated ? "情境燈號" : "每日評估燈號"}</div>
          <LightBadge light={report.light} /><div className="muted">{LIGHT_TEXT[report.light]}</div></div>
        <div className="panel"><div className="muted">高／中／低</div>
          <div className="stat"><span className="lv-high">{report.counts.high}</span> / <span className="lv-medium">{report.counts.medium}</span> / <span className="lv-low">{report.counts.low}</span></div></div>
        <div className="panel"><div className="muted">外部事件</div>
          <div>今日檢查 {intel.checked} 件事件，命中 {intel.affected} 件</div>
          <div className="muted">每日情資：{report.daily_intel_status === "ok" ? "正常" : report.daily_intel_status === "failed" ? "今日新聞情資未更新" : report.daily_intel_status === "replay" ? "重播模式（未搜尋新聞）" : "未執行"}</div></div>
        <div className="panel"><div className="muted">本次執行</div>
          <div>成本 US${report.cost.total_usd.toFixed(2)}；快取命中率 {report.cost.cache_hit_rate == null ? "—" : pct(report.cost.cache_hit_rate)}</div>
          <div className="muted">模式：{report.execution_mode}；評估時間 {fmtTime(report.generated_at)}</div></div>
      </div>
      <div className="panel">
        <h2 style={{ marginTop: 0 }}>CEO 摘要</h2>
        <ol>{report.ceo_summary.map((s, i) => <li key={i}>{s}</li>)}</ol>
        <h2>今日決策事項</h2>
        <ul>{report.decisions.map((d, i) => <li key={i}>{d}</li>)}</ul>
      </div>
      <div className="panel">
        <h2 style={{ marginTop: 0 }}>可見度指標</h2>
        <div className="grid">
          <div>未登記的對外資產：<strong>{cov.unregistered_exposed}</strong>（門檻 0）</div>
          <div>有負責人比例：<strong>{pct(cov.owner_ratio)}</strong>（門檻 90%）</div>
          <div>版本已知比例：<strong>{pct(cov.version_known_ratio)}</strong>（門檻 90%）</div>
          <div>對外且已停止支援：<strong>{cov.eol_exposed}</strong>（門檻 0）</div>
          <div>經 CI/CD 比例：<strong>{pct(cov.ci_ratio)}</strong></div>
          <div>備份驗證比例：<strong>{pct(cov.backup_verified_ratio)}</strong></div>
        </div>
      </div>
      <div className="panel">
        <h2 style={{ marginTop: 0 }}>高風險 <Link className="muted" href={source.simulated ? `/risks?source=${source.key}` : "/risks"}>完整清單</Link></h2>
        <div className="table-wrap"><table><thead><tr><th>等級</th><th>風險</th><th>期限</th><th>狀態</th></tr></thead>
          <tbody>{top.map((r) => <RiskRow key={r.id} r={r} />)}</tbody></table></div>
      </div>
      {!source.simulated && (
        <div className="panel">
          <h2 style={{ marginTop: 0 }}>30 天燈號歷史</h2>
          <div className="chain">{history.map((h) => <span key={h.date} className={`light ${h.light}`} title={h.date}>{h.date.slice(5)}</span>)}</div>
        </div>
      )}
      <div className="panel">
        <h2 style={{ marginTop: 0 }}>手動執行</h2>
        <p>到 <Link href={PAGES.runs.href}>{PAGES.runs.label}</Link> 頁選擇情境並執行，可即時看到每個 Agent 的進度。</p>
      </div>
      {report.data_issues.length > 0 && (
        <div className="panel"><h2 style={{ marginTop: 0 }}>資料狀態</h2>
          <ul>{report.data_issues.map((d, i) => <li key={i}>{d.source}：{d.status}{d.impact ? `（${d.impact}）` : ""}</li>)}</ul></div>
      )}
    </>
  );
}
