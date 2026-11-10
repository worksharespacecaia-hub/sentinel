import { getReport, listSources, resolveSource } from "@/lib/data";
import { RiskDetail, SimNotice, SourceSwitcher } from "@/components/ui";
import { PAGES } from "@/lib/nav";

export const dynamic = "force-dynamic";

export default async function Risks({ searchParams }: { searchParams: Promise<Record<string, string | string[]>> }) {
  const source = await resolveSource((await searchParams).source);
  const [report, sources] = await Promise.all([getReport(source), listSources()]);
  const risks = report?.risks ?? [];
  const groups = [["high", "高風險（24 小時內）"], ["medium", "中風險（7 天內）"], ["low", "低風險（30 天內）"]] as const;
  return (
    <>
      <h1>{PAGES.risks.label}</h1>
      <SourceSwitcher current={source.key} sources={sources} path="/risks" />
      <SimNotice source={source} />
      <p className="muted">每個風險附分數拆解；建議解法只建議、不執行，由工程團隊決定。已修復需要下次完整掃描確認不再命中。</p>
      {groups.map(([lv, title]) => {
        const rows = risks.filter((r) => r.level === lv && r.status !== "fixed");
        return rows.length ? <section key={lv}><h2>{title}：{rows.length} 項</h2>{rows.map((r) => <RiskDetail key={r.id} r={r} />)}</section> : null;
      })}
      {risks.some((r) => r.status === "fixed") && (
        <section><h2>已修復</h2>{risks.filter((r) => r.status === "fixed").map((r) => <RiskDetail key={r.id} r={r} />)}</section>
      )}
    </>
  );
}
