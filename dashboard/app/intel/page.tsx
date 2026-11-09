import { getIntelIndex, getReport, listSources, resolveSource } from "@/lib/data";
import { SimNotice, SourceSwitcher } from "@/components/ui";
import IntelList from "@/components/IntelList";

export const dynamic = "force-dynamic";

export default async function IntelPage({ searchParams }: { searchParams: Promise<Record<string, string | string[]>> }) {
  const source = await resolveSource((await searchParams).source);
  const [events, sources, report] = await Promise.all([getIntelIndex(source), listSources(), getReport(source)]);
  const q = source.simulated ? `?source=${encodeURIComponent(source.key)}` : "";
  return (
    <>
      <h1>情資比對</h1>
      <SourceSwitcher current={source.key} sources={sources} path="/intel" />
      <SimNotice source={source} />
      <p>今日檢查 {report?.intel_summary.checked ?? events.length} 件事件，命中 {report?.intel_summary.affected ?? 0} 件。
        不受影響的事件也有報告，說明為什麼與我們無關。</p>
      <div className="panel"><IntelList events={events} sourceQuery={q} /></div>
    </>
  );
}
