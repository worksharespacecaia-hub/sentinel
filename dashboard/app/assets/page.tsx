import { getReport, listSources, resolveSource } from "@/lib/data";
import { SimNotice, SourceSwitcher } from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function Assets({ searchParams }: { searchParams: Promise<Record<string, string | string[]>> }) {
  const source = await resolveSource((await searchParams).source);
  const [report, sources] = await Promise.all([getReport(source), listSources()]);
  const rows = [...(report?.reconcile ?? [])].sort((a, b) => Number(a.conclusion === "normal") - Number(b.conclusion === "normal"));
  const eol = ((report?.coverage as any)?.eol_exposed_items ?? []) as { asset_id: string; component: string; version: string; eol_date: string }[];
  return (
    <>
      <h1>資產</h1>
      <SourceSwitcher current={source.key} sources={sources} path="/assets" />
      <SimNotice source={source} />
      <p className="muted">清冊 vs 實際觀察（runtime、內網、外部、MDM、付款、SSO）。盲點通常是「沒人知道它存在」。</p>
      {eol.length > 0 && <div className="panel"><strong>對外且已停止支援：</strong>{eol.map((e) => `${e.asset_id}（${e.component} ${e.version}，${e.eol_date} 停止支援）`).join("、")}</div>}
      <div className="panel table-wrap"><table>
        <thead><tr><th>資產</th><th>類型</th><th>清冊</th><th>實際觀察</th><th>結論</th><th>依據</th></tr></thead>
        <tbody>{rows.map((r) => (
          <tr key={r.asset_id}>
            <td>{r.asset_id}<div className="muted">{r.owner ?? "無負責人"}</div></td>
            <td>{r.type}</td>
            <td>{r.registered ? "有" : "無"}</td>
            <td>{r.observed ? r.observed_sources.join("、") : "無"}</td>
            <td className={r.level_floor === "high" ? "lv-high" : r.level_floor === "medium" ? "lv-medium" : ""}>{r.label}</td>
            <td className="muted">{r.reason}</td>
          </tr>))}
        </tbody>
      </table></div>
    </>
  );
}
