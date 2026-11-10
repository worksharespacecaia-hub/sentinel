import { getGraph, getReport, listSources, resolveSource } from "@/lib/data";
import { RiskDetail, SimNotice, SourceSwitcher } from "@/components/ui";
import { PAGES } from "@/lib/nav";

export const dynamic = "force-dynamic";

const LAYERS = ["伺服器端緩解（擋掉攻擊請求、撤銷外洩金鑰、限制舊版可呼叫的 API）— 立即", "遠端設定關閉有問題的功能 — 數分鐘",
  "提高最低支援版本、強制更新 — 新版上架後", "依受影響安裝數排序，分批為各品牌發版 — 數天", "品牌商通知、使用者更新提醒、山寨 App 檢舉下架"];

export default async function AppRisk({ searchParams }: { searchParams: Promise<Record<string, string | string[]>> }) {
  const source = await resolveSource((await searchParams).source);
  const [report, graph, sources] = await Promise.all([getReport(source), getGraph(source), listSources()]);
  const versions = (graph?.nodes ?? []).filter((n: any) => n.type === "app_version") as any[];
  const rows = versions.flatMap((v) => (v.installations ?? []).map((i: any) => ({ version: String(v.id).split("@")[1], ...i })));
  const sdkByVersion = new Map<string, string[]>();
  for (const e of (graph?.edges ?? []) as any[]) if (e.kind === "contains" && String(e.from).startsWith("brand-app@")) {
    sdkByVersion.set(e.from, [...(sdkByVersion.get(e.from) ?? []), String(e.to)]);
  }
  const appRisks = (report?.risks ?? []).filter((r) => ["mobile", "clone_app"].includes(r.category) || r.asset_id === "brand-app" || r.asset_id.startsWith("clone:"));
  const impact = report?.app_impact as Record<string, any> | undefined;
  return (
    <>
      <h1>{PAGES.appRisk.label}</h1>
      <SourceSwitcher current={source.key} sources={sources} path="/app-risk" />
      <SimNotice source={source} />
      <p className="muted">同一套程式碼打包成各品牌 App；修補要經商店審核與使用者更新，舊版會長期留在手機上。安裝數為 Demo 假設數字。</p>
      {impact && impact.affected_installations != null && (
        <div className="panel">受影響：{impact.affected_brands} 個品牌、{Number(impact.affected_installations).toLocaleString()} 個安裝（共 {Number(impact.total_installations).toLocaleString()}）；
          非最新版安裝占 {Math.round((impact.old_version_share ?? 0) * 100)}%。<span className="muted">{impact.note}</span></div>
      )}
      <div className="panel table-wrap">
        <h2 style={{ marginTop: 0 }}>版本分布</h2>
        <table><thead><tr><th>品牌</th><th>平台</th><th>版本</th><th>安裝數</th><th>打包的 SDK</th><th>觀察時間</th></tr></thead>
          <tbody>{rows.map((r, i) => (
            <tr key={i}><td>{r.brand_id}</td><td>{r.platform}</td><td>{r.version}</td><td>{Number(r.active_installations).toLocaleString()}</td>
              <td>{(sdkByVersion.get(`brand-app@${r.version}`) ?? []).join("、")}</td><td className="muted">{r.observed_at?.slice(0, 10)}</td></tr>))}</tbody></table>
      </div>
      <div className="panel"><h2 style={{ marginTop: 0 }}>建議解法分層</h2><ol>{LAYERS.map((l) => <li key={l}>{l}</li>)}</ol></div>
      <h2>App 相關風險</h2>
      {appRisks.map((r) => <RiskDetail key={r.id} r={r} />)}
    </>
  );
}
