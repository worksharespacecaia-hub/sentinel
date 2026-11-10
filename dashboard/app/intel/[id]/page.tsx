import Link from "next/link";
import { notFound } from "next/navigation";
import { getIntelReport, resolveSource } from "@/lib/data";
import { LevelText, SimNotice } from "@/components/ui";
import { SOURCE_TEXT, STATUS_TEXT } from "@/lib/labels";
import { PAGES } from "@/lib/nav";

export const dynamic = "force-dynamic";

const VERDICT: Record<string, string> = { affected: "受影響", not_affected: "不受影響", need_check: "需確認" };

export default async function IntelDetail({ params, searchParams }: {
  params: Promise<{ id: string }>; searchParams: Promise<Record<string, string | string[]>>;
}) {
  const { id } = await params;
  const source = await resolveSource((await searchParams).source);
  const rep = await getIntelReport(source, id);
  if (!rep) notFound();
  const b = rep.blocks;
  const s1 = b["1_summary"];
  const back = source.simulated ? `/intel?source=${encodeURIComponent(source.key)}` : "/intel";
  return (
    <>
      <p><Link href={back}>← 回{PAGES.intel.label}</Link></p>
      <SimNotice source={source} />
      <h1>{s1.title}</h1>
      <p>{[s1.label, s1.confidence, ...s1.cves].map((t: string) => <span key={t} className="tag">{t}</span>)}</p>
      {s1.fixture_note && <div className="panel sim">{s1.fixture_note}</div>}
      <div className="panel"><strong>比對結論：</strong>{b["2_conclusion"].text}</div>

      <div className="panel">
        <h2 style={{ marginTop: 0 }}>事件摘要</h2>
        <p>{s1.summary}</p>
        {s1.summary_note && <p className="muted">{s1.summary_note}</p>}
        <p className="muted">日期 {s1.date}｜產業 {s1.industry ?? "—"}｜ATT&CK {s1.attck.join("、") || "—"}｜摘要來源：{SOURCE_TEXT[rep.summary_source]}</p>
        {s1.attack_chain.length > 0 && <ol>{s1.attack_chain.map((x: string, i: number) => <li key={i}>{x}</li>)}</ol>}
        <h3>來源與原文引用</h3>
        <ul>{s1.sources.map((src: any, i: number) => (
          <li key={i}>{src.url ? <a href={src.url} target="_blank" rel="noreferrer nofollow">{src.title}</a> : src.title}
            {src.quote && <blockquote className="muted">「{src.quote}」</blockquote>}
            <span className="muted">驗證：{src.fetch_status}／{src.verification_basis}</span></li>))}</ul>
      </div>

      {b["3_affected"] && (
        <div className="panel">
          <h2 style={{ marginTop: 0 }}>受影響項目</h2>
          <div className="table-wrap"><table>
            <thead><tr><th>資產</th><th>我們的狀況</th><th>比對依據</th><th>結論</th><th>風險</th></tr></thead>
            <tbody>{b["3_affected"].map((r: any, i: number) => (
              <tr key={i}><td>{r.asset_id}</td><td>{r.our_state}</td><td>{r.basis}</td><td>{VERDICT[r.verdict]}</td>
                <td><LevelText level={r.level} />{r.score != null && `（${r.score} 分）`}</td></tr>))}</tbody>
          </table></div>
          {b["3_affected"].some((r: any) => r.app_impact) && <p className="muted">App 影響為逐品牌、逐版本加總的安裝數（Demo 假設數字），不代表不重複使用者。</p>}
        </div>
      )}

      <div className="panel">
        <h2 style={{ marginTop: 0 }}>不受影響與需確認</h2>
        <ul>
          {b["4_unaffected_and_check"].not_affected.map((r: any, i: number) => <li key={`n${i}`}>{r.asset_id}：{r.our_state}，{r.reason}</li>)}
          {b["4_unaffected_and_check"].need_check.map((r: any, i: number) => <li key={`c${i}`}>需確認：{r.asset_id}：{(r.to_verify ?? []).join("；") || r.reason}</li>)}
          {b["4_unaffected_and_check"].notes.map((n: string, i: number) => <li key={`m${i}`}>{n}</li>)}
        </ul>
      </div>

      {(b["5_solutions"] ?? []).map((sol: any) => (
        <div className="panel" key={sol.risk_id}>
          <h2 style={{ marginTop: 0 }}>可能的解法：{sol.risk_id}</h2>
          <div className="table-wrap"><table>
            <thead><tr><th>選項</th><th>做法</th><th>代價</th><th>時效</th></tr></thead>
            <tbody>{sol.options.map((o: any, i: number) => <tr key={i}><td>{o.name}</td><td>{o.action}</td><td>{o.cost}</td><td>{o.timing}</td></tr>)}</tbody>
          </table></div>
          <p className="muted">建議負責團隊：{sol.suggested_owner ?? "—"}；驗證方式：{sol.verify}。系統只建議，不執行。</p>
        </div>
      ))}

      {b["6_notice"]?.needed && <div className="panel"><h2 style={{ marginTop: 0 }}>建議通知</h2><p>{b["6_notice"].draft}</p></div>}
      <div className="panel"><strong>處理狀態：</strong>{STATUS_TEXT[b["7_status"].status] ?? b["7_status"].label}</div>
    </>
  );
}
