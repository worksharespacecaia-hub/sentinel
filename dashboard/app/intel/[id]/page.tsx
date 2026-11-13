import Link from "next/link";
import { notFound } from "next/navigation";
import { getIntelReport, resolveSource } from "@/lib/data";
import { LevelText, SimNotice } from "@/components/ui";
import { SOURCE_TEXT, STATUS_TEXT } from "@/lib/labels";
import { PAGES } from "@/lib/nav";
import { extraCheckRows, noticeExtra, resultRows, reviewSummarySource } from "@/lib/agentplan";

export const dynamic = "force-dynamic";

const VERDICT: Record<string, string> = { affected: "受影響", not_affected: "不受影響", need_check: "需確認" };
/**
 * 來源欄（specs/check-hints-ai R5.2）：AI 推測；規則推測（source=rule 且 inferred=true）；
 * 依原因與通用建議（source=rule、非推測）為「程式」。source 不認得時顯示「—」，不替它宣稱來源。
 */
function hintSourceText(source: string | null, inferred: boolean): string {
  if (source === "ai") return "AI 推測";
  if (source === "rule") return inferred ? "規則推測" : "程式";
  return "—";
}

interface HintRow { hypothesis: string; check: string; systems: string; how: string; controls: string; basis: string; source: string; inferred: boolean }

const txt = (x: unknown): string | null => (typeof x === "string" && x.trim() ? x : null);
const objs = (x: unknown): Record<string, unknown>[] =>
  Array.isArray(x) ? x.filter((v): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v)) : [];

/** 需確認項目的查核建議（specs/check-hints R5.1）：只當文字顯示，不產生連結；格式不符的欄位顯示「—」。 */
function hintRows(raw: unknown): HintRow[] {
  return objs(raw).map((s) => {
    const systems = objs(s.systems).map((x) => txt(x.label) ?? txt(x.asset_id)).filter((x): x is string => x !== null);
    const controls = objs(s.controls).map((c) => `${txt(c.title) ?? txt(c.control_id) ?? "—"}：${txt(c.status_label) ?? "資料不足"}`);
    const source = txt(s.source);
    const inferred = s.inferred === true;
    return {
      hypothesis: txt(s.hypothesis) ?? "—",
      check: txt(s.check) ?? "—",
      systems: systems.length ? systems.join("、") : source === "rule" && txt(s.target) ? "盤點中沒有對應系統" : "—",
      how: txt(s.how) ?? "—",
      controls: controls.length ? controls.join("；") : "—",
      basis: txt(s.basis) ?? "—",
      source: hintSourceText(source, inferred),
      inferred,
    };
  });
}

function HintTable({ raw }: { raw: unknown }) {
  const rows = hintRows(raw);
  if (rows.length === 0) return null;
  return (
    <>
      {rows.some((r) => r.inferred) && <p className="muted check-hints-note">以下為推測，非來源事實，供人工查核</p>}
      <div className="table-wrap"><table>
        <thead><tr><th>可能破口</th><th>我們要查什麼</th><th>相關系統</th><th>怎麼查</th><th>相關控制項結果</th><th>依據</th><th>來源</th></tr></thead>
        <tbody>{rows.map((r, i) => (
          <tr key={i}><td>{r.hypothesis}</td><td>{r.check}</td><td>{r.systems}</td><td>{r.how}</td><td>{r.controls}</td>
            <td>{r.basis}</td><td>{r.source === "AI 推測" ? <span className="tag">{r.source}</span> : r.source}</td></tr>))}</tbody>
      </table></div>
    </>
  );
}

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
  const runs = `/runs${source.simulated ? `?source=${encodeURIComponent(source.key)}` : ""}`;
  // Orchestrator 追加結果（specs/orchestrator R5.8）：只含 target 為這件事件的項目；通知草稿不在這裡重複列出，另外顯示
  const { extra } = resultRows(rep.orchestrator_results);
  const draftExtra = noticeExtra(b["6_notice"]);
  return (
    <>
      <p><Link href={back}>← 回{PAGES.intel.label}</Link></p>
      <SimNotice source={source} />
      <h1>{s1.title}</h1>
      <p>{[s1.label, s1.confidence, ...s1.cves].map((t: string) => <span key={t} className="tag">{t}</span>)}</p>
      {s1.fixture_note && <div className="panel sim">{s1.fixture_note}</div>}
      <div className="panel"><strong>比對結論：</strong>{b["2_conclusion"].text}</div>
      {rep.update_of && (
        <div className="panel">
          這是 <Link href={`/intel/${encodeURIComponent(rep.update_of.id)}${source.simulated ? `?source=${encodeURIComponent(source.key)}` : ""}`}>{rep.update_of.title ?? rep.update_of.id}</Link> 的新進度；比對時沿用原事件的產品、利用條件與控制項。
        </div>
      )}
      {(rep.updates ?? []).length > 0 && (
        <div className="panel">
          <h2 style={{ marginTop: 0 }}>事件進度</h2>
          <ul>{rep.updates.map((u: any) => (
            <li key={u.id}>{u.date}{" "}
              <Link href={`/intel/${encodeURIComponent(u.id)}${source.simulated ? `?source=${encodeURIComponent(source.key)}` : ""}`}>{u.title}</Link>
              （{STATUS_TEXT[u.status] ?? u.status}）：{u.conclusion}</li>))}</ul>
        </div>
      )}

      <div className="panel">
        <h2 style={{ marginTop: 0 }}>事件摘要</h2>
        <p>{s1.summary}</p>
        {s1.summary_note && <p className="muted">{s1.summary_note}</p>}
        <p className="muted">日期 {s1.date}｜產業 {s1.industry ?? "—"}｜ATT&CK {s1.attck.join("、") || "—"}｜摘要來源：{reviewSummarySource(rep.status, rep.summary_source) ?? SOURCE_TEXT[rep.summary_source]}</p>
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
          {b["4_unaffected_and_check"].need_check.map((r: any, i: number) => (
            <li key={`c${i}`}>需確認：{r.asset_id}：{(r.to_verify ?? []).join("；") || r.reason}
              <HintTable raw={r.suggestions} /></li>))}
          {b["4_unaffected_and_check"].notes.map((n: string, i: number) => <li key={`m${i}`}>{n}</li>)}
        </ul>
      </div>

      {extraCheckRows(b["8_extra_checks"]).length > 0 && (
        <div className="panel">
          <h2 style={{ marginTop: 0 }}>AI 建議加查</h2>
          <p className="muted">程式檢查結果，不影響結論與分數。AI 依這件事件建議一併確認的控制項，結果取自本次已算好的檢查。
            <Link href={runs}>查看本次的核准與拒絕明細</Link></p>
          <div className="table-wrap"><table>
            <thead><tr><th>控制項</th><th>檢查結果</th><th>資產</th><th>檢查說明</th><th>建議理由</th></tr></thead>
            <tbody>{extraCheckRows(b["8_extra_checks"]).map((r, i) => (
              <tr key={i}><td>{r.title}</td><td>{r.status}</td><td>{r.assets}</td><td>{r.checkReason}</td><td>{r.suggestedReason}</td></tr>))}</tbody>
          </table></div>
        </div>
      )}

      {extra.length > 0 && (
        <div className="panel">
          <h2 style={{ marginTop: 0 }}>Orchestrator 追加結果</h2>
          <p className="muted">Orchestrator 依這件事件追加的 AI 說明，只補充說明，不影響結論與分數；標「程式範本」的是 AI 沒有寫出時的通用文字。
            <Link href={runs}>查看本次的派工與驗收</Link></p>
          <ul>{extra.map((r, i) => (
            <li key={i}><span className="tag">{r.stage}</span>{r.label} <span className="tag">{r.source}</span>
              <div>{r.text}</div></li>))}</ul>
        </div>
      )}

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
      {draftExtra && (
        <div className="panel">
          <h2 style={{ marginTop: 0 }}>AI 建議的通知草稿（程式未要求）</h2>
          <p>{draftExtra.text}</p>
          <p className="muted"><span className="tag">{draftExtra.source}</span>程式沒有要求這件事件發通知，這是 Orchestrator 驗收追加的草稿，不改變是否需要通知；發送前請人工確認。</p>
        </div>
      )}
      <div className="panel"><strong>處理狀態：</strong>{STATUS_TEXT[b["7_status"].status] ?? b["7_status"].label}</div>
    </>
  );
}
