"use client";
// 資安事件整理的篩選與列表：依收錄日期分組；新進度縮排在原事件底下；父子事件逐件篩選（R2.6、R2.7）。
// 時間文字已在伺服器端格式化；只顯示白話名稱，不顯示事件或系統的內部 ID（R8.1）。
import Link from "next/link";
import { useMemo, useState } from "react";
import { RELATION_FILTERS, filterDigest, type Card, type DigestSuggestion, type RelationFilter, type ViewDay } from "@/lib/digest";
import { fmtDateHeading } from "@/lib/labels";
import { LevelText } from "@/components/ui";

// 推測區塊標題依來源標示（specs/check-hints-ai R5.1）；mixed 時每條前另外標「AI：」或「規則：」
const HINTS_TITLE: Record<Card["hintsSource"], string> = {
  ai: "可能的破口與先查的地方（AI 推測）",
  rule: "可能的破口與先查的地方（規則推測）",
  mixed: "可能的破口與先查的地方（推測）",
};
const HINT_PREFIX: Record<DigestSuggestion["source"], string> = { ai: "AI：", rule: "規則：" };

export default function DigestList({ days }: { days: ViewDay<Card>[] }) {
  const [filter, setFilter] = useState<RelationFilter>("all");
  const result = useMemo(() => filterDigest(days, filter), [days, filter]);
  const label = RELATION_FILTERS.find((f) => f.key === filter)?.label ?? "";
  return (
    <>
      <div className="digest-filter" role="group" aria-label="依與我們的關係篩選">
        <span className="muted">與我們的關係：</span>
        {RELATION_FILTERS.map((f) => (
          <button key={f.key} type="button" aria-pressed={filter === f.key} onClick={() => setFilter(f.key)}>{f.label}</button>
        ))}
      </div>
      <p className="muted" role="status">{filter === "all" ? `共 ${result.count} 件` : `「${label}」共 ${result.count} 件`}</p>
      {result.days.map((d) => (
        <section key={d.date} className="digest-day">
          <h2>{fmtDateHeading(d.date)}・{d.count} 件</h2>
          <ol className="digest-groups">
            {d.groups.map((g) => (
              <li key={g.head.id}>
                {g.headMatched ? <EventCard c={g.head} />
                  : <div className="digest-marker muted">原事件：{g.head.title}（{g.head.relationText}，不符合目前篩選）</div>}
                {g.updates.length > 0 && (
                  <div className="digest-updates">
                    <div className="muted">新進度 {g.updates.length} 則</div>
                    <ol>{g.updates.map((u) => <li key={u.id}><EventCard c={u} update /></li>)}</ol>
                  </div>
                )}
              </li>
            ))}
          </ol>
        </section>
      ))}
      {result.count === 0 && <p>沒有符合條件的事件。</p>}
    </>
  );
}

function EventCard({ c, update = false }: { c: Card; update?: boolean }) {
  return (
    <article className={`digest-card rel-${c.relation}`}>
      <div className="action-title">
        <span className={`tag rel-${c.relation}`}>{c.relationText}</span>
        {update && <span className="tag">新進度</span>}
        {c.standaloneText && <span className="tag">{c.standaloneText}</span>}
        <strong>{c.title}</strong>
      </div>
      <div className="muted">
        {c.kindText}｜可信度 {c.confidenceText}｜事件日期 {c.eventDate}｜受影響系統 {c.affectedCount} 項｜最高等級 <LevelText level={c.level} />
      </div>
      {c.summary && <p>{c.summary}</p>}
      {c.sources.length === 0 ? <p className="muted">沒有來源紀錄。</p> : (
        <ul className="event-sources">
          {c.sources.map((s, i) => (
            <li key={i}>
              來源：{s.href ? <a href={s.href} target="_blank" rel="noopener noreferrer">{s.title}</a> : s.title}
              {s.domain && <span className="muted">（{s.domain}）</span>}{" "}
              <span className={`tag ${s.verified ? "src-ok" : "src-warn"}`}>{s.verified ? "已驗證" : "未驗證"}</span>
            </li>
          ))}
        </ul>
      )}
      <p className="muted">{c.evaluatedText}{c.relationChangedText && `｜${c.relationChangedText}`}</p>
      {c.detail && (
        <p><Link href={c.detail.href}>查看比對明細</Link>{c.detail.note && <> <span className="muted">{c.detail.note}</span></>}</p>
      )}
      {c.relation === "need_check" && c.suggestions.length > 0 && (
        <div className="digest-hints">
          <strong>{HINTS_TITLE[c.hintsSource]}</strong>
          <ul>{c.suggestions.map((s, i) => <li key={i}>{c.hintsSource === "mixed" && HINT_PREFIX[s.source]}{s.text}</li>)}</ul>
        </div>
      )}
      <details open={!c.detail}>
        <summary>受影響系統與結論（保存的評估結果）</summary>
        <p>{c.conclusion}</p>
        {c.impacts.length > 0 ? (
          <ul>{c.impacts.map((m, i) => (
            <li key={i}>{m.label}{m.count > 1 && `（${m.count} 項）`}：{m.verdictText}
              {m.level && <>，等級 <LevelText level={m.level} /></>}</li>
          ))}</ul>
        ) : <p className="muted">評估結果沒有列出系統。</p>}
        {c.impactsNote && <p className="warn">{c.impactsNote}</p>}
        {c.cves.length > 0 && <p className="muted">CVE：{c.cves.join("、")}</p>}
      </details>
    </article>
  );
}
