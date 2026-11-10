// 行動報告「數字從哪來」：摘要與決策裡每個數字對應的風險或事件清單（全部來自程式結果）。
import Link from "next/link";
import type { Fact, FactKey } from "@/lib/brief";
import { riskHeadline } from "@/lib/brief";
import { LEVEL_TEXT } from "@/lib/labels";
import { PAGES } from "@/lib/nav";

const ORDER: FactKey[] = ["high", "medium", "low", "chained", "eol", "shadow_it", "checked", "affected", "real_checked", "real_affected"];

export default function FactSources({ facts, q, actionIds }: { facts: Record<FactKey, Fact>; q: string; actionIds: Set<string> }) {
  return (
    <section className="panel report-section" id="facts">
      <h2>數字從哪來</h2>
      <p className="muted">摘要與決策裡的數字都由程式計算；點數字會跳到這裡，展開即可看到包含哪些項目。</p>
      {ORDER.map((k) => facts[k]).filter((f) => f.count > 0).map((f) => (
        <details key={f.key} id={`fact-${f.key}`} className="fact">
          <summary><strong>{f.count}</strong> {f.label}</summary>
          <ul>
            {f.risks.map((r) => (
              <li key={r.id}>
                <span className={`lv-${r.level}`}>{LEVEL_TEXT[r.level]}</span>｜
                {actionIds.has(r.id) ? <a href={`#${r.id}`}>{riskHeadline(r).headline}</a>
                  : <Link href={`${PAGES.risks.href}${q}`}>{riskHeadline(r).headline}</Link>}
                <span className="muted">（{r.asset_id}，{r.score} 分）</span>
              </li>
            ))}
            {f.events.map((e) => (
              <li key={e.id}>
                {e.affected_count > 0 ? <a href={`#event-${e.id}`}>{e.title}</a>
                  : <Link href={`${PAGES.intel.href}/${encodeURIComponent(e.id)}${q}`}>{e.title}</Link>}
                <span className="muted">（{e.affected_count > 0 ? `受影響 ${e.affected_count} 項` : "與我們無關"}）</span>
              </li>
            ))}
          </ul>
        </details>
      ))}
    </section>
  );
}
