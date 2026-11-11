// 摘要與決策的數字可點：連到行動報告「數字從哪來」的對應項目；滑過顯示包含哪幾項；對不上程式結果的數字標警告。
import { linkSummary, riskHeadline, type Fact, type FactKey } from "@/lib/brief";
import { LEVEL_TEXT } from "@/lib/labels";
import FactLink from "./FactLink";

const TIP_ITEMS = 5;

function tipLines(f: Fact): string[] {
  return [
    ...f.risks.map((r) => `${LEVEL_TEXT[r.level]}｜${riskHeadline(r).headline}`),
    ...f.events.map((e) => e.affected_count > 0 ? `${e.title}（受影響 ${e.affected_count} 項）` : e.title),
  ];
}

export default function SummaryText({ text, facts, base }: { text: string; facts: Record<FactKey, Fact>; base: string }) {
  return (
    <>
      {linkSummary(text, facts).map((p, i) => {
        if (typeof p === "string") return <span key={i}>{p}</span>;
        if (!p.key) return <span key={i} className="fact-bad" title="這個數字對不上程式結果，請以行動報告的清單為準">{p.text}⚠</span>;
        const f = facts[p.key];
        const all = tipLines(f);
        return <FactLink key={i} href={`${base}#fact-${p.key}`} text={p.text} label={f.label}
          lines={all.slice(0, TIP_ITEMS)} more={Math.max(0, all.length - TIP_ITEMS)} />;
      })}
    </>
  );
}
