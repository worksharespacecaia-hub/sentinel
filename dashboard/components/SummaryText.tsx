// 摘要與決策的數字可點：連到行動報告「數字從哪來」的對應項目；對不上程式結果的數字標警告。
import { linkSummary, type Fact, type FactKey } from "@/lib/brief";

export default function SummaryText({ text, facts, base }: { text: string; facts: Record<FactKey, Fact>; base: string }) {
  return (
    <>
      {linkSummary(text, facts).map((p, i) => typeof p === "string" ? <span key={i}>{p}</span>
        : p.key ? <a key={i} className="fact-link" href={`${base}#fact-${p.key}`} title={`看這 ${p.text}是哪些`}>{p.text}</a>
          : <span key={i} className="fact-bad" title="這個數字對不上程式結果，請以行動報告的清單為準">{p.text}⚠</span>)}
    </>
  );
}
