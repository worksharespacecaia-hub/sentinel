// 燈號權重狀態：讓看報告的人知道燈號是不是用調整過的權重算出來的。
import Link from "next/link";
import type { ScoringInfo } from "@/lib/data";
import { fmtTime } from "@/lib/labels";
import { PAGES } from "@/lib/nav";

export default function ScoringNote({ scoring }: { scoring?: ScoringInfo }) {
  if (!scoring || scoring.is_default) return <Link href={PAGES.weights.href}>燈號權重：預設</Link>;
  const who = scoring.updated_by ? `，${scoring.updated_by}` : "";
  return <Link href={PAGES.weights.href} className="warn">燈號權重：已調整（{fmtTime(scoring.updated_at)}{who}）</Link>;
}
