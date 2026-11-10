// 今日重點與行動報告共用的白話呈現（純函式，不讀檔）。只改呈現方式，不改分數、等級與燈號。
import type { Report, Risk } from "./data";

const ADOPT_RE = /^(.+?) 要納管還是除役$/;

/**
 * 把多條「X 要納管還是除役」合併成一條，放在第一條出現的位置；其他決策原樣保留。
 * 新版 A5 範本已直接輸出合併後的句子（不會再被比對到），所以重複呼叫結果不變。
 */
export function groupDecisions(list: readonly string[]): string[] {
  const assets = list.map((d) => ADOPT_RE.exec(d)?.[1]).filter((x): x is string => Boolean(x));
  if (assets.length < 2) return [...list];
  const unique = [...new Set(assets)];
  const merged = `${unique.length} 個未登記的系統要納管還是除役：${unique.join("、")}`;
  const out: string[] = [];
  let placed = false;
  for (const d of list) {
    if (!ADOPT_RE.test(d)) out.push(d);
    else if (!placed) {
      out.push(merged);
      placed = true;
    }
  }
  return out;
}

const LEVEL_ORDER = { high: 2, medium: 1, low: 0 } as const;

/** 未修復的風險，依等級、分數由高到低（同分維持原順序）。 */
export function openRisks(report: Pick<Report, "risks">, levels: readonly Risk["level"][] = ["high", "medium"]): Risk[] {
  return report.risks
    .map((r, i) => ({ r, i }))
    .filter(({ r }) => r.status !== "fixed" && levels.includes(r.level))
    .sort((a, b) => LEVEL_ORDER[b.r.level] - LEVEL_ORDER[a.r.level] || b.r.score - a.r.score || a.i - b.i)
    .map(({ r }) => r);
}

export function topRisks(report: Pick<Report, "risks">, n = 3): Risk[] {
  return openRisks(report, ["high"]).slice(0, n);
}

const hasFactor = (r: Risk, factor: string) => r.breakdown.some((b) => b.factor === factor);

/** 漏洞類標題多是版本號與 CVE，改成白話；其他類別的標題已是中文控制項名稱，原樣使用。 */
export function riskHeadline(r: Risk): { headline: string; detail: string | null } {
  if (r.category === "vuln") {
    const eol = hasFactor(r, "已停止支援") ? "，且已停止支援" : "";
    return { headline: `${r.asset_id} 有可被入侵的漏洞${eol}`, detail: r.title };
  }
  return { headline: r.title, detail: null };
}

/** 給 CEO 的影響標籤：只用已計算好的分數因子與攻擊路徑，不另外判斷。 */
export function riskTags(r: Risk): string[] {
  const tags: string[] = [];
  if (hasFactor(r, "已遭實際利用")) tags.push("已遭實際利用");
  if (r.matched_events.length > 0) tags.push("同業已出事");
  if (r.attack_path && r.attack_path.length > 1) tags.push(`可串成入侵路徑 → ${r.attack_path[r.attack_path.length - 1]}`);
  if (hasFactor(r, "對外暴露")) tags.push("對外可連到");
  return tags;
}

/** 系統建議的處理期限＝第一次發現時間＋等級對應的時限。 */
export function suggestedDeadline(r: Pick<Risk, "first_seen" | "deadline_hours">): Date | null {
  const t = Date.parse(r.first_seen);
  return Number.isNaN(t) ? null : new Date(t + r.deadline_hours * 3600 * 1000);
}
