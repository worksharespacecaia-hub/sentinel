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

// ---------------------------------------------------------------- 摘要數字的來源
// 與 Python tools/templates.py 的 summary_facts 同一套定義：CEO 摘要與決策裡的數字都要能點出是哪幾項。

export type FactKey = "high" | "medium" | "low" | "chained" | "eol" | "shadow_it" | "checked" | "affected" | "real_checked" | "real_affected";
export interface Fact { key: FactKey; count: number; label: string; risks: Risk[]; events: Report["events"] }

const REAL_KINDS = new Set(["archive", "live"]);

export function summaryFacts(report: Pick<Report, "risks" | "events" | "intel_summary">): Record<FactKey, Fact> {
  const live = report.risks.filter((r) => r.status !== "fixed");
  const highs = live.filter((r) => r.level === "high");
  const shadow = highs.filter((r) => r.category === "shadow_it");
  const real = report.events.filter((e) => REAL_KINDS.has(e.kind));
  const i = report.intel_summary;
  const f = (key: FactKey, label: string, count: number, risks: Risk[] = [], events: Report["events"] = []): Fact =>
    ({ key, label, count, risks, events });
  return {
    high: f("high", "高風險", highs.length, highs),
    medium: f("medium", "中風險", live.filter((r) => r.level === "medium").length, live.filter((r) => r.level === "medium")),
    low: f("low", "低風險", live.filter((r) => r.level === "low").length, live.filter((r) => r.level === "low")),
    chained: f("chained", "可串成入侵路徑的高風險", highs.filter((r) => (r.attack_path?.length ?? 0) > 1).length,
      highs.filter((r) => (r.attack_path?.length ?? 0) > 1)),
    eol: f("eol", "已停止支援、沒有修補版本的對外系統", highs.filter((r) => r.breakdown.some((b) => b.factor === "已停止支援")).length,
      highs.filter((r) => r.breakdown.some((b) => b.factor === "已停止支援"))),
    shadow_it: f("shadow_it", "未登記的系統", new Set(shadow.map((r) => r.asset_id)).size, shadow),
    checked: f("checked", "今天檢查的外部資安事件", i.checked, [], report.events),
    affected: f("affected", "與我們有關的外部事件", i.affected, [], report.events.filter((e) => e.affected_count > 0)),
    real_checked: f("real_checked", "檢查的真實事件", i.real_checked ?? i.checked, [], real),
    real_affected: f("real_affected", "與我們有關的真實事件", i.real_affected ?? i.affected, [], real.filter((e) => e.affected_count > 0)),
  };
}

// 數字後面（同一句內）出現這些字，就對應到該項數字；同一個數字可能對應多項（例如 7 個低風險、7 件有關）
const FACT_WORDS: [FactKey, RegExp][] = [
  ["high", /高風險/], ["medium", /中風險/], ["low", /低風險/], ["chained", /入侵路徑|串/],
  ["eol", /停止支援|官方更新|修補/], ["shadow_it", /未登記|納管|除役/],
  ["affected", /與我們有關|有關|命中|受影響/], ["real_affected", /真實.*有關/],
  ["checked", /外部資安事件|外部事件|資安事件|檢查/], ["real_checked", /真實事件/],
];

export type SummaryPart = string | { text: string; key: FactKey | null };

/** 把摘要切成文字與數字片段；數字對應到程式算出的事實（key），對不上時 key 為 null（畫面標示警告）。 */
export function linkSummary(text: string, facts: Record<FactKey, Fact>): SummaryPart[] {
  const out: SummaryPart[] = [];
  const re = /(\d+)\s*(個|件|項|則|筆)/g;
  let last = 0;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const n = Number(m[1]);
    const after = text.slice(m.index + m[0].length).split(/[，。；、,;]/)[0];
    const before = text.slice(0, m.index).split(/[，。；、,;]/).pop() ?? "";        // 只看同一個短句
    const candidates = (Object.values(facts) as Fact[]).filter((f) => f.count === n).map((f) => f.key);
    const byWord = FACT_WORDS.find(([k, w]) => candidates.includes(k) && w.test(after))?.[0]
      ?? FACT_WORDS.find(([k, w]) => candidates.includes(k) && w.test(before))?.[0];
    const key = byWord ?? (candidates.length ? candidates[0] : null);
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push({ text: m[0], key });
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}
