// 今日重點與行動報告共用的白話呈現（純函式，不讀檔）。只改呈現方式，不改分數、等級與燈號。
import type { Report, Risk } from "./data";
import factWords from "./fact-words.json" with { type: "json" };

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

// ---------------------------------------------------------------- 決策：問題與「不決定的話」

/** 決策的問題與後果以這個字串分隔；必須與 Python agents/tools/templates.py 的 DECISION_SEP 相同（測試比對原始碼）。 */
export const DECISION_SEP = "——不決定的話：";

/** 以第一個分隔字串切開；舊報告沒有分隔字串時整句當問題。先 groupDecisions 再呼叫這個函式。 */
export function splitDecision(text: string): { question: string; ifNot: string | null } {
  const i = text.indexOf(DECISION_SEP);
  if (i < 0) return { question: text, ifNot: null };
  const ifNot = text.slice(i + DECISION_SEP.length).trim();
  return { question: text.slice(0, i).trim(), ifNot: ifNot || null };
}

// ---------------------------------------------------------------- 風險的白話呈現

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
const nonEmpty = (s: unknown): s is string => typeof s === "string" && s.trim() !== "";

/** 系統白話名稱（report.asset_labels）；找不到時回傳原本的 ID（舊報告沒有名稱表）。 */
export function assetLabel(labels: Record<string, string> | undefined, id: string): string {
  if (!labels || !Object.prototype.hasOwnProperty.call(labels, id)) return id;
  const name = labels[id];
  return nonEmpty(name) ? name : id;
}

/** 風險的事件品牌：依 matched_events 順序，第一個有 brand 的相關事件；沒有時為 null（不影響排序）。 */
export function riskBrand(r: Risk, events: Report["events"]): string | null {
  const byId = new Map(events.map((e) => [e.id, e]));
  for (const id of r.matched_events) {
    const brand = byId.get(id)?.brand;
    if (nonEmpty(brand)) return brand.trim();
  }
  return null;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** 把文字中的系統 ID 換成白話名稱；前後是英數字、「-」、「_」時視為別的名稱的一部分，不換。 */
function replaceId(text: string, id: string, name: string): string {
  if (!id || name === id) return text;
  return text.replace(new RegExp(`(?<![A-Za-z0-9_-])${escapeRe(id)}(?![A-Za-z0-9_-])`, "g"), () => name);
}

/**
 * 標題：有 AI 或範本寫的白話標題就用它，原始技術標題放 detail（所有類別）；
 * 舊報告沒有白話標題時退回舊寫法：漏洞改成「{系統} 有可被入侵的漏洞」，其他類別用原標題（系統代號換成白話名稱）。
 */
export function riskHeadline(r: Risk, labels?: Record<string, string>): { headline: string; detail: string | null } {
  const plain = r.solution?.plain_title;
  if (nonEmpty(plain)) return { headline: plain.trim(), detail: r.title };
  if (r.category === "vuln") {
    const eol = hasFactor(r, "已停止支援") ? "，且已停止支援" : "";
    return { headline: `${assetLabel(labels, r.asset_id)} 有可被入侵的漏洞${eol}`, detail: r.title };
  }
  return { headline: replaceId(r.title, r.asset_id, assetLabel(labels, r.asset_id)), detail: null };
}

/** 不處理的話會怎樣（AI 或範本寫的）；舊報告沒有時為 null（畫面不顯示）。 */
export function ifIgnored(r: Risk): string | null {
  const t = r.solution?.if_ignored;
  return nonEmpty(t) ? t.trim() : null;
}

/**
 * 給 CEO 的白話標籤：只用已計算好的分數因子、攻擊路徑與相關事件的種類，不另外判斷。
 * 有品牌時不加事件標籤（標題已有「{brand} 事件同款破口」）。ctx.brand 未提供時由 ctx.events 算出。
 */
export function riskTags(r: Risk, ctx: { labels?: Record<string, string>; events?: Report["events"]; brand?: string | null } = {}): string[] {
  const events = ctx.events ?? [];
  const brand = ctx.brand !== undefined ? ctx.brand : riskBrand(r, events);
  const tags: string[] = [];
  if (hasFactor(r, "已遭實際利用")) tags.push("已經有人在用這個漏洞攻擊");
  if (hasFactor(r, "已停止支援")) tags.push("原廠已不再修補");
  if (!brand && r.matched_events.length > 0) {
    const byId = new Map(events.map((e) => [e.id, e]));
    const related = r.matched_events.map((id) => byId.get(id)).filter((e) => e !== undefined);
    tags.push(related.some((e) => e.kind === "advisory" && !e.demo) ? "已有官方漏洞公告" : "外部已有相關事件");
  }
  const path = r.attack_path ?? [];
  if (path.length > 1) {
    const target = assetLabel(ctx.labels, path[path.length - 1]);
    tags.push(`可一路闖到${/^[A-Za-z0-9]/.test(target) ? " " : ""}${target}`);   // 舊報告沒有名稱表時是系統 ID，前面補空格
  }
  if (hasFactor(r, "對外暴露")) tags.push("外人連得到");
  return tags;
}

/** 收合區塊「看細節與漏洞原因」的內容：原始技術標題與說明、攻擊路徑的白話名稱、相關事件、根本解法。 */
export function riskDetail(r: Risk, report: Pick<Report, "events" | "asset_labels">): {
  cause: string[]; path: string[] | null; events: { title: string; demo: boolean }[]; permanent: string | null;
} {
  const byId = new Map(report.events.map((e) => [e.id, e]));
  const path = r.attack_path ?? [];
  const permanent = r.solution?.permanent;
  return {
    cause: [r.title, r.explanation].filter(nonEmpty),
    path: path.length > 1 ? path.map((id) => assetLabel(report.asset_labels, id)) : null,
    events: r.matched_events.flatMap((id) => {
      const e = byId.get(id);
      return e ? [{ title: e.title, demo: Boolean(e.demo) || e.kind === "demo" }] : [];
    }),
    permanent: nonEmpty(permanent) ? permanent : null,
  };
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

const FACT_KEYS: readonly FactKey[] = ["high", "medium", "low", "chained", "eol", "shadow_it", "checked", "affected", "real_checked", "real_affected"];

// 數字對應指標的關鍵字表：與 Python 共用同一份內容（rules/fact-words.json 的副本，測試比對兩份相同）。順序：具體在前
const FACT_WORDS: readonly [FactKey, RegExp][] = factWords.words.map(([k, p]) => {
  if (!FACT_KEYS.includes(k as FactKey)) throw new Error(`fact-words.json 有未知的指標：${k}`);
  return [k as FactKey, new RegExp(p)] as [FactKey, RegExp];
});

const COUNT_RE = /(\d+)\s*(個|件|項|則|筆)/;            // 每次使用時另建 g 旗標的副本，不共用 lastIndex
const PUNCT = new Set(["，", "。", "；", "、", ",", ";"]);

const wordKey = (segment: string): FactKey | null => FACT_WORDS.find(([, w]) => w.test(segment))?.[0] ?? null;

// 限定指標 → 一般指標（例如 real_checked 是 checked 的「真實事件」限定）：前後兩段分別對到時取較精確的，不算歧義
const FACT_REFINES: Partial<Record<FactKey, FactKey>> = Object.fromEntries(Object.entries(factWords.refines ?? {}).map(([k, v]) => {
  if (!FACT_KEYS.includes(k as FactKey) || !FACT_KEYS.includes(v as FactKey)) throw new Error(`fact-words.json 的 refines 有未知的指標：${k}`);
  return [k, v];
}));

function combineKeys(after: FactKey | null, before: FactKey | null): FactKey | "ambiguous" | null {
  if (!after || !before || after === before) return after ?? before;
  if (FACT_REFINES[after] === before) return after;
  if (FACT_REFINES[before] === after) return before;
  return "ambiguous";
}

interface CountMatch { index: number; end: number; n: number; text: string }

/** 同一句所有「N 個／件／項／則／筆」的位置。 */
function countMatches(text: string): CountMatch[] {
  const re = new RegExp(COUNT_RE.source, "g");
  const out: CountMatch[] = [];
  for (let m = re.exec(text); m; m = re.exec(text)) out.push({ index: m.index, end: m.index + m[0].length, n: Number(m[1]), text: m[0] });
  return out;
}

/** 前後兩段各自找到的指標；"ambiguous"＝兩段都有且不同，null＝兩段都沒有。 */
function factWord(text: string, matches: readonly CountMatch[], i: number): FactKey | "ambiguous" | null {
  const m = matches[i];
  // 後段：數字結尾 → 下一個標點或下一個數字開頭（先到者）
  let afterEnd = i + 1 < matches.length ? matches[i + 1].index : text.length;
  for (let j = m.end; j < afterEnd; j++) if (PUNCT.has(text[j])) { afterEnd = j; break; }
  // 前段：前一個標點或前一個數字結尾（後到者）→ 數字開頭
  let beforeStart = i > 0 ? matches[i - 1].end : 0;
  for (let j = m.index - 1; j >= beforeStart; j--) if (PUNCT.has(text[j])) { beforeStart = j + 1; break; }
  return combineKeys(wordKey(text.slice(m.end, afterEnd)), wordKey(text.slice(beforeStart, m.index)));
}

/**
 * 句中第 i 個數字對應的指標（與 Python templates.fact_key 同一套規則）：兩段各取關鍵字表中第一個命中的指標；
 * 兩段都有且不同 → null（歧義）；否則取有的那一個；都沒有 → null。
 */
export function factKey(text: string, i: number): FactKey | null {
  const w = factWord(text, countMatches(text), i);
  return w === "ambiguous" ? null : w;
}

export type SummaryPart = string | { text: string; key: FactKey | null };

/**
 * 把摘要切成文字與數字片段；數字對應到程式算出的事實（key），對不上時 key 為 null（畫面標示警告）：
 * - 指標找到且數值相同 → 連結；歧義，或指標找到但數值不同 → null
 * - 前後都找不到指標（舊報告的舊句型）→ 只有一個指標等於此數值才用它，否則 null（不再退回「同值的第一項」）
 */
export function linkSummary(text: string, facts: Record<FactKey, Fact>): SummaryPart[] {
  const found = countMatches(text);
  const out: SummaryPart[] = [];
  let last = 0;
  found.forEach((m, i) => {
    const word = factWord(text, found, i);
    let key: FactKey | null;
    if (word === "ambiguous") key = null;
    else if (word) key = facts[word].count === m.n ? word : null;
    else {
      const same = FACT_KEYS.filter((k) => facts[k].count === m.n);
      key = same.length === 1 ? same[0] : null;
    }
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push({ text: m.text, key });
    last = m.end;
  });
  if (last < text.length) out.push(text.slice(last));
  return out;
}
