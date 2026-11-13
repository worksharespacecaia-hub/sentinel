// 資安事件整理（/digest）的純函式：讀取時的保留窗口清理、新進度群組、篩選、明細查驗結果與頁首提示。
// 不讀檔、不修改 latest；updated_at／as_of／next_update_at 等時間只顯示、不刷新（specs/security-digest design 6.2）。
// 注意：本檔會被 client component 匯入，不可匯入 node:fs 或 data.ts 的執行期程式。
import type { Level } from "./data";
import { LEVEL_TEXT, RELATION_TEXT, fmtTime, taipeiDate } from "./labels.ts";

export type Relation = keyof typeof RELATION_TEXT;
export type Verdict = "affected" | "not_affected" | "need_check";
export type RelationFilter = "all" | "affected" | "need_check" | "not_affected";

export interface DigestSource { title: string; domain: string | null; url: string | null; verified: boolean }
export interface DigestImpact { asset_id: string; asset_label: string; verdict: Verdict; level: Level | null }
export interface DigestAssessment {
  evaluated_at: string; run_id: string; relation: Relation; max_level: Level | null; affected_count: number; conclusion: string;
  impacts: DigestImpact[]; impacts_total: number; impacts_truncated: boolean; relation_changed_at: string | null;
  /** 需確認事件的公開查核建議（0.12.0，specs/check-hints）。舊資料沒有；不經 isEvent 檢查，建模時由 parseSuggestions 轉成安全陣列 */
  suggestions?: unknown;
}
export interface DigestSuggestion { text: string; systems: string[] }
export interface DigestEvent {
  id: string; kind: "live" | "archive" | "advisory"; title: string; event_date: string | null; first_seen: string; last_seen: string;
  last_seen_at: string; observed_run_id: string; confidence: "confirmed" | "provisional"; is_update_of: string | null; cves: string[];
  summary: string; sources: DigestSource[]; assessment: DigestAssessment;
  updates?: DigestEvent[]; standalone_reason?: "parent_missing" | "link_invalid" | null;
}
export interface DigestIssue { code: string; impact: string; omitted: number; date: string | null }
export interface DigestCounts { total: number; affected: number; need_check: number; not_affected: number; fixed: number }
export interface DigestDay { date: string; count: number; events: DigestEvent[] }
export interface DigestLatest {
  schema_version: 1; updated_at: string; as_of: string; run_id: string; next_update_at: string; daily_intel_status: string;
  window_days: number; data_issues: DigestIssue[]; counts: DigestCounts; days: DigestDay[];
}

/** 目前已發布的最新 daily 報告中，整理頁需要的欄位（讀不到時為 null）。 */
export interface DailyInfo { run_id: string; generated_at: string; as_of: string; daily_intel_status: string }

export const WINDOW_DAYS = 30;
export const STALE_MS = 12 * 60 * 60 * 1000;
const MAX_UPDATE_DEPTH = 5;   // 與 agents/tools/digest.py 相同：新進度鏈結超過這個深度視為過深
const REL_RANK: Record<Relation, number> = { affected: 0, need_check: 1, not_affected: 2, fixed: 3 };
const LEVEL_RANK: Record<string, number> = { high: 0, medium: 1, low: 2 };
const VERDICT_TEXT: Record<Verdict, string> = { affected: "受影響", need_check: "需確認", not_affected: "不受影響" };
export const DIGEST_KIND_TEXT: Record<DigestEvent["kind"], string> = { live: "真實報導", archive: "收錄事件", advisory: "公告" };
export const CONFIDENCE_TEXT: Record<DigestEvent["confidence"], string> = { confirmed: "已確認", provisional: "暫定" };
export const RELATION_FILTERS: { key: RelationFilter; label: string }[] = [
  { key: "all", label: "全部" }, { key: "affected", label: RELATION_TEXT.affected },
  { key: "need_check", label: RELATION_TEXT.need_check }, { key: "not_affected", label: RELATION_TEXT.not_affected },
];
export const NEWS_FAILED_TEXT = "本次每日評估未更新新聞情資；整理保留先前收錄的新聞、收錄事件與公告";
export const NEWS_UNKNOWN_TEXT = "無法確認最新每日評估狀態";

// ── 文字與格式 ─────────────────────────────────────────────

export function relationLabel(r: string | null | undefined): string {
  return r && r in RELATION_TEXT ? RELATION_TEXT[r as Relation] : "未提供";
}

/** 來源連結只接受 http(s)，拒絕帳密（userinfo）與控制字元；其他一律不當作連結（R6.4）。 */
export function safeHref(url: string | null | undefined): string | null {
  if (typeof url !== "string" || !url || /[\x00-\x20\x7f]/.test(url)) return null;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username || u.password || !u.hostname) return null;
  return u.href;
}

/** 現在時間超過「下次預定更新」12 小時仍未更新即為過期（R3.2）；時間無法解讀時視為過期，不假裝資料是新的。 */
export function isStale(latest: Pick<DigestLatest, "next_update_at">, now: Date): boolean {
  const next = Date.parse(latest.next_update_at);
  if (Number.isNaN(next)) return true;
  return now.getTime() - next > STALE_MS;
}

const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const YMD = /^\d{4}-\d{2}-\d{2}$/;

function addDays(ymd: string, n: number): string {
  const [y, m, d] = ymd.split("-").map(Number);
  return new Date(Date.UTC(y, m - 1, d + n)).toISOString().slice(0, 10);
}

/** 保留窗口：台灣日期 D 往前 29 日到 D（含），不是再往前 30 日（R5.1）。 */
export function windowBounds(now: Date, days = WINDOW_DAYS): { start: string; end: string } {
  const end = taipeiDate(now);
  return { start: addDays(end, -(days - 1)), end };
}

// ── 讀檔後的格式檢查 ───────────────────────────────────────

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);
const isStr = (x: unknown): x is string => typeof x === "string";
const isNum = (x: unknown): x is number => typeof x === "number" && Number.isFinite(x);
const LEVELS = new Set(["high", "medium", "low"]);

function isEvent(x: unknown, depth: number): boolean {
  if (!isObj(x)) return false;
  const a = x.assessment;
  if (!isStr(x.id) || !["live", "archive", "advisory"].includes(x.kind as string) || !isStr(x.title) || !isStr(x.summary)) return false;
  if (!isStr(x.first_seen) || !YMD.test(x.first_seen) || !(x.event_date === null || (isStr(x.event_date) && YMD.test(x.event_date)))) return false;
  if (!["confirmed", "provisional"].includes(x.confidence as string) || !(x.is_update_of === null || isStr(x.is_update_of))) return false;
  if (!Array.isArray(x.cves) || !x.cves.every(isStr)) return false;
  if (!Array.isArray(x.sources) || !x.sources.every((s) => isObj(s) && isStr(s.title) && typeof s.verified === "boolean"
    && (s.domain === null || isStr(s.domain)) && (s.url === null || isStr(s.url)))) return false;
  if (!isObj(a) || !isStr(a.evaluated_at) || !ISO_UTC.test(a.evaluated_at) || !isStr(a.run_id) || !((a.relation as string) in REL_RANK)) return false;
  if (!(a.max_level === null || LEVELS.has(a.max_level as string)) || !isNum(a.affected_count) || !isStr(a.conclusion)) return false;
  if (!isNum(a.impacts_total) || typeof a.impacts_truncated !== "boolean") return false;
  if (!(a.relation_changed_at === null || a.relation_changed_at === undefined || (isStr(a.relation_changed_at) && ISO_UTC.test(a.relation_changed_at)))) return false;
  if (!Array.isArray(a.impacts) || !a.impacts.every((i) => isObj(i) && isStr(i.asset_label) && (i.verdict as string) in VERDICT_TEXT
    && (i.level === null || LEVELS.has(i.level as string)))) return false;
  const ups = x.updates ?? [];
  return Array.isArray(ups) && (ups.length === 0 || (depth === 0 && ups.every((u) => isEvent(u, 1))));
}

/** latest.json 的必要欄位檢查；不合格時頁面顯示「無法讀取」，不嘗試部分顯示。 */
export function isDigestLatest(x: unknown): x is DigestLatest {
  if (!isObj(x) || x.schema_version !== 1) return false;
  if (![x.updated_at, x.as_of, x.next_update_at].every((t) => isStr(t) && ISO_UTC.test(t)) || !isStr(x.run_id)) return false;
  if (!Array.isArray(x.data_issues) || !x.data_issues.every((i) => isObj(i) && isStr(i.code) && isStr(i.impact)
    && (i.omitted === undefined || isNum(i.omitted)) && (i.date === null || i.date === undefined || (isStr(i.date) && YMD.test(i.date))))) return false;
  return Array.isArray(x.days) && x.days.every((d) => isObj(d) && isStr(d.date) && YMD.test(d.date)
    && Array.isArray(d.events) && d.events.every((e) => isEvent(e, 0)));
}

// ── 讀取時清理：扁平化 → 窗口過濾 → 重組新進度群組與計數（與 agents/tools/digest.py 的 group_events 相同規則） ──

export interface DigestGroup { head: DigestEvent; updates: DigestEvent[]; standalone_reason: "parent_missing" | "link_invalid" | null }
export interface GroupedDay { date: string; count: number; groups: DigestGroup[] }

function flat(ev: DigestEvent): DigestEvent {
  const { updates: _u, standalone_reason: _s, ...rest } = ev;
  return rest;
}

export function flattenLatest(latest: Pick<DigestLatest, "days">): DigestEvent[] {
  const out: DigestEvent[] = [];
  for (const d of latest.days) for (const ev of d.events) {
    out.push(flat(ev));
    for (const u of ev.updates ?? []) out.push(flat(u));
  }
  return out;
}

function resolveRoot(ev: DigestEvent, byId: Map<string, DigestEvent>): [string, "parent_missing" | "link_invalid" | null] {
  const parent = ev.is_update_of;
  if (parent === null) return [ev.id, null];
  if (parent === ev.id) return [ev.id, "link_invalid"];
  if (!byId.has(parent)) return [ev.id, "parent_missing"];
  const chain = [ev.id];
  let cur = ev;
  while (cur.is_update_of !== null) {
    const p = cur.is_update_of;
    if (!byId.has(p)) return [cur.id, null];
    if (chain.includes(p) || chain.length > MAX_UPDATE_DEPTH) return [ev.id, "link_invalid"];
    chain.push(p);
    cur = byId.get(p)!;
  }
  return [cur.id, null];
}

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const priority = (ev: DigestEvent): [number, number] => [REL_RANK[ev.assessment.relation], LEVEL_RANK[ev.assessment.max_level ?? ""] ?? 3];
const cmpPri = (a: [number, number], b: [number, number]) => a[0] - b[0] || a[1] - b[1];

/** 扁平事件 → 依收錄日期分組（新到舊）；新進度掛在原事件下，原事件不在集合時單獨顯示；計數以唯一事件 ID 計算。 */
export function groupEvents(events: DigestEvent[]): { days: GroupedDay[]; counts: DigestCounts; invalidLinks: number } {
  const byId = new Map(events.map((e) => [e.id, e]));
  const heads = new Map<string, DigestGroup>();
  const children = new Map<string, DigestEvent[]>();
  let invalidLinks = 0;
  for (const ev of [...byId.values()].sort((a, b) => cmp(a.id, b.id))) {
    const [root, reason] = resolveRoot(ev, byId);
    if (root === ev.id) {
      heads.set(ev.id, { head: ev, updates: [], standalone_reason: reason });
      if (reason === "link_invalid") invalidLinks += 1;
    } else {
      children.set(root, [...(children.get(root) ?? []), ev]);
    }
  }
  const byDay = new Map<string, DigestGroup[]>();
  for (const [hid, g] of heads) {
    g.updates = (children.get(hid) ?? []).sort((a, b) =>
      cmp(a.event_date ?? a.first_seen, b.event_date ?? b.first_seen) || cmp(a.first_seen, b.first_seen) || cmp(a.id, b.id));
    byDay.set(g.head.first_seen, [...(byDay.get(g.head.first_seen) ?? []), g]);
  }
  const groupPri = (g: DigestGroup) => [g.head, ...g.updates].map(priority).sort(cmpPri)[0];
  const days = [...byDay.keys()].sort((a, b) => cmp(b, a)).map((date) => {
    const groups = byDay.get(date)!.sort((a, b) => cmpPri(groupPri(a), groupPri(b)) || cmp(a.head.id, b.head.id));
    return { date, count: groups.reduce((n, g) => n + 1 + g.updates.length, 0), groups };
  });
  const counts: DigestCounts = { total: byId.size, affected: 0, need_check: 0, not_affected: 0, fixed: 0 };
  for (const ev of byId.values()) counts[ev.assessment.relation] += 1;
  return { days, counts, invalidLinks };
}

/**
 * 以「現在」的台灣日期清理保留窗口（D-29～D），重組群組與計數；原事件過期而子事件未過期時，子事件提升為獨立卡片。
 * 回傳新物件，不修改 latest，也不改 updated_at 等時間（R5.2）。
 */
export function pruneForView(latest: DigestLatest, now: Date): { days: GroupedDay[]; counts: DigestCounts; data_issues: DigestIssue[] } {
  const { start, end } = windowBounds(now, WINDOW_DAYS);
  let future = 0;
  const kept: DigestEvent[] = [];
  for (const ev of flattenLatest(latest)) {
    if (ev.first_seen > end) future += 1;
    else if (ev.first_seen >= start) kept.push(ev);
  }
  const { days, counts, invalidLinks } = groupEvents(kept);
  const issues = latest.data_issues.filter((i) => i.code !== "invalid_update_link" && i.code !== "future_first_seen"
    && (i.date == null || (start <= i.date && i.date <= end)));
  if (future) issues.push({ code: "future_first_seen", impact: `${future} 件事件的收錄日期晚於今天，已排除`, omitted: future, date: null });
  if (invalidLinks) issues.push({ code: "invalid_update_link", impact: `${invalidLinks} 件事件的新進度關聯有誤（自我參照、循環或過深），改為獨立顯示`,
    omitted: invalidLinks, date: null });
  return { days, counts, data_issues: issues };
}

// ── 篩選：父子事件逐件判斷，再組回群組 ───────────────────────

export interface FilterItem { id: string; relation: Relation }
export interface ViewGroup<T extends FilterItem> { head: T; updates: T[] }
export interface ViewDay<T extends FilterItem> { date: string; count: number; groups: ViewGroup<T>[] }
export interface FilteredGroup<T extends FilterItem> { head: T; headMatched: boolean; updates: T[] }
export interface FilteredDay<T extends FilterItem> { date: string; count: number; groups: FilteredGroup<T>[] }

/**
 * R2.6／R2.7：原事件不符合但新進度符合時，仍顯示符合的新進度，原事件只作群組標示（headMatched=false），不計入篩選結果。
 * 計數以唯一事件 ID 計算；沒有任何符合事件的日期不顯示。
 */
export function filterDigest<T extends FilterItem>(days: ViewDay<T>[], filter: RelationFilter): { days: FilteredDay<T>[]; count: number } {
  const match = (x: T) => filter === "all" || x.relation === filter;
  const out: FilteredDay<T>[] = [];
  for (const d of days) {
    const seen = new Set<string>();
    const groups: FilteredGroup<T>[] = [];
    for (const g of d.groups) {
      const headMatched = match(g.head);
      const updates = g.updates.filter(match);
      if (!headMatched && updates.length === 0) continue;
      groups.push({ head: g.head, headMatched, updates });
      if (headMatched) seen.add(g.head.id);
      for (const u of updates) seen.add(u.id);
    }
    if (groups.length) out.push({ date: d.date, count: seen.size, groups });
  }
  const all = new Set(out.flatMap((d) => d.groups.flatMap((g) => [...(g.headMatched ? [g.head.id] : []), ...g.updates.map((u) => u.id)])));
  return { days: out, count: all.size };
}

// ── 明細連結（讀取時查驗）與頁首提示 ───────────────────────

/** note：只有明細來自另一次評估時才有附註（R2.8）；同一次評估時為 null，避免與卡片的評估時間重複。 */
export interface DetailLink { href: string; otherRun: boolean; evaluatedAt: string; note: string | null }

/**
 * 只有目前已發布的 daily intel index 有此事件、且明細檔實際存在（available）時才給連結。
 * 明細屬於目前的 daily 報告；與快照的評估 run 不同時附註「明細為另一份每日評估」（R2.8）。
 */
export function detailLink(ev: Pick<DigestEvent, "id" | "assessment">, daily: DailyInfo | null, available: ReadonlySet<string>): DetailLink | null {
  if (!daily || !available.has(ev.id)) return null;
  const otherRun = daily.run_id !== ev.assessment.run_id;
  return {
    href: `/intel/${encodeURIComponent(ev.id)}`, otherRun, evaluatedAt: daily.as_of,
    note: otherRun ? `明細為另一份每日評估（評估於 ${fmtTime(daily.as_of)}）` : null,
  };
}

export interface Notice { kind: "news_failed" | "news_skipped" | "replay" | "unknown"; text: string }

/** R3.3：讀目前已發布的最新 daily 報告，而不是整理快照的 daily_intel_status。 */
export function newsNotice(daily: DailyInfo | null): Notice | null {
  if (!daily) return { kind: "unknown", text: NEWS_UNKNOWN_TEXT };
  const when = fmtTime(daily.generated_at);
  switch (daily.daily_intel_status) {
    case "ok": return null;
    case "failed": return { kind: "news_failed", text: `${NEWS_FAILED_TEXT}（${when} 的每日評估）` };
    case "skipped": return { kind: "news_skipped", text: `${NEWS_FAILED_TEXT}（${when} 的每日評估）` };
    case "replay": return { kind: "replay", text: `重播資料：${when} 的每日評估使用錄製的新聞情資，不代表當日新聞已更新` };
    default: return { kind: "unknown", text: NEWS_UNKNOWN_TEXT };
  }
}

export function capacityOmitted(issues: DigestIssue[]): number {
  return issues.filter((i) => i.code === "capacity").reduce((n, i) => n + (i.omitted ?? 0), 0);
}

export interface MergedImpact { label: string; verdict: Verdict; verdictText: string; level: Level | null; count: number }

/** 同一系統因不同控制項重複出現時，同名且同結論者合併為一筆（例如「辦公室 NAS（3 項）」）；只顯示名稱，不顯示 asset_id。 */
export function mergeImpacts(impacts: DigestImpact[]): MergedImpact[] {
  const out: MergedImpact[] = [];
  for (const i of impacts) {
    const hit = out.find((m) => m.label === i.asset_label && m.verdict === i.verdict);
    if (!hit) {
      out.push({ label: i.asset_label, verdict: i.verdict, verdictText: VERDICT_TEXT[i.verdict], level: i.level, count: 1 });
      continue;
    }
    hit.count += 1;
    if (i.level && (!hit.level || LEVEL_RANK[i.level] < LEVEL_RANK[hit.level])) hit.level = i.level;
  }
  return out;
}

// ── 查核建議（specs/check-hints R6.5）：格式錯誤只略過該項，不讓整份整理無效 ──

export const SUGGESTION_LIMIT = 3;
export const SUGGESTION_TEXT_LIMIT = 300;
export const SUGGESTION_SYSTEM_LIMIT = 5;

/** 字數以 Unicode 字元計算（與後端 Python 的 len 相同），不切開代理字元對。 */
const clip = (text: string, n: number) => {
  const chars = Array.from(text);
  return chars.length > n ? chars.slice(0, n).join("") : text;
};

/**
 * assessment.suggestions → 安全陣列：不是陣列為 []；元素不是物件或 text 不是非空字串就略過；
 * systems 不是陣列為 []、只保留字串；截斷為 text 300 字、systems 5 個、整體 3 項。
 */
export function parseSuggestions(raw: unknown): DigestSuggestion[] {
  if (!Array.isArray(raw)) return [];
  const out: DigestSuggestion[] = [];
  for (const item of raw) {
    if (out.length >= SUGGESTION_LIMIT) break;
    if (!isObj(item) || !isStr(item.text) || !item.text.trim()) continue;
    const systems = Array.isArray(item.systems) ? item.systems.filter(isStr).slice(0, SUGGESTION_SYSTEM_LIMIT) : [];
    out.push({ text: clip(item.text, SUGGESTION_TEXT_LIMIT), systems });
  }
  return out;
}

// ── 頁面用的檢視模型（伺服器端先格式化時間，避免 client 端時區或語系差異） ──

export interface CardSource { title: string; domain: string | null; href: string | null; verified: boolean }
export interface Card extends FilterItem {
  title: string; kindText: string; confidenceText: string; eventDate: string; relationText: string; level: Level | null;
  levelText: string; affectedCount: number; summary: string; sources: CardSource[]; cves: string[]; conclusion: string;
  impacts: MergedImpact[]; impactsNote: string | null; evaluatedText: string; relationChangedText: string | null;
  standaloneText: string | null; detail: DetailLink | null;
  /** 查核建議（已由 parseSuggestions 清理）；畫面只在 relation 為 need_check 時顯示 */
  suggestions: DigestSuggestion[];
}

export interface DigestView {
  /** 原樣保留，不因讀取時清理而刷新 */
  updated_at: string; next_update_at: string;
  updatedText: string; nextUpdateText: string; stale: boolean; staleText: string | null; news: Notice | null;
  counts: DigestCounts; capacityOmitted: number; issues: string[]; days: ViewDay<Card>[];
}

function card(ev: DigestEvent, daily: DailyInfo | null, available: ReadonlySet<string>, reason: DigestGroup["standalone_reason"]): Card {
  const a = ev.assessment;
  const evaluated = fmtTime(a.evaluated_at);
  return {
    id: ev.id, relation: a.relation, title: ev.title, kindText: DIGEST_KIND_TEXT[ev.kind] ?? "外部事件",
    confidenceText: CONFIDENCE_TEXT[ev.confidence] ?? "未提供", eventDate: ev.event_date ?? "未提供",
    relationText: relationLabel(a.relation), level: a.max_level, levelText: a.max_level ? LEVEL_TEXT[a.max_level] : "—",
    affectedCount: a.affected_count, summary: ev.summary,
    sources: ev.sources.map((s) => ({ title: s.title, domain: s.domain, href: safeHref(s.url), verified: s.verified })),
    cves: ev.cves, conclusion: a.conclusion, impacts: mergeImpacts(a.impacts),
    impactsNote: a.impacts_truncated ? `僅列前 ${a.impacts.length} 項，共 ${a.impacts_total} 項` : null,
    // 「本次」指目前已發布的 daily；不是同一次評估（或讀不到 daily）時一律標「上次評估於」，不宣稱本次重新確認（R6.3）
    evaluatedText: daily && a.run_id === daily.run_id ? `評估於 ${evaluated}` : `上次評估於 ${evaluated}`,
    relationChangedText: a.relation_changed_at ? `結論更新於 ${fmtTime(a.relation_changed_at)}` : null,
    standaloneText: reason === "parent_missing" ? "較早事件的新進度" : reason === "link_invalid" ? "新進度的關聯有誤，獨立顯示" : null,
    detail: detailLink(ev, daily, available),
    suggestions: parseSuggestions(a.suggestions),
  };
}

/**
 * 頁面的單一資料來源：頁首計數、篩選與列表共用同一份讀取時清理結果。
 * daily：目前已發布的最新 daily 報告（讀不到為 null）；available：目前 daily intel index 有列且明細檔存在的事件 ID。
 */
export function buildDigestView(latest: DigestLatest, now: Date, daily: DailyInfo | null, available: ReadonlySet<string>): DigestView {
  const pruned = pruneForView(latest, now);
  const stale = isStale(latest, now);
  return {
    updated_at: latest.updated_at, next_update_at: latest.next_update_at,
    updatedText: fmtTime(latest.updated_at), nextUpdateText: fmtTime(latest.next_update_at),
    stale, staleText: stale ? `資料已過期：上次更新於 ${fmtTime(latest.updated_at)}` : null, news: newsNotice(daily),
    counts: pruned.counts, capacityOmitted: capacityOmitted(pruned.data_issues),
    issues: pruned.data_issues.filter((i) => i.code !== "capacity").map((i) => i.impact),
    days: pruned.days.map((d) => ({
      date: d.date, count: d.count,
      groups: d.groups.map((g) => ({
        head: card(g.head, daily, available, g.standalone_reason),
        updates: g.updates.map((u) => card(u, daily, available, null)),
      })),
    })),
  };
}
