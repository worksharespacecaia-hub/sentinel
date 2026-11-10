// 行動報告（純函式）：彙整需要採取行動的結果，網頁、PDF、LINE 訊息與到期提醒共用同一份資料。
// 只整理程式已算好的等級、分數、建議與期限；「處理中」是人為追蹤，不改變風險狀態與燈號。
import type { EventSummary, Level, Light, Report } from "./data";
import { groupDecisions, openRisks, riskHeadline, riskTags, suggestedDeadline } from "./brief.ts";

export const REMIND_BEFORE_MS = 24 * 3600 * 1000;
export const MAX_DUE_MS = 30 * 86400 * 1000;

export type TrackStatus = "in_progress" | "cancelled" | "closed";
export interface TrackChange { at: string; by: string; action: "set" | "cancel" | "auto_close"; due_at?: string; owner?: string; note?: string; reason?: string }
export interface Tracking {
  risk_id: string; status: TrackStatus; owner: string; due_at: string; note: string;
  set_by: string; set_at: string; history: TrackChange[];
  /** Redis CAS 版本；前端以它避免覆蓋別人剛做的修改。 */
  version?: number;
}

/** open＝沒有人認領；in_progress＝處理中且離期限超過 24 小時；due_soon＝24 小時內到期；overdue＝已過期限。 */
export type TrackState = "open" | "in_progress" | "due_soon" | "overdue";

export function trackState(t: Pick<Tracking, "status" | "due_at"> | null | undefined, now = Date.now()): TrackState {
  if (!t || t.status !== "in_progress") return "open";
  const due = Date.parse(t.due_at);
  if (Number.isNaN(due) || now >= due) return "overdue";
  return due - now <= REMIND_BEFORE_MS ? "due_soon" : "in_progress";
}

export const TRACK_TEXT: Record<TrackState, string> = { open: "待處理", in_progress: "處理中", due_soon: "處理中・即將到期", overdue: "處理中・已逾期" };

/** 事件來源：只接受 http(s) 網址；示範事件沒有網址，明確標示非真實報導。 */
export interface EventSource { title: string; url: string | null; publisher: string | null; verified: boolean; demo: boolean; quote: string | null }
export interface EventDetail { date: string | null; confidence: string | null; sources: EventSource[] }
export type ActionEvent = EventSummary & EventDetail;

export interface ActionItem {
  id: string; level: Level; score: number; need_check: boolean; asset_id: string;
  /** 相關的同業事件（可對應到報告中的事件來源）。 */
  events: { id: string; title: string }[];
  headline: string; detail: string | null; tags: string[];
  temporary: string | null; permanent: string | null; owner: string | null;
  suggested_due: string | null; tracking: Tracking | null; track_state: TrackState; beyond_suggested: boolean;
}
export interface Notice { event_id: string; title: string; draft: string }
export interface ActionReport {
  light: Light; generated_at: string; summary: string[]; decisions: string[]; items: ActionItem[];
  events: ActionEvent[]; notices: Notice[];
  counts: { high: number; medium: number; in_progress: number; due_soon: number; overdue: number; unassigned_high: number };
}

export function buildActionReport(report: Report, opts: { light?: Light; tracking?: Record<string, Tracking>; notices?: Notice[];
                                    eventDetails?: Record<string, EventDetail>; now?: number } = {}): ActionReport {
  const now = opts.now ?? Date.now();
  const tracking = opts.tracking ?? {};
  const titles = new Map(report.events.map((e) => [e.id, e.title]));
  const items: ActionItem[] = openRisks(report, ["high", "medium"]).map((r) => {
    const h = riskHeadline(r);
    const suggested = suggestedDeadline(r);
    const t = tracking[r.id]?.status === "in_progress" ? tracking[r.id] : null;
    return {
      id: r.id, level: r.level, score: r.score, need_check: r.status === "need_check", asset_id: r.asset_id,
      events: r.matched_events.filter((e) => titles.has(e)).map((e) => ({ id: e, title: titles.get(e)! })),
      headline: h.headline, detail: h.detail, tags: riskTags(r),
      temporary: r.solution?.temporary ?? null, permanent: r.solution?.permanent ?? null, owner: r.solution?.suggested_owner ?? null,
      suggested_due: suggested ? suggested.toISOString() : null, tracking: t, track_state: trackState(t, now),
      beyond_suggested: Boolean(t && suggested && Date.parse(t.due_at) > suggested.getTime()),
    };
  });
  const count = (s: TrackState) => items.filter((i) => i.track_state === s).length;
  return {
    light: opts.light ?? report.light, generated_at: report.generated_at, summary: report.ceo_summary,
    decisions: groupDecisions(report.decisions), items,
    events: report.events.filter((e) => e.affected_count > 0)
      .map((e) => ({ ...e, ...(opts.eventDetails?.[e.id] ?? { date: null, confidence: null, sources: [] }) })),
    notices: opts.notices ?? [],
    counts: {
      high: items.filter((i) => i.level === "high").length, medium: items.filter((i) => i.level === "medium").length,
      in_progress: items.filter((i) => i.tracking).length, due_soon: count("due_soon"), overdue: count("overdue"),
      unassigned_high: items.filter((i) => i.level === "high" && !i.tracking).length,
    },
  };
}

export interface TrackInput { owner: string; due_at: string; note: string }

/** 設定「處理中」的輸入檢查：期限必填、晚於現在、最多 30 天內；負責人 1～40 字；備註 200 字內。 */
export function checkTrackInput(body: Record<string, unknown>, now = Date.now()): { ok: true; value: TrackInput } | { ok: false; error: string } {
  const owner = String(body.owner ?? "").trim();
  const note = String(body.note ?? "").trim();
  const dueRaw = typeof body.due_at === "string" ? body.due_at : "";
  if (!/^[\p{L}\p{N} ._@()（）-]{1,40}$/u.test(owner)) return { ok: false, error: "請填寫負責人（40 字內）" };
  if (note.length > 200 || /[\u0000-\u001f]/.test(note)) return { ok: false, error: "備註需在 200 字內且不含控制字元" };
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/.test(dueRaw)) return { ok: false, error: "請設定期限（含時區的日期時間）" };
  const due = Date.parse(dueRaw);
  if (Number.isNaN(due)) return { ok: false, error: "期限格式錯誤" };
  if (due <= now) return { ok: false, error: "期限必須晚於現在" };
  if (due - now > MAX_DUE_MS) return { ok: false, error: "期限最多設定在 30 天內" };
  return { ok: true, value: { owner, due_at: new Date(due).toISOString(), note } };
}

export type ReminderKind = "due_soon" | "overdue";

/** 這次排程要送哪一種提醒（每種每個期限只送一次，由呼叫端以 Redis 冪等鍵保證）。 */
export function reminderDue(t: Pick<Tracking, "status" | "due_at">, now = Date.now()): ReminderKind | null {
  const s = trackState(t, now);
  return s === "overdue" ? "overdue" : s === "due_soon" ? "due_soon" : null;
}

/** 從情資比對報告（intel/<id>.json 的 1_summary）整理事件日期、可信度與來源。 */
export function eventDetailFrom(rep: Record<string, any> | null | undefined): EventDetail {
  const s = rep?.blocks?.["1_summary"] ?? {};
  const demo = rep?.event?.kind === "demo" || Boolean(rep?.event?.demo);
  const sources: EventSource[] = (Array.isArray(s.sources) ? s.sources : []).slice(0, 5).map((src: any) => {
    const url = typeof src?.url === "string" && /^https?:\/\/[^\s"'<>]+$/.test(src.url) ? src.url : null;
    let publisher: string | null = null;
    try { publisher = url ? new URL(url).hostname.replace(/^www\./, "") : null; } catch { publisher = null; }
    return { title: String(src?.title ?? "（無標題）").slice(0, 200), url, publisher,
             verified: src?.fetch_status === "ok", demo: demo || src?.verification_basis === "demo" || !url,
             quote: typeof src?.quote === "string" ? src.quote.slice(0, 200) : null };
  });
  return { date: typeof s.date === "string" ? s.date : null, confidence: typeof s.confidence === "string" ? s.confidence : null, sources };
}
