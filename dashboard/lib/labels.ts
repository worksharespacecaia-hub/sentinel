import type { Level, Light } from "./data";

export const LIGHT_TEXT: Record<Light, string> = {
  red: "紅燈：需要今天決策",
  yellow: "黃燈：本週內處理",
  green: "綠燈：目前沒有未處理的中高風險",
};
export const LEVEL_TEXT: Record<Level, string> = { high: "高", medium: "中", low: "低" };
export const STATUS_TEXT: Record<string, string> = {
  open: "待處理", fixed: "已修復", need_check: "需確認", not_affected: "不受影響",
};
export const KIND_TEXT: Record<string, string> = { live: "真實", archive: "真實・已收錄", demo: "示範", advisory: "公告" };
export const SOURCE_TEXT: Record<string, string> = { live: "即時呼叫", replay: "重播錄製", template: "程式範本" };
export const AGENT_TEXT: Record<string, string> = {
  orchestrator: "Orchestrator", a0: "A0 資產探索與對帳", "daily-intel": "每日情資（程式抓新聞＋Claude 判讀）", "claude-analysis": "Claude 撰寫說明（訂閱方案）", a1: "A1 外部情資", a2: "A2 弱點掃描", a3: "A3 早期訊號",
  a4: "A4 攻擊鏈與風險", a5: "A5 報告與建議", incident: "圍堵建議",
};

export function deadlineText(hours: number): string {
  return hours <= 24 ? "24 小時內" : hours <= 168 ? "7 天內" : "30 天內";
}

export function fmtTime(iso: string | undefined | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return new Intl.DateTimeFormat("zh-TW", { timeZone: "Asia/Taipei", dateStyle: "medium", timeStyle: "short" }).format(d);
}

/** 台灣日期 YYYY-MM-DD（行動報告標題、資安事件整理的保留窗口共用）。 */
export function taipeiDate(t: string | Date): string {
  return new Intl.DateTimeFormat("sv-SE", { timeZone: "Asia/Taipei" }).format(typeof t === "string" ? new Date(t) : t);
}

const WEEKDAY = ["日", "一", "二", "三", "四", "五", "六"];

/** 日曆日期標題："2026-11-11" → "11 月 11 日（三）"；格式不符時原樣回傳。 */
export function fmtDateHeading(ymd: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(ymd);
  if (!m) return ymd;
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  if (d.getUTCFullYear() !== Number(m[1]) || d.getUTCMonth() !== Number(m[2]) - 1 || d.getUTCDate() !== Number(m[3])) return ymd;
  return `${Number(m[2])} 月 ${Number(m[3])} 日（${WEEKDAY[d.getUTCDay()]}）`;
}

/** 資安事件整理的「與我們的關係」。 */
export const RELATION_TEXT: Record<"affected" | "need_check" | "not_affected" | "fixed", string> = {
  affected: "受影響", need_check: "需確認", not_affected: "不受影響", fixed: "已修復",
};
