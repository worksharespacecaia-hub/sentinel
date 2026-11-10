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
  orchestrator: "Orchestrator", a0: "A0 資產探索與對帳", "daily-intel": "每日情資（程式抓新聞＋Claude 判讀）", a1: "A1 外部情資", a2: "A2 弱點掃描", a3: "A3 早期訊號",
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
