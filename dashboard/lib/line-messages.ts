// LINE 訊息格式（純函式）：標題一定寫燈號或等級文字（不能只靠顏色）；只放摘要與連結，不放金鑰、IP 等機敏細節。
import type { ActionItem, ActionReport, ReminderKind } from "./actions.ts";
import { TRACK_TEXT } from "./actions.ts";
import type { Light } from "./data";
import { LEVEL_TEXT, LIGHT_TEXT, fmtTime } from "./labels.ts";
import type { LineMessage } from "./line.ts";

const COLOR: Record<Light, string> = { red: "#B42318", yellow: "#8A5A00", green: "#1A7F37" };
const LIGHT_SHORT: Record<Light, string> = { red: "紅燈", yellow: "黃燈", green: "綠燈" };

export const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

const text = (t: string, extra: Record<string, unknown> = {}) => ({ type: "text", text: clip(t || "—", 2000), wrap: true, size: "sm", ...extra });
const uriButton = (label: string, uri: string, primary = false) =>
  ({ type: "button", style: primary ? "primary" : "link", height: "sm", action: { type: "uri", label: clip(label, 20), uri } });
const postbackButton = (label: string, data: string) =>
  ({ type: "button", style: "secondary", height: "sm", action: { type: "postback", label: clip(label, 20), data: data.slice(0, 300), displayText: clip(label, 60) } });

function bubble(title: string, color: string, body: Record<string, unknown>[], buttons: Record<string, unknown>[]) {
  return {
    type: "bubble",
    header: { type: "box", layout: "vertical", backgroundColor: color, contents: [text(title, { color: "#FFFFFF", weight: "bold", size: "md" })] },
    body: { type: "box", layout: "vertical", spacing: "sm", contents: body },
    ...(buttons.length ? { footer: { type: "box", layout: "vertical", spacing: "sm", contents: buttons } } : {}),
  };
}

export const flex = (altText: string, contents: Record<string, unknown>): LineMessage =>
  ({ type: "flex", altText: clip(altText, 400), contents });

export const QUICK_REPLY = {
  items: ["今日燈號", "最新告警", "行動報告"].map((t) => ({ type: "action", action: { type: "message", label: t, text: t } })),
};

export const textMessage = (t: string, quick = false): LineMessage => ({ type: "text", text: clip(t, 4500), ...(quick ? { quickReply: QUICK_REPLY } : {}) });

const itemLine = (i: ActionItem) =>
  `・${LEVEL_TEXT[i.level]}｜${i.headline}${i.tracking ? `（${TRACK_TEXT[i.track_state]}，期限 ${fmtTime(i.tracking.due_at)}）` : ""}`;

/** 行動報告摘要（手動傳送、燈號變化、查詢回覆共用）。 */
export function actionReportMessage(a: ActionReport, site: string | null, title?: string): LineMessage {
  const c = a.counts;
  const heading = title ?? `行動報告｜${LIGHT_TEXT[a.light]}`;
  const body = [
    ...a.summary.slice(0, 2).map((s) => text(s)),
    { type: "separator" },
    text(`高風險 ${c.high} 項、中風險 ${c.medium} 項｜處理中 ${c.in_progress}｜即將到期 ${c.due_soon}｜已逾期 ${c.overdue}`, { weight: "bold" }),
    ...a.items.slice(0, 3).map((i) => text(itemLine(i))),
    ...(a.decisions.length ? [text(`今天要決定的事：${a.decisions.length} 件`, { color: "#B42318" })] : []),
    text(`評估時間 ${fmtTime(a.generated_at)}｜虛構環境 Demo`, { size: "xs", color: "#666666" }),
  ];
  const buttons = site ? [uriButton("開啟行動報告", `${site}/report`, true), uriButton("今日重點", `${site}/brief`)] : [];
  return flex(`${heading}：高風險 ${c.high}、中風險 ${c.medium}`, bubble(heading, COLOR[a.light], body, buttons));
}

export function lightChangeMessage(prev: Light, next: Light, a: ActionReport, site: string | null): LineMessage {
  return actionReportMessage(a, site, `燈號變化：${LIGHT_SHORT[prev]} → ${LIGHT_TEXT[next]}`);
}

export interface AlertLike {
  id: string; rule_id: string; rule_title: string; level: string; light: "red" | "yellow"; asset_id: string; created_at: string;
  maps_to_event: string | null; simulated: boolean; summary: string; issue_url: string | null;
}

export function alertMessage(a: AlertLike, site: string | null): LineMessage {
  const title = `${a.simulated ? "［模擬］" : ""}${LIGHT_SHORT[a.light]}｜${a.rule_id} ${a.rule_title}`;
  const body = [
    text(`等級：${LEVEL_TEXT[a.level as keyof typeof LEVEL_TEXT] ?? a.level}`), text(`資產：${a.asset_id}`),
    text(`時間：${fmtTime(a.created_at)}`), text(`對應事件：${a.maps_to_event ?? "—"}`), text(`模擬：${a.simulated ? "是" : "否"}`),
    text(a.summary, { color: "#444444" }),
  ];
  const buttons = [
    postbackButton("查看圍堵建議", `a=advice&id=${a.id}`),
    ...(site ? [uriButton("開啟網站", `${site}/live`)] : []),
    ...(a.issue_url && a.issue_url.startsWith("https://github.com/") ? [uriButton("開啟 GitHub Issue", a.issue_url)] : []),
  ];
  return flex(title, bubble(title, COLOR[a.light], body, buttons));
}

export function reminderMessage(i: ActionItem, kind: ReminderKind, site: string | null): LineMessage {
  const head = kind === "overdue" ? "已逾期" : "即將到期";
  const title = `${head}｜${LEVEL_TEXT[i.level]}風險`;
  const t = i.tracking;
  const body = [
    text(i.headline, { weight: "bold" }),
    text(`負責人：${t?.owner ?? "—"}`), text(`期限：${t ? fmtTime(t.due_at) : "—"}`),
    ...(t?.note ? [text(`備註：${t.note}`)] : []),
    text("完成修正後，下次評估確認不再命中才會標示已修復。", { size: "xs", color: "#666666" }),
  ];
  const buttons = site ? [uriButton("開啟行動報告", `${site}/report#${encodeURIComponent(i.id)}`, true)] : [];
  return flex(`${title}：${i.headline}`, bubble(title, kind === "overdue" ? COLOR.red : COLOR.yellow, body, buttons));
}
