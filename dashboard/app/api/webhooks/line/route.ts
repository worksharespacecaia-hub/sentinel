// POST /api/webhooks/line：LINE 官方帳號 Webhook（規格第 7.7 節）。
// 以原始 body 驗證 X-Line-Signature（不符回 401）→ 先回 200 → after() 內依序處理事件，一律用 Reply API（不計入額度）。
// - follow：回覆「請輸入綁定碼」；unfollow 或輸入「解除」：移除管理者
// - 未綁定者只能綁定；查詢只得到「請先輸入綁定碼」，不透露任何資訊。只接受 1:1 對話，拒絕 group／room
// - message 與每一個 postback 都重新驗證 userId 是否已綁定；以 webhookEventId 去重；不重用 reply token
import { after } from "next/server";
import { getAlert, getAlerts, openIds } from "@/lib/alertstore";
import { resolveSource } from "@/lib/data";
import { LIGHT_TEXT, fmtTime } from "@/lib/labels";
import { bind, claimEvent, isAdmin, reply, siteUrl, unbind, USER_ID_RE, verifySignature, type LineMessage } from "@/lib/line";
import { QUICK_REPLY, actionReportMessage, textMessage } from "@/lib/line-messages";
import { redisConfigured } from "@/lib/redis";
import { loadActionReport } from "@/lib/report-data";
import { json, passcodeMatches } from "@/lib/security";
import { BodyTooLarge, readRawBody } from "@/lib/webhook";
import { ALERT_ID_RE } from "@/lib/rules";

export const dynamic = "force-dynamic";

const KEYWORDS = new Set(["今日燈號", "最新告警", "行動報告", "解除", "說明"]);
const NEED_BIND = "請先輸入綁定碼。";
const HELP = "可以點下方按鈕查詢：今日燈號、最新告警、行動報告。輸入「解除」可取消綁定。";

interface LineEvent {
  type: string; mode?: string; webhookEventId?: string; replyToken?: string;
  source?: { type?: string; userId?: string };
  message?: { type?: string; text?: string }; postback?: { data?: string };
}

async function reportMessage(title?: string): Promise<LineMessage> {
  const loaded = await loadActionReport(await resolveSource(undefined));
  if (!loaded) return textMessage("尚未有評估結果。", true);
  return { ...actionReportMessage(loaded.action, siteUrl(), title ? `${title}｜${LIGHT_TEXT[loaded.action.light]}` : undefined), quickReply: QUICK_REPLY };
}

async function latestAlerts(): Promise<LineMessage> {
  const list = (await getAlerts(await openIds(false))).sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 5);
  const site = siteUrl();
  if (!list.length) return textMessage(`目前沒有未結案的真實告警。${site ? `\n${site}/live` : ""}`, true);
  const lines = list.map((a) => `${a.light === "red" ? "紅燈" : "黃燈"}｜${a.rule_id} ${a.rule_title}\n資產 ${a.asset_id}｜${fmtTime(a.created_at)}｜${a.status}`);
  return textMessage(`未結案的真實告警（最近 ${list.length} 筆）\n\n${lines.join("\n\n")}${site ? `\n\n${site}/live` : ""}`, true);
}

async function adviceMessage(alertId: string): Promise<LineMessage> {
  if (!ALERT_ID_RE.test(alertId)) return textMessage("找不到這個告警。", true);
  const a = await getAlert(alertId);
  if (!a) return textMessage("找不到這個告警（可能已過保留期）。", true);
  if (a.advice?.comment_url) return textMessage(`${a.rule_id} 的圍堵建議（只建議、不執行）：\n${a.advice.comment_url}`, true);
  return textMessage(`${a.rule_id} 的圍堵建議尚未完成，完成後再點一次即可。${a.issue_url ? `\n${a.issue_url}` : ""}`, true);
}

async function handle(ev: LineEvent): Promise<void> {
  if (ev.mode === "standby") return;                                   // standby 不能回覆
  if (ev.webhookEventId && !(await claimEvent(ev.webhookEventId))) return;
  const userId = ev.source?.userId ?? "";
  const token = ev.replyToken;
  const send = async (m: LineMessage) => { if (token) await reply(token, [m]); };

  if (ev.source?.type !== "user" || !USER_ID_RE.test(userId)) {
    if (ev.type === "message") await send(textMessage("Sentinel 只接受 1 對 1 聊天，請直接加入官方帳號好友。"));
    return;
  }
  if (ev.type === "unfollow") return unbind(userId);
  const admin = await isAdmin(userId);
  if (ev.type === "follow") return send(textMessage(admin ? `已綁定。${HELP}` : "歡迎使用 Sentinel 資安哨兵（Demo）。請輸入綁定碼。", admin));
  if (ev.type === "postback") {
    if (!admin) return send(textMessage(NEED_BIND));
    const p = new URLSearchParams(ev.postback?.data ?? "");
    if (p.get("a") === "advice") return send(await adviceMessage(p.get("id") ?? ""));
    if (p.get("a") === "report") return send(await reportMessage());
    return send(textMessage(HELP, true));
  }
  if (ev.type !== "message" || ev.message?.type !== "text") return;
  const text = (ev.message.text ?? "").trim();

  if (!admin) {
    if (KEYWORDS.has(text)) return send(textMessage(NEED_BIND));
    if (!process.env.LINE_BIND_CODE) return send(textMessage("綁定功能未啟用，請聯絡系統管理者。"));
    const r = await bind(userId, passcodeMatches(text, process.env.LINE_BIND_CODE));
    const msg = { bound: `已綁定。之後會收到高風險告警、燈號變化與到期提醒。${HELP}`, already: `已綁定。${HELP}`,
                  wrong: "綁定碼錯誤。", locked: "錯誤次數過多，請 1 小時後再試。", full: "管理者已滿，無法綁定。" }[r];
    return send(textMessage(msg, r === "bound" || r === "already"));
  }
  if (text === "解除") {
    await unbind(userId);
    return send(textMessage("已解除綁定，不會再收到通知。"));
  }
  if (text === "今日燈號") return send(await reportMessage("今日燈號"));
  if (text === "行動報告") return send(await reportMessage());
  if (text === "最新告警") return send(await latestAlerts());
  return send(textMessage(HELP, true));
}

export async function POST(req: Request): Promise<Response> {
  const secret = process.env.LINE_CHANNEL_SECRET;
  if (!secret || !process.env.LINE_CHANNEL_ACCESS_TOKEN) return json({ error: "LINE 未設定" }, 503);
  let raw: string;
  try {
    raw = await readRawBody(req);
  } catch (e) {
    return json({ error: e instanceof BodyTooLarge ? "請求內容超過 1 MB" : "無法讀取請求內容" }, e instanceof BodyTooLarge ? 413 : 400);
  }
  if (!verifySignature(raw, req.headers.get("x-line-signature"), secret)) return json({ error: "簽章驗證失敗" }, 401);
  let body: { events?: LineEvent[] };
  try {
    body = JSON.parse(raw);
  } catch {
    return json({ error: "JSON 格式錯誤" }, 400);
  }
  const events = Array.isArray(body.events) ? body.events.slice(0, 20) : [];
  if (!events.length) return json({ ok: true });                       // LINE 的連線測試
  if (!redisConfigured()) return json({ error: "Redis 未設定" }, 503);
  after(async () => {
    for (const ev of events) {
      try {
        await handle(ev);
      } catch {
        // 單一事件失敗只略過（回覆失敗不重試），不影響其他事件
      }
    }
  });
  return json({ ok: true });
}
