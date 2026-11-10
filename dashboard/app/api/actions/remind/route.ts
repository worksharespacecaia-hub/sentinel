// POST /api/actions/remind：每小時由 .github/workflows/reminders.yml 呼叫（NOTIFY_TOKEN 保護）。
// 處理中的項目：期限前 24 小時推一次「即將到期」、超過期限推一次「已逾期」（同一期限、同一種提醒只送一次）。
// 重新評估已判定修復（或完整評估中已不存在）的項目自動結束追蹤，不再提醒。推播失敗只記錄、不重試。
import { buildActionReport, reminderDue, type ReminderKind } from "@/lib/actions";
import { getReport, resolveSource } from "@/lib/data";
import { pushToAdmins, siteUrl, type PushState } from "@/lib/line";
import { reminderMessage } from "@/lib/line-messages";
import { redisConfigured } from "@/lib/redis";
import { bearerMatches, json } from "@/lib/security";
import { autoClose, claimReminder, openTracking } from "@/lib/tracking";

export const dynamic = "force-dynamic";

export async function POST(req: Request): Promise<Response> {
  if (!process.env.NOTIFY_TOKEN || !redisConfigured()) return json({ error: "提醒服務未設定" }, 503);
  if (!bearerMatches(req, process.env.NOTIFY_TOKEN)) return json({ error: "未授權" }, 401);
  try {
    const [tracking, report] = await Promise.all([openTracking(), getReport(await resolveSource(undefined))]);
    if (!report) return json({ error: "沒有每日評估結果" }, 503);
    const action = buildActionReport(report, { tracking });
    const now = Date.now();
    const closed: string[] = [];
    const sent: { risk_id: string; kind: ReminderKind; state: PushState; reason?: string }[] = [];
    for (const t of Object.values(tracking)) {
      const risk = report.risks.find((r) => r.id === t.risk_id);
      if (risk?.status === "fixed" || (!risk && report.completeness === "complete")) {
        await autoClose(t.risk_id, risk ? "重新評估判定已修復" : "完整評估中已不存在這一項風險");
        closed.push(t.risk_id);
        continue;
      }
      const kind = reminderDue(t, now);
      const item = action.items.find((i) => i.id === t.risk_id);
      if (!kind || !item || !(await claimReminder(t.risk_id, t.due_at, kind))) continue;
      const r = await pushToAdmins([reminderMessage(item, kind, siteUrl())], "reminder");
      sent.push({ risk_id: t.risk_id, kind, state: r.state, reason: r.reason });
    }
    return json({ ok: true, checked: Object.keys(tracking).length, closed, sent });
  } catch (e) {
    return json({ error: `提醒服務暫時無法處理（${(e as Error).message.slice(0, 80)}）` }, 503);
  }
}
