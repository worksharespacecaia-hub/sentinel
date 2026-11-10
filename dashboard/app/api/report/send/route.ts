// POST /api/report/send：管理者手動把行動報告摘要推給已綁定的 LINE 管理者（demo 現場用）。
// 需 ADMIN_PASSCODE；每來源原子限流；另有全站每小時 3 次上限，保護每月 200 則的推播額度。只傳 daily（正式）報告。
import { resolveSource } from "@/lib/data";
import { pushToAdmins, siteUrl } from "@/lib/line";
import { actionReportMessage } from "@/lib/line-messages";
import { redisConfigured } from "@/lib/redis";
import { loadActionReport } from "@/lib/report-data";
import { HttpError, clientKey, json, passcodeMatches, rateLimit, readJsonBody } from "@/lib/security";

export const dynamic = "force-dynamic";

export async function POST(req: Request): Promise<Response> {
  try {
    if (!process.env.ADMIN_PASSCODE) return json({ error: "管理者密碼未設定，已停用傳送" }, 503);
    if (!redisConfigured()) return json({ error: "Redis 未設定" }, 503);
    const body = await readJsonBody(req, ["admin_passcode"], 1024);
    if (!(await rateLimit(`rl:admin:${clientKey(req)}`, 10, 60))) return json({ error: "操作過於頻繁，請稍後再試" }, 429);
    if (!passcodeMatches(body.admin_passcode, process.env.ADMIN_PASSCODE)) return json({ error: "管理者密碼錯誤" }, 401);
    if (!(await rateLimit("rl:line:report", 3, 3600))) return json({ error: "每小時最多手動傳送 3 次" }, 429);
    const loaded = await loadActionReport(await resolveSource(undefined));
    if (!loaded) return json({ error: "尚未有評估結果" }, 404);
    const result = await pushToAdmins([actionReportMessage(loaded.action, siteUrl())], "report");
    return json({ ok: true, result });
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    return json({ error: "傳送服務暫時無法處理" }, 503);
  }
}
