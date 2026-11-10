// POST /api/budget：Workflow 的 Agent 在呼叫 Claude API 前預留、完成後結算月預算（NOTIFY_TOKEN 保護）。
// GET /api/budget：本月用量（NOTIFY_TOKEN 保護，供對帳）。
// 預留失敗（額度不足、服務未設定）時 Agent 一律改用程式範本，報告照常產出。
import { budgetConfig, reserve, settle, status, toMicro } from "@/lib/budget";
import { redisConfigured } from "@/lib/redis";
import { HttpError, bearerMatches, json, readJsonBody } from "@/lib/security";

export const dynamic = "force-dynamic";

function guard(req: Request): Response | null {
  if (!process.env.NOTIFY_TOKEN || !redisConfigured()) return json({ ok: false, reason: "預算服務未設定" }, 503);
  if (!bearerMatches(req, process.env.NOTIFY_TOKEN)) return json({ ok: false, reason: "未授權" }, 401);
  return null;
}

export async function POST(req: Request): Promise<Response> {
  const denied = guard(req);
  if (denied) return denied;
  try {
    const body = await readJsonBody(req, ["action", "key", "amount_usd", "actual_usd"], 1024);
    const key = String(body.key ?? "");
    if (body.action === "reserve") {
      const amount = toMicro(body.amount_usd);
      if (amount === null) return json({ ok: false, reason: "amount_usd 格式錯誤" }, 400);
      const r = await reserve(key, amount, new Date(), budgetConfig());
      return json(r, r.ok ? 200 : 409);
    }
    if (body.action === "settle") {
      const actual = toMicro(body.actual_usd);
      if (actual === null) return json({ ok: false, reason: "actual_usd 格式錯誤" }, 400);
      const r = await settle(key, actual);
      return json(r, r.ok ? 200 : 404);
    }
    return json({ ok: false, reason: "action 只能是 reserve 或 settle" }, 400);
  } catch (e) {
    if (e instanceof HttpError) return json({ ok: false, reason: e.message }, e.status);
    return json({ ok: false, reason: "預算服務暫時無法使用" }, 503);   // Agent 會改用範本
  }
}

export async function GET(req: Request): Promise<Response> {
  const denied = guard(req);
  if (denied) return denied;
  try {
    return json(await status());
  } catch {
    return json({ ok: false, reason: "預算服務暫時無法使用" }, 503);
  }
}
