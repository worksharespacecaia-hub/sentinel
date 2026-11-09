// POST /api/run：網站觸發 sentinel.yml（第 11.2 節）。
// 伺服器固定 default branch、情境白名單、trigger_source=web、WEB_EXECUTION_MODE（預設 replay）；客戶端不能改成 manual 或 live。
import { randomUUID } from "node:crypto";
import { dispatchSentinel, findRunByRequest } from "@/lib/github";
import { redisConfigured, redis } from "@/lib/redis";
import { HttpError, acquireLock, clientKey, json, passcodeMatches, rateLimit, readJsonBody, releaseLock } from "@/lib/security";

export const dynamic = "force-dynamic";

const WEB_SCENARIOS = new Set(["daily", "intel-demo", "peer-incident", "early-signal", "php2shell", "nas", "insider-path", "mobile-sdk"]);
const LEASE = "run:web:lease";
const COOLDOWN = "run:web:cooldown";

export async function POST(req: Request): Promise<Response> {
  try {
    if (!process.env.DEMO_PASSCODE) return json({ error: "示範密碼未設定，已停用觸發" }, 503);
    if (!redisConfigured()) return json({ error: "Redis 未設定，無法保證不重複觸發，已停用" }, 503);
    const body = await readJsonBody(req, ["scenario", "passcode", "admin_passcode"]);
    if (!(await rateLimit(`rl:run:${clientKey(req)}`, 10, 60))) return json({ error: "嘗試次數過多，請稍後再試" }, 429);
    if (!passcodeMatches(body.passcode, process.env.DEMO_PASSCODE)) return json({ error: "密碼錯誤" }, 401);
    const scenario = String(body.scenario ?? "");
    if (!WEB_SCENARIOS.has(scenario)) return json({ error: "不允許的情境" }, 400);
    let admin = false;
    if (body.admin_passcode !== undefined) {
      admin = passcodeMatches(body.admin_passcode, process.env.ADMIN_PASSCODE);   // 未設定 ADMIN_PASSCODE 時永遠 false
      if (!admin) return json({ error: "管理者密碼錯誤" }, 401);
    }
    const cooldownTtl = Number(await redis<number>("TTL", COOLDOWN));
    if (cooldownTtl > 0 && !admin) return json({ error: `網站每小時最多觸發一次，約 ${Math.ceil(cooldownTtl / 60)} 分鐘後可再執行` }, 429);
    const lease = await acquireLock(LEASE, 120);    // 管理者也不能略過並行鎖
    if (!lease) return json({ error: "已有執行請求處理中" }, 429);

    const requestId = `web-${randomUUID()}`;
    const mode = process.env.WEB_EXECUTION_MODE === "live" ? "live" : "replay";
    await redis("SET", `run:req:${requestId}`, JSON.stringify({ scenario, mode, created_at: new Date().toISOString() }), "EX", 86400);
    const result = await dispatchSentinel({ scenario, trigger_source: "web", execution_mode: mode, request_id: requestId });
    if (result.ok) {
      await redis("SET", COOLDOWN, "1", "EX", 3600);
      await releaseLock(LEASE, lease);
      return json({ request_id: requestId, status_url: `/api/status?request_id=${requestId}` }, 202);
    }
    if (result.definite) {
      await releaseLock(LEASE, lease);
      return json({ error: `派發失敗：${result.error}` }, 502);
    }
    // 逾時且不確定是否送達：先查 request_id，不盲目重送；鎖讓它自然過期
    const run = await findRunByRequest(requestId).catch(() => null);
    if (run) {
      await redis("SET", COOLDOWN, "1", "EX", 3600);
      return json({ request_id: requestId, status_url: `/api/status?request_id=${requestId}` }, 202);
    }
    return json({ error: "派發狀態不確定，請稍後查詢", request_id: requestId }, 504);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    return json({ error: "伺服器暫時無法處理" }, 503);
  }
}
