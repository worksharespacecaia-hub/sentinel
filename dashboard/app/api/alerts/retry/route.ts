// POST /api/alerts/retry：管理者重試尚未成功的交付步驟（Issue、dispatch、狀態同步）。LINE 維持不自動重試。
// 重試前會先查既有 Issue marker／incident 執行，避免重複建立與重複付費。
import { StoreError, getAlert, toPublic } from "@/lib/alertstore";
import { deliver, pendingSteps } from "@/lib/delivery";
import { redisConfigured } from "@/lib/redis";
import { ALERT_ID_RE } from "@/lib/rules";
import { HttpError, clientKey, json, passcodeMatches, rateLimit, readJsonBody } from "@/lib/security";

export const dynamic = "force-dynamic";

export async function POST(req: Request): Promise<Response> {
  try {
    if (!process.env.ADMIN_PASSCODE) return json({ error: "管理者密碼未設定，已停用重試" }, 503);
    if (!redisConfigured()) return json({ error: "Redis 未設定" }, 503);
    const body = await readJsonBody(req, ["admin_passcode", "alert_id"], 1024);
    if (!(await rateLimit(`rl:admin:${clientKey(req)}`, 10, 60))) return json({ error: "操作過於頻繁，請稍後再試" }, 429);
    if (!passcodeMatches(body.admin_passcode, process.env.ADMIN_PASSCODE)) return json({ error: "管理者密碼錯誤" }, 401);
    const id = String(body.alert_id ?? "");
    if (!ALERT_ID_RE.test(id)) return json({ error: "alert_id 格式錯誤" }, 400);
    const before = await getAlert(id);
    if (!before) return json({ error: "找不到這個告警" }, 404);
    const steps = pendingSteps(before).filter((s) => s !== "line");
    if (!steps.length) return json({ ok: true, retried: [], alert: toPublic(before) });
    const after = await deliver(id, steps);
    return json({ ok: true, retried: steps, alert: after ? toPublic(after) : null });
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    if (e instanceof StoreError) return json({ error: e.message }, 409);
    return json({ error: "告警服務暫時無法處理" }, 503);
  }
}
