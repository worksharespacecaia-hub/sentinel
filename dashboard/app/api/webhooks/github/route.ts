// POST /api/webhooks/github：Repo ① 的 Deployments Webhook（第 7.6、11.2 節）。
// 以原始 body 驗證 X-Hub-Signature-256（不符回 401，不拋 500）→ 驗證 Repo ID、event/action、production → 規則引擎。
// 告警先原子寫入 Redis 才回應；Issue／dispatch 由 after()（平台管理的生命週期）接續，不啟動未受管理的背景 Promise。
import { after } from "next/server";
import { deliver } from "@/lib/delivery";
import { redis, redisConfigured } from "@/lib/redis";
import { json } from "@/lib/security";
import { BodyTooLarge, parseDeployment, readRawBody, verifySignature } from "@/lib/webhook";
import { processEvent } from "@/lib/window";

export const dynamic = "force-dynamic";
const DELIVERY_RE = /^[A-Za-z0-9-]{8,64}$/;

export async function POST(req: Request): Promise<Response> {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  const repoId = process.env.GITHUB_TARGET_REPO_ID;
  if (!secret || !repoId || !/^\d+$/.test(repoId)) return json({ error: "Webhook 未設定" }, 503);
  let raw: string;
  try {
    raw = await readRawBody(req);
  } catch (e) {
    return json({ error: e instanceof BodyTooLarge ? "請求內容超過 1 MB" : "無法讀取請求內容" }, e instanceof BodyTooLarge ? 413 : 400);
  }
  if (!verifySignature(raw, req.headers.get("x-hub-signature-256"), secret)) return json({ error: "簽章驗證失敗" }, 401);

  const event = req.headers.get("x-github-event") ?? "";
  const delivery = req.headers.get("x-github-delivery") ?? "";
  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    return json({ error: "JSON 格式錯誤" }, 400);
  }
  if (event === "ping") return json({ ok: true, pong: true });
  if (event !== "deployment") return json({ ignored: `不處理 ${event.replace(/[^\w-]/g, "").slice(0, 40)} 事件` }, 202);
  if (!DELIVERY_RE.test(delivery)) return json({ error: "缺少 X-GitHub-Delivery" }, 400);

  const receivedAt = new Date().toISOString();
  const parsed = parseDeployment(body, repoId, receivedAt);
  if (!parsed.ok) return json(parsed.status < 300 ? { ignored: parsed.reason } : { error: parsed.reason }, parsed.status);
  if (!redisConfigured()) return json({ error: "Redis 未設定，無法保存告警" }, 503);

  try {
    const dkey = `rt:real:delivery:${delivery}`;
    if (await redis<string | null>("GET", dkey)) return json({ duplicate: true, reason: "同一 Webhook delivery 已處理" });
    const pr = await processEvent(parsed.event);
    await redis("SET", dkey, "1", "EX", 2 * 86400);
    for (const id of pr.alerts) after(() => deliver(id).then(() => undefined, () => undefined));
    return json({ event_id: pr.event_id, alerts: pr.alerts, rejected: pr.rejected, results: pr.results, timeline: pr.timeline });
  } catch {
    return json({ error: "告警服務暫時無法處理" }, 503);
  }
}
