// GET /api/status?request_id=...：只查伺服器建立過的 request_id 對應的 run，不回傳「最近一次」（可能是別的情境或排程）。
import { findRunByRequest, listJobs } from "@/lib/github";
import { redis, redisConfigured } from "@/lib/redis";
import { json } from "@/lib/security";

export const dynamic = "force-dynamic";
const REQ_RE = /^web-[0-9a-f-]{36}$/;

export async function GET(req: Request): Promise<Response> {
  const id = new URL(req.url).searchParams.get("request_id") ?? "";
  if (!REQ_RE.test(id)) return json({ error: "request_id 格式錯誤" }, 400);
  if (!redisConfigured()) return json({ error: "Redis 未設定" }, 503);
  try {
    if (!(await redis<string | null>("GET", `run:req:${id}`))) return json({ error: "找不到這個請求" }, 404);
    const cached = await redis<string | null>("GET", `run:status:${id}`);
    if (cached) return json(JSON.parse(cached));
    const run = await findRunByRequest(id);
    const body = run
      ? { request_id: id, status: run.status, conclusion: run.conclusion, html_url: run.html_url, run_id: run.id, jobs: await listJobs(run.id) }
      : { request_id: id, status: "queued", conclusion: null, html_url: null, jobs: [] };
    await redis("SET", `run:status:${id}`, JSON.stringify(body), "EX", 10);   // 伺服器端快取 10 秒
    return json(body);
  } catch {
    return json({ error: "暫時無法取得執行狀態", degraded: true }, 503);
  }
}
