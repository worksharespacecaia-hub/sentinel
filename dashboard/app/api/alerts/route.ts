// GET /api/alerts：最近事件與告警、全部未結案告警的分頁清單（不以最近 50 筆推導 open 數量）。回應只含去敏資料。
// Redis／GitHub 取用失敗或索引需重建時回報 degraded，不能回空清單假裝沒有告警。
import { getAlerts, indexState, openCounts, openIds, pruneSimIndex, toPublic, K } from "@/lib/alertstore";
import { redis, redisConfigured } from "@/lib/redis";
import { json } from "@/lib/security";
import { readFeed } from "@/lib/window";

export const dynamic = "force-dynamic";
const PAGE = 20;

export async function GET(req: Request): Promise<Response> {
  if (!redisConfigured()) return json({ degraded: "即時告警服務（Redis）未設定", available: false }, 503);
  try {
    const page = Math.max(0, Math.min(1000, Number(new URL(req.url).searchParams.get("open_page") ?? 0) || 0));
    const idx = await indexState();
    const [feed, recentIds, realIds, simIds, counts] = await Promise.all([
      readFeed(50), redis<string[]>("LRANGE", K.recent, 0, 49), openIds(false), openIds(true), openCounts(),
    ]);
    realIds.sort();
    const pageIds = realIds.slice(page * PAGE, (page + 1) * PAGE);
    const [recent, openReal, openSim] = await Promise.all([getAlerts(recentIds ?? []), getAlerts(pageIds), getAlerts(simIds)]);
    await pruneSimIndex(simIds, new Set(openSim.map((a) => a.id)));
    const degraded: string[] = [];
    if (idx.degraded) degraded.push(idx.degraded);
    if (openReal.length < pageIds.length) degraded.push("部分未結案告警的資料缺失，需從 GitHub Issues 重建");
    const byCreated = (a: { created_at: string }, b: { created_at: string }) => b.created_at.localeCompare(a.created_at);
    return json({
      available: true, degraded: degraded.join("；") || null, now: new Date().toISOString(),
      counts: { real_open: counts.real, real_high_open: counts.realHigh, simulated_open: openSim.length },
      events: feed, recent: recent.map(toPublic),
      open: { real: openReal.sort(byCreated).map(toPublic), real_total: realIds.length, page, pages: Math.ceil(realIds.length / PAGE),
              simulated: openSim.sort(byCreated).map(toPublic) },
      line: { enabled: false, reason: "LINE 通知未啟用（P2）" },
    });
  } catch (e) {
    return json({ available: false, degraded: `即時告警狀態無法取得（${(e as Error).message.slice(0, 80)}）` }, 503);
  }
}
