// 未結案告警的摘要。Redis 取用失敗或未結案索引需重建時回報 degraded，不能回空清單假裝沒有告警。
import { indexState, openCounts } from "./alertstore.ts";
import { redisConfigured } from "./redis.ts";
import type { OpenAlertsInfo } from "./summary";

export async function openAlertsInfo(): Promise<OpenAlertsInfo> {
  if (!redisConfigured()) return { realHighOpen: 0, simulatedOpen: 0, degraded: "異常行為偵測服務（Redis）未設定" };
  try {
    const idx = await indexState();
    const c = await openCounts();
    return { realHighOpen: c.realHigh, simulatedOpen: c.sim, degraded: idx.degraded };
  } catch (e) {
    return { realHighOpen: 0, simulatedOpen: 0, degraded: `異常行為偵測的告警狀態無法取得（${(e as Error).message}）` };
  }
}
