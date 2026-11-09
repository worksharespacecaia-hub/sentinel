// 未結案告警的摘要（Phase 6 擴充完整告警儲存）。Redis 取用失敗時回報 degraded，不能回空清單假裝沒有告警。
import { redis, redisConfigured } from "./redis";
import type { OpenAlertsInfo } from "./summary";

export const OPEN_INDEX_REAL = "alerts:open:real";
export const OPEN_INDEX_SIM = "alerts:open:sim";

export async function openAlertsInfo(): Promise<OpenAlertsInfo> {
  if (!redisConfigured()) return { realHighOpen: 0, simulatedOpen: 0, degraded: "即時告警服務（Redis）未設定" };
  try {
    const [real, sim] = await Promise.all([redis<number>("SCARD", `${OPEN_INDEX_REAL}:high`), redis<number>("SCARD", OPEN_INDEX_SIM)]);
    return { realHighOpen: Number(real) || 0, simulatedOpen: Number(sim) || 0, degraded: null };
  } catch (e) {
    return { realHighOpen: 0, simulatedOpen: 0, degraded: `即時告警狀態無法取得（${(e as Error).message}）` };
  }
}
