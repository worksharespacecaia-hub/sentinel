// 有效燈號（第 7.5 節）：讀取 daily、正式 advisory 與即時告警狀態，再以 lib/light.ts 的規則合併。
// 情境與模擬告警只影響各自畫面。必要來源失聯時至少黃燈並標示資料不足。
import { getIndex, getReport } from "./data";
import { combineLight, type AdvisoryInfo, type Light, type OpenAlertsInfo } from "./light.ts";

export type { OpenAlertsInfo } from "./light.ts";

export interface Summary {
  light: Light; reasons: string[]; degraded: string[]; daily: { run_id?: string; generated_at?: string; light?: Light } | null;
  advisories: AdvisoryInfo[]; alerts: OpenAlertsInfo; simulated: { alerts: number };
}

export async function computeSummary(alerts: OpenAlertsInfo): Promise<Summary> {
  const idx = await getIndex();
  const daily = idx.latest_daily ? await getReport({ key: "daily", dir: "daily", label: "每日", simulated: false }) : null;
  const advisories = Object.entries(idx.advisories ?? {}).map(([id, e]) => ({ id, light: e.light, run_id: e.run_id }));
  const { light, reasons, degraded } = combineLight(daily, advisories, alerts);
  return {
    light, reasons, degraded,
    daily: daily ? { run_id: daily.run_id, generated_at: daily.generated_at, light: daily.light } : null,
    advisories, alerts, simulated: { alerts: alerts.simulatedOpen },
  };
}
