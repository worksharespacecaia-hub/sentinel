// 有效燈號（第 7.5 節）：取 daily、尚未被完整評估解除的正式 advisory，以及所有未結案的真實高風險告警之最高等級。
// 情境與模擬告警只影響各自畫面。必要來源失聯時至少黃燈並標示資料不足。
import { getIndex, getReport, type Light } from "./data";

const RANK: Record<Light, number> = { green: 0, yellow: 1, red: 2 };

export interface OpenAlertsInfo { realHighOpen: number; simulatedOpen: number; degraded: string | null }

export interface Summary {
  light: Light; reasons: string[]; degraded: string[]; daily: { run_id?: string; generated_at?: string; light?: Light } | null;
  advisories: { id: string; light: Light; run_id: string }[]; alerts: OpenAlertsInfo; simulated: { alerts: number };
}

export async function computeSummary(alerts: OpenAlertsInfo): Promise<Summary> {
  const idx = await getIndex();
  const reasons: string[] = [];
  const degraded: string[] = [];
  let light: Light = "green";
  const bump = (l: Light, why: string) => {
    if (RANK[l] > RANK[light]) light = l;
    if (l !== "green") reasons.push(why);
  };
  const daily = idx.latest_daily ? await getReport({ key: "daily", dir: "daily", label: "每日", simulated: false }) : null;
  if (!daily) {
    degraded.push("每日評估結果缺失");
    bump("yellow", "資料不足：沒有每日評估結果");
  } else {
    bump(daily.light, `每日評估：${daily.light_reasons.join("；")}`);
    const age = Date.now() - new Date(daily.generated_at).getTime();
    if (age > 36 * 3600 * 1000) {
      degraded.push("每日評估超過 36 小時未更新");
      bump("yellow", "資料不足：每日評估過期");
    }
  }
  const advisories = Object.entries(idx.advisories ?? {}).map(([id, e]) => ({ id, light: e.light, run_id: e.run_id }));
  for (const a of advisories) if (a.light !== "green") bump(a.light, `正式公告調查 ${a.id}：${a.light === "red" ? "高風險" : "中風險"}`);
  if (alerts.realHighOpen > 0) bump("red", `${alerts.realHighOpen} 個未結案的即時高風險告警`);
  if (alerts.degraded) {
    degraded.push(alerts.degraded);
    bump("yellow", "資料不足：即時告警狀態無法取得");
  }
  return {
    light, reasons, degraded,
    daily: daily ? { run_id: daily.run_id, generated_at: daily.generated_at, light: daily.light } : null,
    advisories, alerts, simulated: { alerts: alerts.simulatedOpen },
  };
}
