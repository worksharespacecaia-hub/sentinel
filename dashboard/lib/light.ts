// 有效燈號的合併規則（第 7.5 節），不讀檔、不連 Redis，方便單元測試。
// 取 daily、尚未被完整評估解除的正式 advisory，以及所有未結案（open／contained）的真實高風險告警之最高等級。
// 模擬告警只影響即時監控頁；必要來源失聯時至少黃燈並標示資料不足。

export type Light = "red" | "yellow" | "green";

export interface OpenAlertsInfo { realHighOpen: number; simulatedOpen: number; degraded: string | null }

export interface DailyInfo { light: Light; light_reasons: string[]; generated_at: string; run_id?: string }

export interface AdvisoryInfo { id: string; light: Light; run_id: string }

export const DAILY_MAX_AGE_MS = 36 * 3600 * 1000;

const RANK: Record<Light, number> = { green: 0, yellow: 1, red: 2 };

export function combineLight(daily: DailyInfo | null, advisories: AdvisoryInfo[], alerts: OpenAlertsInfo,
                             now = Date.now()): { light: Light; reasons: string[]; degraded: string[] } {
  const reasons: string[] = [];
  const degraded: string[] = [];
  let light: Light = "green";
  const bump = (l: Light, why: string) => {
    if (RANK[l] > RANK[light]) light = l;
    if (l !== "green") reasons.push(why);
  };
  if (!daily) {
    degraded.push("每日評估結果缺失");
    bump("yellow", "資料不足：沒有每日評估結果");
  } else {
    bump(daily.light, `每日評估：${daily.light_reasons.join("；")}`);
    if (now - new Date(daily.generated_at).getTime() > DAILY_MAX_AGE_MS) {
      degraded.push("每日評估超過 36 小時未更新");
      bump("yellow", "資料不足：每日評估過期");
    }
  }
  for (const a of advisories) if (a.light !== "green") bump(a.light, `正式公告調查 ${a.id}：${a.light === "red" ? "高風險" : "中風險"}`);
  if (alerts.realHighOpen > 0) bump("red", `${alerts.realHighOpen} 個未結案的即時高風險告警`);
  if (alerts.degraded) {
    degraded.push(alerts.degraded);
    bump("yellow", "資料不足：異常行為偵測的告警狀態無法取得");
  }
  return { light, reasons, degraded };
}
