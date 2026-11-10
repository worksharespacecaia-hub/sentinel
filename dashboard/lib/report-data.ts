// 伺服器端：組出行動報告需要的全部資料（報告、有效燈號、處理中追蹤、通知草稿）。網頁、LINE 推播與提醒共用。
import { buildActionReport, type ActionReport, type Notice, type Tracking } from "./actions.ts";
import { openAlertsInfo } from "./alerts.ts";
import { getIntelReport, getReport, type Report, type Source } from "./data.ts";
import { redisConfigured } from "./redis.ts";
import { computeSummary } from "./summary.ts";
import { openTracking } from "./tracking.ts";

export interface LoadedActionReport {
  report: Report; action: ActionReport;
  /** 追蹤狀態取不到時的原因（不能當成「沒有人在處理」）。情境不追蹤時為 null。 */
  trackingDegraded: string | null;
}

export async function loadTrackingSafe(): Promise<{ tracking: Record<string, Tracking>; degraded: string | null }> {
  if (!redisConfigured()) return { tracking: {}, degraded: "追蹤服務（Redis）未設定" };
  try {
    return { tracking: await openTracking(), degraded: null };
  } catch (e) {
    return { tracking: {}, degraded: `追蹤狀態暫時無法取得（${(e as Error).message}）` };
  }
}

export async function noticesFor(source: Source, report: Report): Promise<Notice[]> {
  const affected = report.events.filter((e) => e.affected_count > 0);
  const reps = await Promise.all(affected.map((e) => getIntelReport(source, e.id)));
  return reps.flatMap((rep, i) => {
    const n = rep?.blocks?.["6_notice"];
    return n?.needed && typeof n.draft === "string" ? [{ event_id: affected[i].id, title: affected[i].title, draft: n.draft }] : [];
  });
}

export async function loadActionReport(source: Source, now = Date.now()): Promise<LoadedActionReport | null> {
  const report = await getReport(source);
  if (!report) return null;
  const [summary, track, notices] = await Promise.all([
    source.simulated ? Promise.resolve(null) : computeSummary(await openAlertsInfo()),
    source.simulated ? Promise.resolve({ tracking: {}, degraded: null }) : loadTrackingSafe(),
    noticesFor(source, report),
  ]);
  const action = buildActionReport(report, { light: summary?.light ?? report.light, tracking: track.tracking, notices, now });
  return { report, action, trackingDegraded: track.degraded };
}
