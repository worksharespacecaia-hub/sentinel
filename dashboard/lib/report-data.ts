// 伺服器端：組出行動報告需要的全部資料（報告、有效燈號、處理中追蹤、通知草稿）。網頁、LINE 推播與提醒共用。
import { buildActionReport, eventDetailFrom, type ActionReport, type EventDetail, type Notice, type Tracking } from "./actions.ts";
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

/** 受影響事件的通知草稿與來源（讀各事件的情資比對報告）。 */
export async function eventInfoFor(source: Source, report: Report): Promise<{ notices: Notice[]; details: Record<string, EventDetail> }> {
  const affected = report.events.filter((e) => e.affected_count > 0);
  const reps = await Promise.all(affected.map((e) => getIntelReport(source, e.id)));
  const details: Record<string, EventDetail> = {};
  const notices = reps.flatMap((rep, i) => {
    details[affected[i].id] = eventDetailFrom(rep);
    const n = rep?.blocks?.["6_notice"];
    return n?.needed && typeof n.draft === "string" ? [{ event_id: affected[i].id, title: affected[i].title, draft: n.draft }] : [];
  });
  return { notices, details };
}

export async function loadActionReport(source: Source, now = Date.now()): Promise<LoadedActionReport | null> {
  const report = await getReport(source);
  if (!report) return null;
  const [summary, track, info] = await Promise.all([
    source.simulated ? Promise.resolve(null) : computeSummary(await openAlertsInfo()),
    source.simulated ? Promise.resolve({ tracking: {}, degraded: null }) : loadTrackingSafe(),
    eventInfoFor(source, report),
  ]);
  const action = buildActionReport(report, { light: summary?.light ?? report.light, tracking: track.tracking,
                                             notices: info.notices, eventDetails: info.details, now });
  return { report, action, trackingDegraded: track.degraded };
}
