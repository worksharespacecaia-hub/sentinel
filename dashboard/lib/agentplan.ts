// 動態派工（AI 建議、程式核准）的網站文字：純函式，不讀檔、不依賴其他模組，供頁面與測試共用。
// 只顯示白話文字：事件與控制項用名稱，不顯示內部 ID 與欄位名稱（specs/dynamic-planner R9.4）。

export type PlanSource = "subscription" | "live" | "replay" | "template" | "skipped";

export interface PlanApproved {
  type: "control" | "task"; event_id: string; control_id?: string; agent?: string; subagent?: string; reason: string;
}
export interface PlanRejected {
  type: "control" | "task" | "field"; event_id?: string; control_id?: string; agent?: string; subagent?: string;
  suggested_reason?: string; reason: string;
}
export interface AgentPlan {
  source: PlanSource; note: string | null; events: string[]; suggested: number; approved_count: number; rejected_count: number;
  control_titles?: Record<string, string>; approved: PlanApproved[]; rejected: PlanRejected[];
}
export interface ExtraCheck {
  control_id: string; title: string; status: "pass" | "fail" | "unknown"; status_label?: string;
  assets: { asset_id: string; evidence?: string[] }[]; check_reason?: string; suggested_reason?: string;
}

export const PLAN_SOURCE_TEXT: Record<PlanSource, string> = {
  subscription: "訂閱方案", live: "即時呼叫", replay: "重播錄製", template: "程式範本", skipped: "未觸發",
};
const CHECK_TEXT: Record<string, string> = { pass: "符合", fail: "不符合", unknown: "資料不足" };

/** 執行紀錄頁的一行摘要；未觸發、範本、零建議要能區分（R9.5）。 */
export function planSummary(plan: AgentPlan | null | undefined): string | null {
  if (!plan) return null;
  const src = PLAN_SOURCE_TEXT[plan.source] ?? "未知來源";
  if (plan.source === "skipped") return "動態派工：沒有新同業事件，未觸發";
  if (plan.source === "template") return `動態派工：AI 建議未產生，維持原本派工（來源：${src}）`;
  return `動態派工：AI 建議 ${plan.suggested} 項、核准 ${plan.approved_count} 項、拒絕 ${plan.rejected_count} 項（來源：${src}）`;
}

function eventName(id: string | undefined, titles: Record<string, string>): string {
  return (id && titles[id]) || "本次同業事件";
}

function controlName(id: string | undefined, plan: AgentPlan): string {
  return (id && plan.control_titles?.[id]) || "清單外的控制項";
}

/** 核准的工作，白話一句一列。 */
export function approvedLines(plan: AgentPlan, eventTitles: Record<string, string>): string[] {
  return plan.approved.map((a) => a.type === "control"
    ? `${eventName(a.event_id, eventTitles)}：加查「${controlName(a.control_id, plan)}」——${a.reason}`
    : `${eventName(a.event_id, eventTitles)}：請 A4 說明相關風險——${a.reason}`);
}

/** 被拒絕的建議與原因。未知欄位只顯示「多寫的欄位」，不顯示欄位名稱或值。 */
export function rejectedLines(plan: AgentPlan, eventTitles: Record<string, string>): string[] {
  return plan.rejected.map((r) => {
    if (r.type === "field") return `多寫的欄位：${r.reason}`;
    const what = r.type === "control"
      ? (r.control_id ? `加查「${controlName(r.control_id, plan)}」` : "加查控制項")
      : (r.agent ? "請 A4 說明相關風險" : "追加工作");
    return `${eventName(r.event_id, eventTitles)}：${what}——${r.reason}`;
  });
}

/** 事件頁「AI 建議加查」的列：狀態一律附文字，空資產明說（不由空陣列推論符合）。 */
export function extraCheckRows(checks: ExtraCheck[] | undefined | null) {
  return (checks ?? []).map((c) => ({
    title: c.title,
    status: c.status_label ?? CHECK_TEXT[c.status] ?? "資料不足",
    assets: c.assets.length ? c.assets.map((a) => a.asset_id).join("、") : "無列出資產",
    checkReason: c.check_reason || "—",
    suggestedReason: c.suggested_reason || "—",
  }));
}
