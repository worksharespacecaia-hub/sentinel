// Orchestrator（AI 提案、程式核准）的網站文字：純函式，不讀檔、不依賴其他模組，供頁面與測試共用。
// 只顯示白話文字：事件、風險與控制項用名稱，不顯示內部 ID、Subagent 名稱與欄位名稱（specs/dynamic-planner R9.4）。
//
// Report.agent_plan 的格式（specs/orchestrator R9.2）：
// - v0.13 起：{dispatch, review}（tools/orchestration.py 的 public_plan）；停用的那份為 null，兩份都停用時整個是 null
// - v0.11～v0.12：單一計畫（頂層有 source／approved），由每日情資提案、A1 核准，視為派工單
// - 更舊的報告沒有這個欄位

export type PlanSource = "subscription" | "live" | "replay" | "template" | "skipped";
export type PlanMode = "dispatch" | "review";

/** 核准項目：control（加查）、task（追加任務，目標為事件或風險）、priority（排優先）、summary（驗收的執行摘要） */
export interface PlanApproved {
  type: "control" | "task" | "priority" | "summary";
  event_id?: string; control_id?: string; agent?: string; subagent?: string; risk_id?: string; reason?: string; text?: string;
}
export interface PlanRejected {
  type: "control" | "task" | "priority" | "summary" | "field";
  event_id?: string; control_id?: string; agent?: string; subagent?: string; risk_id?: string;
  suggested_reason?: string; reason: string;
}
export interface AgentPlan {
  mode?: PlanMode; source: PlanSource; note: string | null; events: string[]; suggested: number; approved_count: number;
  rejected_count: number; control_titles?: Record<string, string>; approved: PlanApproved[]; rejected: PlanRejected[];
  summary?: string | null;
}
/** Report.agent_plan 可能的原始格式 */
export type RawAgentPlan = { dispatch?: AgentPlan | null; review?: AgentPlan | null } | AgentPlan | null;
/** 正規化後：legacy 為 v0.11～v0.12 的單一計畫（每日情資提案、A1 核准；放在 dispatch） */
export interface Plans { dispatch: AgentPlan | null; review: AgentPlan | null; legacy: boolean }

export interface ExtraCheck {
  control_id: string; title: string; status: "pass" | "fail" | "unknown"; status_label?: string;
  assets: { asset_id: string; evidence?: string[] }[]; check_reason?: string; suggested_reason?: string;
}

/** Orchestrator 追加結果（Report.orchestrator_results 與每份情資報告的同名欄位，R5.7） */
export interface OrchestratorResult {
  stage: "dispatch" | "review"; agent: string; subagent: string; target_type: "event" | "risk"; target_id: string;
  text: string; source: "live" | "replay" | "template";
}

export const PLAN_SOURCE_TEXT: Record<PlanSource, string> = {
  subscription: "訂閱方案", live: "即時呼叫", replay: "重播錄製", template: "程式範本", skipped: "未觸發",
};
const CHECK_TEXT: Record<string, string> = { pass: "符合", fail: "不符合", unknown: "資料不足" };

// 追加結果的白話標籤：與 agents/tools/intel_report.py 的 RESULT_LABEL、RESULT_SOURCE_ZH、STAGE_ZH 用詞一致（Markdown 同步）
export const RESULT_LABEL: Record<string, string> = {
  "a2/dependency-analyst": "依事件解讀套件漏洞", "a2/runtime-analyst": "依事件解讀執行環境與支援期限",
  "a3/retro-hunter": "依事件回溯搜查", "a5/intel-report-writer": "需確認事件的摘要",
  "a5/key-rotation-advisor": "金鑰輪替建議", "a5/brand-notice-writer": "通知草稿",
};
export const RESULT_SOURCE_TEXT: Record<OrchestratorResult["source"], string> = {
  live: "AI 撰寫", replay: "AI 撰寫（重播）", template: "程式範本",
};
export const STAGE_TEXT: Record<OrchestratorResult["stage"], string> = { dispatch: "派工", review: "驗收" };
const NOTICE_SUBAGENT = "brand-notice-writer";

// 追加任務的白話（依 agent／subagent）；選單見 tools/orchestration.py 的 DISPATCH_TASKS、REVIEW_TASKS
const TASK_TEXT: Record<string, string> = {
  "a2/dependency-analyst": "請 A2 依事件解讀套件漏洞",
  "a2/runtime-analyst": "請 A2 依事件解讀執行環境與支援期限",
  "a3/retro-hunter": "請 A3 回溯搜查相關系統的登入與資料庫紀錄",
  "a4/impact-analyst": "請 A4 說明相關風險",
  "a5/intel-report-writer": "請 A5 撰寫需確認事件的摘要",
  "a5/key-rotation-advisor": "請 A5 撰寫金鑰輪替建議",
  "a5/brand-notice-writer": "請 A5 撰寫通知草稿（程式未要求通知）",
};
const PRIORITY_TEXT: Record<string, string> = { a4: "排優先：A4 先說明這項風險", a5: "排優先：A5 先寫這項風險的解法與摘要" };

// ---------------------------------------------------------------- 格式相容（R9.2）

type Obj = Record<string, unknown>;
const isObj = (x: unknown): x is Obj => typeof x === "object" && x !== null && !Array.isArray(x);
const str = (x: unknown): string | undefined => (typeof x === "string" && x ? x : undefined);
const num = (x: unknown, fallback: number): number => (typeof x === "number" && Number.isFinite(x) ? x : fallback);

/** 一份計畫：缺少 approved／rejected 陣列時視為無效（null）；其他欄位補預設值，項目只保留物件。 */
function toPlan(raw: unknown, mode: PlanMode | undefined): AgentPlan | null {
  if (!isObj(raw) || !Array.isArray(raw.approved) || !Array.isArray(raw.rejected)) return null;
  const approved = raw.approved.filter(isObj) as unknown as PlanApproved[];
  const rejected = raw.rejected.filter(isObj) as unknown as PlanRejected[];
  const plan: AgentPlan = {
    source: (str(raw.source) ?? "template") as PlanSource,
    note: str(raw.note) ?? null,
    events: Array.isArray(raw.events) ? raw.events.filter((e): e is string => typeof e === "string") : [],
    suggested: num(raw.suggested, approved.length + rejected.length),
    approved_count: num(raw.approved_count, approved.length),
    rejected_count: num(raw.rejected_count, rejected.length),
    control_titles: isObj(raw.control_titles) ? (raw.control_titles as Record<string, string>) : {},
    approved, rejected,
  };
  if (mode) plan.mode = mode;
  if (mode === "review") plan.summary = str(raw.summary) ?? null;
  return plan;
}

/**
 * Report.agent_plan 的四種相容情況（R9.2）：沒有 agent_plan、舊的單一計畫（視為派工）、新格式但沒有驗收單、完整的雙計畫。
 * 格式不符的那份視為 null，不讓頁面出錯。
 */
export function normalizePlans(raw: unknown): Plans {
  if (!isObj(raw)) return { dispatch: null, review: null, legacy: false };
  if ("dispatch" in raw || "review" in raw) {
    return { dispatch: toPlan(raw.dispatch, "dispatch"), review: toPlan(raw.review, "review"), legacy: false };
  }
  if ("source" in raw) {
    const plan = toPlan(raw, undefined);
    return { dispatch: plan, review: null, legacy: plan !== null };
  }
  return { dispatch: null, review: null, legacy: false };
}

// ---------------------------------------------------------------- 計畫的白話

/** 一行摘要；未觸發、範本、零建議要能區分（dynamic-planner R9.5）。舊的單一計畫沿用「動態派工」字樣。 */
export function planSummary(plan: AgentPlan | null | undefined): string | null {
  if (!plan) return null;
  const head = plan.mode === "review" ? "Orchestrator 驗收" : plan.mode === "dispatch" ? "Orchestrator 派工" : "動態派工";
  const src = PLAN_SOURCE_TEXT[plan.source] ?? "未知來源";
  if (plan.source === "skipped") return `${head}：沒有新同業事件，未觸發`;
  if (plan.source === "template") {
    return plan.mode ? `${head}：AI 提案未產生，只跑必要任務（來源：${src}）` : `${head}：AI 建議未產生，維持原本派工（來源：${src}）`;
  }
  return `${head}：AI 建議 ${plan.suggested} 項、核准 ${plan.approved_count} 項、拒絕 ${plan.rejected_count} 項（來源：${src}）`;
}

export interface Names { events?: Record<string, string>; risks?: Record<string, string> }

function eventName(id: string | undefined, plan: AgentPlan, titles: Record<string, string>): string {
  return (id && titles[id]) || (plan.mode === "review" ? "本次事件" : "本次同業事件");
}

function riskName(id: string | undefined, titles: Record<string, string>): string {
  return (id && titles[id]) || "清單外的風險";
}

function controlName(id: string | undefined, plan: AgentPlan): string {
  return (id && plan.control_titles?.[id]) || "清單外的控制項";
}

/** 任務的對象：有 risk_id 用風險名稱，其他用事件名稱；目標為風險的任務（金鑰輪替）缺 ID 時寫「清單外的風險」。 */
function taskTarget(r: { agent?: string; subagent?: string; event_id?: string; risk_id?: string }, plan: AgentPlan,
                    events: Record<string, string>, risks: Record<string, string>): string {
  if (r.risk_id || r.subagent === "key-rotation-advisor") return riskName(r.risk_id, risks);
  return eventName(r.event_id, plan, events);
}

const taskText = (agent?: string, subagent?: string) => (agent && subagent && TASK_TEXT[`${agent}/${subagent}`]) || "追加工作";
const why = (reason: string | undefined) => (reason ? `——${reason}` : "");

/** 核准的項目，白話一句一列。第二個參數為事件名稱（相容舊呼叫），風險名稱放在第三個參數。 */
export function approvedLines(plan: AgentPlan, eventTitles: Record<string, string>, riskTitles: Record<string, string> = {}): string[] {
  return plan.approved.map((a) => {
    switch (a.type) {
      case "control":
        return `${eventName(a.event_id, plan, eventTitles)}：加查「${controlName(a.control_id, plan)}」${why(a.reason)}`;
      case "task":
        return `${taskTarget(a, plan, eventTitles, riskTitles)}：${taskText(a.agent, a.subagent)}${why(a.reason)}`;
      case "priority":
        return `${riskName(a.risk_id, riskTitles)}：${PRIORITY_TEXT[a.agent ?? ""] ?? "排優先"}${why(a.reason)}`;
      case "summary":
        return "執行摘要：通過程式檢查（內容見上方）";
      default:
        return `追加工作${why(a.reason)}`;
    }
  });
}

/** 被拒絕的建議與原因。未知欄位只顯示「多寫的欄位」，不顯示欄位名稱或值；被拒絕的摘要不保存原文。 */
export function rejectedLines(plan: AgentPlan, eventTitles: Record<string, string>, riskTitles: Record<string, string> = {}): string[] {
  return plan.rejected.map((r) => {
    switch (r.type) {
      case "field":
        return `多寫的欄位：${r.reason}`;
      case "control":
        return `${eventName(r.event_id, plan, eventTitles)}：${r.control_id ? `加查「${controlName(r.control_id, plan)}」` : "加查控制項"}——${r.reason}`;
      case "task":
        return `${taskTarget(r, plan, eventTitles, riskTitles)}：${taskText(r.agent, r.subagent)}——${r.reason}`;
      case "priority":
        return `${riskName(r.risk_id, riskTitles)}：排優先——${r.reason}`;
      case "summary":
        return `執行摘要——${r.reason}`;
      default:
        return `追加工作——${r.reason}`;
    }
  });
}

// ---------------------------------------------------------------- 追加結果（R5.7、R5.8）

const RESULT_STAGES = new Set(["dispatch", "review"]);
const RESULT_SOURCES = new Set(["live", "replay", "template"]);

/** 只保留格式正確的項目；舊報告沒有這個欄位時回傳空陣列。 */
export function normalizeResults(raw: unknown): OrchestratorResult[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((r): r is OrchestratorResult => isObj(r) && RESULT_STAGES.has(r.stage as string)
    && typeof r.agent === "string" && typeof r.subagent === "string"
    && (r.target_type === "event" || r.target_type === "risk") && typeof r.target_id === "string"
    && typeof r.text === "string" && r.text.trim() !== "" && RESULT_SOURCES.has(r.source as string));
}

export interface ResultRow {
  stage: string; label: string; targetType: "event" | "risk"; targetId: string; target: string; text: string;
  source: string; ai: boolean;
}

/**
 * 追加結果的列：notices 為通知草稿（brand-notice-writer，另外顯示），extra 為其他結果。
 * AI 撰寫的排前面、程式範本排後面，各自維持原順序。
 */
export function resultRows(raw: unknown, names: Names = {}): { extra: ResultRow[]; notices: ResultRow[] } {
  const row = (r: OrchestratorResult): ResultRow => ({
    stage: STAGE_TEXT[r.stage],
    label: RESULT_LABEL[`${r.agent}/${r.subagent}`] ?? "追加說明",
    targetType: r.target_type,
    targetId: r.target_id,
    target: r.target_type === "risk" ? riskName(r.target_id, names.risks ?? {}) : (names.events?.[r.target_id] || "本次事件"),
    text: r.text,
    source: RESULT_SOURCE_TEXT[r.source],
    ai: r.source !== "template",
  });
  const order = (xs: OrchestratorResult[]) => [...xs.filter((r) => r.source !== "template"), ...xs.filter((r) => r.source === "template")].map(row);
  const all = normalizeResults(raw);
  return { extra: order(all.filter((r) => r.subagent !== NOTICE_SUBAGENT)), notices: order(all.filter((r) => r.subagent === NOTICE_SUBAGENT)) };
}

/** 情資報告 6_notice 的「AI 建議的通知草稿（程式未要求）」：沒有 draft_extra 時回傳 null。 */
export function noticeExtra(notice: unknown): { text: string; source: string } | null {
  if (!isObj(notice) || typeof notice.draft_extra !== "string" || !notice.draft_extra.trim()) return null;
  const src = notice.draft_extra_source;
  return { text: notice.draft_extra,
           source: typeof src === "string" && src in RESULT_SOURCE_TEXT ? RESULT_SOURCE_TEXT[src as OrchestratorResult["source"]] : "程式範本" };
}

/**
 * 需確認事件的摘要來源：不是程式範本時，代表驗收追加的 intel-report-writer 撰寫（必要任務只寫受影響事件的摘要）。
 * 其他情況回傳 null，由頁面沿用原本的來源文字。
 */
export function reviewSummarySource(status: unknown, source: unknown): string | null {
  if (status !== "need_check" || (source !== "live" && source !== "replay")) return null;
  return `${RESULT_SOURCE_TEXT[source]}，Orchestrator 驗收追加`;
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
