// 即時規則（第 7.6 節）：純函式，判斷單一事件的靜態條件；時間窗與去重由 lib/window.ts 以 Redis Lua 原子完成。
// 規則來源為 rules/realtime.yaml，建置時打包成 realtime-rules.json（scripts/build-rules.py）。刻意不用 LLM。
// 這裡的 RULES 是預設值；網站「偵測規則」頁調整的參數由 lib/rule-store.ts 套用後才是實際判斷用的規則。
import ruleset from "./realtime-rules.json" with { type: "json" };

export type Source = "github.deployment" | "db.audit" | "support.complaint";
export type Level = "high" | "medium" | "low";

export interface RuleWindow {
  minutes?: number; hours?: number; anchor?: "event_time"; group_by?: "account"; metric?: "rows_read_sum";
  over_baseline_multiplier?: number; baseline_source?: string; distinct?: "brand"; threshold?: number;
}
export interface Rule {
  id: string; title: string; source: Source; asset_key: string; level: Level; light?: "red" | "yellow";
  dedup_minutes: number; maps_to_event?: string;
  match: {
    environment?: string; creator_not_in?: string[]; table?: string; event_hour_between?: [number, number];
    ip_seen_before?: boolean; text_regex?: string; text_regex_flags?: string;
  };
  window?: RuleWindow;
}
export interface Baselines { unit: string; default: number; accounts: Record<string, number> }

/** 內部事件：必須有唯一 ID、UTC event_time、伺服器 received_at、source、asset/account。 */
export interface RtEvent {
  id: string; source: Source; event_time: string; received_at: string; asset_id: string;
  account: string | null; simulated: boolean; simulation_id: string | null;
  data: {
    environment?: string; creator?: string; ref?: string; sha?: string;              // github.deployment
    table?: string; rows_read?: number; ip?: string;                                  // db.audit
    brand?: string; text?: string;                                                    // support.complaint
  };
}

export const RULES: Rule[] = ruleset.rules as Rule[];
export const BASELINES: Baselines = ruleset.baselines as Baselines;
export const RULES_DIGEST: string = ruleset.digest;
export const RULE_ASSETS = new Set(RULES.map((r) => r.asset_key));

export const EVENT_ID_RE = /^[a-z0-9][a-z0-9:._-]{2,120}$/;
export const SIM_ID_RE = /^sim-[0-9]{12}-[a-f0-9]{6}$/;
export const ALERT_ID_RE = /^al-rt-[0-9]{3}-[a-f0-9]{16}$/;

/** 台灣不實施日光節約時間，固定 UTC+8。以事件本身的時間戳判斷，不用伺服器時間。 */
export function taipeiHour(iso: string): number {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) throw new Error("時間格式錯誤");
  return new Date(t + 8 * 3600 * 1000).getUTCHours();
}

export function windowMs(w: RuleWindow): number {
  return ((w.minutes ?? 0) * 60 + (w.hours ?? 0) * 3600) * 1000;
}

export function baselineFor(account: string, b: Baselines = BASELINES): number {
  const v = b.accounts[account] ?? b.default;
  if (!(v > 0)) throw new Error("基準必須 > 0");
  return v;
}

export interface StaticResult { ok: boolean; reason: string }

/**
 * 靜態條件（只看這一筆事件）。ip_seen_before 依賴歷史狀態，於 lib/window.ts 的 Lua 內判斷。
 * text_regex 以 text_regex_flags 建立（JavaScript 不支援 (?i)）。
 */
export function staticMatch(rule: Rule, ev: RtEvent): StaticResult {
  if (rule.source !== ev.source) return { ok: false, reason: "來源不同" };
  const m = rule.match;
  if (m.environment !== undefined && ev.data.environment !== m.environment) return { ok: false, reason: `環境不是 ${m.environment}` };
  if (m.creator_not_in && (!ev.data.creator || m.creator_not_in.includes(ev.data.creator))) {
    return { ok: false, reason: "由 Pipeline 發起" };
  }
  if (m.table !== undefined && ev.data.table !== m.table) return { ok: false, reason: `資料表不是 ${m.table}` };
  if (m.event_hour_between) {
    const [from, to] = m.event_hour_between;
    const h = taipeiHour(ev.event_time);
    if (!(h >= from && h < to)) return { ok: false, reason: `事件時間 ${h} 時不在 ${from}～${to} 時` };
  }
  if (m.text_regex !== undefined) {
    const re = new RegExp(m.text_regex, m.text_regex_flags ?? "");
    if (!re.test(ev.data.text ?? "")) return { ok: false, reason: "內容不含訂單資訊" };
  }
  if (rule.window?.group_by === "account" && !ev.account) return { ok: false, reason: "缺少帳號" };
  if (rule.window?.metric === "rows_read_sum" && !(Number.isFinite(ev.data.rows_read) && (ev.data.rows_read ?? 0) >= 0)) {
    return { ok: false, reason: "缺少讀取列數" };
  }
  if (m.ip_seen_before === false && !ev.data.ip) return { ok: false, reason: "缺少來源 IP" };
  if (rule.window?.distinct === "brand" && !ev.data.brand) return { ok: false, reason: "缺少品牌" };
  return { ok: true, reason: "靜態條件成立" };
}

/** rules：套用網站設定後的實際規則（lib/rule-store.ts）；省略時用預設規則。停用的規則不判斷。 */
export function rulesFor(source: Source, rules: (Rule & { enabled?: boolean })[] = RULES): Rule[] {
  return rules.filter((r) => r.source === source && r.enabled !== false);
}

/** 真實事件拒絕未來超過 5 分鐘或延遲超過 24 小時；模擬時間只作用於該次 simulation_id，不套用。 */
export function timeCheck(ev: RtEvent, nowMs: number): string | null {
  const t = Date.parse(ev.event_time);
  if (Number.isNaN(t)) return "事件時間格式錯誤";
  if (ev.simulated) return null;
  if (t > nowMs + 5 * 60 * 1000) return "事件時間超過伺服器時間 5 分鐘以上（未來時間）";
  if (t < nowMs - 24 * 3600 * 1000) return "事件延遲超過 24 小時";
  return null;
}

/** 命名空間：真實為 real，模擬為 sim:<simulation_id>，所有 key、去重、已知 IP 都分開。 */
export function namespaceOf(ev: Pick<RtEvent, "simulated" | "simulation_id">): string {
  if (!ev.simulated) return "real";
  if (!ev.simulation_id || !SIM_ID_RE.test(ev.simulation_id)) throw new Error("模擬事件缺少合法的 simulation_id");
  return `sim:${ev.simulation_id}`;
}

export function validateEvent(ev: RtEvent): string | null {
  if (!EVENT_ID_RE.test(ev.id)) return "事件 ID 格式錯誤";
  if (!RULE_ASSETS.has(ev.asset_id)) return "資產不在即時規則範圍";
  if (ev.account !== null && !/^[A-Za-z0-9._@-]{1,64}$/.test(ev.account)) return "帳號格式錯誤";
  if (ev.data.ip !== undefined && !/^[0-9a-fA-F:.]{3,45}$/.test(ev.data.ip)) return "IP 格式錯誤";
  if (ev.data.brand !== undefined && !/^[a-z0-9-]{2,40}$/.test(ev.data.brand)) return "品牌格式錯誤";
  if ((ev.data.text ?? "").length > 2000) return "內容過長";
  return null;
}

/** 對外顯示的去敏文字：遮蔽訂單編號類字串，不顯示 IP。 */
export function maskText(text: string): string {
  return text.replace(/[A-Z0-9][A-Z0-9-]{7,}/gi, (s) => `${s.slice(0, 2)}${"*".repeat(Math.min(s.length - 2, 8))}`).slice(0, 160);
}
