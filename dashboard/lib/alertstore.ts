// 告警儲存（第 7.6 節「告警交付與結案」）：Redis 為即時狀態，GitHub Issue 為持久稽核來源。
// - 告警以 HASH alert:<id> {json, v} 保存，所有修改以版本號比較後寫入（CAS），避免並行覆蓋
// - 獨立維護全部未結案 ID 索引（不以最近 50 筆推導）；索引不存在時從 Issues 重建，重建完成前標示資料不足
// - 結案只能由管理者附證據執行；TTL、Issue 被關閉或 LLM 建議完成都不會結案
import { evalLua, redis, redisConfigured } from "./redis.ts";
import { ALERT_ID_RE, RULES, type Level } from "./rules.ts";

export type StepState = "pending" | "running" | "done" | "failed" | "skipped";
export interface Step {
  state: StepState; attempts: number; last_error: string | null; updated_at: string | null; lease_until: string | null;
  uncertain?: boolean; reason?: string; target_status?: AlertStatus; history_index?: number;
}
export type AlertStatus = "open" | "contained" | "closed";
export type DeliveryStep = "issue" | "dispatch" | "line" | "sync";
export interface StatusChange { from: AlertStatus; to: AlertStatus; actor: string; reason: string; evidence_url: string; at: string }
export interface Alert {
  id: string; rule_id: string; rule_title: string; level: Level; light: "red" | "yellow"; asset_id: string; account: string | null;
  simulated: boolean; simulation_id: string | null; summary: string; maps_to_event: string | null; metric: number | null;
  repo: string | null; issue_number: number | null; issue_url: string | null; source_event_ids: string[]; dedup_key: string;
  delivery: Record<DeliveryStep, Step>;
  timeline: { event_received: string; rule_evaluated: string | null; alert_created: string; issue_created: string | null;
              dispatched: string | null; advice_ready: string | null };
  advice: { comment_url: string; source: string; run_id: string; at: string } | null;
  status: AlertStatus; status_history: StatusChange[]; created_at: string; rebuilt?: boolean;
  /** 只在狀態變更時遞增；管理者以它避免互相覆蓋（交付紀錄等內部更新不影響）。 */
  status_version: number;
  /** Redis 內部 CAS 版本（每次寫入都遞增），不給前端當作操作依據。 */
  version?: number;
}

export const K = {
  alert: (id: string) => `alert:${id}`,
  open: (sim: boolean) => (sim ? "alerts:open:sim" : "alerts:open:real"),
  openHigh: (sim: boolean) => (sim ? "alerts:open:sim:high" : "alerts:open:real:high"),
  recent: "alerts:recent",
  meta: "alerts:index:meta",
  rebuildLock: "alerts:rebuild:lock",
  stepLock: (id: string, step: DeliveryStep) => `alert:${id}:lock:${step}`,
};
export const SIM_ALERT_TTL = 7 * 86400;
export const CLOSED_ALERT_TTL = 30 * 86400;

export const TRANSITIONS: Record<AlertStatus, AlertStatus[]> = { open: ["contained"], contained: ["closed", "open"], closed: [] };

export function newStep(state: StepState = "pending", reason?: string): Step {
  return { state, attempts: 0, last_error: null, updated_at: null, lease_until: null, ...(reason ? { reason } : {}) };
}

/** 建立告警的 Lua 片段（由 lib/window.ts 的規則腳本內嵌使用，與事件寫入／去重在同一個原子步驟）。 */
export const CREATE_ALERT_LUA = `
local function create_alert(akey, open_key, high_key, recent_key, json, id, is_high, ttl)
  redis.call('HSET', akey, 'json', json, 'v', '1')
  if tonumber(ttl) > 0 then redis.call('EXPIRE', akey, ttl) end
  redis.call('SADD', open_key, id)
  if is_high == '1' then redis.call('SADD', high_key, id) end
  redis.call('LPUSH', recent_key, id)
  redis.call('LTRIM', recent_key, 0, 49)
end
`;

// KEYS: alert, open, openHigh, dedup   ARGV: expected_v, json, status, is_high, id, closed_ttl
const UPDATE_LUA = `
local v = redis.call('HGET', KEYS[1], 'v')
if not v then return {'missing', '0'} end
if v ~= ARGV[1] then return {'conflict', v} end
local nv = tostring(tonumber(v) + 1)
redis.call('HSET', KEYS[1], 'json', ARGV[2], 'v', nv)
if ARGV[3] == 'closed' then
  redis.call('SREM', KEYS[2], ARGV[5])
  redis.call('SREM', KEYS[3], ARGV[5])
  redis.call('EXPIRE', KEYS[1], ARGV[6])
  if redis.call('GET', KEYS[4]) == ARGV[5] then redis.call('DEL', KEYS[4]) end
else
  redis.call('SADD', KEYS[2], ARGV[5])
  if ARGV[4] == '1' then redis.call('SADD', KEYS[3], ARGV[5]) end
end
return {'ok', nv}
`;

export class StoreError extends Error {
  code: "missing" | "conflict" | "invalid";
  constructor(code: "missing" | "conflict" | "invalid", message: string) {
    super(message);
    this.code = code;
  }
}

export async function getAlert(id: string): Promise<Alert | null> {
  if (!ALERT_ID_RE.test(id)) return null;
  const row = await redis<string[] | null>("HMGET", K.alert(id), "json", "v");
  if (!row || !row[0]) return null;
  const a = JSON.parse(row[0]) as Alert;
  a.version = Number(row[1]);
  return a;
}

export async function getAlerts(ids: string[]): Promise<Alert[]> {
  const out = await Promise.all(ids.filter((i) => ALERT_ID_RE.test(i)).map(getAlert));
  return out.filter((a): a is Alert => a !== null);
}

async function writeAlert(a: Alert, expected: number): Promise<number> {
  const { version: _drop, ...body } = a;
  const res = await evalLua<[string, string]>(UPDATE_LUA,
    [K.alert(a.id), K.open(a.simulated), K.openHigh(a.simulated), a.dedup_key],
    [String(expected), JSON.stringify(body), a.status, a.level === "high" ? "1" : "0", a.id, CLOSED_ALERT_TTL]);
  if (res[0] === "missing") throw new StoreError("missing", "告警不存在");
  if (res[0] === "conflict") throw new StoreError("conflict", "告警已被其他操作更新");
  return Number(res[1]);
}

/** 讀取 → 修改 → 以版本號寫回；衝突時重讀重試（最多 4 次）。用於受信任程式的內部更新（交付狀態、建議完成）。 */
export async function patchAlert(id: string, mutate: (a: Alert) => void): Promise<Alert> {
  for (let i = 0; i < 4; i++) {
    const a = await getAlert(id);
    if (!a) throw new StoreError("missing", "告警不存在");
    const before = a.version!;
    mutate(a);
    try {
      a.version = await writeAlert(a, before);
      return a;
    } catch (e) {
      if (!(e instanceof StoreError && e.code === "conflict")) throw e;
    }
  }
  throw new StoreError("conflict", "告警更新衝突過多");
}

export interface StatusInput { to: AlertStatus; actor: string; reason: string; evidence_url: string; containment_confirmed?: boolean; reverified?: boolean }

export function checkTransition(a: Pick<Alert, "status">, input: StatusInput): string | null {
  if (!TRANSITIONS[a.status].includes(input.to)) return `不允許 ${a.status} → ${input.to}`;
  if (input.to === "closed" && !(input.containment_confirmed === true && input.reverified === true)) {
    return "結案前必須確認已圍堵並重新驗證";
  }
  return null;
}

/**
 * 管理者狀態轉移：呼叫端帶入看到的 status_version；其他管理者已先變更狀態就拒絕（避免覆蓋）。
 * 背景交付更新只改內部版本，寫入衝突時重讀並重新檢查 status_version。保留稽核紀錄並排入 Issue 同步。
 */
export async function changeStatus(id: string, expectedStatusVersion: number, input: StatusInput, now = new Date()): Promise<Alert> {
  for (let i = 0; i < 4; i++) {
    const a = await getAlert(id);
    if (!a) throw new StoreError("missing", "告警不存在");
    if (a.status_version !== expectedStatusVersion) throw new StoreError("conflict", "告警狀態已被其他操作更新，請重新整理後再試");
    const err = checkTransition(a, input);
    if (err) throw new StoreError("invalid", err);
    const internal = a.version!;
    a.status_history.push({ from: a.status, to: input.to, actor: input.actor, reason: input.reason, evidence_url: input.evidence_url, at: now.toISOString() });
    a.status = input.to;
    a.status_version += 1;
    a.delivery.sync = { ...newStep(), target_status: input.to, history_index: a.status_history.length - 1 };
    try {
      a.version = await writeAlert(a, internal);
      return a;
    } catch (e) {
      if (!(e instanceof StoreError && e.code === "conflict")) throw e;
    }
  }
  throw new StoreError("conflict", "告警更新衝突過多，請稍後再試");
}

// ------------------------------------------------------------------ 索引與重建

export interface IndexState { ok: boolean; degraded: string | null }

/** 未結案索引是否可信：meta 存在代表索引是完整的（由重建程式設定；建立告警不會設定，避免 Redis 清空後誤判）。 */
export async function indexState(rebuild: () => Promise<RebuildResult> = rebuildFromIssues): Promise<IndexState> {
  const meta = await redis<string | null>("GET", K.meta);
  if (meta) return { ok: true, degraded: null };
  const res = await rebuild().catch((e: Error) => ({ ok: false, reason: `重建失敗：${e.message}` }) as RebuildResult);
  return res.ok ? { ok: true, degraded: null } : { ok: false, degraded: `未結案告警索引需從 GitHub Issues 重建（${res.reason}）` };
}

export interface RebuildResult { ok: boolean; reason: string; restored?: number }

export interface IssueRecord { number: number; html_url: string; state: string; labels: string[]; body: string }

const MARKER_RE = /<!-- sentinel-alert (\{.*?\}) -->/;

/** 從 Issue 內容還原告警（只取受信任程式寫入的 marker 與 status 標籤；Issue 被關閉不代表結案）。 */
export function alertFromIssue(issue: IssueRecord, repo: string): Alert | null {
  const m = MARKER_RE.exec(issue.body ?? "");
  if (!m) return null;
  let meta: Record<string, unknown>;
  try {
    meta = JSON.parse(m[1]);
  } catch {
    return null;
  }
  const id = String(meta.alert_id ?? "");
  const rule = RULES.find((r) => r.id === meta.rule_id);
  if (!ALERT_ID_RE.test(id) || !rule || meta.simulated !== false) return null;   // 只重建真實告警
  const statusLabel = issue.labels.find((l) => l.startsWith("status:"))?.slice(7) as AlertStatus | undefined;
  const status: AlertStatus = statusLabel === "contained" || statusLabel === "closed" ? statusLabel : "open";
  const created = String(meta.created_at ?? new Date(0).toISOString());
  return {
    id, rule_id: rule.id, rule_title: rule.title, level: rule.level, light: rule.light ?? "red", asset_id: rule.asset_key,
    account: null, simulated: false, simulation_id: null, summary: `${rule.title}（由 GitHub Issue #${issue.number} 重建）`,
    maps_to_event: rule.maps_to_event ?? null, metric: null, repo, issue_number: issue.number, issue_url: issue.html_url,
    source_event_ids: [], dedup_key: String(meta.dedup_key ?? ""),
    delivery: { issue: { ...newStep("done") }, dispatch: { ...newStep("done"), reason: "重建：狀態以 Issue 為準" },
                line: newStep("skipped", "重建的告警不重送通知"), sync: newStep("done") },
    timeline: { event_received: created, rule_evaluated: null, alert_created: created, issue_created: created, dispatched: null, advice_ready: null },
    advice: null, status, status_history: [], created_at: created, rebuilt: true, status_version: 1,
  };
}

const RESTORE_LUA = `
if redis.call('EXISTS', KEYS[1]) == 0 then
  redis.call('HSET', KEYS[1], 'json', ARGV[1], 'v', '1')
end
if ARGV[2] ~= 'closed' then
  redis.call('SADD', KEYS[2], ARGV[4])
  if ARGV[3] == '1' then redis.call('SADD', KEYS[3], ARGV[4]) end
end
return 1
`;

export async function rebuildFromIssues(list?: () => Promise<IssueRecord[]>, repo?: string): Promise<RebuildResult> {
  const { acquireLock, releaseLock } = await import("./security.ts");
  const { listAlertIssues, repoName, issuesConfigured } = await import("./github.ts");
  if (!list && !issuesConfigured()) return { ok: false, reason: "ALERT_ISSUE_TOKEN 未設定，無法重建" };
  const lock = await acquireLock(K.rebuildLock, 120);
  if (!lock) return { ok: false, reason: "重建進行中" };
  try {
    const issues = await (list ?? listAlertIssues)();
    const r = repo ?? repoName();
    let restored = 0;
    for (const issue of issues) {
      const a = alertFromIssue(issue, r);
      if (!a || a.status === "closed") continue;
      await evalLua(RESTORE_LUA, [K.alert(a.id), K.open(false), K.openHigh(false)],
        [JSON.stringify(a), a.status, a.level === "high" ? "1" : "0", a.id]);
      restored++;
    }
    await redis("SET", K.meta, JSON.stringify({ rebuilt_at: new Date().toISOString(), issues_scanned: issues.length, restored }));
    return { ok: true, reason: "完成", restored };
  } finally {
    await releaseLock(K.rebuildLock, lock);
  }
}

/** 第一次啟用（尚無任何告警 Issue）時也走重建流程，結果為 0 筆並寫入 meta。 */
export async function openIds(sim: boolean): Promise<string[]> {
  return (await redis<string[]>("SMEMBERS", K.open(sim))) ?? [];
}

export async function openCounts(): Promise<{ realHigh: number; real: number; sim: number }> {
  const [realHigh, real, sim] = await Promise.all([
    redis<number>("SCARD", K.openHigh(false)), redis<number>("SCARD", K.open(false)), redis<number>("SCARD", K.open(true)),
  ]);
  return { realHigh: Number(realHigh) || 0, real: Number(real) || 0, sim: Number(sim) || 0 };
}

/** 模擬告警會過期；索引中已不存在的模擬 ID 才清除。真實告警不做此清理（缺資料時標示需重建）。 */
export async function pruneSimIndex(ids: string[], present: Set<string>): Promise<void> {
  const gone = ids.filter((i) => !present.has(i));
  if (gone.length) {
    await redis("SREM", K.open(true), ...gone);
    await redis("SREM", K.openHigh(true), ...gone);
  }
}

export { redisConfigured };

/** 對外回應只含去敏資料（不含內部去重 key）。 */
export function toPublic(a: Alert) {
  const { dedup_key: _k, version: _v, ...rest } = a;
  return rest;
}

/** 驗證證據必須是 HTTPS 連結（不含帳密），長度 300 以內。 */
export function validEvidenceUrl(u: unknown): u is string {
  if (typeof u !== "string" || u.length > 300) return false;
  try {
    const url = new URL(u);
    return url.protocol === "https:" && !url.username && !url.password;
  } catch {
    return false;
  }
}
