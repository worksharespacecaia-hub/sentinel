// LINE 官方帳號 Messaging API（規格第 7.7 節）。伺服器端專用；Channel secret／access token 不可出現在前端。
// - 主動推播只用在：即時高風險告警、有效燈號變化、手動傳送行動報告、處理中到期提醒；查詢一律用免費的 Reply API
// - 推播前查本月額度（Redis 快取 10 分鐘）：< 150 則正常、150～190 只推告警、> 190 全停
// - 只推給輸入綁定碼的管理者（最多 LINE_MAX_ADMINS 人）；推播失敗只記錄、不重試
// - 缺少 LINE 設定時一律回 skipped，不影響告警、Issue 與調查
import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { evalLua, redis, redisConfigured } from "./redis.ts";

const API = "https://api.line.me";
export const PUSH_NORMAL_BELOW = 150;
export const PUSH_STOP_ABOVE = 190;
export const MONTHLY_FREE = 200;
const QUOTA_CACHE_SECONDS = 600;
const BIND_FAIL_LIMIT = 5;
const BIND_LOCK_SECONDS = 3600;

export type PushKind = "alert" | "light" | "report" | "reminder";
export type PushState = "sent" | "skipped" | "failed";
export interface PushResult { state: PushState; reason?: string; recipients?: number }
export type LineMessage = Record<string, unknown>;

export const LK = {
  admins: "line:admins",                         // ZSET userId → 綁定時間（第一位＝最早綁定）
  bindFail: (u: string) => `line:bindfail:${u}`,
  bindLock: (u: string) => `line:bindlock:${u}`,
  event: (id: string) => `line:evt:${id}`,
  quota: "line:quota",
  stats: (month: string) => `line:stats:${month}`,
};

export const USER_ID_RE = /^U[0-9a-f]{32}$/;

export function lineConfigured(env: Record<string, string | undefined> = process.env): boolean {
  return Boolean(env.LINE_CHANNEL_SECRET && env.LINE_CHANNEL_ACCESS_TOKEN);
}

export function maxAdmins(env: Record<string, string | undefined> = process.env): number {
  const n = Number(env.LINE_MAX_ADMINS ?? 3);
  return Number.isInteger(n) && n >= 1 && n <= 10 ? n : 3;
}

export function siteUrl(env: Record<string, string | undefined> = process.env): string | null {
  const u = env.SENTINEL_BASE_URL;
  return u && /^https:\/\/[A-Za-z0-9.-]+(:\d+)?\/?$/.test(u) ? u.replace(/\/$/, "") : null;
}

/** X-Line-Signature：以 Channel secret 對「原始 body」做 HMAC-SHA256，再 Base64；固定時間比對。 */
export function verifySignature(rawBody: string, header: string | null, secret: string | undefined): boolean {
  if (!secret || !header) return false;
  const expected = createHmac("sha256", secret).update(rawBody, "utf8").digest();
  let given: Buffer;
  try {
    given = Buffer.from(header, "base64");
  } catch {
    return false;
  }
  return given.length === expected.length && timingSafeEqual(given, expected);
}

/** 額度分級（純函式）：已用量未知時只允許高風險告警，寧可少推也不要用完額度。 */
export function pushAllowed(kind: PushKind, used: number | null, recipients: number, limit: number | null = MONTHLY_FREE): { ok: boolean; reason?: string } {
  if (used == null) return kind === "alert" ? { ok: true } : { ok: false, reason: "無法確認 LINE 本月額度，只推播高風險告警" };
  if (used > PUSH_STOP_ABOVE) return { ok: false, reason: "LINE 額度已用完，請查看網站" };
  if (limit != null && used + recipients > limit) return { ok: false, reason: "這次推播會超過本月額度" };
  if (used >= PUSH_NORMAL_BELOW && kind !== "alert") return { ok: false, reason: `本月已用 ${used} 則，只推播高風險告警` };
  return { ok: true };
}

export function quotaTier(used: number | null): "normal" | "alerts_only" | "stopped" | "unknown" {
  if (used == null) return "unknown";
  return used > PUSH_STOP_ABOVE ? "stopped" : used >= PUSH_NORMAL_BELOW ? "alerts_only" : "normal";
}

export class LineError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.status = status;
  }
}

async function lineApi<T>(method: "GET" | "POST", path: string, body?: unknown, extra: Record<string, string> = {}): Promise<T> {
  const token = process.env.LINE_CHANNEL_ACCESS_TOKEN;
  if (!token) throw new LineError("LINE access token 未設定");
  let res: Response;
  try {
    res = await fetch(`${API}${path}`, {
      method, headers: { authorization: `Bearer ${token}`, ...(body ? { "content-type": "application/json" } : {}), ...extra },
      body: body ? JSON.stringify(body) : undefined, cache: "no-store", signal: AbortSignal.timeout(10000),
    });
  } catch (e) {
    throw new LineError((e as Error).name === "TimeoutError" ? "LINE 回應逾時" : "無法連線 LINE");
  }
  if (!res.ok) {
    const msg = ((await res.json().catch(() => ({}))) as { message?: string }).message;
    throw new LineError(`LINE 回應 ${res.status}${msg ? `：${String(msg).slice(0, 80)}` : ""}`, res.status);
  }
  const text = await res.text();
  return (text ? JSON.parse(text) : {}) as T;
}

/** Reply API（不計入額度）：每個 reply token 只能用一次、一次最多 5 則。 */
export async function reply(replyToken: string, messages: LineMessage[]): Promise<void> {
  await lineApi("POST", "/v2/bot/message/reply", { replyToken, messages: messages.slice(0, 5) });
}

async function multicast(to: string[], messages: LineMessage[]): Promise<void> {
  await lineApi("POST", "/v2/bot/message/multicast", { to, messages: messages.slice(0, 5) }, { "X-Line-Retry-Key": randomUUID() });
}

export interface QuotaInfo { limit: number | null; used: number; at: string }

/** 本月額度與已用量（Redis 快取 10 分鐘）。 */
export async function quota(force = false): Promise<QuotaInfo> {
  if (!force) {
    const cached = await redis<string | null>("GET", LK.quota);
    if (cached) return JSON.parse(cached) as QuotaInfo;
  }
  const [q, c] = await Promise.all([
    lineApi<{ type: string; value?: number }>("GET", "/v2/bot/message/quota"),
    lineApi<{ totalUsage: number }>("GET", "/v2/bot/message/quota/consumption"),
  ]);
  const info: QuotaInfo = { limit: q.type === "limited" && typeof q.value === "number" ? q.value : null, used: Number(c.totalUsage) || 0, at: new Date().toISOString() };
  await redis("SET", LK.quota, JSON.stringify(info), "EX", QUOTA_CACHE_SECONDS);
  return info;
}

export async function admins(): Promise<string[]> {
  return ((await redis<string[]>("ZRANGE", LK.admins, 0, -1)) ?? []).filter((u) => USER_ID_RE.test(u));
}

export async function isAdmin(userId: string): Promise<boolean> {
  return USER_ID_RE.test(userId) && (await redis<string | null>("ZSCORE", LK.admins, userId)) != null;
}

export async function unbind(userId: string): Promise<void> {
  await redis("ZREM", LK.admins, userId);
}

// KEYS: admins, fail, lock   ARGV: userId, max, now, code_ok, fail_limit, lock_seconds
const BIND_LUA = `
if redis.call('EXISTS', KEYS[3]) == 1 then return 'locked' end
if ARGV[4] ~= '1' then
  local c = redis.call('INCR', KEYS[2])
  if c == 1 then redis.call('EXPIRE', KEYS[2], ARGV[6]) end
  if c >= tonumber(ARGV[5]) then
    redis.call('SET', KEYS[3], '1', 'EX', ARGV[6])
    redis.call('DEL', KEYS[2])
    return 'locked'
  end
  return 'wrong'
end
if redis.call('ZSCORE', KEYS[1], ARGV[1]) then return 'already' end
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[2]) then return 'full' end
redis.call('ZADD', KEYS[1], ARGV[3], ARGV[1])
redis.call('DEL', KEYS[2])
return 'bound'
`;

export type BindResult = "bound" | "already" | "wrong" | "locked" | "full";

/** 驗碼、容量檢查與加入名單在同一個 Lua 原子步驟完成；錯 5 次暫停該 userId 1 小時。 */
export async function bind(userId: string, codeOk: boolean, now = Date.now()): Promise<BindResult> {
  return evalLua<BindResult>(BIND_LUA, [LK.admins, LK.bindFail(userId), LK.bindLock(userId)],
    [userId, maxAdmins(), now, codeOk ? "1" : "0", BIND_FAIL_LIMIT, BIND_LOCK_SECONDS]);
}

/** 以 webhookEventId 去重（LINE 可能重送）。 */
export async function claimEvent(id: string): Promise<boolean> {
  if (!/^[0-9A-Za-z]{10,40}$/.test(id)) return true;
  return (await redis<string | null>("SET", LK.event(id), "1", "NX", "EX", 86400)) === "OK";
}

const month = (d = new Date()) => new Intl.DateTimeFormat("sv-SE", { timeZone: "Asia/Taipei", year: "numeric", month: "2-digit" }).format(d);

/** 推給管理者：檢查設定 → 名單 → 額度 → multicast。firstOnly 用於排練時的模擬告警（只推給第一位管理者）。 */
export async function pushToAdmins(messages: LineMessage[], kind: PushKind, opts: { firstOnly?: boolean } = {}): Promise<PushResult> {
  if (!lineConfigured()) return { state: "skipped", reason: "LINE 通知未設定" };
  if (!redisConfigured()) return { state: "skipped", reason: "Redis 未設定，無法取得管理者名單" };
  try {
    const list = await admins();
    if (!list.length) return { state: "skipped", reason: "尚未有管理者綁定 LINE" };
    const to = opts.firstOnly ? list.slice(0, 1) : list;
    let q: QuotaInfo | null = null;
    try {
      q = await quota();
    } catch {
      q = null;
    }
    const allowed = pushAllowed(kind, q?.used ?? null, to.length, q?.limit ?? MONTHLY_FREE);
    if (!allowed.ok) return { state: "skipped", reason: allowed.reason };
    await multicast(to, messages);
    // 快取的已用量先自行加上本次則數，避免 10 分鐘快取內連續推播超量
    if (q) await redis("SET", LK.quota, JSON.stringify({ ...q, used: q.used + to.length }), "EX", QUOTA_CACHE_SECONDS);
    await redis("HINCRBY", LK.stats(month()), kind, to.length).catch(() => undefined);
    return { state: "sent", recipients: to.length };
  } catch (e) {
    return { state: "failed", reason: (e as Error).message.slice(0, 120) };
  }
}

export interface LineStatus { enabled: boolean; reason?: string; admins: number; max_admins: number; used: number | null; limit: number | null; tier: ReturnType<typeof quotaTier> }

/** 網站即時告警頁顯示：已綁定管理者人數、本月已用則數。 */
export async function lineStatus(): Promise<LineStatus> {
  const base = { admins: 0, max_admins: maxAdmins(), used: null, limit: null, tier: "unknown" as const };
  if (!lineConfigured()) return { enabled: false, reason: "LINE 通知未設定", ...base };
  if (!redisConfigured()) return { enabled: false, reason: "Redis 未設定", ...base };
  try {
    const n = Number(await redis<number>("ZCARD", LK.admins)) || 0;
    const q = await quota().catch(() => null);
    return { enabled: true, admins: n, max_admins: maxAdmins(), used: q?.used ?? null, limit: q?.limit ?? null, tier: quotaTier(q?.used ?? null) };
  } catch (e) {
    return { enabled: false, reason: `LINE 狀態無法取得（${(e as Error).message.slice(0, 60)}）`, ...base };
  }
}

/** 新告警的 LINE 交付初始狀態：只推真實高風險告警；模擬告警依 LINE_PUSH_SIMULATED。 */
export function initialLineStep(level: string, simulated: boolean, env: Record<string, string | undefined> = process.env): { state: "pending" | "skipped"; reason?: string } {
  if (!lineConfigured(env)) return { state: "skipped", reason: "LINE 通知未設定" };
  if (simulated && env.LINE_PUSH_SIMULATED !== "true") return { state: "skipped", reason: "模擬告警預設不推播" };
  if (level !== "high") return { state: "skipped", reason: "只推播高風險告警" };
  return { state: "pending" };
}
