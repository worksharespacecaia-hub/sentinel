// Claude API 月預算（規格 v2 第 11.2、15 節）：Workflow 的 Agent 在呼叫 API 前先預留、完成後依實際用量結算。
// - 金額以微美元（整數）計算，避免浮點誤差；月額度與單筆上限由伺服器設定，客戶端不能提高
// - 冪等鍵：同一個 key 重送預留回傳同一筆；已結算的 key 不能再預留（避免未計費的呼叫）
// - 未結算的預留保守地一直佔用額度（不因逾時視為零花費），由用量對帳釋放；並行租約有時效，避免中斷的 Job 永久卡住
// - 月份依 BUDGET_TZ（帳務時區）計算；成本是估算，另保留 BUDGET_BUFFER 比例的超支緩衝
import { evalLua, redis } from "./redis.ts";

export const KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,39}(\/[A-Za-z0-9][A-Za-z0-9._-]{0,39}){1,4}$/;   // 每段以英數字開頭（不接受 ..）
const MICRO = 1_000_000;
const LEASE_MS = 30 * 60 * 1000;

type Env = Record<string, string | undefined>;

export interface BudgetConfig { monthlyMicro: number; capMicro: number; maxReserveMicro: number; maxActive: number; tz: string }

export function budgetConfig(env: Env = process.env): BudgetConfig {
  const num = (v: string | undefined, d: number, lo: number, hi: number) => {
    const n = Number(v);
    return Number.isFinite(n) && n >= lo && n <= hi ? n : d;
  };
  const monthly = num(env.BUDGET_MONTHLY_USD, 15, 0, 1000);
  const buffer = num(env.BUDGET_BUFFER, 0.1, 0, 0.9);
  let tz = env.BUDGET_TZ || "UTC";
  try {
    new Intl.DateTimeFormat("en-CA", { timeZone: tz });
  } catch {
    tz = "UTC";
  }
  return {
    monthlyMicro: Math.round(monthly * MICRO), capMicro: Math.round(monthly * (1 - buffer) * MICRO),
    maxReserveMicro: Math.round(num(env.BUDGET_MAX_RESERVATION_USD, 0.5, 0.01, 5) * MICRO),
    maxActive: Math.round(num(env.BUDGET_MAX_ACTIVE, 10, 1, 100)), tz,
  };
}

/** 帳務時區的年月（例如 2026-11）。 */
export function monthKey(now: Date, tz: string): string {
  const parts = new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit" }).formatToParts(now);
  const y = parts.find((p) => p.type === "year")?.value, m = parts.find((p) => p.type === "month")?.value;
  return `${y}-${m}`;
}

export function toMicro(usd: unknown): number | null {
  const n = typeof usd === "number" ? usd : typeof usd === "string" && usd.trim() !== "" ? Number(usd) : NaN;
  return Number.isFinite(n) && n >= 0 ? Math.round(n * MICRO) : null;
}

export const usd = (micro: number) => Math.round(micro) / MICRO;

const mk = (month: string) => ({ spent: `budget:${month}:spent`, reserved: `budget:${month}:reserved`, leases: `budget:${month}:leases` });
const resKey = (key: string) => `budget:res:${key}`;
const KEEP_SECONDS = 400 * 24 * 3600;     // 保留超過一年，供對帳

// KEYS: res, spent, reserved, leases；ARGV: amount, cap, maxActive, month, nowIso, nowMs, leaseUntilMs, keepSeconds, key
const RESERVE_LUA = `
local st = redis.call('HGET', KEYS[1], 'status')
if st then
  return {'exists', st, redis.call('HGET', KEYS[1], 'amount') or '0', redis.call('HGET', KEYS[1], 'month') or ''}
end
redis.call('ZREMRANGEBYSCORE', KEYS[4], '-inf', ARGV[6])
local active = redis.call('ZCARD', KEYS[4])
if active >= tonumber(ARGV[3]) then return {'busy', tostring(active), '', ''} end
local spent = tonumber(redis.call('GET', KEYS[2]) or '0')
local reserved = tonumber(redis.call('GET', KEYS[3]) or '0')
local amount = tonumber(ARGV[1])
if spent + reserved + amount > tonumber(ARGV[2]) then return {'exhausted', tostring(spent), tostring(reserved), ''} end
redis.call('HSET', KEYS[1], 'status', 'reserved', 'amount', ARGV[1], 'month', ARGV[4], 'reserved_at', ARGV[5])
redis.call('EXPIRE', KEYS[1], ARGV[8])
redis.call('INCRBY', KEYS[3], amount)
redis.call('EXPIRE', KEYS[3], ARGV[8])
redis.call('ZADD', KEYS[4], ARGV[7], ARGV[9])
redis.call('EXPIRE', KEYS[4], ARGV[8])
return {'reserved', tostring(spent), tostring(reserved + amount), ARGV[4]}
`;

// KEYS: res, spent, reserved, leases；ARGV: actual, nowIso, keepSeconds, key
const SETTLE_LUA = `
local st = redis.call('HGET', KEYS[1], 'status')
if not st then return {'missing', ''} end
if st == 'settled' then return {'already', redis.call('HGET', KEYS[1], 'actual') or '0'} end
local amount = tonumber(redis.call('HGET', KEYS[1], 'amount') or '0')
redis.call('HSET', KEYS[1], 'status', 'settled', 'actual', ARGV[1], 'settled_at', ARGV[2])
local r = redis.call('DECRBY', KEYS[3], amount)
if r < 0 then redis.call('SET', KEYS[3], '0') end
redis.call('INCRBY', KEYS[2], tonumber(ARGV[1]))
redis.call('EXPIRE', KEYS[2], ARGV[3])
redis.call('ZREM', KEYS[4], ARGV[4])
return {'settled', ARGV[1]}
`;

export type ReserveResult =
  | { ok: true; key: string; month: string; amount_usd: number; remaining_usd: number | null; idempotent?: boolean }
  | { ok: false; reason: string };

export async function reserve(key: string, amountMicro: number, now = new Date(), cfg = budgetConfig()): Promise<ReserveResult> {
  if (!KEY_RE.test(key)) return { ok: false, reason: "key 格式錯誤" };
  if (amountMicro <= 0 || amountMicro > cfg.maxReserveMicro) return { ok: false, reason: `單筆預留須大於 0 且不超過 US$${usd(cfg.maxReserveMicro)}` };
  const month = monthKey(now, cfg.tz);
  const k = mk(month);
  const r = await evalLua<string[]>(RESERVE_LUA, [resKey(key), k.spent, k.reserved, k.leases],
    [amountMicro, cfg.capMicro, cfg.maxActive, month, now.toISOString(), now.getTime(), now.getTime() + LEASE_MS, KEEP_SECONDS, key]);
  const [state, a, b, c] = r.map(String);
  if (state === "exists") {
    // 同一筆預留的重送（網路逾時後重試）才回傳成功；已結算或金額不同都拒絕
    if (a === "reserved" && Number(b) === amountMicro) return { ok: true, key, month: c, amount_usd: usd(amountMicro), remaining_usd: null, idempotent: true };
    return { ok: false, reason: a === "settled" ? "這個 key 已結算，不能再預留" : "同一個 key 的預留金額不同" };
  }
  if (state === "busy") return { ok: false, reason: `同時進行中的預留已達上限（${a}）` };
  if (state === "exhausted") return { ok: false, reason: "本月預算不足" };
  return { ok: true, key, month: c, amount_usd: usd(amountMicro), remaining_usd: usd(cfg.capMicro - Number(a) - Number(b)) };
}

export type SettleResult = { ok: true; key: string; actual_usd: number; idempotent?: boolean } | { ok: false; reason: string };

export async function settle(key: string, actualMicro: number, now = new Date()): Promise<SettleResult> {
  if (!KEY_RE.test(key)) return { ok: false, reason: "key 格式錯誤" };
  const month = await redis<string | null>("HGET", resKey(key), "month");      // 預留時決定的月份（不可變）
  if (!month) return { ok: false, reason: "找不到這筆預留" };
  const k = mk(month);
  const [state, actual] = (await evalLua<string[]>(SETTLE_LUA, [resKey(key), k.spent, k.reserved, k.leases],
    [actualMicro, now.toISOString(), KEEP_SECONDS, key])).map(String);
  if (state === "missing") return { ok: false, reason: "找不到這筆預留" };
  if (state === "already") return { ok: true, key, actual_usd: usd(Number(actual)), idempotent: true };
  return { ok: true, key, actual_usd: usd(Number(actual)) };
}

export async function status(now = new Date(), cfg = budgetConfig()) {
  const month = monthKey(now, cfg.tz);
  const k = mk(month);
  const [spent, reserved] = await Promise.all([redis<string | null>("GET", k.spent), redis<string | null>("GET", k.reserved)]);
  const s = Number(spent ?? 0), r = Number(reserved ?? 0);
  return { month, tz: cfg.tz, monthly_usd: usd(cfg.monthlyMicro), cap_usd: usd(cfg.capMicro), spent_usd: usd(s), reserved_usd: usd(r),
           remaining_usd: usd(Math.max(0, cfg.capMicro - s - r)) };
}
