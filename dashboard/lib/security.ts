// 伺服器端安全工具：body 大小限制、拒絕未知欄位、固定時間密碼比對、原子限流與鎖。
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { evalLua, redis } from "./redis.ts";

export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function readJsonBody(req: Request, allowed: string[], maxBytes = 4096): Promise<Record<string, unknown>> {
  const text = await req.text();
  if (Buffer.byteLength(text, "utf8") > maxBytes) throw new HttpError(413, "請求內容過大");
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new HttpError(400, "JSON 格式錯誤");
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new HttpError(400, "需要 JSON 物件");
  const unknown = Object.keys(body).filter((k) => !allowed.includes(k));
  if (unknown.length) throw new HttpError(400, `不接受的欄位：${unknown.join(", ")}`);
  return body as Record<string, unknown>;
}

/** 固定時間比對：先雜湊成等長再 timingSafeEqual；期望值未設定時一律失敗（不能讓空值比對成功）。 */
export function passcodeMatches(given: unknown, expected: string | undefined): boolean {
  if (!expected || typeof given !== "string" || given.length === 0) return false;
  const a = createHash("sha256").update(given).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

export function bearerMatches(req: Request, expected: string | undefined): boolean {
  const h = req.headers.get("authorization") ?? "";
  return h.startsWith("Bearer ") && passcodeMatches(h.slice(7), expected);
}

export function clientKey(req: Request): string {
  const ip = (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim() || req.headers.get("x-real-ip") || "unknown";
  return createHash("sha256").update(ip).digest("hex").slice(0, 16);
}

const RATE_LUA = "local c = redis.call('INCR', KEYS[1]); if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end; return c";
const RELEASE_LUA = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end";

export async function rateLimit(key: string, limit: number, windowSeconds: number): Promise<boolean> {
  const count = await evalLua<number>(RATE_LUA, [key], [windowSeconds]);
  return Number(count) <= limit;
}

export async function acquireLock(key: string, ttlSeconds: number): Promise<string | null> {
  const token = randomBytes(16).toString("hex");
  const ok = await redis<string | null>("SET", key, token, "NX", "EX", ttlSeconds);
  return ok === "OK" ? token : null;
}

/** 只釋放自己持有的鎖（比較隨機鎖值）。 */
export async function releaseLock(key: string, token: string): Promise<void> {
  await evalLua(RELEASE_LUA, [key], [token]);
}

export function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
}
