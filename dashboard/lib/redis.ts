// Upstash Redis REST 用戶端（伺服器端專用；Token 不可出現在前端程式）。
export class RedisUnavailable extends Error {}

type Env = Record<string, string | undefined>;

/**
 * 取得 REST 端點與 Token。優先使用 UPSTASH_REDIS_REST_*；Vercel Marketplace 的 Upstash 整合注入的是
 * KV_REST_API_*，兩組都接受，但網址與 Token 必須來自同一組。只用可寫入的 Token，不使用 KV_REST_API_READ_ONLY_TOKEN。
 */
export function redisEnv(env: Env = process.env): { url?: string; token?: string } {
  if (env.UPSTASH_REDIS_REST_URL || env.UPSTASH_REDIS_REST_TOKEN) {
    return { url: env.UPSTASH_REDIS_REST_URL, token: env.UPSTASH_REDIS_REST_TOKEN };
  }
  return { url: env.KV_REST_API_URL, token: env.KV_REST_API_TOKEN };
}

function config() {
  const { url, token } = redisEnv();
  // 正式環境只接受 HTTPS；本機整合測試（NODE_ENV 非 production）可連 127.0.0.1 的 Upstash 相容代理
  const local = process.env.NODE_ENV !== "production" && /^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(url ?? "");
  if (!url || !token || !(url.startsWith("https://") || local)) throw new RedisUnavailable("Redis 未設定");
  return { url, token };
}

export function redisConfigured(): boolean {
  try {
    config();
    return true;
  } catch {
    return false;
  }
}

export async function redis<T = unknown>(...cmd: (string | number)[]): Promise<T> {
  const { url, token } = config();
  const res = await fetch(url, {
    method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(cmd.map(String)), cache: "no-store", signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) throw new RedisUnavailable(`Redis HTTP ${res.status}`);
  const body = (await res.json()) as { result?: T; error?: string };
  if (body.error) throw new RedisUnavailable(body.error);
  return body.result as T;
}

export async function pipeline(cmds: (string | number)[][]): Promise<unknown[]> {
  const { url, token } = config();
  const res = await fetch(`${url}/pipeline`, {
    method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(cmds.map((c) => c.map(String))), cache: "no-store", signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) throw new RedisUnavailable(`Redis HTTP ${res.status}`);
  const rows = (await res.json()) as { result?: unknown; error?: string }[];
  return rows.map((r) => {
    if (r.error) throw new RedisUnavailable(r.error);
    return r.result;
  });
}

/** 原子操作：以 Lua 腳本執行（事件寫入、去重、時間窗計數、建立告警須在同一個原子步驟完成）。 */
export async function evalLua<T = unknown>(script: string, keys: string[], args: (string | number)[]): Promise<T> {
  return redis<T>("EVAL", script, keys.length, ...keys, ...args);
}
