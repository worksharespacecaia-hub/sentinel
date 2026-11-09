// Upstash Redis REST 用戶端（伺服器端專用；Token 不可出現在前端程式）。
export class RedisUnavailable extends Error {}

function config() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token || !url.startsWith("https://")) throw new RedisUnavailable("Redis 未設定");
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
