// 處理中追蹤（Redis）：管理者把風險設為「處理中」並指定期限，到期前以 LINE 提醒。
// - 只追蹤 daily（正式）風險；已修復只由重新評估判定，這裡不提供手動「完成」
// - HASH track:<risk_id> {json, v}，以版本號比較後寫入（CAS），避免兩位管理者互相覆蓋
// - 處理中的 ID 放在 track:open；取消或結束的紀錄保留 30 天供查閱
import { evalLua, pipeline, redis } from "./redis.ts";
import type { ReminderKind, TrackChange, Tracking, TrackInput } from "./actions.ts";

export const RISK_ID_RE = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,150}$/;
const ENDED_TTL = 30 * 86400;
const REMIND_TTL = 40 * 86400;

export const TK = {
  item: (id: string) => `track:${id}`,
  open: "track:open",
  remind: (id: string, dueAt: string, kind: ReminderKind) => `track:remind:${id}:${dueAt}:${kind}`,
};

export class TrackError extends Error {
  code: "missing" | "conflict" | "invalid";
  constructor(code: "missing" | "conflict" | "invalid", message: string) {
    super(message);
    this.code = code;
  }
}

// KEYS: item, open   ARGV: expected_v（不存在時為 0）, json, status, id, ended_ttl
const UPSERT_LUA = `
local v = redis.call('HGET', KEYS[1], 'v') or '0'
if v ~= ARGV[1] then return {'conflict', v} end
local nv = tostring(tonumber(v) + 1)
redis.call('HSET', KEYS[1], 'json', ARGV[2], 'v', nv)
if ARGV[3] == 'in_progress' then
  redis.call('SADD', KEYS[2], ARGV[4])
  redis.call('PERSIST', KEYS[1])
else
  redis.call('SREM', KEYS[2], ARGV[4])
  redis.call('EXPIRE', KEYS[1], ARGV[5])
end
return {'ok', nv}
`;

function parse(row: (string | null)[] | null): Tracking | null {
  if (!row || !row[0]) return null;
  const t = JSON.parse(row[0]) as Tracking;
  t.version = Number(row[1]);
  return t;
}

export async function getTracking(id: string): Promise<Tracking | null> {
  if (!RISK_ID_RE.test(id)) return null;
  return parse(await redis<(string | null)[] | null>("HMGET", TK.item(id), "json", "v"));
}

/** 全部處理中的追蹤（risk_id → 紀錄）。 */
export async function openTracking(): Promise<Record<string, Tracking>> {
  const ids = ((await redis<string[]>("SMEMBERS", TK.open)) ?? []).filter((i) => RISK_ID_RE.test(i));
  if (!ids.length) return {};
  const rows = (await pipeline(ids.map((i) => ["HMGET", TK.item(i), "json", "v"]))) as ((string | null)[] | null)[];
  const out: Record<string, Tracking> = {};
  rows.forEach((row) => {
    const t = parse(row);
    if (t && t.status === "in_progress") out[t.risk_id] = t;
  });
  return out;
}

async function write(t: Tracking, expected: number): Promise<Tracking> {
  const { version: _drop, ...body } = t;
  const res = await evalLua<[string, string]>(UPSERT_LUA, [TK.item(t.risk_id), TK.open],
    [String(expected), JSON.stringify(body), t.status, t.risk_id, ENDED_TTL]);
  if (res[0] === "conflict") throw new TrackError("conflict", "這一項剛被其他人修改，請重新整理後再試");
  return { ...t, version: Number(res[1]) };
}

/** 設為處理中（新設定或改期限）。expected＝畫面載入時的版本，沒有紀錄時為 0。 */
export async function setInProgress(id: string, expected: number, input: TrackInput, by: string, now = new Date()): Promise<Tracking> {
  if (!RISK_ID_RE.test(id)) throw new TrackError("invalid", "risk_id 格式錯誤");
  const prev = await getTracking(id);
  const at = now.toISOString();
  const change: TrackChange = { at, by, action: "set", due_at: input.due_at, owner: input.owner, note: input.note };
  const t: Tracking = { risk_id: id, status: "in_progress", owner: input.owner, due_at: input.due_at, note: input.note,
                        set_by: by, set_at: at, history: [...(prev?.history ?? []), change].slice(-20) };
  // 畫面只帶處理中紀錄的版本；已取消或結束的舊紀錄視為「沒有紀錄」（0），寫入時仍以實際版本比對，併發時照樣衝突
  const effective = expected === 0 && prev && prev.status !== "in_progress" ? (prev.version ?? 0) : expected;
  return write(t, effective);
}

/** 取消處理中（回到待處理）。 */
export async function cancelTracking(id: string, expected: number, by: string, reason: string, now = new Date()): Promise<Tracking> {
  const prev = await getTracking(id);
  if (!prev || prev.status !== "in_progress") throw new TrackError("missing", "這一項目前不是處理中");
  const t: Tracking = { ...prev, status: "cancelled", history: [...prev.history, { at: now.toISOString(), by, action: "cancel" as const, reason }].slice(-20) };
  return write(t, expected);
}

/** 重新評估已判定修復或風險已不存在：結束追蹤（不需要人工，不再提醒）。 */
export async function autoClose(id: string, reason: string, now = new Date()): Promise<void> {
  for (let i = 0; i < 3; i++) {
    const prev = await getTracking(id);
    if (!prev || prev.status !== "in_progress") {
      await redis("SREM", TK.open, id);
      return;
    }
    try {
      await write({ ...prev, status: "closed", history: [...prev.history, { at: now.toISOString(), by: "sentinel", action: "auto_close" as const, reason }].slice(-20) },
        prev.version ?? 0);
      return;
    } catch (e) {
      if (!(e instanceof TrackError && e.code === "conflict")) throw e;
    }
  }
}

/** 同一個期限的同一種提醒只送一次：SET NX 搶到的人才送。 */
export async function claimReminder(id: string, dueAt: string, kind: ReminderKind): Promise<boolean> {
  return (await redis<string | null>("SET", TK.remind(id, dueAt, kind), "1", "NX", "EX", REMIND_TTL)) === "OK";
}
