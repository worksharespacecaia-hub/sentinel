// 時間窗與去重（第 7.6 節實作要點）：事件寫入、去重、清窗、計數、門檻判斷與建立告警在同一段 Redis Lua 中原子完成。
// - sorted set 的 member 為事件 ID（不是 JSON），score 為事件時間；相同時間戳的不同事件都會計入
// - watermark = max(已存時間, 本筆時間)，窗為 (watermark - duration, watermark]；亂序事件不能把 watermark 往回移
// - 已知 IP 以 (account, ip) 的 first_seen 與「本次窗起點」比較：同一新 IP 後續事件在窗內仍屬新來源
// - 真實為 real、模擬為 sim:<simulation_id>，所有 key 分開；key 皆有保留期與大小上限
import { createHash } from "node:crypto";
import { CREATE_ALERT_LUA, K, SIM_ALERT_TTL, newStep, type Alert } from "./alertstore.ts";
import { initialLineStep } from "./line.ts";
import { evalLua, redis } from "./redis.ts";
import {
  BASELINES, baselineFor, maskText, namespaceOf, rulesFor, staticMatch, timeCheck, validateEvent, windowMs,
  type Rule, type RtEvent,
} from "./rules.ts";

const EVENT_SEEN_TTL = 2 * 86400;           // 無時間窗規則的事件去重保留 2 天
const IP_KEEP_MS = 30 * 86400 * 1000;       // first_seen 最多保留 30 天（最後一次出現後 30 天）
const IP_MAX_FIELDS = 2000;
const WINDOW_MAX_MEMBERS = 5000;
const FEED_KEY = "rt:feed";
const FEED_MAX = 100;

// KEYS: seen, dedup, alert, open, openHigh, recent
// ARGV: dedup_ms, seen_ttl, json, id, is_high, alert_ttl
const NOWINDOW_LUA = CREATE_ALERT_LUA + `
if not redis.call('SET', KEYS[1], '1', 'NX', 'EX', ARGV[2]) then return {'duplicate', '', ''} end
if not redis.call('SET', KEYS[2], ARGV[4], 'NX', 'PX', ARGV[1]) then return {'suppressed', '', redis.call('GET', KEYS[2]) or ''} end
create_alert(KEYS[3], KEYS[4], KEYS[5], KEYS[6], ARGV[3], ARGV[4], ARGV[5], ARGV[6])
return {'alert', '', ARGV[4]}
`;

// KEYS: ipfs   ARGV: ip, event_ms, keep_ms, ttl_s, max_fields
// 值為 "first:last"；最後一次出現超過保留期就重新記錄（視為新來源）
const OBSERVE_IP_LUA = `
local v = redis.call('HGET', KEYS[1], ARGV[1])
local e, keep = tonumber(ARGV[2]), tonumber(ARGV[3])
local f, l
if v then
  local a, b = string.match(v, '^(%d+):(%d+)$')
  f, l = tonumber(a), tonumber(b)
end
if (not f) or (l < e - keep) then f, l = e, e
else
  if e < f then f = e end
  if e > l then l = e end
end
redis.call('HSET', KEYS[1], ARGV[1], tostring(f) .. ':' .. tostring(l))
redis.call('EXPIRE', KEYS[1], ARGV[4])
if redis.call('HLEN', KEYS[1]) > tonumber(ARGV[5]) then
  local all = redis.call('HGETALL', KEYS[1])
  for i = 1, #all, 2 do
    local last = tonumber(string.match(all[i + 1], ':(%d+)$'))
    if last and last < e - keep then redis.call('HDEL', KEYS[1], all[i]) end
  end
end
return 1
`;

// KEYS: zset, data, watermark, ipfs, dedup, alert, open, openHigh, recent
// ARGV: event_id, event_ms, value, ip, dur_ms, mode(sum_new_ip|distinct), threshold, dedup_ms, json, id, is_high, alert_ttl, key_ttl, max_members
const WINDOW_LUA = CREATE_ALERT_LUA + `
local eid, ems = ARGV[1], tonumber(ARGV[2])
if redis.call('ZSCORE', KEYS[1], eid) then return {'duplicate', '', ''} end
local wm = tonumber(redis.call('GET', KEYS[3]) or '-1')
if ems > wm then
  wm = ems
  redis.call('SET', KEYS[3], tostring(ems), 'EX', ARGV[13])
end
local start = wm - tonumber(ARGV[5])
if ems <= start then return {'late', '', ''} end
redis.call('ZADD', KEYS[1], ems, eid)
redis.call('HSET', KEYS[2], eid, ARGV[3] .. '|' .. ARGV[4])
local old = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', start)
for _, m in ipairs(old) do redis.call('HDEL', KEYS[2], m) end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', start)
local n, cap = redis.call('ZCARD', KEYS[1]), tonumber(ARGV[14])
if n > cap then
  local extra = redis.call('ZRANGE', KEYS[1], 0, n - cap - 1)
  for _, m in ipairs(extra) do redis.call('HDEL', KEYS[2], m) end
  redis.call('ZREMRANGEBYRANK', KEYS[1], 0, n - cap - 1)
end
redis.call('EXPIRE', KEYS[1], ARGV[13])
redis.call('EXPIRE', KEYS[2], ARGV[13])
local members = redis.call('ZRANGEBYSCORE', KEYS[1], '(' .. tostring(start), tostring(wm))
local metric, used, hit = 0, {}, false
if ARGV[6] == 'sum_new_ip' then
  for _, m in ipairs(members) do
    local d = redis.call('HGET', KEYS[2], m)
    if d then
      local rows, ip = string.match(d, '^([^|]*)|(.*)$')
      local rec = redis.call('HGET', KEYS[4], ip)
      local fs = rec and tonumber(string.match(rec, '^(%d+):'))
      if fs and fs > start then
        metric = metric + tonumber(rows)
        table.insert(used, m)
      end
    end
  end
  hit = metric > tonumber(ARGV[7])
else
  local seen = {}
  for _, m in ipairs(members) do
    local d = redis.call('HGET', KEYS[2], m)
    if d then
      local v = string.match(d, '^([^|]*)|')
      if not seen[v] then
        seen[v] = true
        metric = metric + 1
      end
      table.insert(used, m)
    end
  end
  hit = metric >= tonumber(ARGV[7])
end
if not hit then return {'below', tostring(metric), ''} end
if not redis.call('SET', KEYS[5], ARGV[10], 'NX', 'PX', ARGV[8]) then
  return {'suppressed', tostring(metric), redis.call('GET', KEYS[5]) or ''}
end
local ids = '[]'
if #used > 0 then ids = '["' .. table.concat(used, '","', 1, math.min(#used, 50)) .. '"]' end
local json = string.gsub(ARGV[9], '"__EVENTS__"', ids)
json = string.gsub(json, '__METRIC__', tostring(metric))
create_alert(KEYS[6], KEYS[7], KEYS[8], KEYS[9], json, ARGV[10], ARGV[11], ARGV[12])
return {'alert', tostring(metric), ARGV[10]}
`;

export type Outcome = "alert" | "suppressed" | "below" | "duplicate" | "late" | "no_match" | "rejected";
export interface RuleResult { rule_id: string; outcome: Outcome; reason: string; metric: number | null; alert_id: string | null }
export interface ProcessResult {
  event_id: string; namespace: string; rejected: string | null; results: RuleResult[]; alerts: string[];
  timeline: { event_received: string; rule_evaluated: string };
}

function h16(s: string): string {
  return createHash("sha256").update(s).digest("hex").slice(0, 16);
}

export function alertIdFor(rule: Rule, ns: string, group: string, eventId: string): string {
  return `al-${rule.id.toLowerCase()}-${h16(`${ns}|${rule.id}|${group}|${eventId}`)}`;
}

function groupOf(rule: Rule, ev: RtEvent): string {
  return rule.window?.group_by === "account" ? `${ev.asset_id}:${ev.account}` : ev.asset_id;
}

function thresholdOf(rule: Rule, ev: RtEvent): number {
  const w = rule.window!;
  if (w.metric === "rows_read_sum") return baselineFor(ev.account!, BASELINES) * (w.over_baseline_multiplier ?? 10);
  return w.threshold ?? 3;
}

export function summaryFor(rule: Rule, ev: RtEvent, threshold: number | null): string {
  if (rule.source === "github.deployment") {
    return `${ev.data.creator ?? "未知帳號"} 直接建立 ${ev.data.environment} 部署（ref ${ev.data.ref ?? "?"}），未經 Pipeline`;
  }
  if (rule.window?.metric === "rows_read_sum") {
    return `帳號 ${ev.account} 於凌晨自新來源讀取 orders 共 __METRIC__ 列（10 分鐘內），超過基準 10 倍（門檻 ${threshold}）`;
  }
  return `24 小時內 __METRIC__ 個品牌回報含訂單資訊的詐騙`;
}

/** LINE 交付初始狀態（只推真實高風險告警；模擬告警依 LINE_PUSH_SIMULATED；未設定時 skipped）。 */
function lineStep(level: string, simulated: boolean) {
  const s = initialLineStep(level, simulated);
  return s.state === "pending" ? newStep() : newStep("skipped", s.reason);
}

/** 告警 JSON 範本：__METRIC__ 與 "__EVENTS__" 由 Lua 在原子步驟內填入。 */
export function alertTemplate(rule: Rule, ev: RtEvent, id: string, dedupKey: string, threshold: number | null, receivedAt: string, evaluatedAt: string): string {
  const repo = process.env.GH_OWNER && process.env.GH_REPO ? `${process.env.GH_OWNER}/${process.env.GH_REPO}` : null;
  const a: Omit<Alert, "source_event_ids" | "metric"> & { source_event_ids: string; metric: string | null } = {
    id, rule_id: rule.id, rule_title: rule.title, level: rule.level, light: rule.light ?? "red", asset_id: rule.asset_key,
    account: ev.account, simulated: ev.simulated, simulation_id: ev.simulation_id, summary: summaryFor(rule, ev, threshold),
    maps_to_event: rule.maps_to_event ?? null, metric: rule.window ? "__METRIC__" : null, repo, issue_number: null, issue_url: null,
    source_event_ids: "__EVENTS__", dedup_key: dedupKey,
    delivery: {
      issue: newStep(), dispatch: newStep(),
      line: lineStep(rule.level, ev.simulated),
      sync: newStep("done"),
    },
    timeline: { event_received: receivedAt, rule_evaluated: evaluatedAt, alert_created: evaluatedAt, issue_created: null, dispatched: null, advice_ready: null },
    advice: null, status: "open", status_history: [], created_at: evaluatedAt, status_version: 1,
  };
  let json = JSON.stringify(a);
  if (!rule.window) json = json.replace('"__EVENTS__"', JSON.stringify([ev.id]));
  else json = json.replace('"metric":"__METRIC__"', '"metric":__METRIC__');
  return json;
}

async function observeIp(ns: string, ev: RtEvent): Promise<void> {
  if (ev.source !== "db.audit" || !ev.account || !ev.data.ip) return;
  const ttl = ev.simulated ? SIM_ALERT_TTL : Math.ceil(IP_KEEP_MS / 1000);
  await evalLua(OBSERVE_IP_LUA, [`rt:${ns}:ipfs:${ev.account}`], [ev.data.ip, Date.parse(ev.event_time), IP_KEEP_MS, ttl, IP_MAX_FIELDS]);
}

async function evaluateRule(rule: Rule, ev: RtEvent, ns: string, receivedAt: string): Promise<RuleResult> {
  const sm = staticMatch(rule, ev);
  if (!sm.ok) return { rule_id: rule.id, outcome: "no_match", reason: sm.reason, metric: null, alert_id: null };
  const group = groupOf(rule, ev);
  const id = alertIdFor(rule, ns, group, ev.id);
  const dedupKey = `rt:${ns}:dedup:${rule.id}:${group}`;
  const sim = ev.simulated;
  const alertTtl = sim ? SIM_ALERT_TTL : 0;
  const evaluatedAt = new Date().toISOString();
  const dedupMs = rule.dedup_minutes * 60 * 1000;
  let res: [string, string, string];
  if (!rule.window) {
    const json = alertTemplate(rule, ev, id, dedupKey, null, receivedAt, evaluatedAt);
    res = await evalLua(NOWINDOW_LUA,
      [`rt:${ns}:seen:${rule.id}:${ev.id}`, dedupKey, K.alert(id), K.open(sim), K.openHigh(sim), K.recent],
      [dedupMs, sim ? SIM_ALERT_TTL : EVENT_SEEN_TTL, json, id, rule.level === "high" ? "1" : "0", alertTtl]);
  } else {
    const w = rule.window;
    const dur = windowMs(w);
    const threshold = thresholdOf(rule, ev);
    const json = alertTemplate(rule, ev, id, dedupKey, threshold, receivedAt, evaluatedAt);
    const mode = w.metric === "rows_read_sum" ? "sum_new_ip" : "distinct";
    const value = mode === "sum_new_ip" ? String(Math.trunc(ev.data.rows_read ?? 0)) : String(ev.data.brand);
    const keyTtl = sim ? SIM_ALERT_TTL : Math.ceil((dur * 2) / 1000) + 3600;
    const ipfs = mode === "sum_new_ip" ? `rt:${ns}:ipfs:${ev.account}` : `rt:${ns}:ipfs:-`;
    res = await evalLua(WINDOW_LUA,
      [`rt:${ns}:w:${rule.id}:${group}`, `rt:${ns}:wd:${rule.id}:${group}`, `rt:${ns}:wm:${rule.id}:${group}`, ipfs,
       dedupKey, K.alert(id), K.open(sim), K.openHigh(sim), K.recent],
      [ev.id, Date.parse(ev.event_time), value, ev.data.ip ?? "", dur, mode, threshold, dedupMs, json, id,
       rule.level === "high" ? "1" : "0", alertTtl, keyTtl, WINDOW_MAX_MEMBERS]);
  }
  const [outcome, metric, alertId] = res;
  const reasons: Record<string, string> = {
    alert: "命中，已建立告警", suppressed: `命中但在去重期間內（${rule.dedup_minutes} 分鐘），沿用既有告警`,
    below: "未達門檻", duplicate: "重複事件，已忽略", late: "事件早於目前時間窗，未計入",
  };
  return { rule_id: rule.id, outcome: outcome as Outcome, reason: reasons[outcome] ?? outcome, metric: metric === "" ? null : Number(metric),
           alert_id: alertId || null };
}

/** 對外顯示的事件摘要（去敏：不含 IP、遮蔽訂單編號）。 */
export function feedEntry(ev: RtEvent, pr: ProcessResult, ipNew?: boolean) {
  const d = ev.data;
  const detail = ev.source === "github.deployment" ? `${d.creator ?? "?"} → ${d.environment}（ref ${d.ref ?? "?"}）`
    : ev.source === "db.audit" ? `${ev.account} 讀取 ${d.table} ${d.rows_read} 列${ipNew === undefined ? "" : ipNew ? "（新來源）" : ""}`
    : `${d.brand}：${maskText(d.text ?? "")}`;
  return {
    id: ev.id, source: ev.source, event_time: ev.event_time, received_at: ev.received_at, simulated: ev.simulated,
    simulation_id: ev.simulation_id, asset_id: ev.asset_id, detail, rejected: pr.rejected,
    results: pr.results.map((r) => ({ rule_id: r.rule_id, outcome: r.outcome, reason: r.reason, alert_id: r.alert_id })),
  };
}

export async function pushFeed(entry: ReturnType<typeof feedEntry>): Promise<void> {
  await redis("LPUSH", FEED_KEY, JSON.stringify(entry));
  await redis("LTRIM", FEED_KEY, 0, FEED_MAX - 1);
  await redis("EXPIRE", FEED_KEY, 7 * 86400);
}

export async function readFeed(limit = 50): Promise<unknown[]> {
  const rows = (await redis<string[]>("LRANGE", FEED_KEY, 0, limit - 1)) ?? [];
  return rows.map((r) => JSON.parse(r));
}

/** 處理單一事件：驗證 → 時間檢查 → 記錄 IP first_seen → 逐條規則原子判斷 → 寫入事件流。 */
export async function processEvent(ev: RtEvent, now = Date.now()): Promise<ProcessResult> {
  const received = ev.received_at;
  const ns = namespaceOf(ev);
  const base: ProcessResult = { event_id: ev.id, namespace: ns, rejected: null, results: [], alerts: [],
                                timeline: { event_received: received, rule_evaluated: received } };
  const invalid = validateEvent(ev) ?? timeCheck(ev, now);
  if (invalid) {
    base.rejected = invalid;
    await pushFeed(feedEntry(ev, base));
    return base;
  }
  await observeIp(ns, ev);
  for (const rule of rulesFor(ev.source)) {
    const r = await evaluateRule(rule, ev, ns, received);
    base.results.push(r);
    if (r.outcome === "alert" && r.alert_id) base.alerts.push(r.alert_id);
  }
  base.timeline.rule_evaluated = new Date().toISOString();
  await pushFeed(feedEntry(ev, base));
  return base;
}
