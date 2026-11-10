// 偵測規則設定（純函式）：rules/realtime.yaml 是預設規則；網站只能調整下列參數，存成 rules/realtime-settings.json（只記與預設不同的值）。
// - 正規表示式、資料表、事件來源與群組方式不開放在網站修改：寫錯可能拖垮伺服器（ReDoS）或需要新的偵測程式，改 YAML 並經過審查
// - 參數一律有上下限；未知的規則 ID 或欄位一律拒絕，不靜默忽略
import type { Level, Rule } from "./rules.ts";

export type FieldKey = "enabled" | "level" | "light" | "dedup_minutes" | "creator_not_in" | "event_hour_between"
  | "window_minutes" | "window_hours" | "over_baseline_multiplier" | "threshold";
export type FieldValue = boolean | string | number | string[] | [number, number];
export type RuleOverrides = Partial<Record<FieldKey, FieldValue>>;
export type Overrides = Record<string, RuleOverrides>;
export interface EffectiveRule extends Rule { enabled: boolean }

export interface FieldSpec {
  key: FieldKey; label: string; help: string;
  kind: "bool" | "choice" | "int" | "number" | "hours" | "logins";
  min?: number; max?: number; step?: number; choices?: { value: string; label: string }[];
  applies: (r: Rule) => boolean;
  get: (r: Rule & { enabled?: boolean }) => FieldValue;
  set: (r: EffectiveRule, v: FieldValue) => void;
}

const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?$/;

export const FIELDS: FieldSpec[] = [
  { key: "enabled", label: "啟用", help: "停用後這條規則不會判斷、也不會告警", kind: "bool",
    applies: () => true, get: (r) => r.enabled !== false, set: (r, v) => { r.enabled = v as boolean; } },
  { key: "level", label: "告警等級", help: "高風險告警會讓燈號維持紅燈直到結案", kind: "choice",
    choices: [{ value: "high", label: "高" }, { value: "medium", label: "中" }, { value: "low", label: "低" }],
    applies: () => true, get: (r) => r.level, set: (r, v) => { r.level = v as Level; } },
  { key: "light", label: "告警燈號", help: "未結案時對燈號的影響", kind: "choice",
    choices: [{ value: "red", label: "紅" }, { value: "yellow", label: "黃" }],
    applies: () => true, get: (r) => r.light ?? "red", set: (r, v) => { r.light = v as "red" | "yellow"; } },
  { key: "dedup_minutes", label: "去重時間（分鐘）", help: "同一對象在這段時間內再命中，沿用既有告警、不重複建立", kind: "int",
    min: 1, max: 10080, step: 1, applies: () => true, get: (r) => r.dedup_minutes, set: (r, v) => { r.dedup_minutes = v as number; } },
  { key: "creator_not_in", label: "允許的部署者", help: "這些帳號發起的正式部署視為 Pipeline，不告警（GitHub 帳號，一行一個）", kind: "logins",
    applies: (r) => Array.isArray(r.match.creator_not_in), get: (r) => [...(r.match.creator_not_in ?? [])],
    set: (r, v) => { r.match.creator_not_in = [...(v as string[])]; } },
  { key: "event_hour_between", label: "偵測時段（台灣時間）", help: "含開始時，不含結束時；例如 0～6 代表凌晨 0:00～5:59", kind: "hours",
    applies: (r) => Array.isArray(r.match.event_hour_between), get: (r) => [...(r.match.event_hour_between ?? [0, 24])] as [number, number],
    set: (r, v) => { r.match.event_hour_between = [...(v as [number, number])] as [number, number]; } },
  { key: "window_minutes", label: "時間窗（分鐘）", help: "在這段時間內累計", kind: "int", min: 1, max: 240, step: 1,
    applies: (r) => typeof r.window?.minutes === "number", get: (r) => r.window?.minutes ?? 0,
    set: (r, v) => { r.window = { ...r.window, minutes: v as number }; } },
  { key: "window_hours", label: "時間窗（小時）", help: "在這段時間內累計", kind: "int", min: 1, max: 168, step: 1,
    applies: (r) => typeof r.window?.hours === "number", get: (r) => r.window?.hours ?? 0,
    set: (r, v) => { r.window = { ...r.window, hours: v as number }; } },
  { key: "over_baseline_multiplier", label: "超過平常的倍數", help: "時間窗內的讀取量超過該帳號平常量的幾倍才告警", kind: "number",
    min: 1.5, max: 1000, step: 0.5, applies: (r) => typeof r.window?.over_baseline_multiplier === "number",
    get: (r) => r.window?.over_baseline_multiplier ?? 0, set: (r, v) => { r.window = { ...r.window, over_baseline_multiplier: v as number }; } },
  { key: "threshold", label: "門檻（不同品牌數）", help: "時間窗內至少幾個不同品牌回報才告警", kind: "int", min: 2, max: 100, step: 1,
    applies: (r) => typeof r.window?.threshold === "number", get: (r) => r.window?.threshold ?? 0,
    set: (r, v) => { r.window = { ...r.window, threshold: v as number }; } },
];

export const FIELD_BY_KEY = Object.fromEntries(FIELDS.map((f) => [f.key, f])) as Record<FieldKey, FieldSpec>;

export function editableFields(rule: Rule): FieldSpec[] {
  return FIELDS.filter((f) => f.applies(rule));
}

/** 規則中不開放網站修改、需要改 YAML 的條件（顯示給管理者看）。 */
export function fixedConditions(rule: Rule): string[] {
  const m = rule.match, out: string[] = [];
  if (m.environment) out.push(`環境：${m.environment}`);
  if (m.table) out.push(`資料表：${m.table}`);
  if (m.ip_seen_before === false) out.push("只看沒出現過的來源 IP");
  if (m.text_regex) out.push(`內容比對：${m.text_regex}`);
  if (rule.window?.group_by === "account") out.push("依帳號分組");
  if (rule.window?.distinct === "brand") out.push("計算不同品牌數");
  return out;
}

const same = (a: FieldValue, b: FieldValue) => JSON.stringify(a) === JSON.stringify(b);

function checkValue(f: FieldSpec, v: unknown): { ok: true; value: FieldValue } | { ok: false; error: string } {
  const bad = (msg: string) => ({ ok: false as const, error: `${f.label}：${msg}` });
  switch (f.kind) {
    case "bool":
      return typeof v === "boolean" ? { ok: true, value: v } : bad("必須是是或否");
    case "choice":
      return typeof v === "string" && (f.choices ?? []).some((c) => c.value === v) ? { ok: true, value: v } : bad("選項不正確");
    case "int":
    case "number": {
      if (typeof v !== "number" || !Number.isFinite(v)) return bad("必須是數字");
      if (f.kind === "int" && !Number.isInteger(v)) return bad("必須是整數");
      if (f.step && f.kind === "number" && Math.abs(v / f.step - Math.round(v / f.step)) > 1e-9) return bad(`必須是 ${f.step} 的倍數`);
      if (v < (f.min ?? -Infinity) || v > (f.max ?? Infinity)) return bad(`必須在 ${f.min}～${f.max} 之間`);
      return { ok: true, value: v };
    }
    case "hours": {
      if (!Array.isArray(v) || v.length !== 2 || !v.every((x) => Number.isInteger(x))) return bad("必須是兩個整數");
      const [from, to] = v as number[];
      if (from < 0 || from > 23 || to < 1 || to > 24 || from >= to) return bad("開始需在 0～23、結束需在 1～24，且開始早於結束");
      return { ok: true, value: [from, to] };
    }
    case "logins": {
      if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) return bad("必須是帳號清單");
      const list = [...new Set((v as string[]).map((x) => x.trim()).filter(Boolean))];
      if (list.length < 1 || list.length > 10) return bad("需要 1～10 個帳號（全部移除會讓每次正式部署都告警）");
      const wrong = list.find((x) => !LOGIN_RE.test(x));
      if (wrong) return bad(`「${wrong.slice(0, 40)}」不是合法的 GitHub 帳號`);
      return { ok: true, value: list };
    }
  }
}

/** 驗證網站送來的設定；與預設相同的值不保存（只記差異），回傳的 value 可直接寫入設定檔。 */
export function validateOverrides(raw: unknown, defaults: Rule[]): { ok: true; value: Overrides } | { ok: false; error: string } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { ok: false, error: "設定格式錯誤" };
  const byId = new Map(defaults.map((r) => [r.id, r]));
  const out: Overrides = {};
  for (const [id, fields] of Object.entries(raw as Record<string, unknown>)) {
    const rule = byId.get(id);
    if (!rule) return { ok: false, error: `沒有規則 ${id.slice(0, 20)}` };
    if (!fields || typeof fields !== "object" || Array.isArray(fields)) return { ok: false, error: `${id} 的設定格式錯誤` };
    const allowed = new Map(editableFields(rule).map((f) => [f.key, f]));
    const kept: RuleOverrides = {};
    for (const [key, v] of Object.entries(fields as Record<string, unknown>)) {
      const f = allowed.get(key as FieldKey);
      if (!f) return { ok: false, error: `${id} 不能調整「${key.slice(0, 30)}」（請改 rules/realtime.yaml）` };
      const c = checkValue(f, v);
      if (!c.ok) return { ok: false, error: `${id} ${c.error}` };
      if (!same(c.value, f.get(rule))) kept[f.key] = c.value;
    }
    if (Object.keys(kept).length) out[id] = kept;
  }
  return { ok: true, value: out };
}

function applyOne(rule: Rule, o: RuleOverrides): EffectiveRule {
  const r: EffectiveRule = { ...structuredClone(rule), enabled: true };
  for (const f of editableFields(rule)) {
    const v = o[f.key];
    if (v !== undefined) f.set(r, v);
  }
  return r;
}

/** 預設規則套用設定後的實際規則。設定檔中已不存在或不可調整的項目略過，並列在 warnings（讀檔時用，不會拋錯讓偵測停擺）。 */
export function applySettings(defaults: Rule[], overrides: Overrides | null | undefined): { rules: EffectiveRule[]; warnings: string[] } {
  const warnings: string[] = [];
  const byId = new Set(defaults.map((r) => r.id));
  for (const id of Object.keys(overrides ?? {})) if (!byId.has(id)) warnings.push(`設定中的 ${id} 已不在預設規則，略過`);
  const rules = defaults.map((rule) => {
    const o = (overrides ?? {})[rule.id] ?? {};
    const allowed = new Map(editableFields(rule).map((f) => [f.key, f]));
    const ok: RuleOverrides = {};
    for (const [k, v] of Object.entries(o)) {
      const f = allowed.get(k as FieldKey);
      const c = f ? checkValue(f, v) : null;
      if (f && c?.ok) ok[f.key] = c.value;
      else warnings.push(`${rule.id} 的「${k}」不合法，改用預設值`);
    }
    return applyOne(rule, ok);
  });
  return { rules, warnings };
}

export interface RuleSettingsFile {
  version: number; updated_at: string | null; updated_by: string | null; reason: string | null; rules: Overrides;
}

export function settingsText(prevVersion: number, rules: Overrides, actor: string, reason: string, now = new Date()): string {
  const file: RuleSettingsFile = { version: prevVersion + 1, updated_at: now.toISOString(), updated_by: actor, reason, rules };
  return `${JSON.stringify(file, null, 2)}\n`;
}

export function parseSettings(text: string): RuleSettingsFile {
  const raw = JSON.parse(text) as Partial<RuleSettingsFile>;
  const version = Number(raw.version);
  if (!raw.rules || typeof raw.rules !== "object" || Array.isArray(raw.rules)) throw new Error("設定檔缺少 rules");
  return { version: Number.isInteger(version) && version > 0 ? version : 1,
           updated_at: typeof raw.updated_at === "string" ? raw.updated_at : null,
           updated_by: typeof raw.updated_by === "string" ? raw.updated_by : null,
           reason: typeof raw.reason === "string" ? raw.reason : null, rules: raw.rules as Overrides };
}
