// 偵測規則的實際設定（伺服器端）。
// - 正式紀錄：GitHub 的 rules/realtime-settings.json（每次修改一個 commit，記操作人與理由），與燈號權重相同
// - 即時路徑：偵測要在 1 秒內完成，不能每次讀 GitHub，所以儲存時同時寫一份到 Redis；偵測讀 程序內快取（5 秒）→ Redis → 預設規則
// - Redis 沒有這份設定（例如被清掉）時回報 missing，由呼叫端在回應後以 syncRulesFromGitHub 修復；修復前先用預設規則，不阻擋偵測
// - 設定中不合法的項目改用預設值並列在 warnings，偵測不因設定錯誤而停擺
import { contentsConfigured, getRuleSettingsFile, listRuleSettingsHistory, putRuleSettingsFile, type ScoringCommit } from "./github.ts";
import { redis, redisConfigured } from "./redis.ts";
import { applySettings, parseSettings, settingsText, type EffectiveRule, type Overrides, type RuleSettingsFile } from "./rule-settings.ts";
import { RULES } from "./rules.ts";

export const RULES_KEY = "cfg:realtime-rules";
const TTL_MS = 5_000;

interface Stored { sha: string | null; settings: RuleSettingsFile | null; synced_at: string }

export interface ActiveRules {
  rules: EffectiveRule[]; version: number; sha: string | null;
  source: "settings" | "default"; missing: boolean; warnings: string[];
}

let mem: { at: number; value: ActiveRules } | null = null;

export function invalidateRuleCache(): void {
  mem = null;
}

function build(stored: Stored | null): ActiveRules {
  const { rules, warnings } = applySettings(RULES, stored?.settings?.rules);
  return { rules, version: stored?.settings?.version ?? 0, sha: stored?.sha ?? null,
           source: stored?.settings ? "settings" : "default", missing: stored === null, warnings };
}

/** 偵測時使用的規則。Redis 讀取失敗時回傳預設規則且不快取（之後的 Lua 也會失敗，由呼叫端回報 Redis 問題）。 */
export async function activeRules(now = Date.now()): Promise<ActiveRules> {
  if (mem && now - mem.at < TTL_MS) return mem.value;
  let raw: string | null;
  try {
    raw = await redis<string | null>("GET", RULES_KEY);
  } catch {
    return build(null);
  }
  let stored: Stored | null = null;
  try {
    stored = raw ? (JSON.parse(raw) as Stored) : null;
  } catch {
    stored = null;
  }
  const value = build(stored);
  mem = { at: now, value };
  return value;
}

async function writeStored(stored: Stored): Promise<void> {
  await redis("SET", RULES_KEY, JSON.stringify(stored));
  invalidateRuleCache();
}

/** 以 GitHub 的設定檔更新 Redis：Redis 被清掉、或有人直接在 GitHub 改了檔案時修復。 */
export async function syncRulesFromGitHub(): Promise<ActiveRules | null> {
  if (!contentsConfigured() || !redisConfigured()) return null;
  const file = await getRuleSettingsFile();
  const stored: Stored = { sha: file?.sha ?? null, settings: file ? parseSettings(file.text) : null, synced_at: new Date().toISOString() };
  await writeStored(stored);
  return build(stored);
}

export interface RuleSettingsState {
  configured: boolean; error: string | null; sha: string | null; settings: RuleSettingsFile | null;
  active: ActiveRules; in_sync: boolean; history: ScoringCommit[];
}

/** 「偵測規則」頁：讀 GitHub 的正式設定；Redis 與 GitHub 不一致時順便修復，並回報目前偵測實際使用的版本。 */
export async function loadRuleSettingsState(): Promise<RuleSettingsState> {
  const active = await activeRules();
  if (!contentsConfigured()) {
    return { configured: false, error: "GH_DISPATCH_TOKEN 或 GH_OWNER／GH_REPO 未設定，無法讀寫偵測規則設定（偵測使用預設規則）",
             sha: null, settings: null, active, in_sync: active.source === "default", history: [] };
  }
  try {
    const [file, history] = await Promise.all([getRuleSettingsFile(), listRuleSettingsHistory().catch(() => [] as ScoringCommit[])]);
    const sha = file?.sha ?? null;
    const settings = file ? parseSettings(file.text) : null;
    let current = active;
    if ((active.missing || active.sha !== sha) && redisConfigured()) {
      current = (await syncRulesFromGitHub().catch(() => null)) ?? active;
    }
    return { configured: true, error: null, sha, settings, active: current, in_sync: !current.missing && current.sha === sha, history };
  } catch (e) {
    return { configured: true, error: `讀取偵測規則設定失敗（${(e as Error).message.slice(0, 80)}）`, sha: null, settings: null,
             active, in_sync: false, history: [] };
  }
}

export class SettingsConflict extends Error {}

/** 儲存：先寫 GitHub（以 base_sha 做併發檢查），成功後寫 Redis。Redis 寫入失敗時 GitHub 已有紀錄，下次開啟設定頁會自動修復。 */
export async function saveRuleSettings(overrides: Overrides, actor: string, reason: string, baseSha: string | null):
    Promise<{ version: number; commit_sha: string; commit_url: string; redis_synced: boolean }> {
  const file = await getRuleSettingsFile();
  const currentSha = file?.sha ?? null;
  if (currentSha !== baseSha) throw new SettingsConflict("偵測規則剛被其他人修改，請重新整理後再調整");
  const prevVersion = file ? parseSettings(file.text).version : 0;
  const text = settingsText(prevVersion, overrides, actor, reason);
  const message = `rules: 調整偵測規則（${actor}）\n\n理由：${reason}\n\n由 Sentinel 網站「偵測規則」頁送出（管理者密碼驗證）。儲存後數秒內生效。`;
  const commit = await putRuleSettingsFile(text, currentSha, message);
  let redisSynced = true;
  try {
    await writeStored({ sha: commit.blob_sha, settings: parseSettings(text), synced_at: new Date().toISOString() });
  } catch {
    redisSynced = false;
  }
  return { version: prevVersion + 1, commit_sha: commit.commit_sha, commit_url: commit.commit_url, redis_synced: redisSynced };
}
