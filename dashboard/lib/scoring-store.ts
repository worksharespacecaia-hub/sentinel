// 伺服器端：讀取目前生效的 rules/scoring.json（GitHub，快取 10 秒）與調整歷史。網站部署只有 dashboard/，所以經 GitHub API 讀寫。
import { contentsConfigured, getScoringConfig, listScoringHistory, type ScoringCommit } from "./github.ts";
import { validateWeights, type ScoringConfig } from "./scoring.ts";

export interface ScoringState {
  configured: boolean; error: string | null;
  config: ScoringConfig | null; sha: string | null; history: ScoringCommit[];
}

let cache: { at: number; value: ScoringState } | null = null;
const TTL_MS = 10_000;

export function invalidateScoringCache(): void {
  cache = null;
}

export function parseConfig(text: string): ScoringConfig {
  const raw = JSON.parse(text) as Record<string, unknown>;
  const v = validateWeights(raw.factors, raw.thresholds);
  if (!v.ok) throw new Error(v.error);
  const version = Number(raw.version);
  return { ...v.value, version: Number.isInteger(version) && version > 0 ? version : 1,
           updated_at: typeof raw.updated_at === "string" ? raw.updated_at : null,
           updated_by: typeof raw.updated_by === "string" ? raw.updated_by : null,
           reason: typeof raw.reason === "string" ? raw.reason : null };
}

export async function loadScoringState(force = false): Promise<ScoringState> {
  if (!force && cache && Date.now() - cache.at < TTL_MS) return cache.value;
  if (!contentsConfigured()) {
    return { configured: false, error: "GH_DISPATCH_TOKEN 或 GH_OWNER／GH_REPO 未設定，無法讀寫權重設定", config: null, sha: null, history: [] };
  }
  let value: ScoringState;
  try {
    const [{ text, sha }, history] = await Promise.all([getScoringConfig(), listScoringHistory().catch(() => [])]);
    value = { configured: true, error: null, config: parseConfig(text), sha, history };
  } catch (e) {
    value = { configured: true, error: `讀取權重設定失敗（${(e as Error).message.slice(0, 80)}）`, config: null, sha: null, history: [] };
  }
  cache = { at: Date.now(), value };
  return value;
}
