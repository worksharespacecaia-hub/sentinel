// 伺服器端讀取 A5 發布的 public/data（唯讀）。來源只接受 index.json 中存在的 daily 或情境，不接受任意路徑。
import { promises as fs } from "node:fs";
import path from "node:path";
import { buildDigestView, flattenLatest, isDigestLatest, type DailyInfo, type DigestLatest, type DigestView } from "./digest.ts";

export type Level = "high" | "medium" | "low";
export type Light = "red" | "yellow" | "green";

export interface Breakdown { factor: string; points: number; reason: string }
export interface SolutionOption { name: string; action: string; cost: string; timing: string }
export interface Solution {
  risk_id: string; temporary: string; permanent: string; options: SolutionOption[];
  suggested_owner: string | null; verify: string; source: "live" | "replay" | "template";
}
export interface Risk {
  id: string; asset_id: string; title: string; category: string; level: Level; score: number; raw_score: number;
  score_level: Level; level_reason: string; breakdown: Breakdown[]; attack_path: string[] | null;
  matched_events: string[]; deadline_hours: number; solution: Solution | null; status: "open" | "fixed" | "need_check";
  first_seen: string; last_evaluated: string; explanation?: string | null; explanation_source?: string | null;
  /** 規則下限（例如影子 IT 至少高）；權重試算用。舊報告沒有這個欄位。 */
  level_floor?: Level | null;
  /** 暫定情資：最高只到中。 */
  provisional_basis?: boolean;
}
/** 本次評估使用的燈號權重（rules/scoring.json）；舊報告沒有這個欄位，代表使用當時的預設權重。 */
export interface ScoringInfo {
  version: number; hash: string; factors: Record<string, number>; thresholds: { high: number; medium: number };
  is_default: boolean; updated_at: string | null; updated_by: string | null;
}
export interface EventSummary { id: string; kind: string; title: string; affected_count: number; max_level: Level | null; status: string; demo: boolean }
export interface Report {
  run_id: string; scenario: string; trigger_source: string; scope: string; target_sha: string;
  completeness: string; data_issues: { source: string; status: string; impact?: string }[];
  generated_at: string; as_of: string; light: Light; light_reasons: string[]; ceo_summary: string[]; decisions: string[];
  counts: Record<Level, number>; coverage: Record<string, unknown>; risks: Risk[]; events: EventSummary[];
  intel_summary: { checked: number; affected: number; real_checked?: number; real_affected?: number; by_kind: Record<string, number> };
  daily_intel_status: string; cost: { total_usd: number; per_agent: Record<string, number>; cache_hit_rate: number | null };
  signals: { id: string; rule: string; level: string; summary: string; evidence: string[] }[];
  reconcile: { asset_id: string; type: string; registered: boolean; observed: boolean; conclusion: string; label: string;
               level_floor: string | null; reason: string; owner: string | null; observed_sources: string[] }[];
  app_impact: Record<string, unknown>; execution_mode: string; open_alerts: unknown[];
  scoring?: ScoringInfo;
}
export interface IndexEntry { run_id: string; generated_at: string; target_sha: string; completeness: string; path: string; light: Light; execution_mode: string }
export interface DataIndex {
  latest_daily?: IndexEntry; latest_complete_daily?: IndexEntry; scenarios?: Record<string, IndexEntry>;
  advisories?: Record<string, IndexEntry>; updated_at?: string;
}

const DATA_DIR = path.join(process.cwd(), "public", "data");
const SAFE_SEGMENT = /^[a-z0-9][a-z0-9._-]{0,80}$/;

async function readJson<T>(rel: string): Promise<T | null> {
  const parts = rel.split("/");
  if (parts.some((p) => !SAFE_SEGMENT.test(p.replace(/\.jsonl?$/, "")) && p !== "")) return null;
  try {
    return JSON.parse(await fs.readFile(path.join(DATA_DIR, ...parts), "utf8")) as T;
  } catch {
    return null;
  }
}

export async function readText(rel: string): Promise<string | null> {
  const parts = rel.split("/");
  if (parts.some((p) => !SAFE_SEGMENT.test(p.replace(/\.(jsonl|md)$/, "")))) return null;
  try {
    return await fs.readFile(path.join(DATA_DIR, ...parts), "utf8");
  } catch {
    return null;
  }
}

export const getIndex = () => readJson<DataIndex>("index.json").then((x) => x ?? {});

export interface Source { key: string; dir: string; label: string; simulated: boolean }

export async function resolveSource(raw: string | string[] | undefined): Promise<Source> {
  const idx = await getIndex();
  const wanted = Array.isArray(raw) ? raw[0] : raw;
  if (wanted && wanted !== "daily" && idx.scenarios?.[wanted]) {
    return { key: wanted, dir: `scenarios/${wanted}`, label: `情境：${wanted}`, simulated: true };
  }
  return { key: "daily", dir: "daily", label: "每日", simulated: false };
}

export async function listSources(): Promise<{ key: string; label: string }[]> {
  const idx = await getIndex();
  return [{ key: "daily", label: "每日" }, ...Object.keys(idx.scenarios ?? {}).sort().map((k) => ({ key: k, label: `情境：${k}` }))];
}

export const getReport = (s: Source) => readJson<Report>(`${s.dir}/report.json`);
export const getGraph = (s: Source) => readJson<{ nodes: Record<string, unknown>[]; edges: Record<string, unknown>[] }>(`${s.dir}/graph.json`);
export const getPaths = (s: Source) => readJson<{ paths: { id: string; start: string; target: string; nodes: string[]; assumption: string | null;
  steps: { from: string; to: string; kind: string; finding_ids: string[]; evidence: string[] }[] }[] }>(`${s.dir}/attack_paths.json`);
export const getIntelIndex = (s: Source) => readJson<EventSummary[]>(`${s.dir}/intel/index.json`).then((x) => x ?? []);
export const getIntelReport = (s: Source, id: string) =>
  SAFE_SEGMENT.test(id) ? readJson<Record<string, any>>(`${s.dir}/intel/${id}.json`) : Promise.resolve(null);
export const getHistory = async () => {
  try {
    const files = (await fs.readdir(path.join(DATA_DIR, "history"))).filter((f) => f.endsWith("-daily.json")).sort().slice(-30);
    const rows = await Promise.all(files.map((f) => readJson<{ date: string; light: Light; counts: Record<Level, number> }>(`history/${f}`)));
    return rows.filter(Boolean) as { date: string; light: Light; counts: Record<Level, number> }[];
  } catch {
    return [];
  }
};
export const getIntelWatch = () => readJson<Record<string, any>>("intel-watch.json");

export async function getTrace(s: Source) {
  const text = await readText(`${s.dir}/trace.jsonl`);
  if (!text) return [];
  return text.split("\n").filter(Boolean).map((l) => JSON.parse(l) as {
    ts: string; agent: string; subagent: string | null; kind: string; detail: string; source: string | null; cost_usd: number | null;
  });
}

// ── 資安事件整理（/digest）：只讀 digest/latest.json；store.json 與 seen.json 不讀 ──

export type DigestFile = { status: "missing" } | { status: "invalid" } | { status: "ok"; latest: DigestLatest };

async function readDigestFile(): Promise<DigestFile> {
  let text: string;
  try {
    text = await fs.readFile(path.join(DATA_DIR, "digest", "latest.json"), "utf8");
  } catch {
    return { status: "missing" };          // 功能上線後尚未產生（R7.3）
  }
  try {
    const data: unknown = JSON.parse(text);
    return isDigestLatest(data) ? { status: "ok", latest: data } : { status: "invalid" };
  } catch {
    return { status: "invalid" };
  }
}

/** 已發布的整理；不存在或格式不合時回傳 null。 */
export const getDigest = () => readDigestFile().then((f) => (f.status === "ok" ? f.latest : null));

const DAILY: Source = { key: "daily", dir: "daily", label: "每日", simulated: false };

/** 明細檔是否實際存在（只接受安全的 ID，不讀內容）。 */
async function intelDetailExists(id: string): Promise<boolean> {
  if (!SAFE_SEGMENT.test(id)) return false;
  try {
    return (await fs.stat(path.join(DATA_DIR, "daily", "intel", `${id}.json`))).isFile();
  } catch {
    return false;
  }
}

export type DigestPage = { status: "missing" } | { status: "invalid" } | { status: "ok"; view: DigestView };

/**
 * 以明確的 now 組出頁面資料：依台灣日期清理窗口、重組新進度與計數；
 * 新聞情資狀態與明細連結一律讀「目前」已發布的 daily（報告、intel index、明細檔），不沿用整理產生當時的狀態（R2.8、R3.3）。
 * 不改檔案、不改 latest 的更新時間。明細一律對應正式 daily，不繼承情境 source。
 */
export async function getDigestView(now: Date): Promise<DigestPage> {
  const file = await readDigestFile();
  if (file.status !== "ok") return file;
  const [report, index] = await Promise.all([getReport(DAILY), getIntelIndex(DAILY)]);
  const daily: DailyInfo | null = report && typeof report.run_id === "string" && typeof report.as_of === "string"
    && typeof report.generated_at === "string" && typeof report.daily_intel_status === "string"
    ? { run_id: report.run_id, as_of: report.as_of, generated_at: report.generated_at, daily_intel_status: report.daily_intel_status }
    : null;
  const listed = new Set((Array.isArray(index) ? index : []).map((e) => e?.id).filter((x): x is string => typeof x === "string"));
  const ids = [...new Set(flattenLatest(file.latest).map((e) => e.id))].filter((id) => listed.has(id));
  const exists = await Promise.all(ids.map(intelDetailExists));
  const available = new Set(ids.filter((_, i) => exists[i]));
  return { status: "ok", view: buildDigestView(file.latest, now, daily, available) };
}
