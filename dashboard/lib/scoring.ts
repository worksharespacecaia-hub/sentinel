// 燈號權重（rules/scoring.json）的網站端：輸入檢查、設定檔內容、以及「改了權重會怎樣」的試算。
// 正式分數與燈號仍由 Python 評估流程計算（tools/scoring.py）；這裡的試算只用已發布的分數拆解重新加總，供調整前參考。
import limits from "./scoring-limits.json" with { type: "json" };
import type { Level, Light, Risk } from "./data";

export type FactorKey = keyof typeof limits.factors;
export const FACTOR_KEYS = Object.keys(limits.factors) as FactorKey[];
export const LIMITS = limits;
export type Factors = Record<FactorKey, number>;
export interface Thresholds { high: number; medium: number }
export interface Weights { factors: Factors; thresholds: Thresholds }
export interface ScoringConfig extends Weights {
  version: number; updated_at: string | null; updated_by: string | null; reason: string | null;
}

export const DEFAULT_WEIGHTS: Weights = {
  factors: Object.fromEntries(FACTOR_KEYS.map((k) => [k, limits.factors[k].default])) as Factors,
  thresholds: { high: limits.thresholds.high.default, medium: limits.thresholds.medium.default },
};

const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);

/** 與 Python 的 ScoringConfig 相同的規則：每個因子都要有、整數、在範圍內；中門檻 < 高門檻 ≤ 上限。 */
export function validateWeights(factors: unknown, thresholds: unknown): { ok: true; value: Weights } | { ok: false; error: string } {
  if (!factors || typeof factors !== "object" || Array.isArray(factors)) return { ok: false, error: "缺少加分因子" };
  const f = factors as Record<string, unknown>;
  const extra = Object.keys(f).filter((k) => !(k in limits.factors));
  if (extra.length) return { ok: false, error: `不認識的因子：${extra.join(", ")}` };
  const out = {} as Factors;
  for (const k of FACTOR_KEYS) {
    const v = f[k];
    const { min, max, label } = limits.factors[k];
    if (!isInt(v) || v < min || v > max) return { ok: false, error: `${label} 必須是 ${min}～${max} 的整數` };
    out[k] = v;
  }
  if (!thresholds || typeof thresholds !== "object") return { ok: false, error: "缺少門檻" };
  const t = thresholds as Record<string, unknown>;
  const m = limits.thresholds.medium, h = limits.thresholds.high;
  if (Object.keys(t).some((k) => k !== "high" && k !== "medium")) return { ok: false, error: "門檻只有高、中兩個" };
  if (!isInt(t.medium) || t.medium < m.min || t.medium > m.max) return { ok: false, error: `${m.label}必須是 ${m.min}～${m.max} 的整數` };
  if (!isInt(t.high) || t.high <= t.medium || t.high > h.max) return { ok: false, error: `${h.label}必須大於中風險門檻且不超過 ${h.max}` };
  return { ok: true, value: { factors: out, thresholds: { high: t.high, medium: t.medium } } };
}

export function isDefaultWeights(w: Weights): boolean {
  return FACTOR_KEYS.every((k) => w.factors[k] === DEFAULT_WEIGHTS.factors[k])
    && w.thresholds.high === DEFAULT_WEIGHTS.thresholds.high && w.thresholds.medium === DEFAULT_WEIGHTS.thresholds.medium;
}

/** 寫回 rules/scoring.json 的內容（固定格式，方便在 Git 中比對差異）。 */
export function configText(prevVersion: number, w: Weights, actor: string, reason: string, now = new Date()): string {
  const cfg: ScoringConfig = { version: prevVersion + 1, factors: w.factors, thresholds: w.thresholds,
                               updated_at: now.toISOString(), updated_by: actor, reason };
  return `${JSON.stringify(cfg, null, 2)}\n`;
}

const RANK: Record<Level, number> = { low: 0, medium: 1, high: 2 };
const LABEL_TO_KEY = new Map(FACTOR_KEYS.map((k) => [limits.factors[k].label, k] as const));

function levelOf(score: number, t: Thresholds): Level {
  return score >= t.high ? "high" : score >= t.medium ? "medium" : "low";
}

type ScoredRisk = Pick<Risk, "score" | "level" | "score_level" | "level_reason" | "breakdown" | "level_floor" | "provisional_basis">;

/** 用拆解重新加總：基礎分不變、加分因子換成新權重，再套門檻、暫定上限（最高中）與規則下限。 */
export function rescore(r: ScoredRisk, w: Weights): { score: number; level: Level } {
  let raw = 0;
  for (const b of r.breakdown) {
    const key = LABEL_TO_KEY.get(b.factor);
    raw += key ? w.factors[key] : b.points;
  }
  const score = Math.max(raw, 0);
  let level = levelOf(score, w.thresholds);
  // 舊報告沒有 provisional_basis／level_floor 欄位時，從等級說明推回
  const provisional = r.provisional_basis ?? r.level_reason.includes("暫定情資");
  const floor = r.level_floor !== undefined ? r.level_floor
    : r.level_reason.includes("規則下限") && RANK[r.level] > RANK[r.score_level] ? r.level : null;
  if (provisional && level === "high") level = "medium";
  if (floor && RANK[floor] > RANK[level]) level = floor;
  return { score, level };
}

export interface Preview {
  counts: Record<Level, number>; light: Light;
  changed: { id: string; title: string; from: Level; to: Level }[];
}

/** 未修復風險在新權重下的高中低數量與「只看風險」的燈號（早期訊號、可見度、即時告警等其他原因可能讓實際燈號更高）。 */
export function preview(risks: (ScoredRisk & Pick<Risk, "id" | "title" | "status">)[], w: Weights): Preview {
  const counts: Record<Level, number> = { high: 0, medium: 0, low: 0 };
  const changed: Preview["changed"] = [];
  for (const r of risks) {
    if (r.status === "fixed") continue;
    const n = rescore(r, w);
    counts[n.level] += 1;
    if (n.level !== r.level) changed.push({ id: r.id, title: r.title, from: r.level, to: n.level });
  }
  const light: Light = counts.high > 0 ? "red" : counts.medium > 0 ? "yellow" : "green";
  return { counts, light, changed };
}
