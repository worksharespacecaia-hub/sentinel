import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { Report } from "./data";
import { DEFAULT_WEIGHTS, configText, isDefaultWeights, preview, rescore, validateWeights } from "./scoring.ts";

const daily = JSON.parse(readFileSync(new URL("../public/data/daily/report.json", import.meta.url), "utf8")) as Report;

test("預設權重重新加總：已發布 daily 的每一項風險分數與等級都不變（試算與正式評估同一套規則）", () => {
  for (const r of daily.risks) {
    const n = rescore(r, DEFAULT_WEIGHTS);
    assert.deepEqual(n, { score: r.score, level: r.level }, r.id);
  }
  const p = preview(daily.risks, DEFAULT_WEIGHTS);
  assert.deepEqual(p.changed, []);
  assert.equal(p.counts.high, daily.counts.high);
  assert.equal(p.counts.medium, daily.counts.medium);
});

test("調低「位於完整攻擊鏈」與提高門檻會減少高風險；規則下限（影子 IT）仍維持高", () => {
  const softer = { factors: { ...DEFAULT_WEIGHTS.factors, on_attack_chain: 0 }, thresholds: { high: 10, medium: 6 } };
  const p = preview(daily.risks, softer);
  assert.ok(p.counts.high < daily.counts.high);
  const shadow = daily.risks.find((r) => r.category === "shadow_it" && r.level === "high");
  assert.ok(shadow);
  assert.equal(rescore(shadow, softer).level, "high");
  assert.ok(p.changed.every((c) => c.from !== c.to));
});

test("暫定情資最高只到中；新版報告的 level_floor／provisional_basis 優先於等級說明", () => {
  const base = { score: 9, level: "medium" as const, score_level: "high" as const, level_reason: "暫定情資：最高只到中",
    breakdown: [{ factor: "基礎分：漏洞", points: 3, reason: "" }, { factor: "對外暴露", points: 2, reason: "" }, { factor: "位於完整攻擊鏈", points: 3, reason: "" }] };
  assert.equal(rescore(base, DEFAULT_WEIGHTS).level, "medium");
  assert.equal(rescore({ ...base, provisional_basis: false, level_reason: "依分數", level: "high" }, DEFAULT_WEIGHTS).level, "high");
  assert.equal(rescore({ ...base, provisional_basis: false, level_floor: "high", level_reason: "依分數" },
    { ...DEFAULT_WEIGHTS, thresholds: { high: 15, medium: 14 } }).level, "high");
});

test("validateWeights：缺因子、超出範圍、小數、中門檻 ≥ 高門檻、多餘欄位都拒絕", () => {
  assert.equal(validateWeights(DEFAULT_WEIGHTS.factors, DEFAULT_WEIGHTS.thresholds).ok, true);
  const { exposed: _x, ...missing } = DEFAULT_WEIGHTS.factors;
  assert.equal(validateWeights(missing, DEFAULT_WEIGHTS.thresholds).ok, false);
  assert.equal(validateWeights({ ...DEFAULT_WEIGHTS.factors, exposed: 6 }, DEFAULT_WEIGHTS.thresholds).ok, false);
  assert.equal(validateWeights({ ...DEFAULT_WEIGHTS.factors, exposed: 1.5 }, DEFAULT_WEIGHTS.thresholds).ok, false);
  assert.equal(validateWeights({ ...DEFAULT_WEIGHTS.factors, compensating: 1 }, DEFAULT_WEIGHTS.thresholds).ok, false);
  assert.equal(validateWeights({ ...DEFAULT_WEIGHTS.factors, evil: 1 }, DEFAULT_WEIGHTS.thresholds).ok, false);
  assert.equal(validateWeights(DEFAULT_WEIGHTS.factors, { high: 5, medium: 5 }).ok, false);
  assert.equal(validateWeights(DEFAULT_WEIGHTS.factors, { high: 16, medium: 4 }).ok, false);
  assert.equal(validateWeights(DEFAULT_WEIGHTS.factors, { high: 7, medium: 4, low: 1 }).ok, false);
});

test("configText：版本加一、記錄操作人與理由；isDefaultWeights 判斷是否為預設", () => {
  const text = configText(3, DEFAULT_WEIGHTS, "admin", "測試", new Date("2026-11-10T00:00:00Z"));
  const cfg = JSON.parse(text);
  assert.equal(cfg.version, 4);
  assert.equal(cfg.updated_by, "admin");
  assert.equal(cfg.updated_at, "2026-11-10T00:00:00.000Z");
  assert.ok(text.endsWith("\n"));
  assert.equal(isDefaultWeights(DEFAULT_WEIGHTS), true);
  assert.equal(isDefaultWeights({ ...DEFAULT_WEIGHTS, thresholds: { high: 8, medium: 4 } }), false);
});
