// 預算的整合測試：本機 Docker 的 Redis + Upstash REST 相容代理實際執行 Lua（scripts/itest.sh 啟動與清除容器）。
import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { budgetConfig, reserve, settle, status } from "./budget.ts";
import { redis } from "./redis.ts";

const NOV = new Date("2026-11-15T00:00:00Z");
const DEC = new Date("2026-12-02T00:00:00Z");
const cfg = budgetConfig({ BUDGET_MONTHLY_USD: "1", BUDGET_BUFFER: "0" });   // 每月 US$1，方便測上限

beforeEach(async () => {
  const keys = await redis<string[]>("KEYS", "budget:*");
  if (keys.length) await redis("DEL", ...keys);
});

test("預留 → 結算：依實際用量計入，釋放預留額", async () => {
  const r = await reserve("run1-1/a2/a2/1", 300_000, NOV, cfg);
  assert.equal(r.ok, true);
  assert.equal(r.ok && r.remaining_usd, 0.7);
  const s = await settle("run1-1/a2/a2/1", 120_000, NOV);
  assert.deepEqual(s, { ok: true, key: "run1-1/a2/a2/1", actual_usd: 0.12 });
  const st = await status(NOV, cfg);
  assert.equal(st.spent_usd, 0.12);
  assert.equal(st.reserved_usd, 0);
  assert.equal(st.remaining_usd, 0.88);
});

test("冪等：同一筆重送不重複扣額；已結算的 key 不能再預留；重複結算不重複計費", async () => {
  await reserve("run2-1/a4/a4/1", 100_000, NOV, cfg);
  const again = await reserve("run2-1/a4/a4/1", 100_000, NOV, cfg);
  assert.equal(again.ok && again.idempotent, true);
  assert.equal((await status(NOV, cfg)).reserved_usd, 0.1);
  const diff = await reserve("run2-1/a4/a4/1", 200_000, NOV, cfg);
  assert.equal(diff.ok, false);
  await settle("run2-1/a4/a4/1", 50_000, NOV);
  const twice = await settle("run2-1/a4/a4/1", 90_000, NOV);
  assert.equal(twice.ok && twice.idempotent, true);
  assert.equal((await status(NOV, cfg)).spent_usd, 0.05);
  const reuse = await reserve("run2-1/a4/a4/1", 100_000, NOV, cfg);
  assert.deepEqual(reuse, { ok: false, reason: "這個 key 已結算，不能再預留" });
});

test("月額度不足就拒絕；單筆超過上限也拒絕（客戶端不能提高額度）", async () => {
  assert.equal((await reserve("run3-1/a5/a5/1", 500_000, NOV, cfg)).ok, true);
  assert.equal((await reserve("run3-1/a5/a5/2", 500_000, NOV, cfg)).ok, true);
  const over = await reserve("run3-1/a5/a5/3", 10_000, NOV, cfg);
  assert.deepEqual(over, { ok: false, reason: "本月預算不足" });
  const big = await reserve("run3-1/a5/a5/4", 600_000, NOV, budgetConfig({ BUDGET_MONTHLY_USD: "100" }));
  assert.equal(big.ok, false);
});

test("未結算的預留保守地一直佔用額度；並行租約逾時後釋放並行數", async () => {
  const c = budgetConfig({ BUDGET_MONTHLY_USD: "1", BUDGET_BUFFER: "0", BUDGET_MAX_ACTIVE: "1" });
  assert.equal((await reserve("run4-1/a1/a1/1", 200_000, NOV, c)).ok, true);
  const busy = await reserve("run4-1/a2/a2/1", 200_000, NOV, c);
  assert.equal(busy.ok, false);
  const later = new Date(NOV.getTime() + 31 * 60 * 1000);                // 租約 30 分鐘逾時（例如 Job 中斷）
  assert.equal((await reserve("run4-1/a2/a2/1", 200_000, later, c)).ok, true);
  assert.equal((await status(later, c)).reserved_usd, 0.4);             // 中斷那筆的預留額仍保留，等對帳
});

test("跨月：11 月的預留在 12 月結算，計入 11 月；12 月額度獨立", async () => {
  await reserve("run5-1/a5/a5/1", 400_000, NOV, cfg);
  await settle("run5-1/a5/a5/1", 300_000, DEC);
  assert.equal((await status(NOV, cfg)).spent_usd, 0.3);
  assert.equal((await status(DEC, cfg)).spent_usd, 0);
  assert.equal((await reserve("run5-2/a5/a5/1", 500_000, DEC, cfg)).ok, true);
});

test("同時預留：總額不會超過月上限", async () => {
  const c = budgetConfig({ BUDGET_MONTHLY_USD: "1", BUDGET_BUFFER: "0", BUDGET_MAX_ACTIVE: "100" });
  const results = await Promise.all(Array.from({ length: 30 }, (_, i) => reserve(`run6-1/a2/a2/${i}`, 100_000, NOV, c)));
  assert.equal(results.filter((r) => r.ok).length, 10);
  assert.equal((await status(NOV, c)).reserved_usd, 1);
});
