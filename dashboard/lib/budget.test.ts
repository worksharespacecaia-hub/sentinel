import { test } from "node:test";
import assert from "node:assert/strict";
import { KEY_RE, budgetConfig, monthKey, toMicro } from "./budget.ts";

test("預算設定：預設每月 US$15、保留 10% 緩衝、單筆上限 US$0.5；不合理的值改用預設", () => {
  const d = budgetConfig({});
  assert.deepEqual(d, { monthlyMicro: 15_000_000, capMicro: 13_500_000, maxReserveMicro: 500_000, maxActive: 10, tz: "UTC" });
  const c = budgetConfig({ BUDGET_MONTHLY_USD: "20", BUDGET_BUFFER: "0.2", BUDGET_TZ: "Asia/Taipei" });
  assert.equal(c.capMicro, 16_000_000);
  assert.equal(c.tz, "Asia/Taipei");
  const bad = budgetConfig({ BUDGET_MONTHLY_USD: "-1", BUDGET_BUFFER: "abc", BUDGET_TZ: "Mars/Base", BUDGET_MAX_RESERVATION_USD: "999" });
  assert.deepEqual(bad, d);
});

test("月份依帳務時區：跨月邊界", () => {
  const t = new Date("2026-11-30T17:00:00Z");          // 台灣時間 12/1 01:00
  assert.equal(monthKey(t, "UTC"), "2026-11");
  assert.equal(monthKey(t, "Asia/Taipei"), "2026-12");
  assert.equal(monthKey(new Date("2026-12-31T23:59:59Z"), "UTC"), "2026-12");
  assert.equal(monthKey(new Date("2027-01-01T00:00:00Z"), "UTC"), "2027-01");
});

test("金額與冪等鍵格式", () => {
  assert.equal(toMicro(0.05), 50_000);
  assert.equal(toMicro("0.1"), 100_000);
  for (const v of [-1, "abc", "", null, undefined, Infinity]) assert.equal(toMicro(v), null);
  assert.ok(KEY_RE.test("42779838559-1/a2/a2/1"));
  for (const k of ["a2", "../x/y", "run/a2 x", "run//a2", "a/".repeat(10)]) assert.equal(KEY_RE.test(k), false, k);
});
