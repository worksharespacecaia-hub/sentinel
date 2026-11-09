import { test } from "node:test";
import assert from "node:assert/strict";
import { combineLight, type DailyInfo, type OpenAlertsInfo } from "./light.ts";

const NOW = Date.parse("2026-11-10T08:00:00Z");
const fixedDaily: DailyInfo = { light: "yellow", light_reasons: ["14 個中風險"], generated_at: "2026-11-10T06:00:00Z" };
const noAlerts: OpenAlertsInfo = { realHighOpen: 0, simulatedOpen: 0, degraded: null };

test("修復後：daily 已降為黃燈，但仍有未結案的真實高風險告警時維持紅燈；結案後才降為黃燈", () => {
  const blocked = combineLight(fixedDaily, [], { ...noAlerts, realHighOpen: 1 }, NOW);
  assert.equal(blocked.light, "red");
  assert.ok(blocked.reasons.some((r) => r.includes("1 個未結案的即時高風險告警")));
  const closed = combineLight(fixedDaily, [], noAlerts, NOW);
  assert.equal(closed.light, "yellow");
  assert.deepEqual(closed.degraded, []);
});

test("模擬告警不影響有效燈號；告警狀態無法取得時至少黃燈並標示資料不足", () => {
  const green: DailyInfo = { ...fixedDaily, light: "green", light_reasons: ["沒有未處理的中高風險"] };
  assert.equal(combineLight(green, [], { ...noAlerts, simulatedOpen: 5 }, NOW).light, "green");
  const lost = combineLight(green, [], { ...noAlerts, degraded: "Redis 未設定" }, NOW);
  assert.equal(lost.light, "yellow");
  assert.deepEqual(lost.degraded, ["Redis 未設定"]);
});

test("daily 缺失或超過 36 小時未更新時不會是綠燈；正式 advisory 可以提高燈號", () => {
  assert.equal(combineLight(null, [], noAlerts, NOW).light, "yellow");
  const stale = combineLight({ ...fixedDaily, light: "green", generated_at: "2026-11-08T08:00:00Z" }, [], noAlerts, NOW);
  assert.equal(stale.light, "yellow");
  assert.ok(stale.degraded.includes("每日評估超過 36 小時未更新"));
  const adv = combineLight(fixedDaily, [{ id: "adv-php-2026-10-21", light: "red", run_id: "9" }], noAlerts, NOW);
  assert.equal(adv.light, "red");
});
