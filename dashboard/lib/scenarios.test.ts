import { test } from "node:test";
import assert from "node:assert/strict";
import { scenarioAvailability } from "./scenarios.ts";

test("網站情境：P1 情境可派發；P2 情境明確標示未啟用；白名單外拒絕", () => {
  for (const s of ["daily", "intel-demo", "peer-incident", "early-signal", "php2shell"]) assert.equal(scenarioAvailability(s), "enabled", s);
  for (const s of ["nas", "insider-path", "mobile-sdk"]) assert.equal(scenarioAvailability(s), "p2", s);
  for (const s of ["advisory", "after-fix", "", "daily;rm"]) assert.equal(scenarioAvailability(s), "unknown", s);
});
