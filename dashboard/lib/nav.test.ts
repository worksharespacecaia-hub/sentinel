import { test } from "node:test";
import assert from "node:assert/strict";
import { ENGINEERING, PAGES, PRIMARY, isActive } from "./nav.ts";

test("主項只有 3 個；所有頁面都在導覽中且路徑、名稱不重複", () => {
  assert.equal(PRIMARY.length, 3);
  const all = [...PRIMARY, ...ENGINEERING];
  assert.equal(all.length, Object.keys(PAGES).length);
  assert.equal(new Set(all.map((p) => p.href)).size, all.length);
  assert.equal(new Set(all.map((p) => p.label)).size, all.length);
});

test("isActive：/ 與 /brief 只比對完全相同；其他頁涵蓋子路徑但不誤判前綴", () => {
  assert.equal(isActive("/", "/"), true);
  assert.equal(isActive("/risks", "/"), false);
  assert.equal(isActive("/brief", "/brief"), true);
  assert.equal(isActive("/brief/x", "/brief"), false);
  assert.equal(isActive("/intel/evt-91app-2026-10", "/intel"), true);
  assert.equal(isActive("/intel/", "/intel"), true);
  assert.equal(isActive("/intelligence", "/intel"), false);
  assert.equal(isActive(null, "/live"), false);
});
