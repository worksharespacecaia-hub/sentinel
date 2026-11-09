import { test } from "node:test";
import assert from "node:assert/strict";
import { RULES, baselineFor, maskText, namespaceOf, staticMatch, taipeiHour, timeCheck, validateEvent, type RtEvent } from "./rules.ts";

const rule = (id: string) => RULES.find((r) => r.id === id)!;
const ev = (over: Partial<RtEvent> & { data?: RtEvent["data"] }): RtEvent => ({
  id: "evt-test-1", source: "github.deployment", event_time: "2026-11-09T03:00:00Z", received_at: "2026-11-09T03:00:01Z",
  asset_id: "deploy-pipeline", account: null, simulated: false, simulation_id: null, data: {}, ...over,
});

test("RT-001：非 Pipeline 發起的 production 部署命中；github-actions[bot] 與非 production 不命中", () => {
  const r = rule("RT-001");
  assert.equal(staticMatch(r, ev({ data: { environment: "production", creator: "alice-dev" } })).ok, true);
  assert.equal(staticMatch(r, ev({ data: { environment: "production", creator: "github-actions[bot]" } })).ok, false);
  assert.equal(staticMatch(r, ev({ data: { environment: "staging", creator: "alice-dev" } })).ok, false);
  assert.equal(staticMatch(r, ev({ data: { environment: "production" } })).ok, false, "缺少 creator 不能當成非 Pipeline");
});

const complaint = (text: string) => ev({ source: "support.complaint", asset_id: "platform", data: { brand: "brand-bloom", text } });

test("RT-003：全形冒號、半形冒號、無冒號、小寫 order、order no. 都能辨識訂單資訊", () => {
  const r = rule("RT-003");
  for (const text of ["訂單編號：BL20261108001", "訂單編號:BL20261108001", "訂單號碼 HK-20261107-88", "my order #km2026110555",
                      "ORDER NO. AB12345678", "order:XY98765432"]) {
    assert.equal(staticMatch(r, complaint(text)).ok, true, text);
  }
  for (const text of ["App 登入有點慢", "訂單編號：1234", "order is late"]) {
    assert.equal(staticMatch(r, complaint(text)).ok, false, text);
  }
});

const audit = (iso: string, extra: Partial<RtEvent["data"]> = {}) =>
  ev({ source: "db.audit", asset_id: "order-db-prod", account: "dba-alice", event_time: iso,
       data: { table: "orders", rows_read: 10, ip: "203.0.113.45", ...extra } });

test("RT-002：以事件時間（Asia/Taipei）判斷 0～6 時；含 0 時、不含 6 時", () => {
  const r = rule("RT-002");
  assert.equal(taipeiHour("2026-11-08T16:00:00Z"), 0);
  assert.equal(staticMatch(r, audit("2026-11-08T16:00:00Z")).ok, true, "台北 00:00");
  assert.equal(staticMatch(r, audit("2026-11-08T21:59:59Z")).ok, true, "台北 05:59:59");
  assert.equal(staticMatch(r, audit("2026-11-08T22:00:00Z")).ok, false, "台北 06:00");
  assert.equal(staticMatch(r, audit("2026-11-08T15:59:59Z")).ok, false, "台北 23:59:59");
  assert.equal(staticMatch(r, audit("2026-11-08T18:00:00Z", { table: "products" })).ok, false);
  assert.equal(staticMatch(r, audit("2026-11-08T18:00:00Z", { ip: undefined })).ok, false, "缺少 IP 無法判斷新來源");
});

test("基準：帳號基準或預設值，必須 > 0", () => {
  assert.equal(baselineFor("dba-alice"), 200);
  assert.equal(baselineFor("unknown-account"), 100);
  assert.throws(() => baselineFor("x", { unit: "rows/10min", default: 0, accounts: {} }));
});

test("時間：真實事件拒絕未來 > 5 分鐘與延遲 > 24 小時；模擬事件不套用", () => {
  const now = Date.parse("2026-11-09T03:00:00Z");
  assert.equal(timeCheck(ev({ event_time: "2026-11-09T03:04:59Z" }), now), null);
  assert.match(timeCheck(ev({ event_time: "2026-11-09T03:05:01Z" }), now)!, /未來/);
  assert.match(timeCheck(ev({ event_time: "2026-11-08T02:59:59Z" }), now)!, /24 小時/);
  assert.equal(timeCheck(ev({ event_time: "2026-11-01T00:00:00Z", simulated: true, simulation_id: "sim-202611090300-abcdef" }), now), null);
});

test("命名空間：模擬事件必須有合法 simulation_id，與真實分開", () => {
  assert.equal(namespaceOf({ simulated: false, simulation_id: null }), "real");
  assert.equal(namespaceOf({ simulated: true, simulation_id: "sim-202611090300-abcdef" }), "sim:sim-202611090300-abcdef");
  assert.throws(() => namespaceOf({ simulated: true, simulation_id: null }));
  assert.throws(() => namespaceOf({ simulated: true, simulation_id: "real" }));
});

test("事件驗證：資產必須在規則範圍、ID 與欄位格式受限", () => {
  assert.equal(validateEvent(ev({})), null);
  assert.match(validateEvent(ev({ asset_id: "member-db-prod" }))!, /資產/);
  assert.match(validateEvent(ev({ id: "../../x" }))!, /ID/);
  assert.match(validateEvent(audit("2026-11-08T18:00:00Z", { ip: "1.2.3.4; rm -rf" }))!, /IP/);
});

test("去敏：遮蔽訂單編號類字串", () => {
  const masked = maskText("對方說出訂單編號：BL20261108001");
  assert.ok(!masked.includes("BL20261108001"));
  assert.ok(masked.includes("BL"));
});
