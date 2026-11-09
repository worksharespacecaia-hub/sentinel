import { test } from "node:test";
import assert from "node:assert/strict";
import { alertFromIssue, checkTransition, validEvidenceUrl } from "./alertstore.ts";
import { buildPreset, newSimulationId, taipeiToday } from "./presets.ts";
import { SIM_ID_RE, taipeiHour, validateEvent } from "./rules.ts";

const input = (to: "open" | "contained" | "closed", extra = {}) =>
  ({ to, actor: "admin", reason: "已撤銷部署權杖", evidence_url: "https://example.com/evidence", ...extra });

test("狀態轉移：open → contained → closed，或 contained → open；不能從 open 直接結案", () => {
  assert.equal(checkTransition({ status: "open" }, input("contained")), null);
  assert.match(checkTransition({ status: "open" }, input("closed", { containment_confirmed: true, reverified: true }))!, /不允許/);
  assert.equal(checkTransition({ status: "contained" }, input("open")), null);
  assert.match(checkTransition({ status: "closed" }, input("open"))!, /不允許/);
});

test("結案：必須確認已圍堵並重新驗證", () => {
  assert.match(checkTransition({ status: "contained" }, input("closed"))!, /確認/);
  assert.match(checkTransition({ status: "contained" }, input("closed", { containment_confirmed: true }))!, /確認/);
  assert.equal(checkTransition({ status: "contained" }, input("closed", { containment_confirmed: true, reverified: true })), null);
});

test("驗證證據：只接受 HTTPS 且不含帳密", () => {
  assert.equal(validEvidenceUrl("https://github.com/o/r/issues/1"), true);
  assert.equal(validEvidenceUrl("http://example.com"), false);
  assert.equal(validEvidenceUrl("javascript:alert(1)"), false);
  assert.equal(validEvidenceUrl("https://user:pw@example.com"), false);
  assert.equal(validEvidenceUrl(""), false);
});

const issue = (meta: object, labels: string[]) => ({
  number: 7, html_url: "https://github.com/o/sentinel/issues/7", state: "closed", labels,
  body: `<!-- sentinel-alert-id: x -->\n<!-- sentinel-alert ${JSON.stringify(meta)} -->\n內容`,
});
const META = { alert_id: "al-rt-001-0123456789abcdef", rule_id: "RT-001", simulated: false, dedup_key: "rt:real:dedup:RT-001:deploy-pipeline",
               created_at: "2026-11-09T03:00:00Z" };

test("重建：只依受信任 marker 與 status 標籤；Issue 被關閉不代表結案", () => {
  const a = alertFromIssue(issue(META, ["sentinel-alert", "status:open"]), "o/sentinel")!;
  assert.equal(a.id, META.alert_id);
  assert.equal(a.status, "open", "Issue state=closed 但標籤仍是 open");
  assert.equal(a.level, "high");
  assert.equal(a.issue_number, 7);
  assert.equal(alertFromIssue(issue(META, ["status:contained"]), "o/sentinel")!.status, "contained");
  assert.equal(alertFromIssue(issue({ ...META, simulated: true }, ["status:open"]), "o/sentinel"), null, "模擬告警不重建");
  assert.equal(alertFromIssue(issue({ ...META, alert_id: "../x" }, ["status:open"]), "o/sentinel"), null);
  assert.equal(alertFromIssue(issue({ ...META, rule_id: "RT-999" }, ["status:open"]), "o/sentinel"), null);
  assert.equal(alertFromIssue({ ...issue(META, []), body: "沒有 marker" }, "o/sentinel"), null);
});

test("模擬器：simulation_id 由伺服器產生；night-bulk-read 的事件在台北凌晨 2 點多", () => {
  const now = new Date("2026-11-09T06:30:00Z");   // 台北下午 2:30（白天排練）
  const sid = newSimulationId(now);
  assert.match(sid, SIM_ID_RE);
  assert.equal(taipeiToday(now, 2, 10), "2026-11-08T18:10:00.000Z");
  const evs = buildPreset("night-bulk-read", sid, now);
  assert.ok(evs.every((e) => e.simulated && e.simulation_id === sid && validateEvent(e) === null));
  const night = evs.filter((e) => e.data.ip === "203.0.113.45");
  assert.ok(night.every((e) => taipeiHour(e.event_time) === 2));
  assert.ok(night.reduce((s, e) => s + (e.data.rows_read ?? 0), 0) > 2000);
  const fraud = buildPreset("multi-brand-fraud", sid, now);
  assert.equal(new Set(fraud.map((e) => e.data.brand)).size, 3);
  assert.ok(fraud.every((e) => validateEvent(e) === null));
});
