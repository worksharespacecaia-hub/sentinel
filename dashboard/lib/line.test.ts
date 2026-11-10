import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { initialLineStep, pushAllowed, quotaTier, siteUrl, verifySignature } from "./line.ts";
import { actionReportMessage, alertMessage, reminderMessage } from "./line-messages.ts";
import type { ActionItem, ActionReport } from "./actions.ts";

test("X-Line-Signature：原始 body 的 HMAC-SHA256（Base64）才通過；改一個字、缺標頭或缺 secret 都拒絕", () => {
  const body = '{"destination":"U0","events":[]}';
  const sig = createHmac("sha256", "secret").update(body).digest("base64");
  assert.equal(verifySignature(body, sig, "secret"), true);
  assert.equal(verifySignature(`${body} `, sig, "secret"), false);
  assert.equal(verifySignature(body, null, "secret"), false);
  assert.equal(verifySignature(body, sig, undefined), false);
  assert.equal(verifySignature(body, "short", "secret"), false);
});

test("額度分級：< 150 全推；150～190 只推告警；> 190 全停；額度未知只推告警；不能超過上限", () => {
  assert.equal(pushAllowed("report", 100, 3).ok, true);
  assert.equal(pushAllowed("report", 160, 1).ok, false);
  assert.equal(pushAllowed("reminder", 150, 1).ok, false);
  assert.equal(pushAllowed("alert", 160, 3).ok, true);
  assert.equal(pushAllowed("alert", 195, 1).ok, false);
  assert.equal(pushAllowed("alert", null, 1).ok, true);
  assert.equal(pushAllowed("light", null, 1).ok, false);
  assert.equal(pushAllowed("alert", 99, 3, 100).ok, false);
  assert.deepEqual([quotaTier(10), quotaTier(160), quotaTier(195), quotaTier(null)], ["normal", "alerts_only", "stopped", "unknown"]);
});

test("新告警的 LINE 初始狀態：未設定或中風險略過；模擬告警只有 LINE_PUSH_SIMULATED=true 才推", () => {
  const env = { LINE_CHANNEL_SECRET: "s", LINE_CHANNEL_ACCESS_TOKEN: "t" };
  assert.equal(initialLineStep("high", false, {}).state, "skipped");
  assert.equal(initialLineStep("high", false, env).state, "pending");
  assert.equal(initialLineStep("medium", false, env).state, "skipped");
  assert.equal(initialLineStep("high", true, env).reason, "模擬告警預設不推播");
  assert.equal(initialLineStep("high", true, { ...env, LINE_PUSH_SIMULATED: "true" }).state, "pending");
});

test("siteUrl 只接受 HTTPS origin", () => {
  assert.equal(siteUrl({ SENTINEL_BASE_URL: "https://sentinel.example.com/" }), "https://sentinel.example.com");
  assert.equal(siteUrl({ SENTINEL_BASE_URL: "http://sentinel.example.com" }), null);
  assert.equal(siteUrl({ SENTINEL_BASE_URL: "https://x.example.com/evil?x=1" }), null);
  assert.equal(siteUrl({}), null);
});

const item: ActionItem = {
  id: "internal-tool:opsbuilder:vuln", level: "high", score: 11, need_check: false, asset_id: "internal-tool",
  headline: "internal-tool 有可被入侵的漏洞", detail: null, tags: [], temporary: "關閉對外入口", permanent: null, owner: "devops-team",
  suggested_due: "2026-11-11T00:00:00Z", track_state: "overdue", beyond_suggested: false,
  tracking: { risk_id: "internal-tool:opsbuilder:vuln", status: "in_progress", owner: "devops", due_at: "2026-11-10T00:00:00Z", note: "",
              set_by: "admin", set_at: "2026-11-09T00:00:00Z", history: [] },
};

test("LINE 訊息：標題寫燈號／等級文字；沒有網站網址時不放 URI 按鈕；altText 有長度上限", () => {
  const alert = alertMessage({ id: "al-rt-001-x", rule_id: "RT-001", rule_title: "非 Pipeline 發起的正式部署", level: "high", light: "red",
    asset_id: "deploy-pipeline", created_at: "2026-11-10T00:00:00Z", maps_to_event: null, simulated: false, summary: "x", issue_url: null }, null);
  const s = JSON.stringify(alert);
  assert.match(s, /紅燈｜RT-001 非 Pipeline 發起的正式部署/);
  assert.doesNotMatch(s, /"type":"uri"/);
  assert.match(s, /a=advice&id=al-rt-001-x/);

  const report: ActionReport = { light: "red", generated_at: "2026-11-10T00:00:00Z", summary: ["a", "b", "c"], decisions: ["d"], items: [item],
    events: [], notices: [], counts: { high: 1, medium: 0, in_progress: 1, due_soon: 0, overdue: 1, unassigned_high: 0 } };
  const r = actionReportMessage(report, "https://sentinel.example.com");
  assert.match(JSON.stringify(r), /紅燈：需要今天決策/);
  assert.match(JSON.stringify(r), /https:\/\/sentinel\.example\.com\/report/);
  assert.ok(String(r.altText).length <= 400);

  const rem = JSON.stringify(reminderMessage(item, "overdue", "https://sentinel.example.com"));
  assert.match(rem, /已逾期｜高風險/);
  assert.match(rem, /report#internal-tool%3Aopsbuilder%3Avuln/);
});
