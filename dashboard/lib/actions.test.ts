import { test } from "node:test";
import assert from "node:assert/strict";
import type { Report, Risk } from "./data";
import { buildActionReport, checkTrackInput, eventDetailFrom, reminderDue, trackState, type Tracking } from "./actions.ts";

const NOW = Date.parse("2026-11-10T08:00:00Z");
const H = 3600 * 1000;

const risk = (over: Partial<Risk>): Risk => ({
  id: "x", asset_id: "asset", title: "標題", category: "config", level: "high", score: 7, raw_score: 7, score_level: "high",
  level_reason: "依分數", breakdown: [], attack_path: null, matched_events: [], deadline_hours: 24, solution: null, status: "open",
  first_seen: "2026-11-10T00:00:00Z", last_evaluated: "2026-11-10T00:00:00Z", ...over,
});

const report = (risks: Risk[]): Report => ({
  run_id: "1", scenario: "daily", trigger_source: "schedule", scope: "full", target_sha: "s", completeness: "complete", data_issues: [],
  generated_at: "2026-11-10T07:00:00Z", as_of: "2026-11-10T07:00:00Z", light: "red", light_reasons: [], ceo_summary: ["a", "b", "c"],
  decisions: ["x 要納管還是除役", "y 要納管還是除役"], counts: { high: 0, medium: 0, low: 0 }, coverage: {}, risks,
  events: [{ id: "e1", kind: "archive", title: "事件一", affected_count: 2, max_level: "high", status: "open", demo: false },
           { id: "e2", kind: "archive", title: "事件二", affected_count: 0, max_level: null, status: "not_affected", demo: false }],
  intel_summary: { checked: 2, affected: 1, by_kind: {} }, daily_intel_status: "ok", cost: { total_usd: 0, per_agent: {}, cache_hit_rate: null },
  signals: [], reconcile: [], app_impact: {}, execution_mode: "replay", open_alerts: [],
});

const track = (risk_id: string, due_at: string): Tracking => ({
  risk_id, status: "in_progress", owner: "devops", due_at, note: "", set_by: "admin", set_at: "2026-11-10T07:00:00Z", history: [],
});

test("trackState：未認領、處理中、24 小時內到期、已逾期；取消或結束的追蹤視為待處理", () => {
  assert.equal(trackState(null, NOW), "open");
  assert.equal(trackState(track("a", new Date(NOW + 48 * H).toISOString()), NOW), "in_progress");
  assert.equal(trackState(track("a", new Date(NOW + 2 * H).toISOString()), NOW), "due_soon");
  assert.equal(trackState(track("a", new Date(NOW - 1).toISOString()), NOW), "overdue");
  assert.equal(trackState({ ...track("a", new Date(NOW + 2 * H).toISOString()), status: "cancelled" }, NOW), "open");
  assert.equal(reminderDue(track("a", new Date(NOW + 48 * H).toISOString()), NOW), null);
  assert.equal(reminderDue(track("a", new Date(NOW + 2 * H).toISOString()), NOW), "due_soon");
  assert.equal(reminderDue(track("a", new Date(NOW - H).toISOString()), NOW), "overdue");
});

test("buildActionReport：只列未修復的高中風險，合併決策、只列受影響事件，並計算追蹤狀態與超過建議期限", () => {
  const rep = report([risk({ id: "h", score: 9 }), risk({ id: "m", level: "medium", score: 5, deadline_hours: 168 }),
    risk({ id: "l", level: "low" }), risk({ id: "f", status: "fixed" }), risk({ id: "n", status: "need_check", score: 8 })]);
  const a = buildActionReport(rep, { now: NOW, tracking: {
    h: track("h", new Date(NOW + 2 * H).toISOString()),            // 建議期限 11/11 00:00 之前 → 未超過
    m: track("m", "2026-11-20T00:00:00Z"),                         // 建議期限 11/17 → 超過
    n: { ...track("n", "2026-11-11T00:00:00Z"), status: "cancelled" },
  } });
  assert.deepEqual(a.items.map((i) => i.id), ["h", "n", "m"]);
  assert.deepEqual(a.decisions, ["2 個未登記的系統要納管還是除役：x、y"]);
  assert.deepEqual(a.events.map((e) => e.id), ["e1"]);
  const [h, n, m] = a.items;
  assert.equal(h.track_state, "due_soon");
  assert.equal(h.beyond_suggested, false);
  assert.equal(m.beyond_suggested, true);
  assert.equal(n.tracking, null);
  assert.equal(n.need_check, true);
  assert.deepEqual(a.counts, { high: 2, medium: 1, in_progress: 2, due_soon: 1, overdue: 0, unassigned_high: 1 });
});

test("checkTrackInput：期限必填、晚於現在、30 天內；負責人與備註有長度限制", () => {
  const ok = checkTrackInput({ owner: "devops-team", due_at: "2026-11-12T18:00:00+08:00", note: "先關閉對外入口" }, NOW);
  assert.deepEqual(ok, { ok: true, value: { owner: "devops-team", due_at: "2026-11-12T10:00:00.000Z", note: "先關閉對外入口" } });
  assert.equal(checkTrackInput({ owner: "a" }, NOW).ok, false);
  assert.equal(checkTrackInput({ owner: "a", due_at: "2026-11-10T07:00:00Z" }, NOW).ok, false);
  assert.equal(checkTrackInput({ owner: "a", due_at: "2026-12-31T00:00:00Z" }, NOW).ok, false);
  assert.equal(checkTrackInput({ owner: "a", due_at: "2026-11-12T18:00" }, NOW).ok, false, "沒有時區不接受");
  assert.equal(checkTrackInput({ owner: "", due_at: "2026-11-12T18:00:00Z" }, NOW).ok, false);
  assert.equal(checkTrackInput({ owner: "a", due_at: "2026-11-12T18:00:00Z", note: "x".repeat(201) }, NOW).ok, false);
});

test("事件來源：真實事件取出標題、網址、媒體網域與驗證狀態；示範或非 http(s) 網址明確標示", () => {
  const d = eventDetailFrom({ event: { kind: "archive" }, blocks: { "1_summary": { date: "2026-10-03", confidence: "已確認", sources: [
    { url: "https://www.ithome.com.tw/news/180209", title: "iThome 報導", quote: "引用", fetch_status: "ok", verification_basis: "archived" },
    { url: "javascript:alert(1)", title: "壞網址", fetch_status: "failed" },
  ] } } });
  assert.equal(d.date, "2026-10-03");
  assert.deepEqual(d.sources[0], { title: "iThome 報導", url: "https://www.ithome.com.tw/news/180209", publisher: "ithome.com.tw", verified: true, demo: false, quote: "引用" });
  assert.equal(d.sources[1].url, null);
  const demo = eventDetailFrom({ event: { kind: "advisory" }, blocks: { "1_summary": { sources: [{ url: null, title: "虛構示範公告", fetch_status: "skipped", verification_basis: "demo" }] } } });
  assert.equal(demo.sources[0].demo, true);
  assert.deepEqual(eventDetailFrom(null), { date: null, confidence: null, sources: [] });
});

test("行動項目帶出相關事件名稱；事件帶出來源", () => {
  const rep = report([risk({ id: "h", matched_events: ["e1", "unknown"] })]);
  const a = buildActionReport(rep, { now: NOW, eventDetails: { e1: { date: "2026-10-01", confidence: "已確認",
    sources: [{ title: "t", url: "https://x.example/a", publisher: "x.example", verified: true, demo: false, quote: null }] } } });
  assert.deepEqual(a.items[0].events, [{ id: "e1", title: "事件一" }]);
  assert.equal(a.events[0].sources[0].publisher, "x.example");
});

test("v0.14 新欄位：標題用白話標題並保留原始技術標題（所有類別）；帶出品牌與不處理的話；有品牌不加事件標籤", () => {
  const sol = { risk_id: "s", temporary: "馬上把這組密碼作廢換新", permanent: "改用金鑰管理服務", options: [], suggested_owner: "App 團隊",
    verify: "重新掃描", source: "live" as const, plain_title: "品牌 App 的系統密碼寫在程式碼裡，可能造成會員個資外洩",
    if_ignored: "拿到程式碼的人就能讀走會員個資。", plain_source: "live" as const };
  const rep: Report = {
    ...report([risk({ id: "s", category: "secret", asset_id: "brand-app", title: "Git 中不得有正式環境金鑰：brand-app", solution: sol,
                     matched_events: ["e2", "e1"], attack_path: ["internet", "brand-app", "member-db-prod"] })]),
    events: [{ id: "e1", kind: "archive", title: "91APP 訂單資料庫遭入侵", affected_count: 2, max_level: "high", status: "open", demo: false, brand: "91APP" },
             { id: "e2", kind: "advisory", title: "公告", affected_count: 1, max_level: "high", status: "open", demo: false, brand: null }],
    asset_labels: { "brand-app": "品牌 App", "member-db-prod": "正式會員資料庫" },
  };
  const [it] = buildActionReport(rep, { now: NOW }).items;
  assert.equal(it.headline, "品牌 App 的系統密碼寫在程式碼裡，可能造成會員個資外洩");
  assert.equal(it.detail, "Git 中不得有正式環境金鑰：brand-app");
  assert.equal(it.if_ignored, "拿到程式碼的人就能讀走會員個資。");
  assert.equal(it.brand, "91APP");
  assert.deepEqual(it.tags, ["可一路闖到正式會員資料庫"]);
});

test("舊報告（沒有新欄位）：品牌與不處理的話為 null，標題維持現在的寫法", () => {
  const rep = report([risk({ id: "v", category: "vuln", asset_id: "storefront", title: "node 22.11.0 有 17 個已知漏洞", score: 9,
                              matched_events: ["e1"], solution: { risk_id: "v", temporary: "t", permanent: "p", options: [], suggested_owner: null,
                                                                  verify: "v", source: "template" } }),
                      risk({ id: "c", title: "內部工具不得對外開放：internal-tool", asset_id: "internal-tool" })]);
  const [v, c] = buildActionReport(rep, { now: NOW }).items;
  assert.deepEqual([v.headline, v.detail, v.if_ignored, v.brand], ["storefront 有可被入侵的漏洞", "node 22.11.0 有 17 個已知漏洞", null, null]);
  assert.deepEqual(v.tags, ["外部已有相關事件"]);
  assert.deepEqual([c.headline, c.detail, c.if_ignored, c.brand], ["內部工具不得對外開放：internal-tool", null, null, null]);
});
