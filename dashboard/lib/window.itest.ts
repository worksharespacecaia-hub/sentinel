// 整合測試：以本機 Docker 的 Redis + Upstash REST 相容代理實際執行 Lua（scripts/itest.sh 啟動與清除容器）。
// GitHub API 以假的 fetch 回應，不連任何外部服務。
import { after, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { K, changeStatus, getAlert, indexState, openCounts, rebuildFromIssues, type IssueRecord } from "./alertstore.ts";
import { deliver } from "./delivery.ts";
import { buildPreset, newSimulationId } from "./presets.ts";
import { redis } from "./redis.ts";
import type { RtEvent } from "./rules.ts";
import { RULES_KEY, SettingsConflict, invalidateRuleCache, saveRuleSettings, syncRulesFromGitHub } from "./rule-store.ts";
import { processEvent } from "./window.ts";

process.env.GH_OWNER = "demo-owner";
process.env.GH_REPO = "sentinel";
process.env.ALERT_ISSUE_TOKEN = "itest-issue-token";
process.env.GH_DISPATCH_TOKEN = "itest-dispatch-token";

// ---------------------------------------------------------------- 假 GitHub
const realFetch = globalThis.fetch;
type GhCall = { method: string; path: string; body: any };
let ghCalls: GhCall[] = [];
let ghMode: "ok" | "fail" | "timeout_after_create" = "ok";
let issues: { number: number; html_url: string; state: string; body: string; labels: { name: string }[] }[] = [];
let files: Record<string, { text: string; sha: string }> = {};        // 假的 contents API（偵測規則設定檔）
let putCount = 0;
globalThis.fetch = (async (input: any, init?: any) => {
  const url = String(input instanceof Request ? input.url : input);
  if (!url.startsWith("https://api.github.com")) return realFetch(input, init);
  const path = url.slice("https://api.github.com".length);
  const method = init?.method ?? "GET";
  const body = init?.body ? JSON.parse(init.body) : null;
  ghCalls.push({ method, path, body });
  const res = (status: number, data?: unknown) => new Response(data === undefined ? null : JSON.stringify(data), { status });
  if (ghMode === "fail") return res(500, { message: "boom" });
  if (path.startsWith("/repos/demo-owner/sentinel/contents/")) {
    const fp = decodeURIComponent(path.slice("/repos/demo-owner/sentinel/contents/".length).split("?")[0]);
    const cur = files[fp];
    if (method === "GET") return cur ? res(200, { content: Buffer.from(cur.text).toString("base64"), encoding: "base64", sha: cur.sha })
                                     : res(404, { message: "Not Found" });
    if (method === "PUT") {
      if ((cur?.sha ?? undefined) !== body.sha) return res(409, { message: "sha mismatch" });
      files[fp] = { text: Buffer.from(body.content, "base64").toString("utf8"), sha: String(++putCount).padStart(40, "0") };
      return res(201, { content: { sha: files[fp].sha }, commit: { sha: "c".repeat(40), html_url: "https://github.com/demo-owner/sentinel/commit/c" } });
    }
  }
  if (method === "POST" && path === "/repos/demo-owner/sentinel/issues") {
    const n = issues.length + 1;
    const issue = { number: n, html_url: `https://github.com/demo-owner/sentinel/issues/${n}`, state: "open", body: body.body,
                    labels: body.labels.map((name: string) => ({ name })) };
    issues.push(issue);
    if (ghMode === "timeout_after_create") throw Object.assign(new Error("timeout"), { name: "TimeoutError" });
    return res(201, issue);
  }
  if (method === "GET" && path.startsWith("/repos/demo-owner/sentinel/issues?")) return res(200, [...issues].reverse());
  if (method === "PATCH" && path.startsWith("/repos/demo-owner/sentinel/issues/")) {
    const n = Number(path.split("/").pop());
    const i = issues[n - 1];
    if (body.labels) i.labels = body.labels.map((name: string) => ({ name }));
    if (body.state) i.state = body.state;
    return res(200, i);
  }
  if (path.endsWith("/comments")) return method === "POST" ? res(201, { html_url: "https://github.com/x#issuecomment-1" }) : res(200, []);
  if (method === "POST" && path === "/repos/demo-owner/sentinel/dispatches") return res(204);
  if (path.includes("/actions/workflows/incident.yml/runs")) return res(200, { workflow_runs: [] });
  return res(404, { message: "not found" });
}) as typeof fetch;

beforeEach(async () => {
  await redis("FLUSHDB");
  await redis("SET", K.meta, JSON.stringify({ rebuilt_at: "itest" }));
  ghCalls = [];
  ghMode = "ok";
  issues = [];
  files = {};
  invalidateRuleCache();
});
after(() => {
  globalThis.fetch = realFetch;
});

const deploy = (n: number, creator = "alice-dev", minAgo = 1): RtEvent => ({
  id: `gh-deployment-${n}`, source: "github.deployment", event_time: new Date(Date.now() - minAgo * 60000).toISOString(),
  received_at: new Date().toISOString(), asset_id: "deploy-pipeline", account: null, simulated: false, simulation_id: null,
  data: { environment: "production", creator, ref: "main" },
});

const audit = (id: string, iso: string, ip: string, rows: number, sim: string | null = null): RtEvent => ({
  id, source: "db.audit", event_time: iso, received_at: new Date().toISOString(), asset_id: "order-db-prod", account: "dba-alice",
  simulated: sim !== null, simulation_id: sim, data: { table: "orders", rows_read: rows, ip },
});

// 台北 2026-11-09 02:mm:ss = UTC 2026-11-08 18:mm:ss（模擬事件不受真實時間範圍限制）
const night = (mm: number, ss = 0) => `2026-11-08T18:${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}Z`;

test("RT-001：命中一次；重送同一事件為 duplicate；去重期間內另一筆部署被抑制；Pipeline 部署不命中", async () => {
  const a = await processEvent(deploy(1));
  assert.equal(a.alerts.length, 1);
  assert.equal((await processEvent(deploy(1))).results[0].outcome, "duplicate");
  const b = await processEvent(deploy(2));
  assert.equal(b.results[0].outcome, "suppressed");
  assert.equal(b.results[0].alert_id, a.alerts[0], "抑制時回報既有告警");
  assert.equal((await processEvent(deploy(3, "github-actions[bot]"))).results[0].outcome, "no_match");
  const alert = (await getAlert(a.alerts[0]))!;
  assert.deepEqual(alert.source_event_ids, ["gh-deployment-1"]);
  assert.equal(alert.status, "open");
  assert.equal((await openCounts()).realHigh, 1);
});

test("RT-001：真實事件拒絕未來與過期時間，並留原因", async () => {
  const future = { ...deploy(10), event_time: new Date(Date.now() + 10 * 60000).toISOString() };
  assert.match((await processEvent(future)).rejected!, /未來/);
  const old = { ...deploy(11), event_time: new Date(Date.now() - 25 * 3600000).toISOString() };
  assert.match((await processEvent(old)).rejected!, /24 小時/);
  assert.equal((await openCounts()).realHigh, 0);
});

test("RT-002：同一新 IP 的連續讀取全部計入；已知 IP 不計入；超過 10 倍基準才命中且只告警一次", async () => {
  const sid = newSimulationId();
  const evs = buildPreset("night-bulk-read", sid);
  const outcomes = [];
  for (const e of evs) outcomes.push((await processEvent(e)).results.find((r) => r.rule_id === "RT-002")?.outcome ?? "no_match");
  // 1 白天 → 靜態不符；2 已知 IP → below；3～5 累計 600/1200/1800 → below；6 累計 2400 → alert；7 → suppressed
  assert.deepEqual(outcomes, ["no_match", "below", "below", "below", "below", "alert", "suppressed"]);
  const alertId = (await redis<string[]>("SMEMBERS", K.open(true)))[0];
  const a = (await getAlert(alertId))!;
  assert.equal(a.metric, 2400);
  assert.equal(a.simulated, true);
  assert.equal(a.simulation_id, sid);
  assert.equal(a.source_event_ids.length, 4, "只列新來源 IP 的 4 筆");
  assert.match(a.summary, /2400/);
  assert.equal((await openCounts()).realHigh, 0, "模擬告警不影響真實未結案數");
});

test("RT-002：亂序與相同時間戳不漏算；watermark 不往回移；窗外遲到事件不計入", async () => {
  const sid = newSimulationId();
  const ip = "203.0.113.77";
  // 先送較新的事件，再送較舊的事件（同一時間戳兩筆）
  assert.equal((await processEvent(audit("sim-o-1", night(20), ip, 700, sid))).results[0].outcome, "below");
  assert.equal((await processEvent(audit("sim-o-2", night(15), ip, 700, sid))).results[0].outcome, "below");
  const r3 = await processEvent(audit("sim-o-3", night(15), ip, 700, sid));
  assert.equal(r3.results[0].outcome, "alert", "相同時間戳的不同事件都計入：2100 > 2000");
  assert.equal(r3.results[0].metric, 2100);
  // 早於 (watermark - 10 分鐘) 的遲到事件
  const sid2 = newSimulationId();
  await processEvent(audit("sim-l-1", night(30), ip, 10, sid2));
  assert.equal((await processEvent(audit("sim-l-2", night(19, 59), ip, 5000, sid2))).results[0].outcome, "late");
  assert.equal(await redis("GET", `rt:sim:${sid2}:wm:RT-002:order-db-prod:dba-alice`), String(Date.parse(night(30))));
});

test("RT-002：一筆事件超過 10 倍列數也可命中；剛好等於門檻不命中（嚴格大於）", async () => {
  const s1 = newSimulationId();
  assert.equal((await processEvent(audit("sim-b-1", night(5), "203.0.113.9", 2000, s1))).results[0].outcome, "below");
  const s2 = newSimulationId();
  assert.equal((await processEvent(audit("sim-b-2", night(5), "203.0.113.9", 2001, s2))).results[0].outcome, "alert");
});

test("隔離：不同 simulation_id 可重複排練、互不抑制；模擬與真實的已知 IP 分開", async () => {
  const ids = [];
  for (let i = 0; i < 2; i++) {
    const sid = newSimulationId();
    for (const e of buildPreset("night-bulk-read", sid)) await processEvent(e);
    ids.push(...(await redis<string[]>("SMEMBERS", K.open(true))));
  }
  assert.equal(new Set(ids).size, 2, "兩次排練各自產生告警");
  assert.equal(await redis("EXISTS", "rt:real:ipfs:dba-alice"), 0, "模擬不寫入真實已知 IP");
});

test("RT-002：白天排練也能命中（模擬事件帶台北凌晨時間戳）；白天的大量讀取不命中", async () => {
  const afternoon = new Date("2026-11-09T06:00:00Z");          // 台北 14:00 按下模擬器
  const at = afternoon.getTime();
  const sid = newSimulationId();
  const outcomes = [];
  for (const e of buildPreset("night-bulk-read", sid, afternoon)) {
    outcomes.push((await processEvent(e, at)).results.find((r) => r.rule_id === "RT-002")?.outcome ?? "no_match");
  }
  assert.ok(outcomes.includes("alert"), outcomes.join(","));
  const daySid = newSimulationId();
  const day = audit("sim-day-1", "2026-11-09T02:00:00Z", "203.0.113.88", 50000, daySid);   // 台北 10:00
  assert.equal((await processEvent(day, at)).results[0].outcome, "no_match");
});

test("RT-003：只有 2 個品牌不命中；24 小時窗外的品牌不計入；第 3 個品牌進窗才告警", async () => {
  const sid = newSimulationId();
  const now = Date.parse("2026-11-09T06:00:00Z");
  const complaint = (n: number, hoursAgo: number, brand: string): RtEvent => ({
    id: `sim-w-${n}`, source: "support.complaint", event_time: new Date(now - hoursAgo * 3600000).toISOString(),
    received_at: new Date(now).toISOString(), asset_id: "platform", account: null, simulated: true, simulation_id: sid,
    data: { brand, text: `對方報出我的訂單編號：ZX2026110${n}99 要我轉帳` },
  });
  const out = [];
  for (const e of [complaint(1, 30, "brand-a"), complaint(2, 2, "brand-b"), complaint(3, 1, "brand-c"), complaint(4, 0.5, "brand-c")]) {
    out.push((await processEvent(e)).results[0].outcome);
  }
  assert.deepEqual(out, ["below", "below", "below", "below"], "brand-a 在 24 小時窗外，窗內只有 2 個品牌");
  assert.equal((await processEvent(complaint(5, 0.2, "brand-d"))).results[0].outcome, "alert");
});

test("RT-003：24 小時內 3 個品牌命中；同品牌多件不重複計算", async () => {
  const sid = newSimulationId();
  const out = [];
  for (const e of buildPreset("multi-brand-fraud", sid)) out.push((await processEvent(e)).results[0].outcome);
  assert.deepEqual(out, ["below", "no_match", "below", "alert", "suppressed"]);
});

test("結案：版本衝突被拒絕；結案後移出未結案索引，相同異常再出現會產生新告警", async () => {
  const id = (await processEvent(deploy(20))).alerts[0];
  const a = (await getAlert(id))!;
  const ev = "https://example.com/evidence/1";
  const c = await changeStatus(id, a.status_version, { to: "contained", actor: "admin", reason: "已暫停部署權限", evidence_url: ev });
  await assert.rejects(changeStatus(id, a.status_version, { to: "contained", actor: "x", reason: "舊版本操作", evidence_url: ev }), /其他操作/);
  await deliver(id, ["sync"]);   // 背景交付更新只改內部版本，不讓管理者的 status_version 失效
  await assert.rejects(changeStatus(id, c.status_version, { to: "closed", actor: "admin", reason: "未確認", evidence_url: ev }), /確認/);
  assert.equal((await openCounts()).realHigh, 1, "contained 仍算未結案");
  await changeStatus(id, c.status_version, { to: "closed", actor: "admin", reason: "已撤銷權杖並重新驗證", evidence_url: ev,
                                       containment_confirmed: true, reverified: true });
  assert.equal((await openCounts()).realHigh, 0);
  const again = await processEvent(deploy(21));
  assert.equal(again.results[0].outcome, "alert", "結案後的相同異常不被舊的去重抑制");
  assert.notEqual(again.alerts[0], id);
});

test("索引：第 51 筆告警後最近清單只留 50 筆，但未結案索引仍有 51 筆", async () => {
  for (let i = 0; i < 51; i++) {
    const sid = newSimulationId();
    await processEvent(audit(`sim-n-${i}`, night(1), "203.0.113.5", 3000, sid));
  }
  assert.equal(await redis("LLEN", K.recent), 50);
  assert.equal((await openCounts()).sim, 51);
});

test("重建：Redis 清空後索引不可信（資料不足）；從 Issues 重建未結案告警", async () => {
  const id = (await processEvent(deploy(30))).alerts[0];
  await deliver(id);
  assert.equal(issues.length, 1);
  await redis("FLUSHDB");
  const failing = await indexState(async () => ({ ok: false, reason: "GitHub 無法連線" }));
  assert.equal(failing.ok, false);
  assert.match(failing.degraded!, /重建/);
  const list = async (): Promise<IssueRecord[]> =>
    issues.map((i) => ({ number: i.number, html_url: i.html_url, state: i.state, body: i.body, labels: i.labels.map((l) => l.name) }));
  const res = await rebuildFromIssues(list, "demo-owner/sentinel");
  assert.equal(res.ok, true);
  assert.equal(res.restored, 1);
  assert.equal((await openCounts()).realHigh, 1);
  assert.equal((await indexState()).ok, true);
  const restored = (await getAlert(id))!;
  assert.equal(restored.issue_number, 1);
});

test("交付：Issue 失敗不撤銷告警；重試成功後才派發；逾時後重試先查 marker，不重複建立 Issue", async () => {
  const id = (await processEvent(deploy(40))).alerts[0];
  ghMode = "fail";
  let a = (await deliver(id))!;
  assert.equal(a.status, "open");
  assert.equal(a.delivery.issue.state, "failed");
  assert.equal(a.delivery.dispatch.state, "pending", "沒有 Issue 就不派發");
  assert.equal(a.delivery.line.state, "skipped");
  assert.equal((await openCounts()).realHigh, 1, "交付失敗告警仍存在");

  ghMode = "timeout_after_create";   // Issue 其實已建立，但回應逾時
  a = (await deliver(id))!;
  assert.equal(a.delivery.issue.state, "failed");
  assert.equal(a.delivery.issue.uncertain, true);
  assert.equal(issues.length, 1);

  ghMode = "ok";
  a = (await deliver(id))!;
  assert.equal(issues.length, 1, "重試查到既有 marker，不重複建立");
  assert.equal(a.issue_number, 1);
  assert.equal(a.delivery.issue.state, "done");
  assert.equal(a.delivery.dispatch.state, "done");
  assert.ok(a.timeline.issue_created && a.timeline.dispatched);
  const dispatches = ghCalls.filter((c) => c.path.endsWith("/dispatches"));
  assert.equal(dispatches.length, 1);
  assert.deepEqual(dispatches[0].body, { event_type: "incident", client_payload: { alert_id: id, asset_id: "deploy-pipeline" } });
  const issueBody = issues[0].body;
  assert.ok(issueBody.includes(`sentinel-alert-id: ${id}`));
  assert.ok(!/203\.0\.113|198\.51\.100/.test(issueBody), "Issue 不含 IP");

  // 再次 deliver 不重複派發
  await deliver(id);
  assert.equal(ghCalls.filter((c) => c.path.endsWith("/dispatches")).length, 1);
});

test("狀態同步：結案後同步 Issue 標籤與留言；Issue 只在管理者結案後關閉", async () => {
  const id = (await processEvent(deploy(50))).alerts[0];
  await deliver(id);
  let a = (await getAlert(id))!;
  a = await changeStatus(id, a.status_version, { to: "contained", actor: "admin", reason: "已暫停部署", evidence_url: "https://example.com/e" });
  await deliver(id, ["sync"]);
  assert.ok(issues[0].labels.some((l) => l.name === "status:contained"));
  assert.equal(issues[0].state, "open");
  a = (await getAlert(id))!;
  await changeStatus(id, a.status_version, { to: "closed", actor: "admin", reason: "已重新驗證", evidence_url: "https://example.com/e",
                                       containment_confirmed: true, reverified: true });
  await deliver(id, ["sync"]);
  assert.equal(issues[0].state, "closed");
  assert.ok(ghCalls.some((c) => c.method === "POST" && c.path.endsWith("/comments") && /closed/.test(c.body.body)));
});


// ---------------------------------------------------------------- 偵測規則設定（「偵測規則」頁）

test("偵測規則：Redis 沒有設定時用預設並回報 missing；同步後不再 missing", async () => {
  const a = await processEvent(deploy(60, "release-bot[bot]"));
  assert.equal(a.rules.missing, true);
  assert.equal(a.rules.source, "default");
  assert.equal(a.results[0].outcome, "alert");                     // 預設只允許 github-actions[bot]
  await syncRulesFromGitHub();                                     // GitHub 上還沒有設定檔：記下「用預設」
  const b = await processEvent(deploy(61, "github-actions[bot]"));
  assert.equal(b.rules.missing, false);
  assert.equal(b.rules.version, 0);
});

test("偵測規則：儲存後下一筆事件就用新設定；停用的規則不判斷；舊版本不能覆蓋新設定", async () => {
  const saved = await saveRuleSettings({ "RT-001": { creator_not_in: ["github-actions[bot]", "release-bot[bot]"] },
                                         "RT-003": { enabled: false } }, "itest", "加入發版機器人", null);
  assert.equal(saved.version, 1);
  assert.equal(saved.redis_synced, true);
  const e = await processEvent(deploy(70, "release-bot[bot]"));
  assert.equal(e.rules.version, 1);
  assert.equal(e.results[0].outcome, "no_match");
  assert.equal((await processEvent(deploy(71, "mallory"))).results[0].outcome, "alert");
  const sid = newSimulationId();
  for (const ev of buildPreset("multi-brand-fraud", sid)) assert.deepEqual((await processEvent(ev)).results, []);
  await assert.rejects(saveRuleSettings({}, "itest", "用舊版本覆蓋", null), SettingsConflict);
  const put = ghCalls.find((c) => c.method === "PUT")!;
  assert.match(put.body.message, /理由：加入發版機器人/);

  await redis("DEL", RULES_KEY);                                   // Redis 被清掉
  invalidateRuleCache();
  assert.equal((await processEvent(deploy(72, "ci-bot"))).rules.missing, true);
  await syncRulesFromGitHub();                                     // 從 GitHub 修復
  const f = await processEvent(deploy(73, "release-bot[bot]"));
  assert.equal(f.rules.version, 1);
  assert.equal(f.results[0].outcome, "no_match");
});
