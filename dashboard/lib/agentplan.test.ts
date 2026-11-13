import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import {
  approvedLines, extraCheckRows, normalizePlans, noticeExtra, planSummary, rejectedLines, resultRows, reviewSummarySource,
  type AgentPlan,
} from "./agentplan.ts";

// v0.11～v0.12 的單一計畫（每日情資提案、A1 核准；沒有 mode）
const base: AgentPlan = {
  source: "subscription", note: null, events: ["live-a"], suggested: 3, approved_count: 2, rejected_count: 1,
  control_titles: { "C-SECRET-IN-GIT": "Git 中不得有正式環境金鑰" },
  approved: [
    { type: "control", event_id: "live-a", control_id: "C-SECRET-IN-GIT", reason: "手法相近" },
    { type: "task", event_id: "live-a", agent: "a4", subagent: "impact-analyst", reason: "補充說明" },
  ],
  rejected: [{ type: "field", reason: "只能追加，不能關閉或改變必要評估" }],
};
const titles = { "live-a": "某電商會員資料外洩" };

// v0.13 的派工單與驗收單（tools/orchestration.py 的 public_plan）
const dispatch = {
  mode: "dispatch", source: "subscription", note: null, events: ["live-a", "demo-b"], suggested: 9, approved_count: 6,
  rejected_count: 3, control_titles: { "C-SECRET-IN-GIT": "Git 中不得有正式環境金鑰" },
  approved: [
    { type: "control", event_id: "live-a", control_id: "C-SECRET-IN-GIT", reason: "手法相近" },
    { type: "task", agent: "a2", subagent: "dependency-analyst", event_id: "live-a", reason: "同產品的套件漏洞" },
    { type: "task", agent: "a2", subagent: "runtime-analyst", event_id: "demo-b", reason: "執行環境相同" },
    { type: "task", agent: "a3", subagent: "retro-hunter", event_id: "live-a", reason: "登入異常手法" },
    { type: "task", agent: "a4", subagent: "impact-analyst", event_id: "demo-b", reason: "補充說明" },
    { type: "priority", agent: "a4", risk_id: "storefront:node:vuln", reason: "與事件同產品" },
  ],
  rejected: [
    { type: "task", agent: "a3", subagent: "retro-hunter", event_id: "demo-b", reason: "沒有符合條件的對象" },
    { type: "priority", reason: "不在可排優先的清單" },
    { type: "control", event_id: "live-a", reason: "不在控制項清單" },
  ],
};
const review = {
  mode: "review", source: "live", note: null, events: ["demo-b"], suggested: 6, approved_count: 4, rejected_count: 2,
  control_titles: {}, summary: "今天派工追加的三項都已完成，需確認事件已補寫摘要。",
  approved: [
    { type: "task", agent: "a5", subagent: "intel-report-writer", event_id: "demo-b", reason: "需確認事件缺摘要" },
    { type: "task", agent: "a5", subagent: "key-rotation-advisor", risk_id: "brand-app:C-SECRET-IN-GIT", reason: "與事件相關" },
    { type: "priority", agent: "a5", risk_id: "storefront:node:vuln", reason: "先處理" },
    { type: "summary", text: "今天派工追加的三項都已完成，需確認事件已補寫摘要。" },
  ],
  rejected: [
    { type: "task", agent: "a5", subagent: "brand-notice-writer", event_id: "live-a", reason: "程式已要求通知" },
    { type: "summary", reason: "摘要含不允許的內容" },
  ],
};
const names = {
  events: { "live-a": "某電商會員資料外洩", "demo-b": "示範：某平台套件漏洞" },
  risks: { "storefront:node:vuln": "node 22.11.0 有 17 個已知漏洞", "brand-app:C-SECRET-IN-GIT": "Git 中不得有正式環境金鑰：brand-app" },
};
const BANNED = ["C-SECRET-IN-GIT", "live-a", "demo-b", "storefront:node:vuln", "brand-app:", "impact-analyst", "dependency-analyst",
  "runtime-analyst", "retro-hunter", "intel-report-writer", "key-rotation-advisor", "brand-notice-writer", "extra_controls",
  "extra_tasks", "priorities", "skip_agents", "risk_id", "event_id"];

// ---------------------------------------------------------------- 四種相容情況（R9.2）

test("相容：沒有 agent_plan（舊報告）→ 兩份都沒有、不出錯", () => {
  for (const raw of [undefined, null, {}, "x", 3, []]) {
    assert.deepEqual(normalizePlans(raw), { dispatch: null, review: null, legacy: false });
  }
});

test("相容：v0.11 的單一計畫視為派工單，標示舊版", () => {
  const p = normalizePlans(base);
  assert.equal(p.legacy, true);
  assert.equal(p.review, null);
  assert.equal(p.dispatch?.mode, undefined);
  assert.deepEqual(p.dispatch?.approved, base.approved);
  assert.equal(planSummary(p.dispatch), "動態派工：AI 建議 3 項、核准 2 項、拒絕 1 項（來源：訂閱方案）");
  assert.match(approvedLines(p.dispatch!, titles).join("\n"), /某電商會員資料外洩：請 A4 說明相關風險——補充說明/);
});

test("相容：新格式但沒有驗收單（驗收單停用為 null 或沒有這個鍵）", () => {
  for (const raw of [{ dispatch, review: null }, { dispatch }]) {
    const p = normalizePlans(raw);
    assert.equal(p.legacy, false);
    assert.equal(p.review, null);
    assert.equal(p.dispatch?.mode, "dispatch");
    assert.equal(planSummary(p.dispatch), "Orchestrator 派工：AI 建議 9 項、核准 6 項、拒絕 3 項（來源：訂閱方案）");
  }
  const onlyReview = normalizePlans({ dispatch: null, review });       // 派工單停用、驗收單有效（R5.1a）
  assert.equal(onlyReview.dispatch, null);
  assert.equal(onlyReview.review?.summary, review.summary);
});

test("相容：完整的雙計畫", () => {
  const p = normalizePlans({ dispatch, review });
  assert.equal(p.legacy, false);
  assert.equal(p.dispatch?.approved.length, 6);
  assert.equal(p.review?.mode, "review");
  assert.equal(p.review?.summary, review.summary);
  assert.equal(planSummary(p.review), "Orchestrator 驗收：AI 建議 6 項、核准 4 項、拒絕 2 項（來源：即時呼叫）");
});

test("相容：格式不符的那份視為 null，其他欄位補預設值", () => {
  const p = normalizePlans({ dispatch: { source: "live" }, review: { approved: [{ type: "summary", text: "x" }, 3], rejected: [] } });
  assert.equal(p.dispatch, null);                                      // 沒有 approved／rejected 陣列
  assert.deepEqual(p.review?.approved, [{ type: "summary", text: "x" }]);
  assert.equal(p.review?.source, "template");
  assert.equal(p.review?.suggested, 1);
  assert.equal(p.review?.summary, null);
});

test("已發布的報告（舊格式或沒有 agent_plan）都能正規化", () => {
  const dir = new URL("../public/data/", import.meta.url);
  const files = ["daily/report.json", ...readdirSync(new URL("scenarios/", dir)).map((s) => `scenarios/${s}/report.json`)]
    .filter((f) => existsSync(new URL(f, dir)));
  assert.ok(files.length > 0);
  for (const f of files) {
    const rep = JSON.parse(readFileSync(new URL(f, dir), "utf8"));
    const p = normalizePlans(rep.agent_plan);
    for (const plan of [p.dispatch, p.review]) {
      if (!plan) continue;
      assert.ok(planSummary(plan), f);
      approvedLines(plan, {});
      rejectedLines(plan, {});
    }
    const rows = resultRows(rep.orchestrator_results);
    assert.ok(Array.isArray(rows.extra) && Array.isArray(rows.notices), f);
  }
});

// ---------------------------------------------------------------- 白話文字

test("summary distinguishes subscription, zero, skipped and template", () => {
  assert.equal(planSummary(base), "動態派工：AI 建議 3 項、核准 2 項、拒絕 1 項（來源：訂閱方案）");
  assert.equal(planSummary({ ...base, suggested: 0, approved_count: 0, rejected_count: 0, approved: [], rejected: [] }),
    "動態派工：AI 建議 0 項、核准 0 項、拒絕 0 項（來源：訂閱方案）");
  assert.match(planSummary({ ...base, source: "skipped" }) ?? "", /未觸發/);
  assert.match(planSummary({ ...base, source: "template" }) ?? "", /維持原本派工/);
  assert.equal(planSummary({ ...base, mode: "dispatch", source: "skipped" }), "Orchestrator 派工：沒有新同業事件，未觸發");
  assert.equal(planSummary({ ...base, mode: "review", source: "template" }), "Orchestrator 驗收：AI 提案未產生，只跑必要任務（來源：程式範本）");
  assert.equal(planSummary(null), null);
  assert.equal(planSummary(undefined), null);                    // 舊報告沒有這個欄位
});

test("lines use names, never internal ids or field names", () => {
  const lines = [...approvedLines(base, titles), ...rejectedLines(base, titles)].join("\n");
  assert.match(lines, /某電商會員資料外洩：加查「Git 中不得有正式環境金鑰」/);
  assert.match(lines, /請 A4 說明相關風險/);
  for (const banned of ["C-SECRET-IN-GIT", "live-a", "impact-analyst", "extra_controls", "skip_agents"]) {
    assert.ok(!lines.includes(banned), banned);
  }
  const unknown = rejectedLines({ ...base, rejected: [{ type: "control", reason: "不在控制項清單" }] }, {});
  assert.deepEqual(unknown, ["本次同業事件：加查控制項——不在控制項清單"]);
});

test("派工單：每種項目類型（control、各種 task、priority）都有白話一句", () => {
  const p = normalizePlans({ dispatch }).dispatch!;
  assert.deepEqual(approvedLines(p, names.events, names.risks), [
    "某電商會員資料外洩：加查「Git 中不得有正式環境金鑰」——手法相近",
    "某電商會員資料外洩：請 A2 依事件解讀套件漏洞——同產品的套件漏洞",
    "示範：某平台套件漏洞：請 A2 依事件解讀執行環境與支援期限——執行環境相同",
    "某電商會員資料外洩：請 A3 回溯搜查相關系統的登入與資料庫紀錄——登入異常手法",
    "示範：某平台套件漏洞：請 A4 說明相關風險——補充說明",
    "node 22.11.0 有 17 個已知漏洞：排優先：A4 先說明這項風險——與事件同產品",
  ]);
  assert.deepEqual(rejectedLines(p, names.events, names.risks), [
    "示範：某平台套件漏洞：請 A3 回溯搜查相關系統的登入與資料庫紀錄——沒有符合條件的對象",
    "清單外的風險：排優先——不在可排優先的清單",
    "某電商會員資料外洩：加查控制項——不在控制項清單",
  ]);
});

test("驗收單：事件目標、風險目標、排優先與執行摘要都有白話一句，不洩漏 ID", () => {
  const p = normalizePlans({ review }).review!;
  const ok = approvedLines(p, names.events, names.risks);
  assert.deepEqual(ok, [
    "示範：某平台套件漏洞：請 A5 撰寫需確認事件的摘要——需確認事件缺摘要",
    "Git 中不得有正式環境金鑰：brand-app：請 A5 撰寫金鑰輪替建議——與事件相關",
    "node 22.11.0 有 17 個已知漏洞：排優先：A5 先寫這項風險的解法與摘要——先處理",
    "執行摘要：通過程式檢查（內容見上方）",
  ]);
  const no = rejectedLines(p, names.events, names.risks);
  assert.deepEqual(no, ["某電商會員資料外洩：請 A5 撰寫通知草稿（程式未要求通知）——程式已要求通知", "執行摘要——摘要含不允許的內容"]);
  // 名稱缺少時用通用字樣，不顯示 ID
  const bare = [...approvedLines(p, {}), ...rejectedLines(p, {}),
                ...approvedLines(normalizePlans({ dispatch }).dispatch!, {})].join("\n");
  assert.match(bare, /本次事件：請 A5 撰寫需確認事件的摘要/);
  assert.match(bare, /清單外的風險：請 A5 撰寫金鑰輪替建議/);
  assert.match(bare, /本次同業事件：請 A2 依事件解讀套件漏洞/);
  for (const banned of BANNED) assert.ok(!bare.includes(banned) && !ok.join("").includes(banned), banned);
  // 被拒絕的金鑰輪替沒有 risk_id 時，對象寫風險而不是事件
  assert.deepEqual(rejectedLines({ ...p, rejected: [{ type: "task", agent: "a5", subagent: "key-rotation-advisor", reason: "不是本次相關的金鑰風險" }] }, {}),
    ["清單外的風險：請 A5 撰寫金鑰輪替建議——不是本次相關的金鑰風險"]);
  assert.deepEqual(rejectedLines({ ...p, rejected: [{ type: "task", reason: "欄位缺漏或格式不符" }] }, {}), ["本次事件：追加工作——欄位缺漏或格式不符"]);
});

// ---------------------------------------------------------------- 追加結果與通知草稿（R5.7、R5.8）

const results = [
  { stage: "review", agent: "a5", subagent: "key-rotation-advisor", target_type: "risk", target_id: "brand-app:C-SECRET-IN-GIT",
    text: "此金鑰風險與本次事件相關，建議依輪替程序處理。（自動範本）", source: "template" },
  { stage: "dispatch", agent: "a2", subagent: "dependency-analyst", target_type: "event", target_id: "live-a",
    text: "同產品的套件有已知漏洞，建議優先升級。", source: "live" },
  { stage: "review", agent: "a5", subagent: "brand-notice-writer", target_type: "event", target_id: "live-a",
    text: "親愛的品牌商：…", source: "replay" },
  { stage: "dispatch", agent: "a3", subagent: "retro-hunter", target_type: "event", target_id: "demo-b",
    text: "回溯期間有 2 筆外部 IP 登入失敗。", source: "replay" },
  { stage: "review", agent: "a5", subagent: "intel-report-writer", target_type: "event", target_id: "x", text: "  ", source: "live" },
  { stage: "other", agent: "a5", subagent: "x", target_type: "event", target_id: "x", text: "t", source: "live" },
  "not-an-object",
];

test("追加結果：通知草稿另外列出；AI 撰寫的排前面、程式範本排後面並清楚標示", () => {
  const { extra, notices } = resultRows(results, names);
  assert.deepEqual(extra.map((r) => [r.stage, r.label, r.target, r.source]), [
    ["派工", "依事件解讀套件漏洞", "某電商會員資料外洩", "AI 撰寫"],
    ["派工", "依事件回溯搜查", "示範：某平台套件漏洞", "AI 撰寫（重播）"],
    ["驗收", "金鑰輪替建議", "Git 中不得有正式環境金鑰：brand-app", "程式範本"],
  ]);
  assert.deepEqual(extra.map((r) => r.ai), [true, true, false]);
  assert.deepEqual(notices.map((r) => [r.label, r.targetId, r.source]), [["通知草稿", "live-a", "AI 撰寫（重播）"]]);
  assert.ok(!extra.some((r) => r.label === "通知草稿"));               // 追加結果區塊不重複列出通知草稿
});

test("追加結果：舊報告沒有這個欄位、格式不符的項目都略過", () => {
  for (const raw of [undefined, null, {}, "x"]) assert.deepEqual(resultRows(raw), { extra: [], notices: [] });
  const { extra } = resultRows(results);                              // 沒有名稱時不顯示 ID
  assert.deepEqual(extra.map((r) => r.target), ["本次事件", "本次事件", "清單外的風險"]);
});

test("通知草稿（程式未要求）：沒有 draft_extra 時為 null；來源標示與 Markdown 一致", () => {
  assert.equal(noticeExtra(undefined), null);
  assert.equal(noticeExtra({ needed: true, draft: "原本的通知" }), null);   // 舊報告
  assert.equal(noticeExtra({ needed: false, draft: null, draft_extra: " " }), null);
  assert.deepEqual(noticeExtra({ needed: false, draft: null, draft_extra: "草稿", draft_extra_source: "live" }), { text: "草稿", source: "AI 撰寫" });
  assert.deepEqual(noticeExtra({ needed: false, draft: null, draft_extra: "草稿", draft_extra_source: "replay" }), { text: "草稿", source: "AI 撰寫（重播）" });
  assert.deepEqual(noticeExtra({ needed: false, draft: null, draft_extra: "草稿" }), { text: "草稿", source: "程式範本" });
});

test("需確認事件的摘要來源：驗收追加的 AI 摘要另外標示，其他沿用原本的來源文字", () => {
  assert.equal(reviewSummarySource("need_check", "live"), "AI 撰寫，Orchestrator 驗收追加");
  assert.equal(reviewSummarySource("need_check", "replay"), "AI 撰寫（重播），Orchestrator 驗收追加");
  assert.equal(reviewSummarySource("need_check", "template"), null);
  assert.equal(reviewSummarySource("open", "live"), null);                 // 受影響事件：必要任務的摘要
  assert.equal(reviewSummarySource(undefined, undefined), null);
});

test("extra check rows always carry text status", () => {
  const rows = extraCheckRows([
    { control_id: "C-A", title: "A", status: "fail", assets: [{ asset_id: "mail-api" }], check_reason: "未輪替" },
    { control_id: "C-B", title: "B", status: "unknown", assets: [] },
  ]);
  assert.deepEqual(rows.map((r) => [r.status, r.assets]), [["不符合", "mail-api"], ["資料不足", "無列出資產"]]);
  assert.deepEqual(extraCheckRows(undefined), []);
});
