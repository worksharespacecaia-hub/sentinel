import { test } from "node:test";
import assert from "node:assert/strict";
import { approvedLines, extraCheckRows, planSummary, rejectedLines, type AgentPlan } from "./agentplan.ts";

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

test("summary distinguishes subscription, zero, skipped and template", () => {
  assert.equal(planSummary(base), "動態派工：AI 建議 3 項、核准 2 項、拒絕 1 項（來源：訂閱方案）");
  assert.equal(planSummary({ ...base, suggested: 0, approved_count: 0, rejected_count: 0, approved: [], rejected: [] }),
    "動態派工：AI 建議 0 項、核准 0 項、拒絕 0 項（來源：訂閱方案）");
  assert.match(planSummary({ ...base, source: "skipped" }) ?? "", /未觸發/);
  assert.match(planSummary({ ...base, source: "template" }) ?? "", /維持原本派工/);
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

test("extra check rows always carry text status", () => {
  const rows = extraCheckRows([
    { control_id: "C-A", title: "A", status: "fail", assets: [{ asset_id: "mail-api" }], check_reason: "未輪替" },
    { control_id: "C-B", title: "B", status: "unknown", assets: [] },
  ]);
  assert.deepEqual(rows.map((r) => [r.status, r.assets]), [["不符合", "mail-api"], ["資料不足", "無列出資產"]]);
  assert.deepEqual(extraCheckRows(undefined), []);
});
