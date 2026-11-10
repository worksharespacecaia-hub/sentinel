import { test } from "node:test";
import assert from "node:assert/strict";
import { flowStages, fmtSeconds, publishedRunId, resultPath, statusOf } from "./runflow.ts";

test("Job 狀態對應：未建立＝等待、執行中、各種結論", () => {
  assert.equal(statusOf(undefined), "waiting");
  assert.equal(statusOf({ name: "x", status: "queued", conclusion: null }), "waiting");
  assert.equal(statusOf({ name: "x", status: "in_progress", conclusion: null }), "running");
  assert.equal(statusOf({ name: "x", status: "completed", conclusion: "success" }), "success");
  assert.equal(statusOf({ name: "x", status: "completed", conclusion: "skipped" }), "skipped");
  assert.equal(statusOf({ name: "x", status: "completed", conclusion: "cancelled" }), "cancelled");
  for (const c of ["failure", "timed_out", "startup_failure", null]) {
    assert.equal(statusOf({ name: "x", status: "completed", conclusion: c }), "failure");
  }
});

test("流程：依 workflow 的 Job 名稱分到各階段，缺少的 Job 顯示等待", () => {
  const now = Date.parse("2026-11-10T07:00:30Z");
  const stages = flowStages([
    { name: "orchestrator", status: "completed", conclusion: "success", started_at: "2026-11-10T07:00:00Z",
      completed_at: "2026-11-10T07:00:20Z", html_url: "https://github.com/o/sentinel/actions/runs/1/job/2" },
    { name: "a0-assets", status: "in_progress", conclusion: null, started_at: "2026-11-10T07:00:25Z",
      html_url: "javascript:alert(1)" },
    { name: "daily-intel", status: "completed", conclusion: "skipped", started_at: "2026-11-10T07:00:25Z", completed_at: "2026-11-10T07:00:25Z" },
    { name: "unknown-job", status: "completed", conclusion: "success" },
  ], now);
  assert.deepEqual(stages.map((s) => s.title), ["規劃", "資產", "掃描與蒐集", "分析", "風險", "發布"]);
  const nodes = Object.fromEntries(stages.flatMap((s) => s.nodes).map((n) => [n.key, n]));
  assert.equal(Object.keys(nodes).length, 11);
  assert.equal(nodes["orchestrator"].status, "success");
  assert.equal(nodes["orchestrator"].seconds, 20);
  assert.equal(nodes["orchestrator"].url, "https://github.com/o/sentinel/actions/runs/1/job/2");
  assert.equal(nodes["a0-assets"].status, "running");
  assert.equal(nodes["a0-assets"].seconds, 5);
  assert.equal(nodes["a0-assets"].url, undefined);                 // 只接受 GitHub 的 Job 網址
  assert.equal(nodes["daily-intel"].note, "只在每日排程與 GitHub 手動 daily 執行");
  assert.equal(nodes["daily-intel"].seconds, undefined);           // 略過的 Job 不顯示 0 秒
  assert.equal(nodes["a5-report"].status, "waiting");
});

test("已發布判斷與結果頁網址", () => {
  const idx = { latest_daily: { run_id: "42769337664" }, scenarios: { php2shell: { run_id: "offline-p0" } } };
  assert.equal(publishedRunId(idx, "daily"), "42769337664");
  assert.equal(publishedRunId(idx, "php2shell"), "offline-p0");
  assert.equal(publishedRunId(idx, "intel-demo"), null);
  assert.equal(publishedRunId(null, "daily"), null);
  assert.equal(resultPath("daily"), "/runs");
  assert.equal(resultPath("php2shell"), "/runs?source=php2shell");
  assert.equal(fmtSeconds(undefined), "");
  assert.equal(fmtSeconds(45), "45 秒");
  assert.equal(fmtSeconds(125), "2 分 5 秒");
});
