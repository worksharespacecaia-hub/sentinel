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
    { name: "router", status: "completed", conclusion: "success", started_at: "2026-11-10T07:00:00Z",
      completed_at: "2026-11-10T07:00:20Z", html_url: "https://github.com/o/sentinel/actions/runs/1/job/2" },
    { name: "a0-assets", status: "in_progress", conclusion: null, started_at: "2026-11-10T07:00:25Z",
      html_url: "javascript:alert(1)" },
    { name: "daily-intel", status: "completed", conclusion: "skipped", started_at: "2026-11-10T07:00:25Z", completed_at: "2026-11-10T07:00:25Z" },
    { name: "unknown-job", status: "completed", conclusion: "success" },
  ], now);
  // 第一階段由「規劃」改為「開工」：開工路由是純程式、不屬於 Orchestrator（specs/orchestrator R1.2、R1.3），
  // 規劃（派工）與驗收是 Orchestrator 的兩個 Job，各自一個階段
  assert.deepEqual(stages.map((s) => s.title), ["開工", "資產", "掃描與蒐集", "外部情資", "派工", "分析", "風險", "驗收", "撰寫", "發布"]);
  const nodes = Object.fromEntries(stages.flatMap((s) => s.nodes).map((n) => [n.key, n]));
  assert.equal(Object.keys(nodes).length, 14);
  assert.equal(nodes["router"].status, "success");
  assert.equal(nodes["router"].label, "開工路由（程式）");
  assert.equal(nodes["router"].seconds, 20);
  assert.equal(nodes["router"].url, "https://github.com/o/sentinel/actions/runs/1/job/2");
  assert.equal(nodes["a0-assets"].status, "running");
  assert.equal(nodes["a0-assets"].seconds, 5);
  assert.equal(nodes["a0-assets"].url, undefined);                 // 只接受 GitHub 的 Job 網址
  assert.equal(nodes["daily-intel"].note, "只在每日排程與 GitHub 手動 daily 執行");
  assert.equal(nodes["daily-intel"].seconds, undefined);           // 略過的 Job 不顯示 0 秒
  assert.equal(nodes["a5-report"].status, "waiting");
});

test("流程：新 DAG 的順序，A3 等派工完成；派工與驗收失敗只停用那一份計畫", () => {
  const stages = flowStages([
    { name: "orchestrator-dispatch", status: "completed", conclusion: "failure" },
    { name: "orchestrator-review", status: "completed", conclusion: "skipped" },
  ]);
  const at = (key: string) => stages.findIndex((s) => s.nodes.some((n) => n.key === key));
  const order = ["router", "a0-assets", "daily-intel", "a1-intel", "orchestrator-dispatch", "a3-signals", "a4-risk",
                 "orchestrator-review", "claude-analysis", "a5-report"];
  for (let i = 1; i < order.length; i++) assert.ok(at(order[i - 1]) < at(order[i]), `${order[i - 1]} → ${order[i]}`);
  assert.equal(at("a2-scan"), at("a3-signals"));                  // A2、A3 同時進行，都在派工之後
  assert.ok(at("scanners (trivy)") < at("orchestrator-dispatch")); // 派工要用掃描結果算候選（R1.6）
  const nodes = Object.fromEntries(stages.flatMap((s) => s.nodes).map((n) => [n.key, n]));
  assert.equal(nodes["orchestrator-dispatch"].status, "failure");
  assert.match(nodes["orchestrator-dispatch"].note ?? "", /只停用派工單.*報告照常產生/);
  assert.equal(nodes["orchestrator-review"].status, "skipped");
  assert.match(nodes["orchestrator-review"].note ?? "", /A5 只跑必要任務/);
  assert.equal(stages.flatMap((s) => s.nodes).filter((n) => n.key === "orchestrator").length, 0);   // 沒有舊名稱的常駐節點
});

test("流程：v0.13 以前的 Job 名稱 orchestrator 顯示為開工路由（舊版），不標示成 AI 派工", () => {
  const old = flowStages([{ name: "orchestrator", status: "completed", conclusion: "success" }]);
  const first = old[0].nodes[0];
  assert.equal(first.key, "router");
  assert.equal(first.status, "success");
  assert.equal(first.label, "開工路由（舊版）");
  const both = flowStages([{ name: "router", status: "in_progress", conclusion: null },
                           { name: "orchestrator", status: "completed", conclusion: "success" }]);
  assert.equal(both[0].nodes[0].status, "running");               // 新名稱優先
  assert.equal(both[0].nodes[0].label, "開工路由（程式）");
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
