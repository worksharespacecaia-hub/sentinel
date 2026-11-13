import { test } from "node:test";
import assert from "node:assert/strict";
import { AGENT_TEXT, TRACE_ORDER } from "./labels.ts";

test("執行紀錄：開工路由是純程式；舊報告的 orchestrator 顯示為開工路由（舊版），不標示成 AI 派工", () => {
  assert.equal(AGENT_TEXT.router, "開工路由（程式）");
  assert.equal(AGENT_TEXT.orchestrator, "開工路由（舊版）");
  assert.doesNotMatch(AGENT_TEXT.orchestrator, /Orchestrator|派工|AI/);
  assert.match(AGENT_TEXT["orchestrator-dispatch"], /^Orchestrator 派工/);
  assert.match(AGENT_TEXT["orchestrator-review"], /^Orchestrator 驗收/);
});

test("執行紀錄的順序依新 DAG（design §3.7），每個 trace 名稱都有白話標籤", () => {
  const want = ["router", "a0", "daily-intel", "a1", "orchestrator-dispatch", "a2", "a3", "a4", "orchestrator-review",
                "claude-analysis", "a5"];
  assert.deepEqual(TRACE_ORDER.filter((a) => want.includes(a)), want);
  assert.equal(TRACE_ORDER.indexOf("orchestrator"), 0);              // 舊報告的開工路由排在最前面
  for (const a of TRACE_ORDER) assert.ok(AGENT_TEXT[a], a);
  assert.equal(new Set(TRACE_ORDER).size, TRACE_ORDER.length);
});
