import { test } from "node:test";
import assert from "node:assert/strict";
import type { Risk } from "./data";
import { groupDecisions, linkSummary, openRisks, riskHeadline, riskTags, suggestedDeadline, summaryFacts, topRisks } from "./brief.ts";

const risk = (over: Partial<Risk>): Risk => ({
  id: "x", asset_id: "asset", title: "標題", category: "config", level: "high", score: 7, raw_score: 7, score_level: "high",
  level_reason: "依分數", breakdown: [], attack_path: null, matched_events: [], deadline_hours: 24, solution: null, status: "open",
  first_seen: "2026-11-09T01:00:00Z", last_evaluated: "2026-11-10T01:00:00Z", ...over,
});

test("groupDecisions：4 條納管合併成一條，下架問題仍在前；只有 1 條不合併；重複呼叫結果不變", () => {
  const raw = ["是否暫時下架 marketing-site（已停止支援且沒有修補版本）", "internal-tool 要納管還是除役",
    "marketing-site 要納管還是除役", "nas-office-01 要納管還是除役", "saas-quicksite-builder 要納管還是除役"];
  const merged = groupDecisions(raw);
  assert.deepEqual(merged, ["是否暫時下架 marketing-site（已停止支援且沒有修補版本）",
    "4 個未登記的系統要納管還是除役：internal-tool、marketing-site、nas-office-01、saas-quicksite-builder"]);
  assert.deepEqual(groupDecisions(merged), merged);
  assert.deepEqual(groupDecisions(["a 要納管還是除役", "其他"]), ["a 要納管還是除役", "其他"]);
  assert.deepEqual(groupDecisions([]), []);
});

test("openRisks／topRisks：排除已修復與低風險，依等級、分數排序，同分維持原順序", () => {
  const risks = [risk({ id: "m", level: "medium", score: 6 }), risk({ id: "h1", score: 9 }), risk({ id: "f", score: 11, status: "fixed" }),
    risk({ id: "h2", score: 11 }), risk({ id: "h3", score: 9 }), risk({ id: "l", level: "low", score: 2 })];
  assert.deepEqual(openRisks({ risks }).map((r) => r.id), ["h2", "h1", "h3", "m"]);
  assert.deepEqual(topRisks({ risks }, 2).map((r) => r.id), ["h2", "h1"]);
});

test("riskHeadline：漏洞改白話並保留原標題；已停止支援加註；其他類別用原標題", () => {
  const eol = risk({ category: "vuln", asset_id: "marketing-site", title: "php 8.1.27：PHP2Shell",
    breakdown: [{ factor: "已停止支援", points: 1, reason: "無修補可用" }] });
  assert.deepEqual(riskHeadline(eol), { headline: "marketing-site 有可被入侵的漏洞，且已停止支援", detail: "php 8.1.27：PHP2Shell" });
  assert.deepEqual(riskHeadline(risk({ title: "內部工具不得對外開放：internal-tool" })),
    { headline: "內部工具不得對外開放：internal-tool", detail: null });
});

test("riskTags 只依已計算的因子與攻擊路徑；suggestedDeadline＝第一次發現＋時限", () => {
  const r = risk({ breakdown: [{ factor: "已遭實際利用", points: 2, reason: "" }, { factor: "對外暴露", points: 2, reason: "" }],
    matched_events: ["evt-91app-2026-10"], attack_path: ["internet", "internal-tool", "order-db-prod"] });
  assert.deepEqual(riskTags(r), ["已遭實際利用", "同業已出事", "可串成入侵路徑 → order-db-prod", "對外可連到"]);
  assert.deepEqual(riskTags(risk({})), []);
  assert.equal(suggestedDeadline(r)?.toISOString(), "2026-11-10T01:00:00.000Z");
  assert.equal(suggestedDeadline(risk({ first_seen: "bad" })), null);
});

test("summaryFacts／linkSummary：摘要數字對應到程式結果；同值數字依後面的字區分；對不上的數字標 null", () => {
  const risks = [risk({ id: "a", attack_path: ["internet", "x", "db"] }), risk({ id: "b", category: "shadow_it", asset_id: "nas" }),
    risk({ id: "c", level: "low", score: 2 }), risk({ id: "d", level: "low", score: 1 })];
  const events = [{ id: "e1", kind: "archive", title: "一", affected_count: 1, max_level: "high" as const, status: "open", demo: false },
                  { id: "e2", kind: "live", title: "二", affected_count: 0, max_level: null, status: "not_affected", demo: false }];
  const facts = summaryFacts({ risks, events, intel_summary: { checked: 2, affected: 1, by_kind: {} } });
  assert.equal(facts.high.count, 2);
  assert.deepEqual(facts.chained.risks.map((r) => r.id), ["a"]);
  assert.equal(facts.shadow_it.count, 1);
  const parts = linkSummary("今天 2 個高風險、2 個低風險；檢查 2 件外部資安事件，其中 1 件與我們有關，另有 9 個問題。", facts);
  const keys = parts.filter((p) => typeof p !== "string").map((p) => (p as { key: string | null }).key);
  assert.deepEqual(keys, ["high", "low", "checked", "affected", null]);
  assert.equal(parts.map((p) => (typeof p === "string" ? p : p.text)).join(""), "今天 2 個高風險、2 個低風險；檢查 2 件外部資安事件，其中 1 件與我們有關，另有 9 個問題。");
});
