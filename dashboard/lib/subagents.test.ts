import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { AGENT_SUBAGENTS, SDK_SUBAGENT_COUNT, type AgentKey } from "./subagents.ts";

const ROOT = new URL("../../", import.meta.url);

// registry.py 的 AGENTS：每個 Agent 區塊以 `"<key>": AgentSpec(` 開頭，Subagent 以 `_s("<name>"` 定義
function registrySubagents(): Map<string, string[]> {
  const src = readFileSync(new URL("agents/registry.py", ROOT), "utf8");
  const out = new Map<string, string[]>();
  let current = "";
  for (const line of src.split("\n")) {
    const agent = line.match(/^\s*"([a-z0-9]+)": AgentSpec\(/);
    if (agent) { current = agent[1]; out.set(current, []); }
    const sub = line.match(/_s\("([a-z-]+)"/);
    if (sub && current) out.get(current)!.push(sub[1]);
  }
  return out;
}

const PAGE_KEY: Record<string, AgentKey> = { a0: "a0", a1: "a1", a2: "a2", a3: "a3", a4: "a4", a5: "a5", incident: "incident" };

test("運作原理頁的 Subagent 清單與 agents/registry.py 一致", () => {
  const reg = registrySubagents();
  assert.deepEqual(reg.get("orchestrator"), [], "Orchestrator 不派 Subagent");
  for (const [agent, key] of Object.entries(PAGE_KEY)) {
    assert.deepEqual(AGENT_SUBAGENTS[key].subs.map((s) => s.name).sort(), [...(reg.get(agent) ?? [])].sort(), agent);
  }
  const regAgents = [...reg.keys()].filter((k) => k !== "orchestrator").sort();
  assert.deepEqual(regAgents, Object.keys(PAGE_KEY).sort(), "registry.py 有新的 Agent，運作原理頁也要加上");
  assert.equal(SDK_SUBAGENT_COUNT, [...reg.values()].reduce((n, s) => n + s.length, 0));
});

test("每日情資的 Subagent 與 .claude/agents/ 一致", () => {
  const files = readdirSync(new URL(".claude/agents/", ROOT)).filter((f) => f.endsWith(".md")).map((f) => f.replace(/\.md$/, ""));
  assert.deepEqual(AGENT_SUBAGENTS.daily.subs.map((s) => s.name).sort(), files.sort());
});
