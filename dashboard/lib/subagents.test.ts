import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { AGENT_SUBAGENTS, SDK_SUBAGENT_COUNT, type AgentKey } from "./subagents.ts";

const ROOT = new URL("../../", import.meta.url);

// registry.py 的 AGENTS：每個 Agent 區塊以 `"<key>": AgentSpec(` 開頭，Subagent 以 `_s("<name>"` 定義。
// key 可含連字號（orchestrator-dispatch、orchestrator-review），否則兩個 Orchestrator Agent 會被略過、沒有比對
function registrySubagents(): Map<string, string[]> {
  const src = readFileSync(new URL("agents/registry.py", ROOT), "utf8");
  const out = new Map<string, string[]>();
  let current = "";
  for (const line of src.split("\n")) {
    const agent = line.match(/^\s*"([a-z0-9-]+)": AgentSpec\(/);
    if (agent) { current = agent[1]; out.set(current, []); }
    const sub = line.match(/_s\("([a-z-]+)"/);
    if (sub && current) out.get(current)!.push(sub[1]);
  }
  return out;
}

const PAGE_KEY: Record<string, AgentKey> = {
  "orchestrator-dispatch": "dispatch", "orchestrator-review": "review",
  a0: "a0", a1: "a1", a2: "a2", a3: "a3", a4: "a4", a5: "a5", incident: "incident",
};

test("運作原理頁的 Subagent 清單與 agents/registry.py 一致", () => {
  const reg = registrySubagents();
  // 開工路由（router，原 orchestrator）是純程式，不在 registry；Orchestrator 是派工與驗收兩個 Agent
  assert.ok(!reg.has("orchestrator") && !reg.has("router"), "開工路由是純程式，不應出現在 registry");
  assert.deepEqual(reg.get("orchestrator-dispatch"), ["planner"]);
  assert.deepEqual(reg.get("orchestrator-review"), ["reviewer"]);
  for (const [agent, key] of Object.entries(PAGE_KEY)) {
    assert.deepEqual(AGENT_SUBAGENTS[key].subs.map((s) => s.name).sort(), [...(reg.get(agent) ?? [])].sort(), agent);
  }
  assert.deepEqual([...reg.keys()].sort(), Object.keys(PAGE_KEY).sort(), "registry.py 有新的 Agent，運作原理頁也要加上");
  assert.equal(SDK_SUBAGENT_COUNT, [...reg.values()].reduce((n, s) => n + s.length, 0));
});

// 「尚未實作」的標示要和程式一致：Agent 程式（agents/agents、agents/tools）沒有引用的 Subagent 才能標 planned，
// 有引用的不能標。實作某個 Subagent 後忘了拿掉標示，或標了還在用的 Subagent，這個測試都會失敗。
test("尚未實作的標示與 Agent 程式一致", () => {
  const src = ["agents/agents/", "agents/tools/"].flatMap((dir) =>
    readdirSync(new URL(dir, ROOT)).filter((f) => f.endsWith(".py")).map((f) => readFileSync(new URL(dir + f, ROOT), "utf8")));
  for (const key of Object.values(PAGE_KEY)) {
    for (const s of AGENT_SUBAGENTS[key].subs) {
      const used = src.some((code) => code.includes(`"${s.name}"`) || code.includes(`'${s.name}'`));
      assert.equal(!!s.planned, !used, `${s.name}：${used ? "程式有派發，不應標尚未實作" : "程式沒有派發，應標尚未實作"}`);
    }
  }
  assert.ok(!AGENT_SUBAGENTS.daily.subs.some((s) => s.planned), "每日情資的 Subagent 由 .claude/agents/ 定義，不用 planned");
});

test("每日情資的 Subagent 與 .claude/agents/ 一致", () => {
  const files = readdirSync(new URL(".claude/agents/", ROOT)).filter((f) => f.endsWith(".md")).map((f) => f.replace(/\.md$/, ""));
  assert.deepEqual(AGENT_SUBAGENTS.daily.subs.map((s) => s.name).sort(), files.sort());
});
