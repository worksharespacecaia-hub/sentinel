import { test } from "node:test";
import assert from "node:assert/strict";
import { applySettings, editableFields, parseSettings, settingsText, validateOverrides } from "./rule-settings.ts";
import { RULES, rulesFor, staticMatch, type RtEvent } from "./rules.ts";

const rule = (id: string) => RULES.find((r) => r.id === id)!;
const deploy = (creator: string): RtEvent => ({
  id: "evt-test-1", source: "github.deployment", event_time: "2026-11-09T03:00:00Z", received_at: "2026-11-09T03:00:01Z",
  asset_id: "deploy-pipeline", account: null, simulated: false, simulation_id: null, data: { environment: "production", creator },
});

test("每條規則只開放自己有的參數；正規表示式、資料表不開放", () => {
  const keys = (id: string) => editableFields(rule(id)).map((f) => f.key);
  assert.deepEqual(keys("RT-001"), ["enabled", "level", "light", "dedup_minutes", "creator_not_in"]);
  assert.ok(keys("RT-002").includes("event_hour_between") && keys("RT-002").includes("over_baseline_multiplier"));
  assert.ok(keys("RT-003").includes("threshold") && keys("RT-003").includes("window_hours"));
  const r = validateOverrides({ "RT-003": { text_regex: ".*" } }, RULES);
  assert.equal(r.ok, false);
  assert.match((r as { error: string }).error, /rules\/realtime\.yaml/);
});

test("驗證：範圍、型別、未知規則都拒絕；與預設相同的值不保存", () => {
  const bad = (raw: unknown) => assert.equal(validateOverrides(raw, RULES).ok, false, JSON.stringify(raw));
  bad({ "RT-999": { enabled: false } });
  bad({ "RT-002": { event_hour_between: [6, 0] } });
  bad({ "RT-002": { event_hour_between: [0, 25] } });
  bad({ "RT-002": { window_minutes: 0 } });
  bad({ "RT-002": { window_minutes: 2.5 } });
  bad({ "RT-002": { over_baseline_multiplier: 1.2 } });
  bad({ "RT-003": { threshold: 1 } });
  bad({ "RT-001": { creator_not_in: [] } });                    // 全部移除會讓每次正式部署都告警
  bad({ "RT-001": { creator_not_in: ["bad name; rm -rf"] } });
  bad({ "RT-001": { level: "critical" } });
  bad({ "RT-001": { dedup_minutes: "30" } });
  const ok = validateOverrides({
    "RT-001": { enabled: true, level: "high", creator_not_in: ["github-actions[bot]", "release-bot[bot]"] },
    "RT-002": { window_minutes: 10, over_baseline_multiplier: 20 },
    "RT-003": { threshold: 3 },
  }, RULES);
  assert.ok(ok.ok);
  assert.deepEqual(ok.value, { "RT-001": { creator_not_in: ["github-actions[bot]", "release-bot[bot]"] },
                               "RT-002": { over_baseline_multiplier: 20 } });
});

test("套用設定：調整後的參數影響判斷，停用的規則不判斷，預設規則不被改動", () => {
  const { rules, warnings } = applySettings(RULES, {
    "RT-001": { creator_not_in: ["github-actions[bot]", "release-bot[bot]"] },
    "RT-003": { enabled: false },
  });
  assert.deepEqual(warnings, []);
  const r1 = rules.find((r) => r.id === "RT-001")!;
  assert.equal(staticMatch(r1, deploy("release-bot[bot]")).ok, false);            // 新加入的部署者不告警
  assert.equal(staticMatch(rule("RT-001"), deploy("release-bot[bot]")).ok, true);  // 預設規則沒有被改到
  assert.deepEqual(rulesFor("support.complaint", rules), []);
  assert.equal(rulesFor("support.complaint").length, 1);
});

test("設定檔中不合法或已不存在的項目改用預設值並回報，不讓偵測停擺", () => {
  const { rules, warnings } = applySettings(RULES, { "RT-002": { window_minutes: -5, threshold: 3 }, "RT-404": { enabled: false } } as never);
  assert.equal(rules.find((r) => r.id === "RT-002")!.window!.minutes, rule("RT-002").window!.minutes);
  assert.equal(warnings.length, 3);
  assert.equal(rules.length, RULES.length);
});

test("設定檔格式：版本遞增並記錄操作人與理由", () => {
  const text = settingsText(2, { "RT-003": { threshold: 5 } }, "Ethan", "降低誤報", new Date("2026-11-11T00:00:00Z"));
  const f = parseSettings(text);
  assert.equal(f.version, 3);
  assert.equal(f.updated_by, "Ethan");
  assert.equal(f.reason, "降低誤報");
  assert.deepEqual(f.rules, { "RT-003": { threshold: 5 } });
  assert.throws(() => parseSettings("{}"));
});
