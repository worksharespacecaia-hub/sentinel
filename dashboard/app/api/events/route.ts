// POST /api/events：攻擊模擬器（第 11.2 節）。{passcode, preset}；事件序列由伺服器依預設產生，前端不能送任意事件。
// 與 /api/run 相同的必填密碼與缺值拒絕；每來源每分鐘 10 次；伺服器產生 simulation_id，所有 key／Issue／通知都帶此 ID。
import { after } from "next/server";
import { deliver } from "@/lib/delivery";
import { PRESETS, buildPreset, newSimulationId, type Preset } from "@/lib/presets";
import { redisConfigured } from "@/lib/redis";
import { HttpError, clientKey, json, passcodeMatches, rateLimit, readJsonBody } from "@/lib/security";
import { processEvent } from "@/lib/window";
import { syncRulesFromGitHub } from "@/lib/rule-store";

export const dynamic = "force-dynamic";

export async function POST(req: Request): Promise<Response> {
  try {
    if (!process.env.DEMO_PASSCODE) return json({ error: "示範密碼未設定，已停用模擬器" }, 503);
    if (!redisConfigured()) return json({ error: "Redis 未設定，已停用模擬器" }, 503);
    const body = await readJsonBody(req, ["passcode", "preset"], 1024);
    if (!(await rateLimit(`rl:events:${clientKey(req)}`, 10, 60))) return json({ error: "嘗試次數過多，請稍後再試" }, 429);
    if (!passcodeMatches(body.passcode, process.env.DEMO_PASSCODE)) return json({ error: "密碼錯誤" }, 401);
    const preset = String(body.preset ?? "");
    if (!(PRESETS as readonly string[]).includes(preset)) return json({ error: "不允許的預設" }, 400);

    const simulationId = newSimulationId();
    const events = buildPreset(preset as Preset, simulationId);
    const results = [];
    const alerts: string[] = [];
    let rulesMissing = false;
    for (const ev of events) {
      const pr = await processEvent(ev);
      results.push({ event_id: pr.event_id, results: pr.results.map((r) => ({ rule_id: r.rule_id, outcome: r.outcome, metric: r.metric })) });
      alerts.push(...pr.alerts);
      rulesMissing = rulesMissing || pr.rules.missing;
    }
    for (const id of alerts) after(() => deliver(id).then(() => undefined, () => undefined));
    if (rulesMissing) after(() => syncRulesFromGitHub().then(() => undefined, () => undefined));   // Redis 沒有規則設定：回應後修復
    return json({ simulation_id: simulationId, simulated: true, events: events.length, alerts, results });
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    return json({ error: "模擬器暫時無法處理" }, 503);
  }
}
