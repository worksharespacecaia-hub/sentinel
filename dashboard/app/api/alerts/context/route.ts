// GET /api/alerts/context?alert_id=...：供 incident.yml 以 NOTIFY_TOKEN 讀取已存在告警的權威上下文（第 11.2 節）。
// dispatch payload 只是查詢提示；這裡逐一驗證 alert_id 格式、所屬 Repo 與資產範圍，不接受任意查詢 URL 或 Issue number。
import { getAlert } from "@/lib/alertstore";
import { repoName } from "@/lib/github";
import { redisConfigured } from "@/lib/redis";
import { ALERT_ID_RE, RULE_ASSETS } from "@/lib/rules";
import { bearerMatches, json } from "@/lib/security";

export const dynamic = "force-dynamic";

export async function GET(req: Request): Promise<Response> {
  if (!process.env.NOTIFY_TOKEN || !redisConfigured()) return json({ error: "服務未設定" }, 503);
  if (!bearerMatches(req, process.env.NOTIFY_TOKEN)) return json({ error: "未授權" }, 401);
  const id = new URL(req.url).searchParams.get("alert_id") ?? "";
  if (!ALERT_ID_RE.test(id)) return json({ error: "alert_id 格式錯誤" }, 400);
  let repo: string;
  try {
    repo = repoName();
  } catch {
    return json({ error: "GH_OWNER／GH_REPO 未設定" }, 503);
  }
  try {
    const a = await getAlert(id);
    if (!a) return json({ error: "找不到這個告警" }, 404);
    if (a.repo !== repo) return json({ error: "告警不屬於本 Repo" }, 409);
    if (!RULE_ASSETS.has(a.asset_id)) return json({ error: "資產不在即時規則範圍" }, 409);
    if (!a.issue_number) return json({ error: "Issue 尚未建立" }, 409);
    return json({
      alert_id: a.id, rule_id: a.rule_id, rule_title: a.rule_title, level: a.level, asset_id: a.asset_id, account: a.account, summary: a.summary,
      repo: a.repo, issue_number: a.issue_number, simulated: a.simulated, simulation_id: a.simulation_id, status: a.status,
      maps_to_event: a.maps_to_event, source_event_ids: a.source_event_ids, created_at: a.created_at, advice: a.advice,
    });
  } catch {
    return json({ error: "告警服務暫時無法處理" }, 503);
  }
}
