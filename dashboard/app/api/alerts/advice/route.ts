// POST /api/alerts/advice：incident.yml 完成圍堵建議後呼叫（NOTIFY_TOKEN 保護），更新 timeline.advice_ready 與 Issue 留言連結。
// 冪等：重跑只保留第一次的完成時間；留言連結必須指向這個告警自己的 Issue。
import { StoreError, getAlert, patchAlert } from "@/lib/alertstore";
import { redisConfigured } from "@/lib/redis";
import { ALERT_ID_RE } from "@/lib/rules";
import { HttpError, bearerMatches, json, readJsonBody } from "@/lib/security";

export const dynamic = "force-dynamic";
const SOURCES = new Set(["live", "replay", "template"]);
const RUN_RE = /^[A-Za-z0-9._-]{1,40}$/;

export async function POST(req: Request): Promise<Response> {
  if (!process.env.NOTIFY_TOKEN || !redisConfigured()) return json({ error: "服務未設定" }, 503);
  if (!bearerMatches(req, process.env.NOTIFY_TOKEN)) return json({ error: "未授權" }, 401);
  try {
    const body = await readJsonBody(req, ["alert_id", "comment_url", "source", "run_id"], 2048);
    const id = String(body.alert_id ?? "");
    if (!ALERT_ID_RE.test(id)) return json({ error: "alert_id 格式錯誤" }, 400);
    const source = String(body.source ?? "");
    const runId = String(body.run_id ?? "");
    if (!SOURCES.has(source) || !RUN_RE.test(runId)) return json({ error: "source 或 run_id 格式錯誤" }, 400);
    const a = await getAlert(id);
    if (!a) return json({ error: "找不到這個告警" }, 404);
    const expected = new RegExp(`^https://github\\.com/${(a.repo ?? "").replace(/[.]/g, "\\.")}/issues/${a.issue_number}#issuecomment-\\d{1,20}$`);
    const url = String(body.comment_url ?? "");
    if (!a.repo || !a.issue_number || !expected.test(url)) return json({ error: "留言連結不屬於這個告警的 Issue" }, 400);
    const now = new Date().toISOString();
    const updated = await patchAlert(id, (x) => {
      x.advice = x.advice ?? { comment_url: url, source, run_id: runId, at: now };
      x.timeline.advice_ready = x.timeline.advice_ready ?? now;
    });
    return json({ ok: true, timeline: updated.timeline, advice: updated.advice });
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    if (e instanceof StoreError) return json({ error: e.message }, e.code === "missing" ? 404 : 409);
    return json({ error: "告警服務暫時無法處理" }, 503);
  }
}
