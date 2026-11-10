// POST /api/notify/light：A5 成功發布後呼叫（sentinel.yml「通知有效燈號」步驟；NOTIFY_TOKEN 保護）。
// 以 GitHub API 讀取該 commit 已發布的 index／manifest／report（不讀本機尚未重新部署的 public/data），確認 run_id 後
// 依第 7.5 節算有效燈號；跟上次通知的燈號不同才推播「燈號變化＋行動報告摘要」。情境與示範事件不推播。
import { buildActionReport } from "@/lib/actions";
import { openAlertsInfo } from "@/lib/alerts";
import type { DataIndex, Light, Report } from "@/lib/data";
import { GitHubError, SHA_RE, getRepoJson } from "@/lib/github";
import { combineLight } from "@/lib/light";
import { pushToAdmins, siteUrl, type PushResult } from "@/lib/line";
import { lightChangeMessage } from "@/lib/line-messages";
import { redis, redisConfigured } from "@/lib/redis";
import { loadTrackingSafe } from "@/lib/report-data";
import { HttpError, bearerMatches, json, readJsonBody } from "@/lib/security";

export const dynamic = "force-dynamic";
const DATA = "dashboard/public/data";
const PATH_RE = /^(daily|advisories\/[a-z0-9][a-z0-9._-]{0,80})$/;
const LAST_KEY = "notify:light:last";

export async function POST(req: Request): Promise<Response> {
  if (!process.env.NOTIFY_TOKEN || !redisConfigured()) return json({ error: "通知服務未設定" }, 503);
  if (!bearerMatches(req, process.env.NOTIFY_TOKEN)) return json({ error: "未授權" }, 401);
  let claimKey: string | null = null;
  try {
    const body = await readJsonBody(req, ["scope", "run_id", "sha"], 1024);
    const scope = String(body.scope ?? "");
    const runId = String(body.run_id ?? "");
    const sha = String(body.sha ?? "");
    if (scope !== "daily" && scope !== "advisory") return json({ ignored: "情境不推播" }, 202);
    if (!/^\d{1,20}$/.test(runId) || !SHA_RE.test(sha)) return json({ error: "run_id 或 sha 格式錯誤" }, 400);

    claimKey = `notify:light:run:${runId}`;
    if ((await redis<string | null>("SET", claimKey, "1", "NX", "EX", 7 * 86400)) !== "OK") {
      claimKey = null;
      return json({ ok: true, duplicate: true });
    }

    const index = await getRepoJson<DataIndex>(`${DATA}/index.json`, sha);
    const entry = scope === "daily" ? index.latest_daily
      : Object.values(index.advisories ?? {}).find((e) => e.run_id === runId);
    if (!entry || entry.run_id !== runId || !PATH_RE.test(entry.path)) throw new HttpError(409, "這個 commit 的已發布資料中找不到這次執行");
    const manifest = await getRepoJson<{ run_id: string }>(`${DATA}/${entry.path}/manifest.json`, sha);
    if (manifest.run_id !== runId) throw new HttpError(409, "manifest 的 run_id 不符");

    const daily = index.latest_daily && PATH_RE.test(index.latest_daily.path)
      ? await getRepoJson<Report>(`${DATA}/${index.latest_daily.path}/report.json`, sha) : null;
    const advisories = Object.entries(index.advisories ?? {}).map(([id, e]) => ({ id, light: e.light, run_id: e.run_id }));
    const alerts = await openAlertsInfo();
    const { light } = combineLight(daily ? { light: daily.light, light_reasons: daily.light_reasons, generated_at: daily.generated_at, run_id: daily.run_id } : null,
      advisories, alerts);

    const prev = (await redis<string | null>("GET", LAST_KEY)) as Light | null;
    await redis("SET", LAST_KEY, light);
    let pushed: PushResult;
    if (!prev) pushed = { state: "skipped", reason: "第一次記錄燈號，之後有變化才推播" };
    else if (prev === light) pushed = { state: "skipped", reason: "燈號沒有變化" };
    else if (!daily) pushed = { state: "skipped", reason: "沒有每日評估結果可附上" };
    else {
      const { tracking } = await loadTrackingSafe();
      const action = buildActionReport(daily, { light, tracking });
      pushed = await pushToAdmins([lightChangeMessage(prev, light, action, siteUrl())], "light");
    }
    return json({ ok: true, light, previous: prev, pushed });
  } catch (e) {
    if (claimKey) await redis("DEL", claimKey).catch(() => undefined);   // 讓 Workflow 重跑時可再處理
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    if (e instanceof GitHubError) return json({ error: `讀取已發布資料失敗：${e.message}` }, 502);
    return json({ error: "通知服務暫時無法處理" }, 503);
  }
}
