// GET /api/summary：有效燈號、daily 時效、正式公告警示、真實未結案高風險告警數、degraded 原因；模擬摘要獨立列出。
import { openAlertsInfo } from "@/lib/alerts";
import { computeSummary } from "@/lib/summary";
import { json } from "@/lib/security";

export const dynamic = "force-dynamic";

export async function GET(): Promise<Response> {
  const summary = await computeSummary(await openAlertsInfo());
  return json(summary);
}
