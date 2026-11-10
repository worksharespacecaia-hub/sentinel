// POST /api/actions/status：管理者把行動報告中的風險設為「處理中」（必須有期限）或取消處理中。
// 必須驗證 ADMIN_PASSCODE（未設定回 503）；原子限流；以 version 避免管理者併發覆蓋。
// 只接受目前 daily（正式）報告中未修復的風險；已修復只由重新評估判定，不能手動標示。
import { checkTrackInput } from "@/lib/actions";
import { getReport, resolveSource } from "@/lib/data";
import { redisConfigured } from "@/lib/redis";
import { HttpError, clientKey, json, passcodeMatches, rateLimit, readJsonBody } from "@/lib/security";
import { RISK_ID_RE, TrackError, cancelTracking, setInProgress } from "@/lib/tracking";

export const dynamic = "force-dynamic";
const ACTOR_RE = /^[\p{L}\p{N} ._@-]{1,40}$/u;

export async function POST(req: Request): Promise<Response> {
  try {
    if (!process.env.ADMIN_PASSCODE) return json({ error: "管理者密碼未設定，已停用處理中設定" }, 503);
    if (!redisConfigured()) return json({ error: "Redis 未設定" }, 503);
    const body = await readJsonBody(req, ["admin_passcode", "risk_id", "action", "actor", "owner", "due_at", "note", "reason", "version"], 4096);
    if (!(await rateLimit(`rl:admin:${clientKey(req)}`, 10, 60))) return json({ error: "操作過於頻繁，請稍後再試" }, 429);
    if (!passcodeMatches(body.admin_passcode, process.env.ADMIN_PASSCODE)) return json({ error: "管理者密碼錯誤" }, 401);

    const id = String(body.risk_id ?? "");
    const action = String(body.action ?? "");
    const actor = String(body.actor ?? "").trim();
    const version = Number(body.version);
    if (!RISK_ID_RE.test(id) || (action !== "set" && action !== "cancel")) return json({ error: "risk_id 或動作錯誤" }, 400);
    if (!ACTOR_RE.test(actor)) return json({ error: "請填寫操作人（40 字內）" }, 400);
    if (!Number.isInteger(version) || version < 0) return json({ error: "缺少版本號" }, 400);

    const report = await getReport(await resolveSource(undefined));
    const risk = report?.risks.find((r) => r.id === id);
    if (!risk) return json({ error: "目前的每日評估沒有這一項風險" }, 404);
    if (risk.status === "fixed") return json({ error: "這一項已由重新評估判定修復，不需要追蹤" }, 409);

    if (action === "cancel") {
      const reason = String(body.reason ?? "").trim();
      if (reason.length < 2 || reason.length > 200) return json({ error: "請填寫取消理由（2～200 字）" }, 400);
      const t = await cancelTracking(id, version, actor, reason);
      return json({ ok: true, tracking: t });
    }
    const input = checkTrackInput(body);
    if (!input.ok) return json({ error: input.error }, 400);
    const t = await setInProgress(id, version, input.value, actor);
    return json({ ok: true, tracking: t });
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    if (e instanceof TrackError) return json({ error: e.message }, e.code === "conflict" ? 409 : e.code === "missing" ? 404 : 400);
    return json({ error: "追蹤服務暫時無法處理" }, 503);
  }
}
