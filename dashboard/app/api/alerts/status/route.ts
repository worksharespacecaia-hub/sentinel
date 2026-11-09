// POST /api/alerts/status：管理者變更告警狀態（第 7.6 節）。open → contained → closed，或 contained → open。
// 必須驗證 ADMIN_PASSCODE（未設定回 503）；原子限流；以 status_version 避免管理者併發覆蓋；附操作人、理由、時間與驗證證據連結。
// closed 必須確認已圍堵並重新驗證；TTL、Issue 被關閉或 LLM 建議完成都不能結案。只接受 POST。
import { after } from "next/server";
import { StoreError, changeStatus, toPublic, validEvidenceUrl, type AlertStatus } from "@/lib/alertstore";
import { deliver } from "@/lib/delivery";
import { redisConfigured } from "@/lib/redis";
import { ALERT_ID_RE } from "@/lib/rules";
import { HttpError, clientKey, json, passcodeMatches, rateLimit, readJsonBody } from "@/lib/security";

export const dynamic = "force-dynamic";
const STATUSES = new Set<AlertStatus>(["open", "contained", "closed"]);

export async function POST(req: Request): Promise<Response> {
  try {
    if (!process.env.ADMIN_PASSCODE) return json({ error: "管理者密碼未設定，已停用狀態變更" }, 503);
    if (!redisConfigured()) return json({ error: "Redis 未設定" }, 503);
    const body = await readJsonBody(req,
      ["admin_passcode", "alert_id", "to", "actor", "reason", "evidence_url", "containment_confirmed", "reverified", "version"], 4096);
    if (!(await rateLimit(`rl:admin:${clientKey(req)}`, 10, 60))) return json({ error: "操作過於頻繁，請稍後再試" }, 429);
    if (!passcodeMatches(body.admin_passcode, process.env.ADMIN_PASSCODE)) return json({ error: "管理者密碼錯誤" }, 401);
    const id = String(body.alert_id ?? "");
    const to = String(body.to ?? "") as AlertStatus;
    const actor = String(body.actor ?? "").trim();
    const reason = String(body.reason ?? "").trim();
    const version = Number(body.version);
    if (!ALERT_ID_RE.test(id) || !STATUSES.has(to)) return json({ error: "alert_id 或狀態錯誤" }, 400);
    if (!/^[\p{L}\p{N} ._@-]{1,40}$/u.test(actor)) return json({ error: "請填寫操作人（40 字內）" }, 400);
    if (reason.length < 4 || reason.length > 500) return json({ error: "請填寫理由（4～500 字）" }, 400);
    if (!validEvidenceUrl(body.evidence_url)) return json({ error: "驗證證據需為 HTTPS 連結" }, 400);
    if (!Number.isInteger(version) || version < 1) return json({ error: "缺少版本號" }, 400);
    const a = await changeStatus(id, version, {
      to, actor, reason, evidence_url: body.evidence_url as string,
      containment_confirmed: body.containment_confirmed === true, reverified: body.reverified === true,
    });
    after(() => deliver(id, ["sync"]).then(() => undefined, () => undefined));
    return json({ ok: true, alert: toPublic(a) });
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    if (e instanceof StoreError) return json({ error: e.message }, e.code === "missing" ? 404 : e.code === "conflict" ? 409 : 400);
    return json({ error: "告警服務暫時無法處理" }, 503);
  }
}
