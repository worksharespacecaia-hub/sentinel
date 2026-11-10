// GET /api/rules：偵測規則的預設值、目前生效的設定、與 GitHub 是否一致、調整歷史（公開資料，不含任何 Token）。
// POST /api/rules：管理者調整偵測規則（需 ADMIN_PASSCODE、操作人與理由）；以 base_sha 做併發檢查，寫回 rules/realtime-settings.json 一個 commit，
// 同時更新 Redis，數秒內生效。只能調整 lib/rule-settings.ts 開放的參數；正規表示式等條件要改 rules/realtime.yaml。
import { GitHubError, SHA_RE, contentsConfigured } from "@/lib/github";
import { redisConfigured } from "@/lib/redis";
import { SettingsConflict, loadRuleSettingsState, saveRuleSettings } from "@/lib/rule-store";
import { validateOverrides } from "@/lib/rule-settings";
import { RULES } from "@/lib/rules";
import { HttpError, clientKey, json, passcodeMatches, rateLimit, readJsonBody } from "@/lib/security";

export const dynamic = "force-dynamic";
const ACTOR_RE = /^[\p{L}\p{N} ._@-]{1,40}$/u;

export async function GET(): Promise<Response> {
  const s = await loadRuleSettingsState();
  return json({ ...s, defaults: RULES }, s.error && s.configured ? 502 : 200);
}

export async function POST(req: Request): Promise<Response> {
  try {
    if (!process.env.ADMIN_PASSCODE) return json({ error: "管理者密碼未設定，已停用規則調整" }, 503);
    if (!redisConfigured()) return json({ error: "Redis 未設定，偵測無法讀取新設定" }, 503);
    if (!contentsConfigured()) return json({ error: "GH_DISPATCH_TOKEN 或 GH_OWNER／GH_REPO 未設定，無法保存調整紀錄" }, 503);
    const body = await readJsonBody(req, ["admin_passcode", "actor", "reason", "rules", "base_sha"], 8192);
    if (!(await rateLimit(`rl:admin:${clientKey(req)}`, 10, 60))) return json({ error: "操作過於頻繁，請稍後再試" }, 429);
    if (!passcodeMatches(body.admin_passcode, process.env.ADMIN_PASSCODE)) return json({ error: "管理者密碼錯誤" }, 401);

    const actor = String(body.actor ?? "").trim();
    const reason = String(body.reason ?? "").trim();
    const baseSha = body.base_sha === null || body.base_sha === "" ? null : String(body.base_sha ?? "");
    if (!ACTOR_RE.test(actor)) return json({ error: "請填寫操作人（40 字內）" }, 400);
    if (reason.length < 4 || reason.length > 200 || /[\u0000-\u001f]/.test(reason)) return json({ error: "請填寫調整理由（4～200 字，不含換行）" }, 400);
    if (baseSha !== null && !SHA_RE.test(baseSha)) return json({ error: "缺少設定版本（請重新整理頁面）" }, 400);
    const v = validateOverrides(body.rules, RULES);
    if (!v.ok) return json({ error: v.error }, 400);

    const res = await saveRuleSettings(v.value, actor, reason, baseSha);
    return json({ ok: true, ...res,
                  note: res.redis_synced ? "已儲存，數秒內生效" : "已寫入 GitHub，但更新 Redis 失敗；重新開啟本頁會自動同步，同步前偵測仍用舊設定" });
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    if (e instanceof SettingsConflict) return json({ error: e.message }, 409);
    if (e instanceof GitHubError && (e.status === 409 || e.status === 422)) return json({ error: "偵測規則剛被其他人修改，請重新整理後再調整" }, 409);
    if (e instanceof GitHubError) return json({ error: `寫回 GitHub 失敗：${e.message}` }, 502);
    return json({ error: "規則設定服務暫時無法處理" }, 503);
  }
}
