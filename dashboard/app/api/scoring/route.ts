// GET /api/scoring：目前生效的燈號權重、blob sha 與調整歷史（公開資料，不含任何 Token）。
// POST /api/scoring：管理者調整權重（需 ADMIN_PASSCODE、操作人與理由）；以 base_sha 做併發檢查，寫回 rules/scoring.json 一個 commit。
// 新權重由下一次評估（每日 08:00、公告觸發或手動執行）套用；網站不自行改燈號。
import { GitHubError, SHA_RE, putScoringConfig } from "@/lib/github";
import { redisConfigured } from "@/lib/redis";
import { configText, validateWeights } from "@/lib/scoring";
import { invalidateScoringCache, loadScoringState } from "@/lib/scoring-store";
import { HttpError, clientKey, json, passcodeMatches, rateLimit, readJsonBody } from "@/lib/security";

export const dynamic = "force-dynamic";
const ACTOR_RE = /^[\p{L}\p{N} ._@-]{1,40}$/u;

export async function GET(): Promise<Response> {
  const s = await loadScoringState();
  return json(s, s.error && s.configured ? 502 : s.configured ? 200 : 503);
}

export async function POST(req: Request): Promise<Response> {
  try {
    if (!process.env.ADMIN_PASSCODE) return json({ error: "管理者密碼未設定，已停用權重調整" }, 503);
    if (!redisConfigured()) return json({ error: "Redis 未設定" }, 503);
    const body = await readJsonBody(req, ["admin_passcode", "actor", "reason", "factors", "thresholds", "base_sha"], 4096);
    if (!(await rateLimit(`rl:admin:${clientKey(req)}`, 10, 60))) return json({ error: "操作過於頻繁，請稍後再試" }, 429);
    if (!passcodeMatches(body.admin_passcode, process.env.ADMIN_PASSCODE)) return json({ error: "管理者密碼錯誤" }, 401);

    const actor = String(body.actor ?? "").trim();
    const reason = String(body.reason ?? "").trim();
    const baseSha = String(body.base_sha ?? "");
    if (!ACTOR_RE.test(actor)) return json({ error: "請填寫操作人（40 字內）" }, 400);
    if (reason.length < 4 || reason.length > 200 || /[\u0000-\u001f]/.test(reason)) return json({ error: "請填寫調整理由（4～200 字，不含換行）" }, 400);
    if (!SHA_RE.test(baseSha)) return json({ error: "缺少設定版本（請重新整理頁面）" }, 400);
    const v = validateWeights(body.factors, body.thresholds);
    if (!v.ok) return json({ error: v.error }, 400);

    const current = await loadScoringState(true);
    if (!current.config || !current.sha) return json({ error: current.error ?? "無法讀取目前的權重設定" }, 503);
    if (current.sha !== baseSha) return json({ error: "權重設定剛被其他人修改，請重新整理後再調整" }, 409);

    const text = configText(current.config.version, v.value, actor, reason);
    const message = `scoring: 調整燈號權重（${actor}）\n\n理由：${reason}\n\n由 Sentinel 網站「燈號權重」頁送出（管理者密碼驗證）。下一次評估起生效。`;
    const commit = await putScoringConfig(text, baseSha, message);
    invalidateScoringCache();
    return json({ ok: true, version: current.config.version + 1, commit });
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    if (e instanceof GitHubError && (e.status === 409 || e.status === 422)) return json({ error: "權重設定剛被其他人修改，請重新整理後再調整" }, 409);
    if (e instanceof GitHubError) return json({ error: `寫回 GitHub 失敗：${e.message}` }, 502);
    return json({ error: "權重服務暫時無法處理" }, 503);
  }
}
