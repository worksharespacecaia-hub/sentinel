// GitHub Webhook（第 7.6 節）：以原始 body 驗證 X-Hub-Signature-256，通過後才 JSON.parse 並驗證 schema。
import { createHmac, timingSafeEqual } from "node:crypto";
import type { RtEvent } from "./rules.ts";

export const MAX_WEBHOOK_BYTES = 1024 * 1024;
const SIG_RE = /^sha256=([0-9a-f]{64})$/;

export class BodyTooLarge extends Error {}

/** 以串流讀取原始 body，超過上限立即中止（不先整個讀進記憶體）。 */
export async function readRawBody(req: Request, max = MAX_WEBHOOK_BYTES): Promise<string> {
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (declared > max) throw new BodyTooLarge();
  if (!req.body) return "";
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      throw new BodyTooLarge();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** 簽章格式必須為 sha256= 加 64 個十六進位字元；解碼長度一致才以 timingSafeEqual 比對。任何不符都回 false（不拋例外）。 */
export function verifySignature(raw: string, header: string | null, secret: string | undefined): boolean {
  if (!secret || !header) return false;
  const m = SIG_RE.exec(header);
  if (!m) return false;
  const given = Buffer.from(m[1], "hex");
  const expected = createHmac("sha256", secret).update(raw, "utf8").digest();
  if (given.length !== expected.length) return false;
  return timingSafeEqual(given, expected);
}

export function sign(raw: string, secret: string): string {
  return `sha256=${createHmac("sha256", secret).update(raw, "utf8").digest("hex")}`;
}

export type ParseResult = { ok: true; event: RtEvent } | { ok: false; status: number; reason: string };

const LOGIN_RE = /^[A-Za-z0-9-]{1,39}(\[bot\])?$/;

/**
 * deployment 事件 → 內部事件。合法但不相關（非預期 Repo、非 created、非 production）回 2xx 不產生告警；
 * 欄位格式錯誤回 400。預期 Repo ID 為受審查設定（環境變數），不接受 request 動態指定。
 */
export function parseDeployment(body: unknown, expectedRepoId: string, receivedAt: string): ParseResult {
  if (!body || typeof body !== "object") return { ok: false, status: 400, reason: "需要 JSON 物件" };
  const b = body as Record<string, any>;
  const repoId = b.repository?.id;
  if (typeof repoId !== "number") return { ok: false, status: 400, reason: "缺少 repository.id" };
  if (String(repoId) !== expectedRepoId) return { ok: false, status: 202, reason: "非預期的 Repo，忽略" };
  if (b.action !== "created") return { ok: false, status: 202, reason: `action=${String(b.action).slice(0, 20)}，忽略` };
  const d = b.deployment;
  if (!d || typeof d !== "object" || typeof d.id !== "number") return { ok: false, status: 400, reason: "缺少 deployment" };
  const env = typeof d.environment === "string" ? d.environment : "";
  if (env !== "production") return { ok: false, status: 202, reason: "非 production 環境，忽略" };
  const creator = d.creator?.login;
  if (typeof creator !== "string" || !LOGIN_RE.test(creator)) return { ok: false, status: 400, reason: "deployment.creator 格式錯誤" };
  const created = typeof d.created_at === "string" && !Number.isNaN(Date.parse(d.created_at)) ? new Date(d.created_at).toISOString() : null;
  if (!created) return { ok: false, status: 400, reason: "deployment.created_at 格式錯誤" };
  const ref = typeof d.ref === "string" ? d.ref.replace(/[^\w./-]/g, "").slice(0, 80) : "";
  const sha = typeof d.sha === "string" && /^[0-9a-f]{7,40}$/.test(d.sha) ? d.sha.slice(0, 12) : "";
  return {
    ok: true,
    event: {
      id: `gh-deployment-${d.id}`, source: "github.deployment", event_time: created, received_at: receivedAt,
      asset_id: "deploy-pipeline", account: null, simulated: false, simulation_id: null,
      data: { environment: env, creator, ref, sha },
    },
  };
}
