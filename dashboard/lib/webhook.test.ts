import { test } from "node:test";
import assert from "node:assert/strict";
import { BodyTooLarge, parseDeployment, readRawBody, sign, verifySignature } from "./webhook.ts";

const SECRET = "test-webhook-secret";
const raw = JSON.stringify({ hello: "世界" });

test("簽章：正確簽章通過；偽造、格式錯誤、長度不符、缺 secret 一律 false（不拋例外）", () => {
  assert.equal(verifySignature(raw, sign(raw, SECRET), SECRET), true);
  assert.equal(verifySignature(raw, sign(raw, "other"), SECRET), false);
  assert.equal(verifySignature(raw + " ", sign(raw, SECRET), SECRET), false, "body 被改動");
  assert.equal(verifySignature(raw, sign(raw, SECRET).toUpperCase(), SECRET), false, "前綴大小寫不符");
  assert.equal(verifySignature(raw, "sha256=" + "a".repeat(63), SECRET), false, "長度不足");
  assert.equal(verifySignature(raw, "sha256=" + "g".repeat(64), SECRET), false, "非十六進位");
  assert.equal(verifySignature(raw, "sha1=" + "a".repeat(40), SECRET), false);
  assert.equal(verifySignature(raw, null, SECRET), false);
  assert.equal(verifySignature(raw, sign(raw, SECRET), undefined), false);
  assert.equal(verifySignature(raw, sign(raw, ""), ""), false, "空 secret 不能比對成功");
});

test("body：超過 1 MB 立即中止", async () => {
  const big = new Request("http://x/", { method: "POST", body: "x".repeat(1024 * 1024 + 1) });
  await assert.rejects(readRawBody(big), (e: unknown) => e instanceof BodyTooLarge);
  const ok = new Request("http://x/", { method: "POST", body: raw });
  assert.equal(await readRawBody(ok), raw);
});

const payload = (over: Record<string, unknown> = {}, dep: Record<string, unknown> = {}) => ({
  action: "created", repository: { id: 4242, full_name: "demo/shopsaas-demo-platform" },
  deployment: { id: 99, environment: "production", creator: { login: "alice-dev" }, created_at: "2026-11-09T03:00:00Z",
                ref: "main", sha: "8ae244637733e6f55917dc981b0b862e9e8bb18a", ...dep },
  ...over,
});

test("deployment：轉成內部事件；不相關事件回 2xx 不產生告警；格式錯誤回 400", () => {
  const r = parseDeployment(payload(), "4242", "2026-11-09T03:00:01Z");
  assert.ok(r.ok);
  if (r.ok) {
    assert.equal(r.event.id, "gh-deployment-99");
    assert.equal(r.event.data.creator, "alice-dev");
    assert.equal(r.event.asset_id, "deploy-pipeline");
    assert.equal(r.event.simulated, false);
  }
  const other = parseDeployment(payload({ repository: { id: 1 } }), "4242", "t");
  assert.ok(!other.ok && other.status === 202, "非預期 Repo");
  const staging = parseDeployment(payload({}, { environment: "staging" }), "4242", "t");
  assert.ok(!staging.ok && staging.status === 202);
  const bad = parseDeployment(payload({}, { creator: { login: "evil<script>" } }), "4242", "t");
  assert.ok(!bad.ok && bad.status === 400);
  const noDate = parseDeployment(payload({}, { created_at: "yesterday" }), "4242", "t");
  assert.ok(!noDate.ok && noDate.status === 400);
});
