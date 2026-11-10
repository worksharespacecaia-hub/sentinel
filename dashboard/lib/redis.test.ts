import { test } from "node:test";
import assert from "node:assert/strict";
import { redisEnv } from "./redis.ts";

test("Redis 設定：接受 Vercel Marketplace 注入的 KV_REST_API_*，且不使用唯讀 Token", () => {
  const kv = { KV_REST_API_URL: "https://kv.example", KV_REST_API_TOKEN: "rw", KV_REST_API_READ_ONLY_TOKEN: "ro" };
  assert.deepEqual(redisEnv(kv), { url: "https://kv.example", token: "rw" });
  assert.deepEqual(redisEnv({ KV_REST_API_URL: "https://kv.example", KV_REST_API_READ_ONLY_TOKEN: "ro" }),
    { url: "https://kv.example", token: undefined });
});

test("Redis 設定：UPSTASH_REDIS_REST_* 優先，網址與 Token 不混用兩組", () => {
  const both = { UPSTASH_REDIS_REST_URL: "https://up.example", UPSTASH_REDIS_REST_TOKEN: "up",
                 KV_REST_API_URL: "https://kv.example", KV_REST_API_TOKEN: "kv" };
  assert.deepEqual(redisEnv(both), { url: "https://up.example", token: "up" });
  // 只設了一半的 UPSTASH 組合不會拿 KV 的值補，維持「未設定」
  assert.deepEqual(redisEnv({ UPSTASH_REDIS_REST_URL: "https://up.example", KV_REST_API_TOKEN: "kv" }),
    { url: "https://up.example", token: undefined });
  assert.deepEqual(redisEnv({}), { url: undefined, token: undefined });
});
