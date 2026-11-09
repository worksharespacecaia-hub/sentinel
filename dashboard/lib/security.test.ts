import { test } from "node:test";
import assert from "node:assert/strict";
import { HttpError, passcodeMatches, readJsonBody } from "./security.ts";

test("passcode: 未設定期望值時永遠失敗，空值不能比對成功", () => {
  assert.equal(passcodeMatches("", undefined), false);
  assert.equal(passcodeMatches("", ""), false);
  assert.equal(passcodeMatches("abc", undefined), false);
  assert.equal(passcodeMatches("abc", "abc"), true);
  assert.equal(passcodeMatches("abd", "abc"), false);
  assert.equal(passcodeMatches(123, "123"), false);
});

const req = (body: string) => new Request("http://x/api/run", { method: "POST", body });

test("body：拒絕未知欄位（例如前端偽造 trigger_source、execution_mode、ref）", async () => {
  for (const extra of ["trigger_source", "execution_mode", "ref", "advisory_id", "assets"]) {
    await assert.rejects(readJsonBody(req(JSON.stringify({ scenario: "daily", passcode: "x", [extra]: "manual" })), ["scenario", "passcode"]),
      (e: unknown) => e instanceof HttpError && e.status === 400);
  }
});

test("body：超過 4 KB 回 413、非物件回 400", async () => {
  await assert.rejects(readJsonBody(req(JSON.stringify({ scenario: "x".repeat(5000) })), ["scenario"]),
    (e: unknown) => e instanceof HttpError && e.status === 413);
  await assert.rejects(readJsonBody(req("[1]"), ["scenario"]), (e: unknown) => e instanceof HttpError && e.status === 400);
  await assert.rejects(readJsonBody(req("{oops"), ["scenario"]), (e: unknown) => e instanceof HttpError && e.status === 400);
});
