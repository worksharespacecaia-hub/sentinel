import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  NEWS_FAILED_TEXT, NEWS_UNKNOWN_TEXT, buildDigestView, detailLink, filterDigest, groupEvents, isDigestLatest, isStale,
  mergeImpacts, newsNotice, parseSuggestions, pruneForView, relationLabel, safeHref, windowBounds,
  type Card, type DailyInfo, type DigestAssessment, type DigestEvent, type DigestLatest,
} from "./digest.ts";
import { fmtDateHeading, fmtTime, taipeiDate } from "./labels.ts";

// 凍結的「現在」：台灣 2026-11-11 10:00（UTC 02:00）
const NOW = new Date("2026-11-11T02:00:00Z");

const assess = (over: Partial<DigestAssessment> = {}): DigestAssessment => ({
  evaluated_at: "2026-11-11T00:00:00Z", run_id: "run-1", relation: "not_affected", max_level: null, affected_count: 0,
  conclusion: "沒有受影響的項目。", impacts: [], impacts_total: 0, impacts_truncated: false, relation_changed_at: null, ...over,
});

const ev = (id: string, over: Partial<DigestEvent> = {}, a: Partial<DigestAssessment> = {}): DigestEvent => ({
  id, kind: "live", title: `事件 ${id}`, event_date: "2026-11-10", first_seen: "2026-11-11", last_seen: "2026-11-11",
  last_seen_at: "2026-11-11T00:00:00Z", observed_run_id: "run-1", confidence: "confirmed", is_update_of: null, cves: [],
  summary: "摘要", sources: [{ title: "報導", domain: "www.ithome.com.tw", url: "https://www.ithome.com.tw/news/1", verified: true }],
  assessment: assess(a), ...over,
});

/** 由扁平事件組出與後端相同結構的 latest（days 依收錄日期、新進度掛在 updates）。 */
const latestOf = (events: DigestEvent[], over: Partial<DigestLatest> = {}): DigestLatest => {
  const { days, counts } = groupEvents(events);
  return {
    schema_version: 1, updated_at: "2026-11-11T00:20:00Z", as_of: "2026-11-11T00:00:00Z", run_id: "run-1",
    next_update_at: "2026-11-12T00:00:00Z", daily_intel_status: "ok", window_days: 30, data_issues: [], counts,
    days: days.map((d) => ({ date: d.date, count: d.count, events: d.groups.map((g) => ({ ...g.head, updates: g.updates.map((u) => ({ ...u, updates: [], standalone_reason: null })), standalone_reason: g.standalone_reason })) })),
    ...over,
  };
};

const DAILY: DailyInfo = { run_id: "run-1", as_of: "2026-11-11T00:00:00Z", generated_at: "2026-11-11T00:20:00Z", daily_intel_status: "ok" };
const ids = (cards: Card[]) => cards.map((c) => c.id);

test("isStale：超過下次預定更新 12 小時才算過期；剛好 12 小時不算；時間無法解讀視為過期", () => {
  const latest = { next_update_at: "2026-11-12T00:00:00Z" };
  assert.equal(isStale(latest, new Date("2026-11-11T23:59:59Z")), false);
  assert.equal(isStale(latest, new Date("2026-11-12T11:59:59Z")), false);
  assert.equal(isStale(latest, new Date("2026-11-12T12:00:00Z")), false);
  assert.equal(isStale(latest, new Date("2026-11-12T12:00:01Z")), true);
  assert.equal(isStale({ next_update_at: "不是時間" }, NOW), true);
});

test("safeHref：只接受 http(s)，拒絕帳密、其他協定、相對路徑與控制字元", () => {
  assert.equal(safeHref("https://www.ithome.com.tw/news/1?a=1"), "https://www.ithome.com.tw/news/1?a=1");
  assert.equal(safeHref("http://example.com"), "http://example.com/");
  for (const bad of ["javascript:alert(1)", "JAVASCRIPT:alert(1)", "data:text/html,x", "ftp://example.com/a", "file:///etc/passwd",
    "https://user:pass@example.com/", "https://user@example.com/", "/intel/x", "//example.com/a", "https://exa mple.com",
    "https://example.com/\nx", "", null, undefined]) {
    assert.equal(safeHref(bad as string | null | undefined), null, String(bad));
  }
});

test("fmtDateHeading 與 taipeiDate：星期、無效日期原樣回傳、UTC 跨台灣午夜", () => {
  assert.equal(fmtDateHeading("2026-11-11"), "11 月 11 日（三）");
  assert.equal(fmtDateHeading("2026-11-01"), "11 月 1 日（日）");
  assert.equal(fmtDateHeading("2026-12-05"), "12 月 5 日（六）");
  assert.equal(fmtDateHeading("2026-02-30"), "2026-02-30");
  assert.equal(fmtDateHeading("abc"), "abc");
  assert.equal(taipeiDate("2026-11-10T15:59:59Z"), "2026-11-10");
  assert.equal(taipeiDate("2026-11-10T16:00:00Z"), "2026-11-11");
  assert.equal(taipeiDate(new Date("2026-11-10T12:22:28Z")), "2026-11-10");   // 行動報告標題的既有行為不變
});

test("relationLabel：四種關係附文字；未知值不顯示欄位名稱", () => {
  assert.equal(relationLabel("affected"), "受影響");
  assert.equal(relationLabel("need_check"), "需確認");
  assert.equal(relationLabel("not_affected"), "不受影響");
  assert.equal(relationLabel("fixed"), "已修復");
  assert.equal(relationLabel("open"), "未提供");
  assert.equal(relationLabel(null), "未提供");
});

test("windowBounds：台灣 D-29～D；UTC 16:00 起算台灣隔日", () => {
  assert.deepEqual(windowBounds(new Date("2026-11-30T03:00:00Z")), { start: "2026-11-01", end: "2026-11-30" });
  assert.deepEqual(windowBounds(new Date("2026-11-29T15:59:59Z")), { start: "2026-10-31", end: "2026-11-29" });
  assert.deepEqual(windowBounds(new Date("2026-11-29T16:00:00Z")), { start: "2026-11-01", end: "2026-11-30" });
});

test("父子事件篩選：原事件不符合時仍顯示符合的新進度與群組標示；群組依最優先的子事件排序；唯一 ID 計數", () => {
  const parent = ev("parent", {}, { relation: "not_affected" });
  const child = ev("child", { is_update_of: "parent", event_date: "2026-11-11" }, { relation: "affected", max_level: "high", affected_count: 2 });
  const other = ev("other", {}, { relation: "need_check" });
  const view = buildDigestView(latestOf([parent, child, other]), NOW, DAILY, new Set());
  assert.equal(view.counts.total, 3);
  assert.deepEqual([view.counts.affected, view.counts.need_check, view.counts.not_affected], [1, 1, 1]);
  assert.equal(view.days.length, 1);
  assert.equal(view.days[0].count, 3);
  // 含受影響子事件的群組排在「需確認」之前
  assert.deepEqual(view.days[0].groups.map((g) => g.head.id), ["parent", "other"]);
  assert.deepEqual(ids(view.days[0].groups[0].updates), ["child"]);

  const affected = filterDigest(view.days, "affected");
  assert.equal(affected.count, 1);
  assert.equal(affected.days[0].count, 1);
  assert.equal(affected.days[0].groups.length, 1);
  assert.equal(affected.days[0].groups[0].head.id, "parent");
  assert.equal(affected.days[0].groups[0].headMatched, false);
  assert.deepEqual(ids(affected.days[0].groups[0].updates), ["child"]);

  const notAffected = filterDigest(view.days, "not_affected");
  assert.equal(notAffected.count, 1);
  assert.equal(notAffected.days[0].groups[0].headMatched, true);
  assert.deepEqual(notAffected.days[0].groups[0].updates, []);

  assert.equal(filterDigest(view.days, "all").count, 3);
  assert.deepEqual(filterDigest(view.days, "need_check").days[0].groups.map((g) => g.head.id), ["other"]);
  // 沒有符合事件的日期不顯示
  const onlyFixed = buildDigestView(latestOf([ev("f", {}, { relation: "fixed" })]), NOW, DAILY, new Set());
  assert.deepEqual(filterDigest(onlyFixed.days, "affected"), { days: [], count: 0 });
  assert.equal(filterDigest(onlyFixed.days, "all").count, 1);
});

test("自我參照與循環的新進度不會消失，改為獨立卡片並記錄資料狀態", () => {
  const self = ev("self", { is_update_of: "self" });
  const a = ev("cyc-a", { is_update_of: "cyc-b" });
  const b = ev("cyc-b", { is_update_of: "cyc-a" });
  const view = buildDigestView(latestOf([self, a, b]), NOW, DAILY, new Set());
  assert.equal(view.counts.total, 3);
  const heads = view.days.flatMap((d) => d.groups.map((g) => g.head));
  assert.deepEqual(heads.map((h) => h.id).sort(), ["cyc-a", "cyc-b", "self"]);
  assert.ok(heads.every((h) => h.standaloneText === "新進度的關聯有誤，獨立顯示"));
  assert.ok(view.issues.some((t) => t.includes("3 件事件的新進度關聯有誤")));
});

test("讀取時窗口清理：D-29 保留、D-30 移除、未來排除；原事件過期時子事件提升並重算計數；不刷新時間、不改 latest", () => {
  const parent = ev("old-parent", { first_seen: "2026-10-12" }, { relation: "affected", max_level: "high" });   // D-30
  const child = ev("new-child", { first_seen: "2026-11-01", is_update_of: "old-parent" }, { relation: "need_check" });
  const edge = ev("edge", { first_seen: "2026-10-13" });                                                       // D-29
  const future = ev("future", { first_seen: "2026-11-12" });
  const latest = latestOf([parent, child, edge, future], {
    data_issues: [
      { code: "capacity", impact: "2026-10-12 收錄的事件超過容量上限，省略 4 件", omitted: 4, date: "2026-10-12" },
      { code: "capacity", impact: "2026-11-01 收錄的事件超過容量上限，省略 2 件", omitted: 2, date: "2026-11-01" },
      { code: "capacity", impact: "2026-11-10 收錄的事件超過容量上限，省略 3 件", omitted: 3, date: "2026-11-10" },
      { code: "pending_assessment", impact: "1 件事件尚待完整評估，暫不列入整理", omitted: 1, date: null },
    ],
  });
  // 原事件與子事件在 latest 中同一群組
  assert.equal(latest.days.find((d) => d.date === "2026-10-12")?.events[0].updates?.[0].id, "new-child");
  const before = structuredClone(latest);

  const view = buildDigestView(latest, NOW, DAILY, new Set());
  assert.deepEqual(latest, before);
  assert.equal(view.updated_at, "2026-11-11T00:20:00Z");
  assert.equal(view.next_update_at, "2026-11-12T00:00:00Z");
  assert.equal(view.updatedText, fmtTime("2026-11-11T00:20:00Z"));
  assert.deepEqual(view.days.map((d) => d.date), ["2026-11-01", "2026-10-13"]);
  const promoted = view.days[0].groups[0].head;
  assert.equal(promoted.id, "new-child");
  assert.equal(promoted.standaloneText, "較早事件的新進度");
  assert.ok(!JSON.stringify(view).includes("old-parent"));
  assert.ok(!JSON.stringify(view).includes("事件 old-parent"));
  assert.deepEqual(view.counts, { total: 2, affected: 0, need_check: 1, not_affected: 1, fixed: 0 });
  // 容量省略只計窗口內的日期；其他資料狀態照常顯示
  assert.equal(view.capacityOmitted, 5);
  assert.ok(view.issues.includes("1 件事件尚待完整評估，暫不列入整理"));
  assert.ok(view.issues.some((t) => t.includes("收錄日期晚於今天")));

  // 跨日：同一份 latest 隔天再讀，D-29 的事件也到期
  const tomorrow = pruneForView(latest, new Date("2026-11-11T16:00:00Z"));
  assert.deepEqual(tomorrow.days.map((d) => d.date), ["2026-11-12", "2026-11-01"]);
  assert.equal(tomorrow.counts.total, 2);
});

test("明細連結：讀取時查驗目前 daily；明細消失時不給連結；不同 run 附註「明細為另一份每日評估」", () => {
  const e = ev("evt-a", {}, { run_id: "run-1" });
  const latest = latestOf([e]);
  const same = detailLink(e, DAILY, new Set(["evt-a"]));
  assert.equal(same?.href, "/intel/evt-a");
  assert.equal(same?.otherRun, false);
  assert.equal(same?.note, null);   // 同一次評估：不重複標示評估時間

  // latest 未更新，daily 被取代：明細仍在但屬於另一次評估
  const replaced: DailyInfo = { run_id: "run-2", as_of: "2026-11-12T00:00:00Z", generated_at: "2026-11-12T00:15:00Z", daily_intel_status: "ok" };
  const other = buildDigestView(latest, NOW, replaced, new Set(["evt-a"])).days[0].groups[0].head;
  assert.equal(other.detail?.otherRun, true);
  assert.equal(other.detail?.evaluatedAt, "2026-11-12T00:00:00Z");
  assert.ok(other.detail?.note?.startsWith("明細為另一份每日評估"));
  assert.ok(other.detail?.note?.includes(fmtTime("2026-11-12T00:00:00Z")));
  assert.equal(other.evaluatedText, `上次評估於 ${fmtTime("2026-11-11T00:00:00Z")}`);   // 快照時間不變，且不宣稱本次重新確認
  assert.equal(buildDigestView(latest, NOW, DAILY, new Set()).days[0].groups[0].head.evaluatedText, `評估於 ${fmtTime("2026-11-11T00:00:00Z")}`);
  assert.ok(buildDigestView(latest, NOW, null, new Set()).days[0].groups[0].head.evaluatedText.startsWith("上次評估於"));

  // daily 被取代且明細已移除：退回保存的快照（無連結，結論與系統仍在）
  const gone = buildDigestView(latest, NOW, replaced, new Set()).days[0].groups[0].head;
  assert.equal(gone.detail, null);
  assert.equal(gone.conclusion, "沒有受影響的項目。");
  // 讀不到 daily：不給連結
  assert.equal(buildDigestView(latest, NOW, null, new Set(["evt-a"])).days[0].groups[0].head.detail, null);
  // ID 一律 encodeURIComponent
  assert.equal(detailLink(ev("a b"), DAILY, new Set(["a b"]))?.href, "/intel/a%20b");
});

test("新聞情資提示採最新 daily：failed／skipped／replay／未知；快照為 ok 也照最新 daily；歷史新聞仍保留", () => {
  const when = fmtTime(DAILY.generated_at);
  assert.equal(newsNotice(DAILY), null);
  assert.equal(newsNotice({ ...DAILY, daily_intel_status: "failed" })?.text, `${NEWS_FAILED_TEXT}（${when} 的每日評估）`);
  assert.equal(newsNotice({ ...DAILY, daily_intel_status: "skipped" })?.text, `${NEWS_FAILED_TEXT}（${when} 的每日評估）`);
  assert.ok(newsNotice({ ...DAILY, daily_intel_status: "replay" })?.text.startsWith("重播資料"));
  assert.equal(newsNotice(null)?.text, NEWS_UNKNOWN_TEXT);
  assert.equal(newsNotice({ ...DAILY, daily_intel_status: "weird" })?.text, NEWS_UNKNOWN_TEXT);

  const latest = latestOf([ev("news-1", { kind: "live" }), ev("arch-1", { kind: "archive" }), ev("adv-1", { kind: "advisory" })]);
  assert.equal(latest.daily_intel_status, "ok");
  const view = buildDigestView(latest, NOW, { ...DAILY, run_id: "run-2", daily_intel_status: "failed" }, new Set());
  assert.equal(view.news?.kind, "news_failed");
  const kinds = view.days.flatMap((d) => d.groups.map((g) => g.head.kindText)).sort();
  assert.deepEqual(kinds, ["公告", "收錄事件", "真實報導"]);
  // 快照為 failed 但最新 daily 已 ok：不顯示提示
  assert.equal(buildDigestView({ ...latest, daily_intel_status: "failed" }, NOW, DAILY, new Set()).news, null);
});

test("卡片：同名系統合併、不顯示內部 ID、截斷提示、事件日期未提供、歷史評估與結論更新時間", () => {
  const impacts = [
    { asset_id: "nas-office-01", asset_label: "辦公室 NAS", verdict: "affected" as const, level: "medium" as const },
    { asset_id: "nas-office-01", asset_label: "辦公室 NAS", verdict: "affected" as const, level: "high" as const },
    { asset_id: "nas-office-01", asset_label: "辦公室 NAS", verdict: "affected" as const, level: null },
    { asset_id: "storefront", asset_label: "商店網站", verdict: "need_check" as const, level: null },
  ];
  const merged = mergeImpacts(impacts);
  assert.deepEqual(merged.map((m) => [m.label, m.count, m.level, m.verdictText]), [["辦公室 NAS", 3, "high", "受影響"], ["商店網站", 1, null, "需確認"]]);

  const e = ev("evt-nas", { event_date: null }, {
    run_id: "run-0", evaluated_at: "2026-11-10T00:00:00Z", relation: "affected", max_level: "high", affected_count: 7,
    impacts, impacts_total: 25, impacts_truncated: true, relation_changed_at: "2026-11-10T00:00:00Z",
  });
  const c = buildDigestView(latestOf([e]), NOW, DAILY, new Set()).days[0].groups[0].head;
  assert.equal(c.eventDate, "未提供");
  assert.equal(c.affectedCount, 7);                // 不由合併或截斷結果重算
  assert.equal(c.impactsNote, "僅列前 4 項，共 25 項");
  assert.equal(c.evaluatedText, `上次評估於 ${fmtTime("2026-11-10T00:00:00Z")}`);
  assert.equal(c.relationChangedText, `結論更新於 ${fmtTime("2026-11-10T00:00:00Z")}`);
  assert.equal(c.relationText, "受影響");
  assert.equal(c.levelText, "高");
  const shown = JSON.stringify({ ...c, id: undefined, detail: undefined });
  assert.ok(!shown.includes("nas-office-01") && !shown.includes("storefront") && !shown.includes("run-0"));
  // 非 http(s) 來源不當作連結，但保留標題與網域
  const bad = buildDigestView(latestOf([ev("evt-x", { sources: [{ title: "t", domain: "x.com", url: "javascript:alert(1)", verified: false }] })]),
    NOW, DAILY, new Set()).days[0].groups[0].head;
  assert.deepEqual(bad.sources, [{ title: "t", domain: "x.com", href: null, verified: false }]);
});

test("isDigestLatest：必要欄位與時間格式不合格時不採用", () => {
  const ok = latestOf([ev("a"), ev("b", { is_update_of: "a" })]);
  assert.equal(isDigestLatest(ok), true);
  assert.equal(isDigestLatest({ ...ok, schema_version: 2 }), false);
  assert.equal(isDigestLatest({ ...ok, updated_at: "2026-11-11" }), false);
  assert.equal(isDigestLatest({ ...ok, days: [{ date: "2026-11-11", count: 1, events: [{ id: "x" }] }] }), false);
  const badRel = structuredClone(ok);
  (badRel.days[0].events[0].assessment as { relation: string }).relation = "open";
  assert.equal(isDigestLatest(badRel), false);
  assert.equal(isDigestLatest(null), false);
});

test("getDigestView：整理不存在／格式不合；daily 被取代後重新查驗 index 與明細檔", async () => {
  const root = mkdtempSync(path.join(tmpdir(), "digest-view-"));
  const data = path.join(root, "public", "data");
  const cwd = process.cwd();
  try {
    mkdirSync(path.join(data, "daily", "intel"), { recursive: true });
    process.chdir(root);
    const { getDigestView, getDigest } = await import("./data.ts");
    assert.deepEqual(await getDigestView(NOW), { status: "missing" });
    assert.equal(await getDigest(), null);

    mkdirSync(path.join(data, "digest"));
    writeFileSync(path.join(data, "digest", "latest.json"), "{ 不是 JSON");
    assert.deepEqual(await getDigestView(NOW), { status: "invalid" });

    const latest = latestOf([ev("evt-a", {}, { run_id: "run-1" }), ev("evt-b", {}, { run_id: "run-1" })]);
    writeFileSync(path.join(data, "digest", "latest.json"), JSON.stringify(latest));
    // 沒有 daily 報告：狀態未知、沒有明細連結
    let page = await getDigestView(NOW);
    assert.equal(page.status, "ok");
    if (page.status !== "ok") return;
    assert.equal(page.view.news?.text, NEWS_UNKNOWN_TEXT);
    assert.ok(page.view.days[0].groups.every((g) => g.head.detail === null));

    // 目前 daily（另一次評估）：evt-a 有列且有檔、evt-b 有列但明細檔不存在 → 只有 evt-a 有連結
    writeFileSync(path.join(data, "daily", "report.json"), JSON.stringify({
      run_id: "run-2", as_of: "2026-11-12T00:00:00Z", generated_at: "2026-11-12T00:15:00Z", daily_intel_status: "replay" }));
    writeFileSync(path.join(data, "daily", "intel", "index.json"), JSON.stringify([{ id: "evt-a" }, { id: "evt-b" }]));
    writeFileSync(path.join(data, "daily", "intel", "evt-a.json"), "{}");
    page = await getDigestView(NOW);
    assert.equal(page.status, "ok");
    if (page.status !== "ok") return;
    const byId = new Map(page.view.days.flatMap((d) => d.groups.map((g) => [g.head.id, g.head] as const)));
    assert.equal(byId.get("evt-a")?.detail?.otherRun, true);
    assert.equal(byId.get("evt-b")?.detail, null);
    assert.equal(page.view.news?.kind, "replay");
    assert.equal(page.view.updated_at, latest.updated_at);
  } finally {
    process.chdir(cwd);
    rmSync(root, { recursive: true, force: true });
  }
});

// ── 查核建議（specs/check-hints R5.2、R5.4、R6.5） ─────────────────────────

test("parseSuggestions：缺欄位、null、字串、錯誤項目都視為空陣列或略過；超量截斷", () => {
  for (const raw of [undefined, null, "委外廠商被入侵", 3, {}, { text: "x" }]) assert.deepEqual(parseSuggestions(raw), [], String(raw));
  assert.deepEqual(parseSuggestions([
    null, "字串", 1, [], { text: "" }, { text: "   " }, { text: 5, systems: ["寄信服務"] }, { systems: ["寄信服務"] },
    { text: "沒有系統欄位" },
    { text: "系統不是陣列", systems: "寄信服務" },
    { text: "只留字串系統", systems: ["寄信服務", 1, null, { label: "x" }, "商店網站"] },
  ]), [
    { text: "沒有系統欄位", systems: [] },
    { text: "系統不是陣列", systems: [] },
    { text: "只留字串系統", systems: ["寄信服務", "商店網站"] },
  ]);
  const many = parseSuggestions([
    { text: "長".repeat(400), systems: Array.from({ length: 8 }, (_, i) => `系統${i}`) },
    { text: "第二條" }, { text: "第三條" }, { text: "第四條" }, { text: "第五條" },
  ]);
  assert.equal(many.length, 3);
  assert.equal(Array.from(many[0].text).length, 300);
  assert.deepEqual(many[0].systems, ["系統0", "系統1", "系統2", "系統3", "系統4"]);
  assert.deepEqual(many.map((s) => s.text.slice(0, 3)), ["長長長", "第二條", "第三條"]);
  // 字數以 Unicode 字元計算，不切開代理字元對
  assert.equal(parseSuggestions([{ text: "𠀋".repeat(301) }])[0].text, "𠀋".repeat(300));
});

test("卡片：父事件與新進度都帶出查核建議；沒有建議的舊資料為空陣列", () => {
  const s1 = [{ text: "委外廠商被入侵，連帶外流我們交給它的資料；先查：寄信服務", systems: ["寄信服務"] }];
  const s2 = [{ text: "資料庫或管理工具可能可以被直接連上", systems: [] }];
  const parent = ev("evt-p", {}, { relation: "need_check", suggestions: s1 });
  const child = ev("evt-c", { is_update_of: "evt-p" }, { relation: "need_check", suggestions: s2 });
  const old = ev("evt-old", {}, { relation: "need_check" });                  // 0.12.0 之前的資料：沒有 suggestions
  const view = buildDigestView(latestOf([parent, child, old]), NOW, DAILY, new Set());
  const groups = view.days[0].groups;
  const g = groups.find((x) => x.head.id === "evt-p")!;
  assert.deepEqual(g.head.suggestions, s1);
  assert.deepEqual(g.updates.map((u) => [u.id, u.suggestions]), [["evt-c", s2]]);
  assert.deepEqual(groups.find((x) => x.head.id === "evt-old")!.head.suggestions, []);
});

test("suggestions 格式錯誤不讓整份整理無效：isDigestLatest 仍通過，該卡片的建議為空陣列", () => {
  for (const bad of [null, "字串", { text: "x" }, [1, "x", { text: 2 }], 42]) {
    const latest = latestOf([ev("evt-a", {}, { relation: "need_check", suggestions: bad }),
      ev("evt-b", { is_update_of: "evt-a" }, { relation: "need_check", suggestions: [null, { text: "保留這條", systems: "x" }] })]);
    assert.equal(isDigestLatest(latest), true, JSON.stringify(bad));
    const g = buildDigestView(latest, NOW, DAILY, new Set()).days[0].groups[0];
    assert.deepEqual(g.head.suggestions, []);
    assert.deepEqual(g.updates[0].suggestions, [{ text: "保留這條", systems: [] }]);
  }
});
