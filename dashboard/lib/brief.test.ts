import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import type { Report, Risk, Solution } from "./data";
import {
  DECISION_SEP, assetLabel, factKey, groupDecisions, ifIgnored, linkSummary, openRisks, riskBrand, riskDetail, riskHeadline,
  riskTags, splitDecision, suggestedDeadline, summaryFacts, topRisks, type Fact, type FactKey, type SummaryPart,
} from "./brief.ts";

const risk = (over: Partial<Risk>): Risk => ({
  id: "x", asset_id: "asset", title: "標題", category: "config", level: "high", score: 7, raw_score: 7, score_level: "high",
  level_reason: "依分數", breakdown: [], attack_path: null, matched_events: [], deadline_hours: 24, solution: null, status: "open",
  first_seen: "2026-11-09T01:00:00Z", last_evaluated: "2026-11-10T01:00:00Z", ...over,
});

const solution = (over: Partial<Solution> = {}): Solution => ({
  risk_id: "x", temporary: "先關閉對外入口", permanent: "升級到已修補的版本", options: [], suggested_owner: "平台工程團隊",
  verify: "重新掃描", source: "live", ...over,
});

type Ev = Report["events"][number];
const ev = (id: string, over: Partial<Ev> = {}): Ev =>
  ({ id, kind: "archive", title: `事件 ${id}`, affected_count: 1, max_level: "high", status: "open", demo: false, ...over });

const LABELS = { "internal-tool": "內部營運工具", "order-db-prod": "正式訂單資料庫", "marketing-site": "行銷官網", internet: "網際網路" };

const keysOf = (parts: SummaryPart[]) => parts.filter((p) => typeof p !== "string").map((p) => (p as { key: FactKey | null }).key);

const ALL_KEYS: FactKey[] = ["high", "medium", "low", "chained", "eol", "shadow_it", "checked", "affected", "real_checked", "real_affected"];
/** 指定各指標的數值（未指定的為 0），用來單獨測數字配對。 */
const factsWith = (counts: Partial<Record<FactKey, number>>): Record<FactKey, Fact> =>
  Object.fromEntries(ALL_KEYS.map((k): [FactKey, Fact] => [k, { key: k, label: k, count: counts[k] ?? 0, risks: [], events: [] }])) as unknown as Record<FactKey, Fact>;

test("groupDecisions：4 條納管合併成一條，下架問題仍在前；只有 1 條不合併；重複呼叫結果不變", () => {
  const raw = ["是否暫時下架 marketing-site（已停止支援且沒有修補版本）", "internal-tool 要納管還是除役",
    "marketing-site 要納管還是除役", "nas-office-01 要納管還是除役", "saas-quicksite-builder 要納管還是除役"];
  const merged = groupDecisions(raw);
  assert.deepEqual(merged, ["是否暫時下架 marketing-site（已停止支援且沒有修補版本）",
    "4 個未登記的系統要納管還是除役：internal-tool、marketing-site、nas-office-01、saas-quicksite-builder"]);
  assert.deepEqual(groupDecisions(merged), merged);
  assert.deepEqual(groupDecisions(["a 要納管還是除役", "其他"]), ["a 要納管還是除役", "其他"]);
  assert.deepEqual(groupDecisions([]), []);
});

test("openRisks／topRisks：排除已修復與低風險，依等級、分數排序，同分維持原順序", () => {
  const risks = [risk({ id: "m", level: "medium", score: 6 }), risk({ id: "h1", score: 9 }), risk({ id: "f", score: 11, status: "fixed" }),
    risk({ id: "h2", score: 11 }), risk({ id: "h3", score: 9 }), risk({ id: "l", level: "low", score: 2 })];
  assert.deepEqual(openRisks({ risks }).map((r) => r.id), ["h2", "h1", "h3", "m"]);
  assert.deepEqual(topRisks({ risks }, 2).map((r) => r.id), ["h2", "h1"]);
});

test("assetLabel：有白話名稱用名稱；沒有名稱、名稱表不存在（舊報告）或名稱為空時回傳 ID；不讀到物件原型", () => {
  assert.equal(assetLabel(LABELS, "internal-tool"), "內部營運工具");
  assert.equal(assetLabel(LABELS, "gitlab"), "gitlab");
  assert.equal(assetLabel(undefined, "internal-tool"), "internal-tool");
  assert.equal(assetLabel({ a: " " }, "a"), "a");
  assert.equal(assetLabel({}, "constructor"), "constructor");
});

test("riskHeadline 情況一：有白話標題就用它，原始技術標題放 detail（所有類別）", () => {
  const vuln = risk({ category: "vuln", asset_id: "internal-tool", title: "opsbuilder 1.88：帳號接管漏洞",
    solution: solution({ plain_title: "內部營運工具有帳號被盜用的漏洞，可能造成訂單與會員資料外洩" }) });
  assert.deepEqual(riskHeadline(vuln, LABELS),
    { headline: "內部營運工具有帳號被盜用的漏洞，可能造成訂單與會員資料外洩", detail: "opsbuilder 1.88：帳號接管漏洞" });
  const secret = risk({ category: "secret", asset_id: "brand-app", title: "Git 中不得有正式環境金鑰：brand-app",
    solution: solution({ plain_title: "品牌 App 的系統密碼寫在程式碼裡" }) });
  assert.deepEqual(riskHeadline(secret), { headline: "品牌 App 的系統密碼寫在程式碼裡", detail: "Git 中不得有正式環境金鑰：brand-app" });
  // 空白的白話標題視為沒有，退回舊寫法
  assert.deepEqual(riskHeadline(risk({ title: "原標題", solution: solution({ plain_title: "  " }) })), { headline: "原標題", detail: null });
});

test("riskHeadline 情況二：沒有白話標題的漏洞改寫成「{系統} 有可被入侵的漏洞」，保留原標題；已停止支援加註", () => {
  const eol = risk({ category: "vuln", asset_id: "marketing-site", title: "php 8.1.27：PHP2Shell",
    breakdown: [{ factor: "已停止支援", points: 1, reason: "無修補可用" }] });
  // 舊報告（沒有名稱表）與現在的寫法完全相同
  assert.deepEqual(riskHeadline(eol), { headline: "marketing-site 有可被入侵的漏洞，且已停止支援", detail: "php 8.1.27：PHP2Shell" });
  assert.deepEqual(riskHeadline(eol, LABELS), { headline: "行銷官網 有可被入侵的漏洞，且已停止支援", detail: "php 8.1.27：PHP2Shell" });
  assert.deepEqual(riskHeadline(risk({ category: "vuln", asset_id: "internal-tool", title: "t" }), LABELS),
    { headline: "內部營運工具 有可被入侵的漏洞", detail: "t" });
});

test("riskHeadline 情況三：沒有白話標題的其他類別用原標題，系統代號換成白話名稱（只換完整的 ID）", () => {
  const r = risk({ asset_id: "internal-tool", title: "內部工具不得對外開放：internal-tool" });
  assert.deepEqual(riskHeadline(r), { headline: "內部工具不得對外開放：internal-tool", detail: null });
  assert.deepEqual(riskHeadline(r, LABELS), { headline: "內部工具不得對外開放：內部營運工具", detail: null });
  const partial = risk({ asset_id: "gitlab", title: "權限過大：gitlab（gitlab-read-token、mygitlab）" });
  assert.deepEqual(riskHeadline(partial, { gitlab: "程式碼管理平台" }),
    { headline: "權限過大：程式碼管理平台（gitlab-read-token、mygitlab）", detail: null });
  // 名稱裡的 $ 不會被當成取代語法
  assert.equal(riskHeadline(risk({ asset_id: "a1", title: "x：a1" }), { a1: "$& 系統" }).headline, "x：$& 系統");
});

test("ifIgnored：有就回傳（去前後空白），舊報告或空字串為 null", () => {
  assert.equal(ifIgnored(risk({ solution: solution({ if_ignored: " 外人可以冒用帳號登入。 " }) })), "外人可以冒用帳號登入。");
  assert.equal(ifIgnored(risk({ solution: solution() })), null);
  assert.equal(ifIgnored(risk({ solution: solution({ if_ignored: "" }) })), null);
  assert.equal(ifIgnored(risk({})), null);
});

test("riskBrand：依 matched_events 順序取第一個有 brand 的事件；舊報告、空字串、找不到的事件都不算", () => {
  const events = [ev("adv", { kind: "advisory" }), ev("e91", { brand: "91APP" }), ev("syn", { brand: "Synology NAS" }), ev("blank", { brand: " " })];
  assert.equal(riskBrand(risk({ matched_events: ["missing", "adv", "blank", "syn", "e91"] }), events), "Synology NAS");
  assert.equal(riskBrand(risk({ matched_events: ["e91", "syn"] }), events), "91APP");
  assert.equal(riskBrand(risk({ matched_events: ["adv", "blank"] }), events), null);
  assert.equal(riskBrand(risk({ matched_events: ["e91"] }), [ev("e91")]), null);          // 舊報告沒有 brand 欄位
  assert.equal(riskBrand(risk({}), events), null);
});

test("riskTags：每一列的條件與順序（因子、品牌、事件種類、攻擊路徑、對外暴露）", () => {
  const f = (factor: string) => ({ factor, points: 1, reason: "" });
  const events = [ev("adv", { kind: "advisory" }), ev("demo-adv", { kind: "advisory", demo: true }), ev("arc"), ev("e91", { brand: "91APP" })];
  // 全部條件，無品牌、有非示範公告
  const all = risk({ breakdown: [f("對外暴露"), f("已停止支援"), f("已遭實際利用")], matched_events: ["arc", "adv"],
    attack_path: ["internet", "internal-tool", "order-db-prod"] });
  assert.deepEqual(riskTags(all, { labels: LABELS, events }),
    ["已經有人在用這個漏洞攻擊", "原廠已不再修補", "已有官方漏洞公告", "可一路闖到正式訂單資料庫", "外人連得到"]);
  // 有品牌：不加事件標籤（標題已有品牌）；品牌可由 events 算出，也可直接傳入
  assert.deepEqual(riskTags(risk({ matched_events: ["e91", "adv"] }), { events }), []);
  assert.deepEqual(riskTags(risk({ matched_events: ["adv"] }), { events, brand: "91APP" }), []);
  // 只有示範公告或其他事件 → 外部已有相關事件
  assert.deepEqual(riskTags(risk({ matched_events: ["demo-adv"] }), { events }), ["外部已有相關事件"]);
  assert.deepEqual(riskTags(risk({ matched_events: ["arc"] }), { events }), ["外部已有相關事件"]);
  // 沒有事件清單時只知道有相關事件
  assert.deepEqual(riskTags(risk({ matched_events: ["adv"] })), ["外部已有相關事件"]);
  // 沒有名稱表（舊報告）時終點用 ID；路徑只有一個節點不算
  assert.deepEqual(riskTags(risk({ attack_path: ["internet", "order-db-prod"] })), ["可一路闖到 order-db-prod"]);
  assert.deepEqual(riskTags(risk({ attack_path: ["internal-tool"] })), []);
  assert.deepEqual(riskTags(risk({})), []);
});

test("riskDetail：漏洞原因、攻擊路徑白話名稱（沒有路徑為 null）、相關事件（示範標示）、根本解法", () => {
  const events = [ev("e91", { title: "91APP 訂單資料庫遭入侵" }), ev("adv", { kind: "advisory", title: "示範公告：OpsBuilder", demo: true }),
    ev("d1", { kind: "demo", title: "示範事件" })];
  const r = risk({ title: "opsbuilder 1.88：帳號接管", explanation: "CVSS 9.8，已被實際用於攻擊", attack_path: ["internet", "internal-tool", "gitlab"],
    matched_events: ["e91", "missing", "adv", "d1"], solution: solution({ permanent: "升級到 1.90 以上" }) });
  assert.deepEqual(riskDetail(r, { events, asset_labels: LABELS }), {
    cause: ["opsbuilder 1.88：帳號接管", "CVSS 9.8，已被實際用於攻擊"],
    path: ["網際網路", "內部營運工具", "gitlab"],
    events: [{ title: "91APP 訂單資料庫遭入侵", demo: false }, { title: "示範公告：OpsBuilder", demo: true }, { title: "示範事件", demo: true }],
    permanent: "升級到 1.90 以上",
  });
  assert.deepEqual(riskDetail(risk({ title: "t", explanation: null, attack_path: ["internal-tool"] }), { events: [] }),
    { cause: ["t"], path: null, events: [], permanent: null });
});

test("splitDecision：以第一個「——不決定的話：」切開；舊報告沒有分隔字串時整句當問題", () => {
  assert.equal(DECISION_SEP, "——不決定的話：");
  assert.deepEqual(splitDecision("是否先把行銷官網暫時關掉？——不決定的話：漏洞會一直開著。"),
    { question: "是否先把行銷官網暫時關掉？", ifNot: "漏洞會一直開著。" });
  assert.deepEqual(splitDecision("問題？——不決定的話：後果——不決定的話：其他"), { question: "問題？", ifNot: "後果——不決定的話：其他" });
  assert.deepEqual(splitDecision("是否暫時下架 marketing-site（已停止支援且沒有修補版本）"),
    { question: "是否暫時下架 marketing-site（已停止支援且沒有修補版本）", ifNot: null });
  assert.deepEqual(splitDecision("問題？——不決定的話： "), { question: "問題？", ifNot: null });
  // 先合併舊句型再切
  assert.deepEqual(groupDecisions(["a 要納管還是除役", "b 要納管還是除役"]).map(splitDecision),
    [{ question: "2 個未登記的系統要納管還是除役：a、b", ifNot: null }]);
});

test("suggestedDeadline＝第一次發現＋時限", () => {
  assert.equal(suggestedDeadline(risk({}))?.toISOString(), "2026-11-10T01:00:00.000Z");
  assert.equal(suggestedDeadline(risk({ first_seen: "bad" })), null);
});

test("summaryFacts／linkSummary：摘要數字對應到程式結果；同值數字依前後的字區分；對不上的數字標 null", () => {
  const risks = [risk({ id: "a", attack_path: ["internet", "x", "db"] }), risk({ id: "b", category: "shadow_it", asset_id: "nas" }),
    risk({ id: "c", level: "low", score: 2 }), risk({ id: "d", level: "low", score: 1 })];
  const events = [{ id: "e1", kind: "archive", title: "一", affected_count: 1, max_level: "high" as const, status: "open", demo: false },
                  { id: "e2", kind: "live", title: "二", affected_count: 0, max_level: null, status: "not_affected", demo: false }];
  const facts = summaryFacts({ risks, events, intel_summary: { checked: 2, affected: 1, by_kind: {} } });
  assert.equal(facts.high.count, 2);
  assert.deepEqual(facts.chained.risks.map((r) => r.id), ["a"]);
  assert.equal(facts.shadow_it.count, 1);
  const parts = linkSummary("今天 2 個高風險、2 個低風險；檢查 2 件外部資安事件，其中 1 件與我們有關，另有 9 個問題。", facts);
  assert.deepEqual(keysOf(parts), ["high", "low", "checked", "affected", null]);
  assert.equal(parts.map((p) => (typeof p === "string" ? p : p.text)).join(""), "今天 2 個高風險、2 個低風險；檢查 2 件外部資安事件，其中 1 件與我們有關，另有 9 個問題。");
});

test("linkSummary：新版範本（design §5.1）每個數字都對到正確指標", () => {
  const facts = factsWith({ high: 20, medium: 22, chained: 5, eol: 1, shadow_it: 4, checked: 19, affected: 14, real_checked: 13, real_affected: 9 });
  const cases: [string, (FactKey | null)[]][] = [
    ["紅燈：有 20 個高風險、22 個中風險的問題還沒處理。", ["high", "medium"]],
    ["最急的是 5 個問題可以被駭客串起來一路闖進去，最後可能拿到訂單資料、會員個資；另有 1 個對外系統的軟體原廠已不再修補。", ["chained", "eol"]],
    ["最急的是 1 個對外系統的軟體原廠已不再修補。", ["eol"]],
    ["最急的是 20 個高風險要在 24 小時內處理。", ["high"]],
    ["今天看了 19 件外面發生的資安事件，其中 14 件的問題我們也有。", ["checked", "affected"]],
    ["這 4 個沒登記的系統（內部營運工具、行銷官網、辦公室 NAS、未登記的架站服務），要正式列管（指定負責人、定期更新），還是確認沒人用後關掉？", ["shadow_it"]],
    ["今天看了 13 件真實事件，其中 9 件真實事件與我們有關。", ["real_checked", "real_affected"]],
  ];
  for (const [text, want] of cases) assert.deepEqual(keysOf(linkSummary(text, facts)), want, text);
  // 決策的後果部分沒有數字；切開後問題與後果各自配對
  const d = splitDecision("這 4 個沒登記的系統（內部營運工具），要正式列管，還是確認沒人用後關掉？——不決定的話：負責人沒確認前，出事時也可能沒人發現。");
  assert.deepEqual(keysOf(linkSummary(d.question, facts)), ["shadow_it"]);
  assert.deepEqual(keysOf(linkSummary(d.ifNot ?? "", facts)), []);
});

test("linkSummary：指標錯置（「高風險 18 個與中風險 14 個」）兩個數字都標 null；數值不符也標 null", () => {
  const facts = factsWith({ high: 14, medium: 18 });
  assert.equal(factKey("高風險 18 個與中風險 14 個", 0), null, "前段高風險、後段中風險 → 歧義");
  assert.equal(factKey("高風險 18 個與中風險 14 個", 1), "medium");
  assert.deepEqual(keysOf(linkSummary("高風險 18 個與中風險 14 個", facts)), [null, null]);
  assert.deepEqual(keysOf(linkSummary("有 18 個高風險。", facts)), [null], "18 對到高風險，但高風險是 14");
  assert.deepEqual(keysOf(linkSummary("有 14 個高風險、18 個中風險。", facts)), ["high", "medium"]);
  // 後段不跨到下一個數字：「18 個」的後段只到「14」之前
  assert.equal(factKey("18 個與 14 個中風險", 0), null);
  assert.equal(factKey("18 個與 14 個中風險", 1), "medium");
});

test("factKey：前後分別對到一般與「真實」限定的同類指標時取限定的，不算歧義；不同類仍是歧義", () => {
  assert.equal(factKey("今天檢查 13 件真實事件", 0), "real_checked");
  assert.equal(factKey("其中有關的 3 件真實事件", 0), null);                     // 前段 affected、後段 real_checked：不同類 → 歧義
  assert.equal(factKey("今天檢查 13 件與我們有關", 0), null);                    // checked 與 affected 不同類 → 歧義
  assert.deepEqual(keysOf(linkSummary("今天檢查 13 件真實事件。", factsWith({ real_checked: 13 }))), ["real_checked"]);
});

test("riskTags：舊報告沒有名稱表時，系統 ID 前補空格", () => {
  const r = { id: "x", asset_id: "a", title: "t", category: "secret", level: "high", score: 9, raw_score: 9, score_level: "high",
    level_reason: "", breakdown: [], attack_path: ["a", "order-db-prod"], matched_events: [], deadline_hours: 24, solution: null,
    status: "open", first_seen: "2026-11-13T00:00:00Z", last_evaluated: "2026-11-13T00:00:00Z" } as Risk;
  assert.ok(riskTags(r).includes("可一路闖到 order-db-prod"));
  assert.ok(riskTags(r, { labels: { "order-db-prod": "正式訂單資料庫" } }).includes("可一路闖到正式訂單資料庫"));
});

test("linkSummary：前後都找不到指標的舊句型，只有一個指標等於此數值才用它", () => {
  assert.deepEqual(keysOf(linkSummary("疑似已發生外洩：3 個品牌回報疑似外洩詐騙", factsWith({ high: 3 }))), ["high"]);
  assert.deepEqual(keysOf(linkSummary("疑似已發生外洩：3 個品牌回報疑似外洩詐騙", factsWith({ high: 3, checked: 3 }))), [null]);
  assert.deepEqual(keysOf(linkSummary("另有 9 個問題", factsWith({}))), [null]);
});

// ---------------------------------------------------------------- 與後端、已發布報告的一致性

const ROOT = new URL("../../", import.meta.url);         // repo 根目錄（dashboard 的上一層）

test("DECISION_SEP 與 Python agents/tools/templates.py 的字串相同", () => {
  const py = readFileSync(new URL("agents/tools/templates.py", ROOT), "utf8");
  const m = /^DECISION_SEP\s*(?::\s*\w+\s*)?=\s*(["'])(.+?)\1/m.exec(py);
  assert.ok(m, "templates.py 應定義 DECISION_SEP");
  assert.equal(m[2], DECISION_SEP);
});

test("lib/fact-words.json 與 rules/fact-words.json 內容相同（網站與 Python 用同一套關鍵字表）", () => {
  const local = JSON.parse(readFileSync(new URL("./fact-words.json", import.meta.url), "utf8"));
  assert.deepEqual(local, JSON.parse(readFileSync(new URL("rules/fact-words.json", ROOT), "utf8")));
});

// 舊規則（v0.13）：數字後面或前面的字依舊表找指標，只在同值的候選中找；都找不到就用同值的第一項
const LEGACY_WORDS: [FactKey, RegExp][] = [
  ["high", /高風險/], ["medium", /中風險/], ["low", /低風險/], ["chained", /入侵路徑|串/],
  ["eol", /停止支援|官方更新|修補/], ["shadow_it", /未登記|納管|除役/],
  ["affected", /與我們有關|有關|命中|受影響/], ["real_affected", /真實.*有關/],
  ["checked", /外部資安事件|外部事件|資安事件|檢查/], ["real_checked", /真實事件/],
];
function legacyKeys(text: string, facts: Record<FactKey, Fact>): (FactKey | null)[] {
  const out: (FactKey | null)[] = [];
  const re = /(\d+)\s*(個|件|項|則|筆)/g;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const n = Number(m[1]);
    const after = text.slice(m.index + m[0].length).split(/[，。；、,;]/)[0];
    const before = text.slice(0, m.index).split(/[，。；、,;]/).pop() ?? "";
    const candidates = (Object.values(facts) as Fact[]).filter((f) => f.count === n).map((f) => f.key);
    const byWord = LEGACY_WORDS.find(([k, w]) => candidates.includes(k) && w.test(after))?.[0]
      ?? LEGACY_WORDS.find(([k, w]) => candidates.includes(k) && w.test(before))?.[0];
    out.push(byWord ?? (candidates.length ? candidates[0] : null));
  }
  return out;
}

// 唯一允許的差異：舊規則連到「數值相同但指標錯誤」的項目、新規則改為 null。有的話逐筆列在這裡（目前沒有）
const ALLOWED_DIFFS: { file: string; text: string; old: (FactKey | null)[]; new: (FactKey | null)[] }[] = [];

test("已發布報告（daily 與各情境）的摘要與決策：新舊規則逐筆比對結果相同，不多出警告", () => {
  const data = new URL("../public/data/", import.meta.url);
  const files = ["daily/report.json",
    ...readdirSync(new URL("scenarios/", data), { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => `scenarios/${d.name}/report.json`)]
    .filter((f) => existsSync(new URL(f, data)));
  assert.ok(files.length >= 2, "至少要比對 daily 與一個情境");
  const diffs: typeof ALLOWED_DIFFS = [];
  let numbers = 0;
  for (const file of files) {
    const report = JSON.parse(readFileSync(new URL(file, data), "utf8")) as Report;
    const facts = summaryFacts(report);
    const texts = [...report.ceo_summary, ...report.decisions,
      ...groupDecisions(report.decisions).flatMap((d) => { const s = splitDecision(d); return s.ifNot ? [s.question, s.ifNot] : [s.question]; })];
    for (const text of texts) {
      const now = keysOf(linkSummary(text, facts));
      const old = legacyKeys(text, facts);
      numbers += now.length;
      if (JSON.stringify(now) !== JSON.stringify(old)) diffs.push({ file, text, old, new: now });
    }
  }
  assert.ok(numbers > 0, "已發布報告應有可比對的數字");
  assert.deepEqual(diffs, ALLOWED_DIFFS);
});
