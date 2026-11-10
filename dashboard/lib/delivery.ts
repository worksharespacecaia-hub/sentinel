// 告警交付（第 7.6 節、第 11.2 節 raiseAlert）：告警與 outbox 已先寫入 Redis，這裡才嘗試外部步驟。
// - 順序：建立或查回 Issue → repository_dispatch（incident.yml）→ LINE（未設定時 skipped）；狀態變更另有 sync 步驟
// - LINE 使用獨立交付狀態：Issue 失敗也照樣推播；推播失敗只記錄、不自動重試（規格第 7.7 節）
// - 每一步有 pending/running/done/failed、attempts、last_error、鎖期限；外部呼叫逾時先查既有 Issue marker／workflow，不盲目重送
// - 外部步驟失敗不撤銷已成立告警；管理者可由 /api/alerts/retry 重試
import {
  commentIssue, createIssue, dispatchIncident, findIncidentRun, findIssueByMarker, GitHubError, hasCommentMarker,
  issueMarker, issuesConfigured, updateIssue,
} from "./github.ts";
import { K, getAlert, patchAlert, type Alert, type DeliveryStep } from "./alertstore.ts";
import { LEVEL_TEXT } from "./labels.ts";
import { pushToAdmins, siteUrl as lineSiteUrl } from "./line.ts";
import { alertMessage } from "./line-messages.ts";
import { acquireLock, releaseLock } from "./security.ts";

const STEP_LOCK_SECONDS = 60;
const ORDER: DeliveryStep[] = ["issue", "dispatch", "line", "sync"];

export function issueLabels(a: Alert): string[] {
  return ["sentinel-alert", `rule:${a.rule_id}`, `level:${a.level}`, `status:${a.status}`, a.simulated ? "simulated" : "real"];
}

export function issueTitle(a: Alert): string {
  return `${a.simulated ? "［模擬］" : ""}${a.light === "red" ? "紅燈" : "黃燈"}｜${a.rule_id} ${a.rule_title}（${a.asset_id}）`;
}

/** Issue 內容：只放去敏摘要；marker 供查回既有 Issue 與 Redis 清空後重建。 */
export function issueBody(a: Alert, siteUrl: string | null): string {
  const meta = { alert_id: a.id, rule_id: a.rule_id, level: a.level, asset_id: a.asset_id, simulated: a.simulated,
                 simulation_id: a.simulation_id, dedup_key: a.dedup_key, created_at: a.created_at };
  return [
    issueMarker(a.id),
    `<!-- sentinel-alert ${JSON.stringify(meta)} -->`,
    "> 虛構環境，非 91APP 或任何公司的實際系統。所有金鑰皆為 DEMO-FAKE 假值。",
    "",
    `## ${issueTitle(a)}`,
    "",
    `- 等級：${LEVEL_TEXT[a.level]}`,
    `- 資產：\`${a.asset_id}\``,
    `- 告警時間：${a.created_at}`,
    `- 對應事件：${a.maps_to_event ?? "—"}`,
    `- 模擬：${a.simulated ? `是（${a.simulation_id}）` : "否"}`,
    `- 摘要：${a.summary}`,
    "",
    "圍堵建議將由 incident 流程以留言補上（只建議、不執行）。",
    "狀態只能由 Sentinel 網站的管理者附理由與證據變更；**關閉此 Issue 不代表告警結案**。",
    siteUrl ? `\n[開啟即時監控](${siteUrl}/live)` : "",
  ].join("\n");
}

function errText(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  return msg.replace(/(gh[pousr]_|github_pat_)[A-Za-z0-9_]+/g, "***").slice(0, 200);
}

function siteUrl(): string | null {
  const u = process.env.SENTINEL_BASE_URL;
  return u && u.startsWith("https://") ? u.replace(/\/$/, "") : null;
}

type StepFn = (a: Alert) => Promise<(x: Alert) => void>;

const STEPS: Record<DeliveryStep, StepFn> = {
  async issue(a) {
    if (!issuesConfigured()) throw new GitHubError("ALERT_ISSUE_TOKEN 或 GH_OWNER／GH_REPO 未設定", true);
    // 曾經嘗試過（可能逾時但已建立）→ 先查 marker
    const existing = a.delivery.issue.attempts > 1 || a.delivery.issue.uncertain ? await findIssueByMarker(a.id) : null;
    const issue = existing ?? (await createIssue(issueTitle(a), issueBody(a, siteUrl()), issueLabels(a)));
    const now = new Date().toISOString();
    return (x) => {
      x.issue_number = issue.number;
      x.issue_url = issue.html_url;
      x.repo = x.repo ?? `${process.env.GH_OWNER}/${process.env.GH_REPO}`;
      x.timeline.issue_created = x.timeline.issue_created ?? now;
    };
  },
  async dispatch(a) {
    if (!a.issue_number) throw new GitHubError("等待 Issue 建立後才派發調查", true);
    if (!process.env.GH_DISPATCH_TOKEN) throw new GitHubError("GH_DISPATCH_TOKEN 未設定", true);
    const prior = a.delivery.dispatch.attempts > 1 || a.delivery.dispatch.uncertain ? await findIncidentRun(a.id) : null;
    if (!prior) await dispatchIncident(a.id, a.asset_id);
    const now = new Date().toISOString();
    return (x) => {
      x.timeline.dispatched = x.timeline.dispatched ?? now;
    };
  },
  async line(a) {
    // 模擬告警只推給第一位管理者（排練用，避免用完額度）；失敗不阻擋 Issue 與調查
    const r = await pushToAdmins([alertMessage(a, lineSiteUrl())], "alert", { firstOnly: a.simulated });
    if (r.state === "failed") throw new Error(r.reason ?? "LINE 推播失敗");
    return (x) => {
      if (r.state === "skipped") x.delivery.line = { ...x.delivery.line, state: "skipped", reason: r.reason };
      else x.delivery.line = { ...x.delivery.line, reason: `已推播給 ${r.recipients} 位管理者` };
    };
  },
  async sync(a) {
    if (!a.issue_number) throw new GitHubError("Issue 尚未建立，狀態同步等待中", true);
    const idx = a.delivery.sync.history_index ?? a.status_history.length - 1;
    const change = a.status_history[idx];
    await updateIssue(a.issue_number, { labels: issueLabels(a), state: a.status === "closed" ? "closed" : "open",
                                        ...(a.status === "closed" ? { state_reason: "completed" } : {}) });
    if (change) {
      const marker = `<!-- sentinel-status: ${a.id}#${idx} -->`;
      if (!(a.delivery.sync.attempts > 1 && (await hasCommentMarker(a.issue_number, marker)))) {
        await commentIssue(a.issue_number, [marker, `### 狀態變更：${change.from} → ${change.to}`, "",
          `- 操作人：${change.actor}`, `- 時間：${change.at}`, `- 理由：${change.reason}`, `- 驗證證據：${change.evidence_url}`].join("\n"));
      }
    }
    return () => {};
  },
};

function needsRun(a: Alert, step: DeliveryStep): boolean {
  const s = a.delivery[step];
  if (step === "line" && s.state === "failed" && s.attempts > 0) return false;   // LINE 不自動重試
  return s.state === "pending" || s.state === "failed" || (s.state === "running" && (!s.lease_until || Date.parse(s.lease_until) < Date.now()));
}

/** 依序執行尚未完成的步驟。每一步以 Redis 鎖保護（同一告警同一步驟同時只有一個執行者）。 */
export async function deliver(alertId: string, only?: DeliveryStep[]): Promise<Alert | null> {
  const blocked = new Set<DeliveryStep>();
  for (const step of ORDER) {
    if (only && !only.includes(step)) continue;
    if (blocked.has(step)) continue;
    const a = await getAlert(alertId);
    if (!a) return null;
    if (!needsRun(a, step)) continue;
    const token = await acquireLock(K.stepLock(alertId, step), STEP_LOCK_SECONDS);
    if (!token) continue;   // 另一個請求正在處理
    try {
      const leaseUntil = new Date(Date.now() + STEP_LOCK_SECONDS * 1000).toISOString();
      const running = await patchAlert(alertId, (x) => {
        x.delivery[step] = { ...x.delivery[step], state: "running", attempts: x.delivery[step].attempts + 1,
                             lease_until: leaseUntil, updated_at: new Date().toISOString() };
      });
      try {
        const apply = await STEPS[step](running);
        await patchAlert(alertId, (x) => {
          apply(x);
          if (x.delivery[step].state !== "skipped") {
            x.delivery[step] = { ...x.delivery[step], state: "done", last_error: null, lease_until: null, uncertain: false,
                                 updated_at: new Date().toISOString() };
          }
        });
      } catch (e) {
        const uncertain = e instanceof GitHubError && !e.definite;
        await patchAlert(alertId, (x) => {
          x.delivery[step] = { ...x.delivery[step], state: "failed", last_error: errText(e), lease_until: null,
                               uncertain: uncertain || x.delivery[step].uncertain, updated_at: new Date().toISOString() };
        });
        // 沒有 Issue 就不派發調查（避免調查結果無處留言）、也不同步狀態；LINE 仍照常推播
        if (step === "issue") ["dispatch", "sync"].forEach((x) => blocked.add(x as DeliveryStep));
      }
    } finally {
      await releaseLock(K.stepLock(alertId, step), token);
    }
  }
  return getAlert(alertId);
}

export function pendingSteps(a: Alert): DeliveryStep[] {
  return ORDER.filter((s) => a.delivery[s].state === "failed" || a.delivery[s].state === "pending");
}
