// GitHub API（伺服器端）：派發 sentinel.yml、依 request_id 查詢對應的 run 與 Jobs；即時告警的 Issue 與 repository_dispatch。
// Token 只存在伺服器端：GH_DISPATCH_TOKEN（Actions／Contents）、ALERT_ISSUE_TOKEN（Issues）。
const API = "https://api.github.com";
export const ID_RE = /^[A-Za-z0-9_.-]{1,100}$/;

function repo() {
  const owner = process.env.GH_OWNER, name = process.env.GH_REPO;
  if (!owner || !name || !ID_RE.test(owner) || !ID_RE.test(name)) throw new Error("GH_OWNER／GH_REPO 未設定");
  return { owner, name };
}

export function repoName(): string {
  const { owner, name } = repo();
  return `${owner}/${name}`;
}

export function issuesConfigured(): boolean {
  try {
    repo();
    return Boolean(process.env.ALERT_ISSUE_TOKEN);
  } catch {
    return false;
  }
}

function headers(token: string | undefined) {
  if (!token) throw new GitHubError("GitHub Token 未設定", true);
  return { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "sentinel-dashboard" };
}

/** definite=false 表示逾時或連線中斷，無法確定對方是否已處理（重試前必須先查詢既有結果）。 */
export class GitHubError extends Error {
  definite: boolean;
  status?: number;
  constructor(message: string, definite: boolean, status?: number) {
    super(message);
    this.definite = definite;
    this.status = status;
  }
}

async function gh<T>(method: string, path: string, token: string | undefined, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API}${path}`, {
      method, headers: { ...headers(token), ...(body ? { "content-type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined, cache: "no-store", signal: AbortSignal.timeout(10000),
    });
  } catch (e) {
    if (e instanceof GitHubError) throw e;
    throw new GitHubError((e as Error).name === "TimeoutError" ? "GitHub 回應逾時" : "無法連線 GitHub", false);
  }
  if (!res.ok) throw new GitHubError(`GitHub 回應 ${res.status}`, true, res.status);
  return (res.status === 204 ? null : await res.json()) as T;
}

export type DispatchResult = { ok: true } | { ok: false; definite: boolean; status?: number; error: string };

export async function dispatchSentinel(inputs: Record<string, string>): Promise<DispatchResult> {
  const { owner, name } = repo();
  try {
    await gh("POST", `/repos/${owner}/${name}/actions/workflows/sentinel.yml/dispatches`, process.env.GH_DISPATCH_TOKEN,
      { ref: process.env.GH_DEFAULT_BRANCH || "main", inputs });
    return { ok: true };
  } catch (e) {
    const g = e as GitHubError;
    return { ok: false, definite: g.definite, status: g.status, error: g.definite ? g.message : g.message === "GitHub 回應逾時" ? "派發逾時" : g.message };
  }
}

export interface RunInfo { id: number; status: string; conclusion: string | null; html_url: string; display_title: string; created_at: string }

export async function findRunByRequest(requestId: string): Promise<RunInfo | null> {
  const { owner, name } = repo();
  const body = await gh<{ workflow_runs: RunInfo[] }>("GET",
    `/repos/${owner}/${name}/actions/workflows/sentinel.yml/runs?event=workflow_dispatch&per_page=30`, process.env.GH_DISPATCH_TOKEN);
  return body.workflow_runs.find((r) => r.display_title.split("/")[1] === requestId) ?? null;
}

export async function listJobs(runId: number) {
  const { owner, name } = repo();
  const body = await gh<{ jobs: { name: string; status: string; conclusion: string | null; started_at: string | null;
    completed_at: string | null; html_url: string | null }[] }>("GET",
    `/repos/${owner}/${name}/actions/runs/${runId}/jobs?per_page=50`, process.env.GH_DISPATCH_TOKEN);
  // 只回傳顯示進度需要的欄位（不含 runner、步驟 log 等）
  return body.jobs.map((j) => ({ name: j.name, status: j.status, conclusion: j.conclusion, started_at: j.started_at,
                                 completed_at: j.completed_at, html_url: j.html_url }));
}

// ------------------------------------------------------------------ 即時告警：Issue（Repo ②）

export const issueMarker = (alertId: string) => `<!-- sentinel-alert-id: ${alertId} -->`;

interface RawIssue { number: number; html_url: string; state: string; body: string | null; labels: ({ name: string } | string)[]; pull_request?: unknown }

function toRecord(i: RawIssue) {
  return { number: i.number, html_url: i.html_url, state: i.state, body: i.body ?? "",
           labels: i.labels.map((l) => (typeof l === "string" ? l : l.name)) };
}

export async function createIssue(title: string, body: string, labels: string[]) {
  const { owner, name } = repo();
  const i = await gh<RawIssue>("POST", `/repos/${owner}/${name}/issues`, process.env.ALERT_ISSUE_TOKEN, { title, body, labels });
  return toRecord(i);
}

/** 逾時重試前先查既有 Issue marker，避免重複建立（不使用搜尋 API，避免索引延遲）。 */
export async function findIssueByMarker(alertId: string) {
  const { owner, name } = repo();
  const list = await gh<RawIssue[]>("GET",
    `/repos/${owner}/${name}/issues?labels=sentinel-alert&state=all&sort=created&direction=desc&per_page=100`, process.env.ALERT_ISSUE_TOKEN);
  const hit = list.find((i) => !i.pull_request && (i.body ?? "").includes(issueMarker(alertId)));
  return hit ? toRecord(hit) : null;
}

export async function listAlertIssues(maxPages = 5) {
  const { owner, name } = repo();
  const out: ReturnType<typeof toRecord>[] = [];
  for (let page = 1; page <= maxPages; page++) {
    const list = await gh<RawIssue[]>("GET",
      `/repos/${owner}/${name}/issues?labels=sentinel-alert&state=all&per_page=100&page=${page}`, process.env.ALERT_ISSUE_TOKEN);
    out.push(...list.filter((i) => !i.pull_request).map(toRecord));
    if (list.length < 100) return out;
  }
  throw new GitHubError(`告警 Issue 超過 ${maxPages * 100} 筆，重建未完成`, true);
}

export async function updateIssue(issueNumber: number, patch: { labels?: string[]; state?: "open" | "closed"; state_reason?: string }) {
  const { owner, name } = repo();
  return toRecord(await gh<RawIssue>("PATCH", `/repos/${owner}/${name}/issues/${issueNumber}`, process.env.ALERT_ISSUE_TOKEN, patch));
}

export async function commentIssue(issueNumber: number, body: string) {
  const { owner, name } = repo();
  return gh<{ html_url: string }>("POST", `/repos/${owner}/${name}/issues/${issueNumber}/comments`, process.env.ALERT_ISSUE_TOKEN, { body });
}

export async function hasCommentMarker(issueNumber: number, marker: string): Promise<boolean> {
  const { owner, name } = repo();
  const list = await gh<{ body: string }[]>("GET", `/repos/${owner}/${name}/issues/${issueNumber}/comments?per_page=100`, process.env.ALERT_ISSUE_TOKEN);
  return list.some((c) => (c.body ?? "").includes(marker));
}

// ------------------------------------------------------------------ 即時告警：repository_dispatch → incident.yml

export async function dispatchIncident(alertId: string, assetId: string): Promise<void> {
  const { owner, name } = repo();
  await gh("POST", `/repos/${owner}/${name}/dispatches`, process.env.GH_DISPATCH_TOKEN,
    { event_type: "incident", client_payload: { alert_id: alertId, asset_id: assetId } });
}

/** incident.yml 的 run-name 為「incident <alert_id>」；逾時重試前先查是否已有對應執行。 */
export async function findIncidentRun(alertId: string): Promise<RunInfo | null> {
  const { owner, name } = repo();
  const body = await gh<{ workflow_runs: RunInfo[] }>("GET",
    `/repos/${owner}/${name}/actions/workflows/incident.yml/runs?event=repository_dispatch&per_page=50`, process.env.GH_DISPATCH_TOKEN);
  return body.workflow_runs.find((r) => r.display_title === `incident ${alertId}`) ?? null;
}
