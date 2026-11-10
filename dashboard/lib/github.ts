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

// ------------------------------------------------------------------ 已發布檔案（Repo ②，指定 commit）

const REPO_PATH_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$/;
export const SHA_RE = /^[0-9a-f]{40}$/;

/** 讀取指定 commit 的檔案（raw）。燈號通知用它讀 A5 剛發布、Vercel 可能尚未重新部署的 report／manifest。 */
export async function getRepoText(filePath: string, ref: string): Promise<string> {
  if (!REPO_PATH_RE.test(filePath) || filePath.includes("..") || !(SHA_RE.test(ref) || ID_RE.test(ref))) throw new GitHubError("路徑或 ref 格式錯誤", true);
  const { owner, name } = repo();
  let res: Response;
  try {
    res = await fetch(`${API}/repos/${owner}/${name}/contents/${filePath}?ref=${encodeURIComponent(ref)}`, {
      headers: { ...headers(process.env.GH_DISPATCH_TOKEN), accept: "application/vnd.github.raw+json" },
      cache: "no-store", signal: AbortSignal.timeout(10000),
    });
  } catch (e) {
    throw new GitHubError((e as Error).name === "TimeoutError" ? "GitHub 回應逾時" : "無法連線 GitHub", false);
  }
  if (!res.ok) throw new GitHubError(`GitHub 回應 ${res.status}`, true, res.status);
  return res.text();
}

export async function getRepoJson<T>(filePath: string, ref: string): Promise<T> {
  return JSON.parse(await getRepoText(filePath, ref)) as T;
}

// ------------------------------------------------------------------ 燈號權重（rules/scoring.json，Repo ② 預設分支）

const SCORING_PATH = "rules/scoring.json";
const branch = () => process.env.GH_DEFAULT_BRANCH || "main";

export function contentsConfigured(): boolean {
  try {
    repo();
    return Boolean(process.env.GH_DISPATCH_TOKEN);
  } catch {
    return false;
  }
}

/** 目前的設定與 blob sha（寫回時以 sha 做併發檢查：別人先改過就回 409）。 */
export async function getScoringConfig(): Promise<{ text: string; sha: string }> {
  const { owner, name } = repo();
  const body = await gh<{ content: string; encoding: string; sha: string }>("GET",
    `/repos/${owner}/${name}/contents/${SCORING_PATH}?ref=${encodeURIComponent(branch())}`, process.env.GH_DISPATCH_TOKEN);
  if (body.encoding !== "base64") throw new GitHubError("設定檔編碼不支援", true);
  return { text: Buffer.from(body.content, "base64").toString("utf8"), sha: body.sha };
}

/** 寫回設定（一個 commit）。不指定 committer／author：由 Token 身分記錄是誰改的。 */
export async function putScoringConfig(text: string, sha: string, message: string): Promise<{ commit_sha: string; commit_url: string }> {
  const { owner, name } = repo();
  const body = await gh<{ commit: { sha: string; html_url: string } }>("PUT", `/repos/${owner}/${name}/contents/${SCORING_PATH}`,
    process.env.GH_DISPATCH_TOKEN, { message, content: Buffer.from(text, "utf8").toString("base64"), sha, branch: branch() });
  return { commit_sha: body.commit.sha, commit_url: body.commit.html_url };
}

export interface ScoringCommit { sha: string; url: string; date: string; message: string }

export async function listScoringHistory(limit = 10): Promise<ScoringCommit[]> {
  const { owner, name } = repo();
  const list = await gh<{ sha: string; html_url: string; commit: { message: string; committer: { date: string } | null } }[]>("GET",
    `/repos/${owner}/${name}/commits?path=${SCORING_PATH}&sha=${encodeURIComponent(branch())}&per_page=${limit}`, process.env.GH_DISPATCH_TOKEN);
  return list.map((c) => ({ sha: c.sha.slice(0, 7), url: c.html_url, date: c.commit.committer?.date ?? "",
                            message: c.commit.message.slice(0, 300) }));
}
