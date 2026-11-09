// GitHub API（伺服器端）：派發 sentinel.yml、依 request_id 查詢對應的 run 與 Jobs。Token 只存在伺服器端。
const API = "https://api.github.com";
export const ID_RE = /^[A-Za-z0-9_.-]{1,100}$/;

function repo() {
  const owner = process.env.GH_OWNER, name = process.env.GH_REPO;
  if (!owner || !name || !ID_RE.test(owner) || !ID_RE.test(name)) throw new Error("GH_OWNER／GH_REPO 未設定");
  return { owner, name };
}

function headers(token: string | undefined) {
  if (!token) throw new Error("GitHub Token 未設定");
  return { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "sentinel-dashboard" };
}

export type DispatchResult = { ok: true } | { ok: false; definite: boolean; status?: number; error: string };

export async function dispatchSentinel(inputs: Record<string, string>): Promise<DispatchResult> {
  const { owner, name } = repo();
  try {
    const res = await fetch(`${API}/repos/${owner}/${name}/actions/workflows/sentinel.yml/dispatches`, {
      method: "POST", headers: { ...headers(process.env.GH_DISPATCH_TOKEN), "content-type": "application/json" },
      body: JSON.stringify({ ref: process.env.GH_DEFAULT_BRANCH || "main", inputs }), signal: AbortSignal.timeout(10000),
    });
    if (res.status === 204 || res.status === 200) return { ok: true };
    return { ok: false, definite: true, status: res.status, error: `GitHub 回應 ${res.status}` };
  } catch (e) {
    return { ok: false, definite: false, error: (e as Error).name === "TimeoutError" ? "派發逾時" : "無法連線 GitHub" };
  }
}

export interface RunInfo { id: number; status: string; conclusion: string | null; html_url: string; display_title: string; created_at: string }

export async function findRunByRequest(requestId: string): Promise<RunInfo | null> {
  const { owner, name } = repo();
  const res = await fetch(`${API}/repos/${owner}/${name}/actions/workflows/sentinel.yml/runs?event=workflow_dispatch&per_page=30`, {
    headers: headers(process.env.GH_DISPATCH_TOKEN), cache: "no-store", signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`GitHub 回應 ${res.status}`);
  const body = (await res.json()) as { workflow_runs: RunInfo[] };
  return body.workflow_runs.find((r) => r.display_title.split("/")[1] === requestId) ?? null;
}

export async function listJobs(runId: number) {
  const { owner, name } = repo();
  const res = await fetch(`${API}/repos/${owner}/${name}/actions/runs/${runId}/jobs?per_page=50`, {
    headers: headers(process.env.GH_DISPATCH_TOKEN), cache: "no-store", signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`GitHub 回應 ${res.status}`);
  const body = (await res.json()) as { jobs: { name: string; status: string; conclusion: string | null }[] };
  return body.jobs.map((j) => ({ name: j.name, status: j.status, conclusion: j.conclusion }));
}
