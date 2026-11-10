// Agent 執行頁的即時進度：把 GitHub Actions 的 Job 狀態對應到 Agent 流程（純函式，前後端共用）。
// Job 名稱來自 .github/workflows/sentinel.yml；Job 尚未建立時顯示「等待」。

export interface JobInfo {
  name: string; status: string; conclusion: string | null;
  started_at?: string | null; completed_at?: string | null; html_url?: string | null;
}

export type NodeStatus = "waiting" | "running" | "success" | "failure" | "skipped" | "cancelled";

export interface FlowNode { key: string; label: string; status: NodeStatus; note?: string; seconds?: number; url?: string }
export interface FlowStage { title: string; nodes: FlowNode[] }

const STAGES: { title: string; nodes: { key: string; label: string; skippedNote?: string; failureNote?: string }[] }[] = [
  { title: "規劃", nodes: [{ key: "orchestrator", label: "Orchestrator 規劃派工" }] },
  { title: "資產", nodes: [{ key: "a0-assets", label: "A0 資產探索與對帳" }] },
  { title: "掃描與蒐集", nodes: [
    { key: "scanners (trivy)", label: "掃描：Trivy" },
    { key: "scanners (gitleaks)", label: "掃描：Gitleaks" },
    { key: "scanners (checkov)", label: "掃描：Checkov" },
    { key: "daily-intel", label: "每日情資（程式抓新聞＋Claude 判讀）", skippedNote: "只在每日排程與 GitHub 手動 daily 執行",
      failureNote: "失敗不影響流程，報告標示今日新聞情資未更新" },
    { key: "a3-signals", label: "A3 早期訊號" },
  ] },
  { title: "分析", nodes: [{ key: "a1-intel", label: "A1 外部情資" }, { key: "a2-scan", label: "A2 弱點掃描" }] },
  { title: "風險", nodes: [{ key: "a4-risk", label: "A4 攻擊鏈與風險" }] },
  { title: "發布", nodes: [{ key: "a5-report", label: "A5 報告與發布" }] },
];

export const STATUS_LABEL: Record<NodeStatus, string> = {
  waiting: "等待", running: "執行中", success: "成功", failure: "失敗", skipped: "略過", cancelled: "已取消",
};

export function statusOf(job: JobInfo | undefined): NodeStatus {
  if (!job) return "waiting";
  if (job.status !== "completed") return job.status === "in_progress" ? "running" : "waiting";
  switch (job.conclusion) {
    case "success": case "neutral": return "success";
    case "skipped": return "skipped";
    case "cancelled": return "cancelled";
    default: return "failure";                 // failure、timed_out、action_required、startup_failure
  }
}

function seconds(job: JobInfo | undefined, now: number): number | undefined {
  const start = job?.started_at ? Date.parse(job.started_at) : NaN;
  if (Number.isNaN(start)) return undefined;
  const end = job?.completed_at ? Date.parse(job.completed_at) : now;
  return Number.isNaN(end) || end < start ? undefined : Math.round((end - start) / 1000);
}

const GH_JOB_URL = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/actions\/runs\/\d+\/job\/\d+$/;

export function flowStages(jobs: JobInfo[], now: number = Date.now()): FlowStage[] {
  const byName = new Map(jobs.map((j) => [j.name, j]));
  return STAGES.map((stage) => ({
    title: stage.title,
    nodes: stage.nodes.map((n) => {
      const job = byName.get(n.key);
      const status = statusOf(job);
      const note = status === "skipped" ? n.skippedNote : status === "failure" ? n.failureNote : undefined;
      const url = job?.html_url && GH_JOB_URL.test(job.html_url) ? job.html_url : undefined;
      const secs = status === "skipped" || status === "waiting" ? undefined : seconds(job, now);
      return { key: n.key, label: n.label, status, note, seconds: secs, url };
    }),
  }));
}

export function fmtSeconds(s: number | undefined): string {
  if (s === undefined) return "";
  return s < 60 ? `${s} 秒` : `${Math.floor(s / 60)} 分 ${s % 60} 秒`;
}

/** index.json 中該情境最新的 run_id（daily 看 latest_daily）。用來判斷新結果是否已隨 Vercel 重新部署上線。 */
export function publishedRunId(index: unknown, scenario: string): string | null {
  if (!index || typeof index !== "object") return null;
  const idx = index as { latest_daily?: { run_id?: unknown }; scenarios?: Record<string, { run_id?: unknown }> };
  const id = scenario === "daily" ? idx.latest_daily?.run_id : idx.scenarios?.[scenario]?.run_id;
  return typeof id === "string" || typeof id === "number" ? String(id) : null;
}

/** 結果頁網址：daily 是 /runs，其他情境帶 source。 */
export function resultPath(scenario: string): string {
  return scenario === "daily" ? "/runs" : `/runs?source=${encodeURIComponent(scenario)}`;
}
