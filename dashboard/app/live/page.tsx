import Link from "next/link";
import LiveMonitor from "@/components/LiveMonitor";
import { PAGES } from "@/lib/nav";

export const metadata = { title: `${PAGES.live.label}｜Sentinel` };

export default function Live() {
  return (
    <>
      <h1>{PAGES.live.label}</h1>
      <div className="panel">
        <p>即時規則刻意不使用 LLM：事件進來後由程式依規則判斷、以 Redis 原子操作計算時間窗與去重，命中就先保存告警，
          再建立 GitHub Issue 並觸發圍堵建議流程（只建議、不執行）。</p>
        <p className="muted">目標：規則判斷與告警保存 1 秒內；網站顯示 10 秒內；圍堵建議 3 分鐘內（GitHub 排隊與外部服務延遲不保證，超過 5 分鐘會標示原因）。
          告警只有管理者附理由與證據才能結案；關閉 Issue、時間到期或建議完成都不會自動結案。</p>
        <p className="muted">偵測規則（時段、門檻、時間窗、允許的部署者等）可在「<Link href={PAGES.rules.href}>{PAGES.rules.label}</Link>」調整，需要管理者密碼。</p>
      </div>
      <details className="panel">
        <summary><strong>如何觸發「非 Pipeline 發起的正式部署」（RT-001，真實事件）</strong></summary>
        <p>在已登入 GitHub CLI 的筆電，對 Repo ① 建立一筆 production Deployment（不經過 CI）：</p>
        <pre>{`gh api -X POST repos/<owner>/shopsaas-demo-platform/deployments --input - <<'EOF'
{"ref":"main","environment":"production","auto_merge":false,"required_contexts":[],"description":"manual deploy (demo)"}
EOF`}</pre>
        <p className="muted">Repo ① 的 Webhook（只勾選 Deployments）會送到 /api/webhooks/github，簽章通過後轉成內部事件。
          由 CI（github-actions[bot]）建立的部署不會告警。</p>
      </details>
      <LiveMonitor />
    </>
  );
}
