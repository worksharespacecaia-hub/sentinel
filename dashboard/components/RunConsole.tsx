"use client";
// Agent 執行頁的操作面板：送出執行請求 → 每 5 秒顯示各 Agent（Job）的即時進度 → 偵測新結果隨 Vercel 重新部署上線。
// 伺服器端（/api/run）固定白名單、trigger_source=web 與執行模式；這裡只是操作介面。
import { useCallback, useEffect, useRef, useState } from "react";
import { P2_SCENARIOS, WEB_SCENARIOS } from "@/lib/scenarios";
import { STATUS_LABEL, flowStages, fmtSeconds, publishedRunId, resultPath, type JobInfo } from "@/lib/runflow";

const STORE = "sentinel.activeRun";
const MAX_AGE_MS = 3 * 3600_000;
const PUBLISH_WAIT_MS = 15 * 60_000;

interface Active { requestId: string; scenario: string; startedAt: number }
type Phase = "idle" | "dispatched" | "running" | "completed" | "published";

function loadActive(): Active | null {
  try {
    const v = JSON.parse(localStorage.getItem(STORE) ?? "null") as Active | null;
    return v && /^web-[0-9a-f-]{36}$/.test(v.requestId) && Date.now() - v.startedAt < MAX_AGE_MS ? v : null;
  } catch {
    return null;
  }
}
function saveActive(v: Active | null) {
  try {
    if (v) localStorage.setItem(STORE, JSON.stringify(v));
    else localStorage.removeItem(STORE);
  } catch { /* 無法使用儲存空間時只是重新整理後不再追蹤 */ }
}

export default function RunConsole() {
  const [scenario, setScenario] = useState("daily");
  const [passcode, setPasscode] = useState("");
  const [admin, setAdmin] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [active, setActive] = useState<Active | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [jobs, setJobs] = useState<JobInfo[]>([]);
  const [run, setRun] = useState<{ id?: number; url?: string | null; conclusion?: string | null }>({});
  const [now, setNow] = useState(() => Date.now());
  const completedAt = useRef<number | null>(null);

  useEffect(() => {          // 重新整理或換頁回來時，繼續追蹤尚未結束的執行
    const v = loadActive();
    if (v) { setActive(v); setScenario(v.scenario); setPhase("dispatched"); }
  }, []);

  const reset = useCallback(() => {
    saveActive(null); setActive(null); setPhase("idle"); setJobs([]); setRun({}); setMsg(null); completedAt.current = null;
  }, []);

  useEffect(() => {
    if (!active || phase === "published") return;
    let stop = false;
    const tick = async () => {
      if (stop || document.visibilityState !== "visible") return;     // 分頁隱藏時停止輪詢
      setNow(Date.now());
      try {
        if (phase !== "completed") {
          const res = await fetch(`/api/status?request_id=${encodeURIComponent(active.requestId)}`, { cache: "no-store" });
          if (res.status === 404) { setMsg("找不到這個執行請求（可能已過期）"); reset(); return; }
          if (!res.ok) return;
          const body = await res.json();
          setJobs(body.jobs ?? []);
          setRun({ id: body.run_id, url: body.html_url, conclusion: body.conclusion });
          if (body.status === "completed") { completedAt.current = Date.now(); setPhase("completed"); }
          else if (body.status !== "queued") setPhase("running");
        } else if (run.id) {
          // A5 發布後 Vercel 重新部署；index.json 出現這次的 run_id 才算新結果上線
          const res = await fetch(`/data/index.json?t=${Date.now()}`, { cache: "no-store" });
          if (res.ok && publishedRunId(await res.json(), active.scenario) === String(run.id)) {
            setPhase("published"); saveActive(null);
          } else if (completedAt.current && Date.now() - completedAt.current > PUBLISH_WAIT_MS) {
            setMsg("超過 15 分鐘仍未看到新結果上線，請到 GitHub Actions 確認 A5 是否發布成功、Vercel 是否重新部署。");
            saveActive(null); setPhase("published");
          }
        }
      } catch { /* 網路暫時中斷：下一輪再試 */ }
    };
    tick();
    const t = setInterval(tick, phase === "completed" ? 15000 : 5000);
    return () => { stop = true; clearInterval(t); };
  }, [active, phase, run.id, reset]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setMsg("送出中…");
    try {
      const body: Record<string, string> = { scenario, passcode };
      if (admin) body.admin_passcode = admin;
      const res = await fetch("/api/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const data = await res.json().catch(() => ({}));
      if (res.status === 202 && data.request_id) {
        const v = { requestId: data.request_id, scenario, startedAt: Date.now() };
        saveActive(v); setActive(v); setPhase("dispatched"); setJobs([]); setRun({}); setPasscode(""); setAdmin("");
        setMsg("已派發，等待 GitHub Actions 開始執行。");
      } else {
        setMsg(data.error ?? `失敗（HTTP ${res.status}）`);
      }
    } catch {
      setMsg("無法連線網站伺服器，請稍後再試");
    } finally {
      setBusy(false);
    }
  }

  const stages = flowStages(jobs, now);
  const elapsed = active ? fmtSeconds(Math.round((now - active.startedAt) / 1000)) : "";
  const phaseText: Record<Phase, string> = {
    idle: "", dispatched: "已派發，等待 GitHub Actions 排入執行…", running: `執行中（已經過 ${elapsed}）`,
    completed: `執行結束（${run.conclusion ?? "—"}），等待 A5 發布與 Vercel 重新部署…`, published: "新結果已上線",
  };

  return (
    <div>
      {!active && (
        <form onSubmit={submit} className="run-form">
          <label>情境 <select value={scenario} onChange={(e) => setScenario(e.target.value)}>
            {WEB_SCENARIOS.map((s) => <option key={s} value={s} disabled={P2_SCENARIOS.has(s)}>
              {P2_SCENARIOS.has(s) ? `${s}（P2 未啟用）` : s}</option>)}</select></label>
          <label>示範密碼 <input type="password" value={passcode} onChange={(e) => setPasscode(e.target.value)} required autoComplete="off" /></label>
          <details><summary className="muted">管理者</summary>
            <input type="password" placeholder="管理者密碼（只略過冷卻）" value={admin} onChange={(e) => setAdmin(e.target.value)} autoComplete="off" />
          </details>
          <button className="primary" type="submit" disabled={busy}>{busy ? "送出中…" : "執行"}</button>
        </form>
      )}
      {!active && scenario === "daily" && (
        <p className="muted">網站觸發的 daily 不會搜尋新聞（不使用訂閱方案），每日情資會顯示「重播模式」；要含今日新聞請等每日排程，或在 GitHub 手動執行。</p>
      )}
      {msg && <p role="status">{msg}</p>}

      {active && (
        <div className="run-live" aria-live="polite">
          <p><strong>{active.scenario}</strong>：{phaseText[phase]}
            {run.url && <> ｜ <a href={run.url} target="_blank" rel="noreferrer">GitHub Actions 執行頁</a></>}</p>
          <div className="flow">
            {stages.map((s, i) => (
              <div className="flow-stage" key={s.title}>
                <div className="muted">{i + 1}. {s.title}</div>
                {s.nodes.map((n) => {
                  const inner = <>
                    <span className="flow-label">{n.label}</span>
                    <span className="flow-status">{STATUS_LABEL[n.status]}{n.seconds !== undefined ? `・${fmtSeconds(n.seconds)}` : ""}</span>
                    {n.note && <span className="flow-note">{n.note}</span>}
                  </>;
                  return n.url
                    ? <a key={n.key} className={`flow-node st-${n.status}`} href={n.url} target="_blank" rel="noreferrer">{inner}</a>
                    : <div key={n.key} className={`flow-node st-${n.status}`}>{inner}</div>;
                })}
              </div>
            ))}
          </div>
          {phase === "published" && <p><a className="button primary" href={resultPath(active.scenario)}>查看這次的分析結果</a></p>}
          <p><button type="button" onClick={reset}>{phase === "published" ? "關閉" : "停止追蹤（不會取消 GitHub 上的執行）"}</button></p>
        </div>
      )}
    </div>
  );
}
