"use client";
import { useEffect, useRef, useState } from "react";

const WEB_SCENARIOS = ["daily", "intel-demo", "peer-incident", "early-signal", "php2shell", "nas", "insider-path", "mobile-sdk"];

interface Job { name: string; status: string; conclusion: string | null }

export default function RunButton({ sources }: { sources: string[] }) {
  const [scenario, setScenario] = useState("daily");
  const [passcode, setPasscode] = useState("");
  const [admin, setAdmin] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [requestId, setRequestId] = useState<string | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [runUrl, setRunUrl] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!requestId) return;
    let done = false;
    const poll = async () => {
      if (done || document.visibilityState !== "visible") return;   // 分頁隱藏時停止輪詢
      const res = await fetch(`/api/status?request_id=${encodeURIComponent(requestId)}`, { cache: "no-store" });
      if (!res.ok) return;
      const body = await res.json();
      setJobs(body.jobs ?? []);
      setRunUrl(body.html_url ?? null);
      if (body.status === "completed") {
        done = true;
        setMsg(`執行完成（${body.conclusion}）。網站會在 A5 發布、Vercel 重新部署後顯示新結果。`);
        if (timer.current) clearInterval(timer.current);
      }
    };
    poll();
    timer.current = setInterval(poll, 5000);
    return () => { done = true; if (timer.current) clearInterval(timer.current); };
  }, [requestId]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setMsg("送出中…");
    const body: Record<string, string> = { scenario, passcode };
    if (admin) body.admin_passcode = admin;
    const res = await fetch("/api/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const data = await res.json().catch(() => ({}));
    if (res.status === 202) {
      setRequestId(data.request_id);
      setMsg("已派發，等待 GitHub Actions 開始執行。派發成功不代表評估或部署完成。");
    } else {
      setMsg(data.error ?? `失敗（HTTP ${res.status}）`);
    }
  }

  const options = WEB_SCENARIOS;   // 伺服器端另有白名單；sources 只用來顯示已有結果的情境
  void sources;
  return (
    <form onSubmit={submit}>
      <p className="muted">網站觸發一律使用伺服器設定的執行模式（預設重播，不花 API 費用），不會使用訂閱方案；每小時最多一次。</p>
      <label>情境 <select value={scenario} onChange={(e) => setScenario(e.target.value)}>
        {options.map((s) => <option key={s} value={s}>{s}</option>)}</select></label>{" "}
      <label>示範密碼 <input type="password" value={passcode} onChange={(e) => setPasscode(e.target.value)} required autoComplete="off" /></label>{" "}
      <details style={{ display: "inline-block" }}><summary className="muted">管理者</summary>
        <input type="password" placeholder="管理者密碼（只略過冷卻）" value={admin} onChange={(e) => setAdmin(e.target.value)} autoComplete="off" />
      </details>{" "}
      <button className="primary" type="submit">執行</button>
      {msg && <p>{msg}</p>}
      {jobs.length > 0 && (
        <ul className="tree">{jobs.map((j) => <li key={j.name}>{j.name}：{j.conclusion ?? j.status}</li>)}</ul>
      )}
      {runUrl && <p><a href={runUrl} target="_blank" rel="noreferrer">開啟 GitHub Actions 執行頁</a></p>}
    </form>
  );
}
