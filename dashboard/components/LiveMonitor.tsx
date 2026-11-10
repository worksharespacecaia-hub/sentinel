"use client";
// 即時監控（第 11.1 節）：事件流、告警清單、時間軸、攻擊模擬器、管理者狀態變更與重試。
// 只在分頁可見時每 3 秒輪詢 /api/alerts；取用失敗時顯示資料不足，不顯示「沒有告警」。
import { useCallback, useEffect, useState } from "react";

type StepState = "pending" | "running" | "done" | "failed" | "skipped";
interface Step { state: StepState; attempts: number; last_error: string | null; reason?: string }
interface Alert {
  id: string; rule_id: string; rule_title: string; level: "high" | "medium" | "low"; light: "red" | "yellow"; asset_id: string;
  simulated: boolean; simulation_id: string | null; summary: string; maps_to_event: string | null; issue_url: string | null;
  issue_number: number | null; status: "open" | "contained" | "closed"; status_version: number; created_at: string;
  delivery: Record<"issue" | "dispatch" | "line" | "sync", Step>;
  timeline: { event_received: string; rule_evaluated: string | null; alert_created: string; issue_created: string | null;
              dispatched: string | null; advice_ready: string | null };
  advice: { comment_url: string; source: string } | null;
  status_history: { from: string; to: string; actor: string; reason: string; evidence_url: string; at: string }[];
}
interface FeedEntry {
  id: string; source: string; event_time: string; simulated: boolean; simulation_id: string | null; detail: string;
  rejected: string | null; results: { rule_id: string; outcome: string; reason: string; alert_id: string | null }[];
}
interface AlertsResponse {
  available: boolean; degraded: string | null; now?: string;
  counts?: { real_open: number; real_high_open: number; simulated_open: number };
  events?: FeedEntry[]; recent?: Alert[]; open?: { real: Alert[]; real_total: number; simulated: Alert[] };
  line?: { enabled: boolean; reason?: string; admins: number; max_admins: number; used: number | null; limit: number | null; tier: string };
}

const SOURCE_TEXT: Record<string, string> = { "github.deployment": "GitHub 部署", "db.audit": "資料庫稽核", "support.complaint": "客服回報" };
const OUTCOME_TEXT: Record<string, string> = {
  alert: "命中→告警", suppressed: "命中（去重中）", below: "未達門檻", duplicate: "重複事件", late: "窗外遲到", no_match: "不符條件",
};
const STATUS_TEXT: Record<string, string> = { open: "未處理", contained: "已圍堵", closed: "已結案" };
const STEP_TEXT: Record<StepState, string> = { pending: "等待中", running: "進行中", done: "完成", failed: "失敗", skipped: "略過" };
const LEVEL_TEXT = { high: "高", medium: "中", low: "低" };

const fmt = (iso: string | null | undefined) =>
  iso ? new Intl.DateTimeFormat("zh-TW", { timeZone: "Asia/Taipei", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(iso)) : "—";
const secs = (from: string | null, to: string | null) =>
  from && to ? `${Math.max(0, (Date.parse(to) - Date.parse(from)) / 1000).toFixed(1)} 秒` : "—";

function Timeline({ a, now }: { a: Alert; now: number }) {
  const t = a.timeline;
  const waited = (now - Date.parse(t.alert_created)) / 1000;
  return (
    <div className="muted">
      時間軸：事件收到 {fmt(t.event_received)} → 規則判斷 {secs(t.event_received, t.rule_evaluated)} → Issue {secs(t.alert_created, t.issue_created)}
      {" "}→ 派發調查 {secs(t.alert_created, t.dispatched)} → 圍堵建議 {t.advice_ready ? secs(t.alert_created, t.advice_ready) : "等待中"}
      {!t.advice_ready && a.status !== "closed" && waited > 300 && (
        <strong>（已超過 5 分鐘：GitHub 排隊、外部服務延遲或交付失敗，請查看交付狀態）</strong>
      )}
      {!t.advice_ready && waited > 180 && waited <= 300 && <span>（超過目標 3 分鐘）</span>}
    </div>
  );
}

function AdminActions({ a, onDone }: { a: Alert; onDone: () => void }) {
  const [pass, setPass] = useState("");
  const [to, setTo] = useState(a.status === "open" ? "contained" : "closed");
  const [actor, setActor] = useState("");
  const [reason, setReason] = useState("");
  const [evidence, setEvidence] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [reverified, setReverified] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const options = a.status === "open" ? ["contained"] : a.status === "contained" ? ["closed", "open"] : [];
  const failed = (["issue", "dispatch", "sync"] as const).filter((s) => a.delivery[s].state === "failed" || a.delivery[s].state === "pending");

  async function post(url: string, body: object) {
    setMsg("送出中…");
    const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const data = await res.json().catch(() => ({}));
    setMsg(res.ok ? "已更新" : data.error ?? `失敗（HTTP ${res.status}）`);
    if (res.ok) onDone();
  }

  if (!options.length && !failed.length) return null;
  return (
    <details>
      <summary className="muted">管理者操作（需管理者密碼）</summary>
      <p><input type="password" placeholder="管理者密碼" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="off" /></p>
      {options.length > 0 && (
        <form onSubmit={(e) => { e.preventDefault(); post("/api/alerts/status", {
          admin_passcode: pass, alert_id: a.id, to, actor, reason, evidence_url: evidence, version: a.status_version,
          containment_confirmed: confirmed, reverified }); }}>
          <label>變更為 <select value={to} onChange={(e) => setTo(e.target.value)}>
            {options.map((o) => <option key={o} value={o}>{STATUS_TEXT[o]}</option>)}</select></label>{" "}
          <input placeholder="操作人" value={actor} onChange={(e) => setActor(e.target.value)} required maxLength={40} />{" "}
          <input placeholder="理由" value={reason} onChange={(e) => setReason(e.target.value)} required maxLength={500} />{" "}
          <input placeholder="驗證證據連結（https://）" value={evidence} onChange={(e) => setEvidence(e.target.value)} required type="url" />
          {to === "closed" && (
            <p>
              <label><input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} /> 已確認圍堵</label>{" "}
              <label><input type="checkbox" checked={reverified} onChange={(e) => setReverified(e.target.checked)} /> 已重新驗證異常停止</label>
            </p>
          )}
          <button type="submit">送出狀態變更</button>
        </form>
      )}
      {failed.length > 0 && (
        <p><button type="button" onClick={() => post("/api/alerts/retry", { admin_passcode: pass, alert_id: a.id })}>
          重試未完成步驟（{failed.join("、")}）</button></p>
      )}
      {msg && <p>{msg}</p>}
    </details>
  );
}

function AlertCard({ a, now, refresh }: { a: Alert; now: number; refresh: () => void }) {
  return (
    <div className={`panel${a.simulated ? " sim" : ""}`}>
      <p>
        <span className={`light ${a.light}`}>{a.light === "red" ? "紅燈" : "黃燈"}｜{a.rule_id} {a.rule_title}</span>{" "}
        {a.simulated && <span className="tag">模擬（{a.simulation_id}）</span>}
        <span className="tag">{STATUS_TEXT[a.status]}</span>
      </p>
      <p>{a.summary}</p>
      <p className="muted">
        等級：<span className={`lv-${a.level}`}>{LEVEL_TEXT[a.level]}</span>｜資產：{a.asset_id}｜對應事件：{a.maps_to_event ?? "—"}｜
        告警時間：{fmt(a.created_at)}｜{a.issue_url ? <a href={a.issue_url} target="_blank" rel="noreferrer">GitHub Issue #{a.issue_number}</a> : "Issue 尚未建立"}
        {a.advice && <>｜<a href={a.advice.comment_url} target="_blank" rel="noreferrer">圍堵建議</a>（{a.advice.source === "live" ? "即時呼叫" : a.advice.source === "replay" ? "重播錄製" : "程式範本"}）</>}
      </p>
      <p className="muted">交付：{(["issue", "dispatch", "line"] as const).map((s) => (
        <span key={s} className="tag">{s === "issue" ? "Issue" : s === "dispatch" ? "圍堵調查" : "LINE"}：{STEP_TEXT[a.delivery[s].state]}
          {a.delivery[s].state === "failed" && a.delivery[s].last_error ? `（${a.delivery[s].last_error}）` : ""}
          {a.delivery[s].state === "skipped" && a.delivery[s].reason ? `（${a.delivery[s].reason}）` : ""}</span>
      ))}</p>
      <Timeline a={a} now={now} />
      {a.status_history.length > 0 && (
        <ul className="muted">{a.status_history.map((h, i) => (
          <li key={i}>{fmt(h.at)} {STATUS_TEXT[h.from]} → {STATUS_TEXT[h.to]}，{h.actor}：{h.reason}（<a href={h.evidence_url} target="_blank" rel="noreferrer">證據</a>）</li>
        ))}</ul>
      )}
      <AdminActions a={a} onDone={refresh} />
    </div>
  );
}

function Simulator({ onDone }: { onDone: () => void }) {
  const [pass, setPass] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  async function run(preset: string) {
    setMsg("送出中…");
    const res = await fetch("/api/events", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ passcode: pass, preset }) });
    const data = await res.json().catch(() => ({}));
    setMsg(res.ok ? `已產生 ${data.events} 筆模擬事件（${data.simulation_id}），命中 ${data.alerts.length} 個告警。` : data.error ?? `失敗（HTTP ${res.status}）`);
    onDone();
  }
  return (
    <div className="panel">
      <h2>攻擊模擬器</h2>
      <p className="muted">事件由伺服器產生，一律標示「模擬」並使用獨立的 simulation_id，不改變正式燈號；每分鐘最多 10 次。</p>
      <p><input type="password" placeholder="示範密碼" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="off" />{" "}
        <button type="button" onClick={() => run("night-bulk-read")}>凌晨大量讀取訂單（RT-002）</button>{" "}
        <button type="button" onClick={() => run("multi-brand-fraud")}>多品牌回報詐騙（RT-003）</button></p>
      {msg && <p>{msg}</p>}
    </div>
  );
}

export default function LiveMonitor() {
  const [data, setData] = useState<AlertsResponse | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/alerts", { cache: "no-store" });
      setData(await res.json());
    } catch {
      setData({ available: false, degraded: "無法連線異常行為偵測服務" });
    }
    setNow(Date.now());
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(() => {
      if (document.visibilityState === "visible") load();   // 分頁隱藏時停止輪詢
    }, 3000);
    const onVis = () => { if (document.visibilityState === "visible") load(); };
    document.addEventListener("visibilitychange", onVis);
    return () => { clearInterval(t); document.removeEventListener("visibilitychange", onVis); };
  }, [load]);

  if (!data) return <div className="panel">載入中…</div>;
  const open = data.open;
  return (
    <>
      {data.degraded && <div className="panel sim"><strong>資料不足：</strong>{data.degraded}。告警狀態無法確認，不能視為沒有告警。</div>}
      {data.counts && (
        <div className="grid">
          <div className="panel"><div className="muted">真實未結案高風險告警</div><div className="stat">{data.counts.real_high_open}</div></div>
          <div className="panel"><div className="muted">真實未結案告警（含已圍堵）</div><div className="stat">{data.counts.real_open}</div></div>
          <div className="panel"><div className="muted">模擬告警（不影響正式燈號）</div><div className="stat">{data.counts.simulated_open}</div></div>
          <div className="panel"><div className="muted">LINE 通知</div><div>{data.line?.enabled ? "已啟用" : data.line?.reason ?? "未啟用"}</div>
            <div className="muted">已綁定管理者 {data.line?.enabled ? `${data.line.admins} / ${data.line.max_admins}` : "—"} 人；
              本月已用 {data.line?.used ?? "—"} / {data.line?.limit ?? 200} 則</div>
            {data.line?.tier === "alerts_only" && <div className="warn">本月額度偏高：只推播高風險告警</div>}
            {data.line?.tier === "stopped" && <div className="lv-high">LINE 額度已用完，請查看網站</div>}</div>
        </div>
      )}
      <Simulator onDone={load} />
      <h2>未結案告警</h2>
      {open && open.real.length === 0 && open.simulated.length === 0 && !data.degraded && <p className="muted">目前沒有未結案的告警。</p>}
      {open?.real.map((a) => <AlertCard key={a.id} a={a} now={now} refresh={load} />)}
      {open && open.real_total > open.real.length && <p className="muted">共 {open.real_total} 筆真實未結案告警，只顯示前 {open.real.length} 筆。</p>}
      {open?.simulated.map((a) => <AlertCard key={a.id} a={a} now={now} refresh={load} />)}
      <h2>最近告警</h2>
      <div className="table-wrap"><table>
        <thead><tr><th>時間</th><th>規則</th><th>等級</th><th>資產</th><th>狀態</th><th>Issue</th></tr></thead>
        <tbody>{(data.recent ?? []).map((a) => (
          <tr key={a.id}><td>{fmt(a.created_at)}</td><td>{a.rule_id} {a.rule_title}{a.simulated && <span className="tag">模擬</span>}</td>
            <td><span className={`lv-${a.level}`}>{LEVEL_TEXT[a.level]}</span></td><td>{a.asset_id}</td><td>{STATUS_TEXT[a.status]}</td>
            <td>{a.issue_url ? <a href={a.issue_url} target="_blank" rel="noreferrer">#{a.issue_number}</a> : "—"}</td></tr>
        ))}</tbody>
      </table></div>
      <h2>事件流</h2>
      <div className="table-wrap"><table>
        <thead><tr><th>事件時間</th><th>來源</th><th>內容</th><th>規則結果</th></tr></thead>
        <tbody>{(data.events ?? []).map((e) => (
          <tr key={`${e.simulation_id ?? "real"}-${e.id}`}>
            <td>{fmt(e.event_time)}</td>
            <td>{SOURCE_TEXT[e.source] ?? e.source}<div className="muted">{e.simulated ? "模擬" : "真實"}</div></td>
            <td>{e.detail}</td>
            <td>{e.rejected ? <span className="lv-medium">拒絕：{e.rejected}</span>
              : e.results.map((r) => <span key={r.rule_id} className="tag">{r.rule_id}：{OUTCOME_TEXT[r.outcome] ?? r.outcome}</span>)}</td>
          </tr>
        ))}</tbody>
      </table></div>
    </>
  );
}
