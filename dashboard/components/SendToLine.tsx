"use client";
// 手動把行動報告摘要推給已綁定的 LINE 管理者（需管理者密碼；會用掉每月主動推播額度）。
import { useState } from "react";

export default function SendToLine() {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function send(form: HTMLFormElement) {
    const f = new FormData(form);
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch("/api/report/send", { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ admin_passcode: f.get("admin_passcode") }) });
      const data = (await res.json().catch(() => ({}))) as { error?: string; result?: { state: string; reason?: string; recipients?: number } };
      if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`);
      const r = data.result;
      setMsg(r?.state === "sent" ? `已傳送給 ${r.recipients} 位管理者` : `未傳送：${r?.reason ?? "LINE 未啟用"}`);
    } catch (e) {
      setMsg(`失敗：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <details className="send-line no-print">
      <summary className="button">傳送到 LINE</summary>
      <form onSubmit={(e) => { e.preventDefault(); void send(e.currentTarget); }}>
        <label>管理者密碼 <input name="admin_passcode" type="password" required autoComplete="current-password" /></label>
        <button type="submit" disabled={busy}>{busy ? "傳送中…" : "傳送摘要"}</button>
        <p className="muted">推給已綁定的管理者，會用掉每月主動推播額度（輕用量 200 則）。</p>
        {msg && <p role="status">{msg}</p>}
      </form>
    </details>
  );
}
