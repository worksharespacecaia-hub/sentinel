"use client";
// 設定「處理中」：負責人、期限（必填）、備註；需要管理者密碼。期限前 24 小時與逾期時會以 LINE 提醒。
import { useState } from "react";
import { useRouter } from "next/navigation";

interface Props { riskId: string; version: number; inProgress: boolean; owner: string; dueAt: string | null; note: string }

/** ISO → datetime-local 的值（以瀏覽器所在時區顯示）。 */
function toLocalInput(iso: string | null): string {
  const d = iso ? new Date(iso) : new Date(Date.now() + 24 * 3600 * 1000);
  const target = d.getTime() > Date.now() ? d : new Date(Date.now() + 24 * 3600 * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${target.getFullYear()}-${pad(target.getMonth() + 1)}-${pad(target.getDate())}T${pad(target.getHours())}:${pad(target.getMinutes())}`;
}

export default function TrackForm({ riskId, version, inProgress, owner, dueAt, note }: Props) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function submit(form: HTMLFormElement, action: "set" | "cancel") {
    const f = new FormData(form);
    const local = String(f.get("due_local") ?? "");
    const due = local ? new Date(local) : null;
    const body: Record<string, unknown> = {
      admin_passcode: f.get("admin_passcode"), risk_id: riskId, action, actor: f.get("actor"), version,
    };
    if (action === "set") Object.assign(body, { owner: f.get("owner"), note: f.get("note"), due_at: due && !Number.isNaN(due.getTime()) ? due.toISOString() : "" });
    else body.reason = f.get("note");
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch("/api/actions/status", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const data = (await res.json().catch(() => ({}))) as { error?: string };
      if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`);
      setMsg(action === "set" ? "已設為處理中" : "已取消處理中");
      router.refresh();
    } catch (e) {
      setMsg(`失敗：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <details className="track-form no-print">
      <summary>{inProgress ? "修改處理中／取消" : "設為處理中"}</summary>
      <form onSubmit={(e) => { e.preventDefault(); void submit(e.currentTarget, "set"); }}>
        <label>負責人 <input name="owner" required maxLength={40} defaultValue={owner} /></label>
        <label>期限（必填） <input name="due_local" type="datetime-local" required defaultValue={toLocalInput(dueAt)} /></label>
        <label>備註／取消理由 <input name="note" maxLength={200} defaultValue={note} /></label>
        <label>操作人 <input name="actor" required maxLength={40} autoComplete="name" /></label>
        <label>管理者密碼 <input name="admin_passcode" type="password" required autoComplete="current-password" /></label>
        <p className="muted">期限最多 30 天；到期前 24 小時與逾期時會以 LINE 提醒。已修復只由重新評估判定。</p>
        <div className="run-form">
          <button type="submit" className="primary" disabled={busy}>{busy ? "處理中…" : "儲存"}</button>
          {inProgress && <button type="button" disabled={busy}
            onClick={(e) => { const form = e.currentTarget.form; if (form) void submit(form, "cancel"); }}>取消處理中</button>}
        </div>
        {msg && <p role="status">{msg}</p>}
      </form>
    </details>
  );
}
