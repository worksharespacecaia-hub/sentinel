"use client";
// 燈號權重編輯：即時試算（用已發布的分數拆解重新加總），儲存需操作人、理由與管理者密碼；下一次評估起生效。
import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import type { Light, Risk } from "@/lib/data";
import { DEFAULT_WEIGHTS, FACTOR_KEYS, LIMITS, preview, validateWeights, type Weights } from "@/lib/scoring";
import { LEVEL_TEXT } from "@/lib/labels";
import { TrafficLight } from "@/components/ui";

type PreviewRisk = Pick<Risk, "id" | "title" | "status" | "score" | "level" | "score_level" | "level_reason" | "breakdown" | "level_floor" | "provisional_basis">;

interface Props {
  saved: Weights; baseSha: string | null; risks: PreviewRisk[];
  current: { counts: { high: number; medium: number; low: number }; light: Light };
}

export default function WeightsEditor({ saved, baseSha, risks, current }: Props) {
  const router = useRouter();
  const [w, setW] = useState<Weights>(saved);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string; url?: string } | null>(null);
  const check = validateWeights(w.factors, w.thresholds);
  const p = useMemo(() => (check.ok ? preview(risks, check.value) : null), [risks, check]);
  const dirty = JSON.stringify(w) !== JSON.stringify(saved);

  const setFactor = (k: (typeof FACTOR_KEYS)[number], v: string) => setW({ ...w, factors: { ...w.factors, [k]: Number(v) } });
  const setThreshold = (k: "high" | "medium", v: string) => setW({ ...w, thresholds: { ...w.thresholds, [k]: Number(v) } });

  async function save(form: HTMLFormElement) {
    if (!check.ok || !baseSha) return;
    const f = new FormData(form);
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch("/api/scoring", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({
        admin_passcode: f.get("admin_passcode"), actor: f.get("actor"), reason: f.get("reason"),
        factors: check.value.factors, thresholds: check.value.thresholds, base_sha: baseSha }) });
      const data = (await res.json().catch(() => ({}))) as { error?: string; version?: number; commit?: { commit_url: string } };
      if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`);
      setMsg({ ok: true, text: `已儲存為第 ${data.version} 版，下一次評估起生效。`, url: data.commit?.commit_url });
      router.refresh();
    } catch (e) {
      setMsg({ ok: false, text: `儲存失敗：${(e as Error).message}` });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="panel weights" onSubmit={(e) => { e.preventDefault(); void save(e.currentTarget); }}>
      <h2>調整權重</h2>
      <div className="table-wrap"><table>
        <thead><tr><th>加分因子</th><th>預設</th><th>已儲存</th><th>新值</th></tr></thead>
        <tbody>
          {FACTOR_KEYS.map((k) => {
            const l = LIMITS.factors[k];
            return (
              <tr key={k}>
                <td><label htmlFor={`f-${k}`}>{l.label}</label><div className="muted">{l.hint}</div></td>
                <td>{l.default}</td><td>{saved.factors[k]}</td>
                <td><input id={`f-${k}`} type="number" step={1} min={l.min} max={l.max} value={w.factors[k]} onChange={(e) => setFactor(k, e.target.value)} /></td>
              </tr>
            );
          })}
          {(["high", "medium"] as const).map((k) => (
            <tr key={k}>
              <td><label htmlFor={`t-${k}`}>{LIMITS.thresholds[k].label}</label><div className="muted">分數達到這個值就算{k === "high" ? "高" : "中"}風險</div></td>
              <td>{LIMITS.thresholds[k].default}</td><td>{saved.thresholds[k]}</td>
              <td><input id={`t-${k}`} type="number" step={1} min={k === "medium" ? LIMITS.thresholds.medium.min : 2} max={LIMITS.thresholds[k].max}
                value={w.thresholds[k]} onChange={(e) => setThreshold(k, e.target.value)} /></td>
            </tr>
          ))}
        </tbody>
      </table></div>
      {!check.ok && <p className="lv-high" role="alert">{check.error}</p>}

      {p && (
        <div className="weights-preview" aria-live="polite">
          <h3>試算（以最新每日評估重新加總）</h3>
          <TrafficLight light={p.light} size="small" />
          <p>高風險 {current.counts.high} → <strong>{p.counts.high}</strong>｜中風險 {current.counts.medium} → <strong>{p.counts.medium}</strong>｜
            低風險 {current.counts.low} → <strong>{p.counts.low}</strong></p>
          <p className="muted">只看風險分數；早期訊號、可見度不足、即時告警等其他原因可能讓實際燈號更高（目前實際燈號為
            {current.light === "red" ? "紅燈" : current.light === "yellow" ? "黃燈" : "綠燈"}）。規則下限（例如影子 IT）與暫定情資上限不受權重影響。</p>
          {p.changed.length > 0 && <details><summary>{p.changed.length} 項風險的等級會改變</summary>
            <ul>{p.changed.slice(0, 30).map((c) => <li key={c.id}>{c.title}：{LEVEL_TEXT[c.from]} → {LEVEL_TEXT[c.to]}</li>)}</ul></details>}
        </div>
      )}

      <div className="run-form">
        <button type="button" onClick={() => setW(DEFAULT_WEIGHTS)}>填入預設值</button>
        <button type="button" disabled={!dirty} onClick={() => setW(saved)}>放棄修改</button>
      </div>
      <div className="weights-save">
        <label>操作人 <input name="actor" required maxLength={40} autoComplete="name" /></label>
        <label>調整理由（4～200 字） <input name="reason" required minLength={4} maxLength={200} /></label>
        <label>管理者密碼 <input name="admin_passcode" type="password" required autoComplete="current-password" /></label>
        <button type="submit" className="primary" disabled={busy || !check.ok || !dirty || !baseSha}>{busy ? "儲存中…" : "儲存（下一次評估生效）"}</button>
        {!baseSha && <p className="warn">目前無法讀取已儲存的設定，暫時不能儲存。</p>}
        {msg && <p role="status" className={msg.ok ? undefined : "lv-high"}>{msg.text} {msg.url && <a href={msg.url} target="_blank" rel="noreferrer">查看這次的 commit</a>}</p>}
      </div>
    </form>
  );
}
