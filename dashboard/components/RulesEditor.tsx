"use client";
// 偵測規則編輯：只能調整 lib/rule-settings.ts 開放的參數；儲存需操作人、理由與管理者密碼，寫回 GitHub 並更新 Redis，數秒內生效。
import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import type { Rule } from "@/lib/rules";
import { editableFields, fixedConditions, validateOverrides, type FieldSpec, type FieldValue } from "@/lib/rule-settings";

type Values = Record<string, Record<string, FieldValue>>;

interface Props {
  defaults: Rule[]; saved: Values; baseSha: string | null; canSave: boolean;
}

const SOURCE_TEXT: Record<string, string> = {
  "github.deployment": "GitHub 部署紀錄", "db.audit": "資料庫稽核日誌", "support.complaint": "客服客訴",
};

function fmt(f: FieldSpec, v: FieldValue | undefined): string {
  if (v === undefined) return "—";
  if (f.kind === "bool") return v ? "啟用" : "停用";
  if (f.kind === "choice") return f.choices?.find((c) => c.value === v)?.label ?? String(v);
  if (f.kind === "hours") return `${(v as number[])[0]}～${(v as number[])[1]} 時`;
  if (f.kind === "logins") return (v as string[]).join("、");
  return String(v);
}

function FieldInput({ f, id, value, onChange }: { f: FieldSpec; id: string; value: FieldValue; onChange: (v: FieldValue) => void }) {
  switch (f.kind) {
    case "bool":
      return <input id={id} type="checkbox" checked={value as boolean} onChange={(e) => onChange(e.target.checked)} />;
    case "choice":
      return (
        <select id={id} value={value as string} onChange={(e) => onChange(e.target.value)}>
          {f.choices?.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
        </select>
      );
    case "hours": {
      const [a, b] = value as [number, number];
      return (
        <span>
          <input id={id} aria-label={`${f.label} 開始`} type="number" min={0} max={23} step={1} value={a}
            onChange={(e) => onChange([Number(e.target.value), b])} /> 時 ～{" "}
          <input aria-label={`${f.label} 結束`} type="number" min={1} max={24} step={1} value={b}
            onChange={(e) => onChange([a, Number(e.target.value)])} /> 時
        </span>
      );
    }
    case "logins":
      return <textarea id={id} rows={3} value={(value as string[]).join("\n")}
        onChange={(e) => onChange(e.target.value.split("\n").map((x) => x.trim()).filter(Boolean))} />;
    default:
      return <input id={id} type="number" min={f.min} max={f.max} step={f.step} value={value as number}
        onChange={(e) => onChange(e.target.value === "" ? Number.NaN : Number(e.target.value))} />;
  }
}

export default function RulesEditor({ defaults, saved, baseSha, canSave }: Props) {
  const router = useRouter();
  const [values, setValues] = useState<Values>(saved);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string; url?: string } | null>(null);
  const check = useMemo(() => validateOverrides(values, defaults), [values, defaults]);
  const savedCheck = useMemo(() => validateOverrides(saved, defaults), [saved, defaults]);
  const dirty = JSON.stringify(values) !== JSON.stringify(saved);
  const changedCount = check.ok ? Object.values(check.value).reduce((n, o) => n + Object.keys(o).length, 0) : 0;

  const set = (ruleId: string, key: string, v: FieldValue) => setValues({ ...values, [ruleId]: { ...values[ruleId], [key]: v } });
  const resetDefaults = () => setValues(Object.fromEntries(defaults.map((r) => [r.id,
    Object.fromEntries(editableFields(r).map((f) => [f.key, f.get(r)]))])));

  async function save(form: HTMLFormElement) {
    if (!check.ok || !canSave) return;
    const f = new FormData(form);
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch("/api/rules", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({
        admin_passcode: f.get("admin_passcode"), actor: f.get("actor"), reason: f.get("reason"), rules: values, base_sha: baseSha }) });
      const data = (await res.json().catch(() => ({}))) as { error?: string; version?: number; commit_url?: string; note?: string };
      if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`);
      setMsg({ ok: true, text: `已儲存為第 ${data.version} 版。${data.note ?? ""}`, url: data.commit_url });
      router.refresh();
    } catch (e) {
      setMsg({ ok: false, text: `儲存失敗：${(e as Error).message}` });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); void save(e.currentTarget); }}>
      {defaults.map((rule) => {
        const fields = editableFields(rule);
        const fixed = fixedConditions(rule);
        const on = values[rule.id]?.enabled !== false;
        return (
          <div className="panel" key={rule.id}>
            <h2 style={{ marginTop: 0 }}>{rule.id} {rule.title}{!on && <span className="tag">已停用</span>}</h2>
            <p className="muted">資料來源：{SOURCE_TEXT[rule.source] ?? rule.source}｜資產：{rule.asset_key}
              {fixed.length > 0 && <>｜固定條件（要改 rules/realtime.yaml）：{fixed.join("；")}</>}</p>
            <div className="table-wrap"><table>
              <thead><tr><th>參數</th><th>預設</th><th>已儲存</th><th>新值</th></tr></thead>
              <tbody>{fields.map((f) => {
                const id = `${rule.id}-${f.key}`;
                return (
                  <tr key={f.key}>
                    <td><label htmlFor={id}>{f.label}</label><div className="muted">{f.help}</div></td>
                    <td>{fmt(f, f.get(rule))}</td>
                    <td>{fmt(f, saved[rule.id]?.[f.key])}</td>
                    <td><FieldInput f={f} id={id} value={values[rule.id]?.[f.key] ?? f.get(rule)} onChange={(v) => set(rule.id, f.key, v)} /></td>
                  </tr>
                );
              })}</tbody>
            </table></div>
          </div>
        );
      })}

      <div className="panel">
        {!check.ok && <p className="lv-high" role="alert">{check.error}</p>}
        {check.ok && <p className="muted">與預設值不同的參數：{changedCount} 項{savedCheck.ok && !dirty ? "（已儲存）" : ""}。調高門檻或縮短時段後，攻擊模擬器的預設情境可能不再命中。</p>}
        <div className="run-form">
          <button type="button" onClick={resetDefaults}>全部填入預設值</button>
          <button type="button" disabled={!dirty} onClick={() => setValues(saved)}>放棄修改</button>
        </div>
        <div className="weights-save">
          <label>操作人 <input name="actor" required maxLength={40} autoComplete="name" /></label>
          <label>調整理由（4～200 字） <input name="reason" required minLength={4} maxLength={200} /></label>
          <label>管理者密碼 <input name="admin_passcode" type="password" required autoComplete="current-password" /></label>
          <button type="submit" className="primary" disabled={busy || !check.ok || !dirty || !canSave}>{busy ? "儲存中…" : "儲存（數秒內生效）"}</button>
          {!canSave && <p className="warn">目前無法讀取已儲存的設定，暫時不能儲存。</p>}
          {msg && <p role="status" className={msg.ok ? undefined : "lv-high"}>{msg.text} {msg.url && <a href={msg.url} target="_blank" rel="noreferrer">查看這次的 commit</a>}</p>}
        </div>
      </div>
    </form>
  );
}
