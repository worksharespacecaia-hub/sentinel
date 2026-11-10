import Link from "next/link";
import type { Light, Level, Risk, Source } from "@/lib/data";
import { LIGHT_TEXT, LEVEL_TEXT, STATUS_TEXT, SOURCE_TEXT, deadlineText } from "@/lib/labels";

export function LightBadge({ light, label }: { light: Light; label?: string }) {
  return <span className={`light ${light}`} aria-label={LIGHT_TEXT[light]}>{label ?? LIGHT_TEXT[light]}</span>;
}

const LAMPS: Light[] = ["red", "yellow", "green"];
const LAMP_NAME: Record<Light, string> = { red: "紅", yellow: "黃", green: "綠" };

/** 紅黃綠三顆燈，亮目前燈號、其他變暗；旁邊一定附文字（燈號不能只靠顏色）。 */
export function TrafficLight({ light, size = "large" }: { light: Light; size?: "large" | "small" }) {
  return (
    <div className={`traffic-light ${size}`} role="img" aria-label={LIGHT_TEXT[light]}>
      <div className="lamps" aria-hidden="true">
        {LAMPS.map((l) => (
          <span key={l} className={`lamp ${l}${l === light ? " on" : ""}`}><span className="lamp-name">{LAMP_NAME[l]}</span></span>
        ))}
      </div>
      <strong className={`lamp-text ${light}`}>{LIGHT_TEXT[light]}</strong>
    </div>
  );
}

export function LevelText({ level }: { level: Level | null | undefined }) {
  if (!level) return <span className="muted">—</span>;
  return <span className={`lv-${level}`}>{LEVEL_TEXT[level]}</span>;
}

export function SourceSwitcher({ current, sources, path }: { current: string; sources: { key: string; label: string }[]; path: string }) {
  return (
    <p className="muted">
      資料來源：{sources.map((s) => (
        <span key={s.key}>
          {s.key === current ? <strong className="tag">{s.label}</strong>
            : <Link className="tag" href={s.key === "daily" ? path : `${path}?source=${encodeURIComponent(s.key)}`}>{s.label}</Link>}
        </span>
      ))}
    </p>
  );
}

export function SimNotice({ source }: { source: Source }) {
  if (!source.simulated) return null;
  return <div className="panel sim">模擬情境「{source.key}」：結果只影響此畫面，不改變正式燈號。</div>;
}

export function RiskRow({ r }: { r: Risk }) {
  return (
    <tr>
      <td><LevelText level={r.level} />（{r.score} 分）</td>
      <td>{r.title}<div className="muted">{r.asset_id}</div></td>
      <td>{deadlineText(r.deadline_hours)}</td>
      <td>{STATUS_TEXT[r.status] ?? r.status}</td>
    </tr>
  );
}

export function RiskDetail({ r }: { r: Risk }) {
  return (
    <details className="panel">
      <summary><LevelText level={r.level} />（{r.score} 分）{r.title} <span className="muted">｜{STATUS_TEXT[r.status]}｜{deadlineText(r.deadline_hours)}</span></summary>
      <p className="muted">資產：{r.asset_id}；等級說明：{r.level_reason}；分數等級 {LEVEL_TEXT[r.score_level]}，原始分數 {r.raw_score}</p>
      <div className="table-wrap"><table>
        <thead><tr><th>因子</th><th>加減分</th><th>原因</th></tr></thead>
        <tbody>{r.breakdown.map((b, i) => <tr key={i}><td>{b.factor}</td><td>{b.points > 0 ? `+${b.points}` : b.points}</td><td>{b.reason}</td></tr>)}</tbody>
      </table></div>
      {r.attack_path && <p>攻擊鏈：{r.attack_path.join(" → ")}</p>}
      {r.matched_events.length > 0 && <p>命中的事件：{r.matched_events.map((e) => <span key={e} className="tag">{e}</span>)}</p>}
      {r.explanation && <p>說明：{r.explanation} <span className="muted">（{SOURCE_TEXT[r.explanation_source ?? "template"]}）</span></p>}
      {r.solution && (
        <>
          <p><strong>暫時緩解：</strong>{r.solution.temporary}</p>
          <p><strong>根本修復：</strong>{r.solution.permanent}</p>
          <div className="table-wrap"><table>
            <thead><tr><th>選項</th><th>做法</th><th>代價</th><th>時效</th></tr></thead>
            <tbody>{r.solution.options.map((o, i) => <tr key={i}><td>{o.name}</td><td>{o.action}</td><td>{o.cost}</td><td>{o.timing}</td></tr>)}</tbody>
          </table></div>
          <p className="muted">建議負責團隊：{r.solution.suggested_owner ?? "—"}；驗證方式：{r.solution.verify}；文字來源：{SOURCE_TEXT[r.solution.source]}。系統只建議，不執行。</p>
        </>
      )}
    </details>
  );
}
