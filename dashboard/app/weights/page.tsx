// 燈號權重：說明分數怎麼算、顯示目前燈號用的是哪一版權重、讓管理者調整並試算。正式分數與燈號仍由評估流程計算。
import Link from "next/link";
import { getReport, resolveSource } from "@/lib/data";
import { fmtTime } from "@/lib/labels";
import { PAGES } from "@/lib/nav";
import { DEFAULT_WEIGHTS, FACTOR_KEYS, LIMITS, type Weights } from "@/lib/scoring";
import { loadScoringState } from "@/lib/scoring-store";
import WeightsEditor from "@/components/WeightsEditor";

export const dynamic = "force-dynamic";
export const metadata = { title: `${PAGES.weights.label}｜Sentinel` };

const same = (a: Weights, b: Weights) =>
  FACTOR_KEYS.every((k) => a.factors[k] === b.factors[k]) && a.thresholds.high === b.thresholds.high && a.thresholds.medium === b.thresholds.medium;

export default async function WeightsPage() {
  const [report, state] = await Promise.all([getReport(await resolveSource(undefined)), loadScoringState()]);
  const used: Weights = report?.scoring
    ? { factors: { ...DEFAULT_WEIGHTS.factors, ...report.scoring.factors }, thresholds: report.scoring.thresholds }
    : DEFAULT_WEIGHTS;
  const saved: Weights = state.config ?? used;
  const pending = Boolean(state.config && !same(state.config, used));
  const risks = (report?.risks ?? []).map((r) => ({ id: r.id, title: r.title, status: r.status, score: r.score, level: r.level,
    score_level: r.score_level, level_reason: r.level_reason, breakdown: r.breakdown, level_floor: r.level_floor, provisional_basis: r.provisional_basis }));

  return (
    <>
      <h1>{PAGES.weights.label}</h1>
      <div className="panel">
        <p>風險分數＝基礎分（漏洞嚴重度或控制項）＋下列加分因子。分數達到<strong>高風險門檻</strong>就是高風險，有任何一項高風險就是紅燈；
          達到<strong>中風險門檻</strong>就是中風險（黃燈）。目前預設：高 ≥ {LIMITS.thresholds.high.default}、中 ≥ {LIMITS.thresholds.medium.default}。</p>
        <p className="muted">燈號一律由每日評估程式計算；這裡只調整計算用的權重。調整需要管理者密碼，會在 GitHub 留下一筆 commit（操作人與理由），
          從下一次評估（每天 08:00、公告觸發或到「<Link href={PAGES.runs.href}>{PAGES.runs.label}</Link>」手動執行 daily）起生效。
          規則下限（例如未登記的對外系統至少高風險）與暫定情資上限不受權重影響。</p>
      </div>

      <div className="panel">
        <h2>目前狀態</h2>
        <ul>
          <li>目前燈號使用的權重：{report?.scoring ? `第 ${report.scoring.version || "—"} 版${report.scoring.is_default ? "（預設）" : `（${report.scoring.updated_by ?? "—"}，${fmtTime(report.scoring.updated_at)}）`}` : "預設（這份評估早於權重設定功能）"}
            ，評估時間 {fmtTime(report?.generated_at)}</li>
          <li>已儲存的最新版本：{state.config ? `第 ${state.config.version} 版${state.config.updated_by ? `（${state.config.updated_by}，${fmtTime(state.config.updated_at)}）` : "（預設）"}` : state.error ?? "—"}</li>
        </ul>
        {pending && <p className="warn">已儲存的權重還沒套用到燈號：下一次評估起生效。要立即套用，請到「{PAGES.runs.label}」執行 daily。</p>}
      </div>

      <WeightsEditor saved={saved} baseSha={state.sha} risks={risks}
        current={{ counts: report?.counts ?? { high: 0, medium: 0, low: 0 }, light: report?.light ?? "yellow" }} />

      <div className="panel">
        <h2>調整歷史</h2>
        {state.history.length === 0 ? <p className="muted">{state.configured ? "尚無紀錄。" : state.error}</p> : (
          <ul>{state.history.map((c) => (
            <li key={c.sha}><a href={c.url} target="_blank" rel="noreferrer">{c.sha}</a>｜{fmtTime(c.date)}｜{c.message.split("\n")[0]}
              {c.message.includes("理由：") && <div className="muted">{c.message.split("理由：")[1].split("\n")[0]}</div>}</li>))}</ul>
        )}
      </div>
    </>
  );
}
