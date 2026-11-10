import { getIndex, getIntelWatch } from "@/lib/data";
import { fmtTime } from "@/lib/labels";
import { PAGES } from "@/lib/nav";

export const dynamic = "force-dynamic";

const TRIGGERS = [
  ["① CI/CD 把關", "每次 PR、每次部署", "完整掃描變更，高風險擋下 PR；部署時產出 SBOM", "不用 LLM"],
  ["② 事件觸發", "每小時輪詢公告", "新情資比對已存的 SBOM 與圖譜，命中才深入調查", "第 1 層不用 LLM"],
  ["③ 每日例行", "每天 08:00", "用最新情資重新評估全部資產，檢查不隨程式碼變動的項目", "只處理差異"],
  ["④ 即時規則", "事件一出現", "非 Pipeline 部署、凌晨大量讀取、多品牌詐騙回報 → 秒級告警", "告警後才產生圍堵建議"],
];

export default async function Triggers() {
  const [idx, watch] = await Promise.all([getIndex(), getIntelWatch()]);
  return (
    <>
      <h1>{PAGES.triggers.label}</h1>
      <div className="panel table-wrap"><table>
        <thead><tr><th>觸發</th><th>時機</th><th>做什麼</th><th>LLM</th></tr></thead>
        <tbody>{TRIGGERS.map((t) => <tr key={t[0]}>{t.map((c, i) => <td key={i}>{c}</td>)}</tr>)}</tbody>
      </table><p className="muted">單靠任一種都會漏：程式碼沒變但新公布漏洞、不走 CI/CD 的設備、45 分鐘就爆量的攻擊。</p></div>
      <div className="panel">
        <h2 style={{ marginTop: 0 }}>③ 每日執行</h2>
        <p>最近一次：{idx.latest_daily ? `${fmtTime(idx.latest_daily.generated_at)}（${idx.latest_daily.run_id}，${idx.latest_daily.completeness}）` : "尚未執行"}</p>
        <p className="muted">最近一次完整評估：{idx.latest_complete_daily ? fmtTime(idx.latest_complete_daily.generated_at) : "—"}</p>
      </div>
      <div className="panel">
        <h2 style={{ marginTop: 0 }}>② 公告輪詢</h2>
        {watch ? <>
          <p>最近檢查：{fmtTime(watch.checked_at)}；已檢查 {watch.advisories_checked} 則，命中 {watch.hits?.length ?? 0} 則</p>
          <ul>{(watch.items ?? []).map((i: any) => <li key={i.input_hash ?? i.advisory_id}>{i.advisory_id}：{i.status}／{i.verdict ?? ""}（{i.reason}）</li>)}</ul>
        </> : <p className="muted">尚未執行公告輪詢。</p>}
        <p className="muted">正式公告調查：{Object.keys(idx.advisories ?? {}).join("、") || "無"}</p>
      </div>
      <div className="panel"><h2 style={{ marginTop: 0 }}>① PR 把關／④ 即時告警</h2>
        <p className="muted">PR 把關結果在 Repo ① 的 Pull Request 頁面；即時告警見「{PAGES.live.label}」與 GitHub Issues。</p></div>
    </>
  );
}
