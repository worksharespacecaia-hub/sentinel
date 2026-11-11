// 資安事件整理：近 30 天外部資安事件，依收錄日期整理，標示與我們的關係與資料更新時間（specs/security-digest）。
// 只讀 public/data/digest/latest.json 與目前的 daily 報告／明細；網站沒有任何更新整理或調整頻率的控制項（R4.2）。
import { getDigestView } from "@/lib/data";
import type { DigestView } from "@/lib/digest";
import { PAGES } from "@/lib/nav";
import DigestList from "@/components/DigestList";

export const dynamic = "force-dynamic";
export const metadata = { title: `${PAGES.digest.label}｜Sentinel` };

export default async function DigestPage() {
  const page = await getDigestView(new Date());
  return (
    <div className="digest">
      <h1>{PAGES.digest.label}</h1>
      <p className="muted">近 30 天外部資安事件，以及和我們有沒有關係。</p>
      {page.status === "missing" && <div className="panel">整理尚未產生，將於下次每日評估後出現。</div>}
      {page.status === "invalid" && <div className="panel warn">整理資料格式無法辨識，暫時無法顯示；請工程團隊檢查最新一次每日評估的資料狀態。</div>}
      {page.status === "ok" && <DigestBody view={page.view} />}
    </div>
  );
}

function DigestBody({ view }: { view: DigestView }) {
  const c = view.counts;
  return (
    <>
      <section className="panel digest-meta" aria-label="更新資訊">
        <p>最後更新 <strong>{view.updatedText}</strong>｜更新頻率 每天一次｜下次預定更新 {view.nextUpdateText}（GitHub 排程可能延遲）</p>
        {view.staleText && <p className="warn" role="status">注意：{view.staleText}</p>}
        {view.news && <p className="warn" role="status">{view.news.text}</p>}
        {view.capacityOmitted > 0 && (
          <p className="warn">因容量上限，近 30 天有 {view.capacityOmitted} 件事件未列入整理；下方件數只計算畫面上保留的事件。</p>
        )}
      </section>

      <p className="digest-counts">近 30 天 <strong>{c.total}</strong> 件，
        受影響 <strong className={c.affected ? "lv-high" : undefined}>{c.affected}</strong> 件、
        需確認 <strong className={c.need_check ? "warn" : undefined}>{c.need_check}</strong> 件</p>

      {c.total === 0 ? <div className="panel">近 30 天沒有收錄的外部資安事件。</div> : <DigestList days={view.days} />}

      {view.issues.length > 0 && <p className="muted digest-issues">資料狀態：{view.issues.join("；")}</p>}
      <p className="muted">「與我們的關係」取自每件事件最近一次完整的每日評估；「上次評估於」表示該結論不是這次重新確認的。</p>
    </>
  );
}
