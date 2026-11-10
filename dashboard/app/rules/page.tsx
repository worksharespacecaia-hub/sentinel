// 偵測規則：說明異常行為偵測的每條規則，讓管理者調整開放的參數（啟用、等級、時段、時間窗、門檻、允許的部署者）。
// 儲存寫回 GitHub（一個 commit，記操作人與理由）並更新 Redis，數秒內生效；正規表示式、資料表與新規則類型要改 rules/realtime.yaml。
import Link from "next/link";
import { fmtTime } from "@/lib/labels";
import { PAGES } from "@/lib/nav";
import { loadRuleSettingsState } from "@/lib/rule-store";
import { editableFields, type FieldValue } from "@/lib/rule-settings";
import { RULES } from "@/lib/rules";
import RulesEditor from "@/components/RulesEditor";

export const dynamic = "force-dynamic";
export const metadata = { title: `${PAGES.rules.label}｜Sentinel` };

export default async function RulesPage() {
  const state = await loadRuleSettingsState();
  const active = new Map(state.active.rules.map((r) => [r.id, r]));
  // 已儲存的值：以目前生效的規則為準（GitHub 與 Redis 一致時兩者相同）
  const saved = Object.fromEntries(RULES.map((rule) => {
    const eff = active.get(rule.id) ?? { ...rule, enabled: true };
    return [rule.id, Object.fromEntries(editableFields(rule).map((f) => [f.key, f.get(eff)])) as Record<string, FieldValue>];
  }));
  const canSave = state.configured && !state.error;
  const live = state.active;

  return (
    <>
      <h1>{PAGES.rules.label}</h1>
      <div className="panel">
        <p>這些規則決定「<Link href={PAGES.live.href}>{PAGES.live.label}</Link>」什麼時候告警。判斷全由程式依規則執行，不使用 AI，
          所以快而且結果固定；沒有寫成規則的異常不會被發現。</p>
        <p className="muted">調整需要管理者密碼，每次儲存都在 GitHub 留下一筆 commit（操作人與理由），並同步到 Redis，數秒內生效，不必重新部署。
          網站只開放調整參數；正規表示式、資料表、資料來源與新的規則類型需要改 <code>rules/realtime.yaml</code> 並經過程式審查。</p>
      </div>

      <div className="panel">
        <h2>目前狀態</h2>
        <ul>
          <li>偵測實際使用：{live.source === "settings" ? `第 ${live.version} 版設定` : "預設規則（尚未調整過）"}
            {state.settings?.updated_by && `（${state.settings.updated_by}，${fmtTime(state.settings.updated_at)}）`}</li>
          <li>已啟用 {live.rules.filter((r) => r.enabled).length} 條，停用 {live.rules.filter((r) => !r.enabled).length} 條</li>
        </ul>
        {state.error && <p className="warn">{state.error}</p>}
        {state.configured && !state.error && !state.in_sync && <p className="warn">偵測使用的設定與 GitHub 上的紀錄不一致，請重新整理本頁；仍不一致時檢查 Redis 設定。</p>}
        {live.warnings.length > 0 && <ul className="warn">{live.warnings.map((w) => <li key={w}>{w}</li>)}</ul>}
      </div>

      <RulesEditor defaults={RULES} saved={saved} baseSha={state.sha} canSave={canSave} />

      <div className="panel">
        <h2>調整歷史</h2>
        {state.history.length === 0 ? <p className="muted">{state.configured ? "尚無紀錄（目前使用預設規則）。" : state.error}</p> : (
          <ul>{state.history.map((c) => (
            <li key={c.sha}><a href={c.url} target="_blank" rel="noreferrer">{c.sha}</a>｜{fmtTime(c.date)}｜{c.message.split("\n")[0]}
              {c.message.includes("理由：") && <div className="muted">{c.message.split("理由：")[1].split("\n")[0]}</div>}</li>))}</ul>
        )}
      </div>
    </>
  );
}
