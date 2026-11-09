export default function Live() {
  return (
    <>
      <h1>即時監控</h1>
      <div className="panel">
        <p>即時規則層（非 Pipeline 部署告警、攻擊模擬器、告警時間軸）在 Phase 6 加入。</p>
        <p className="muted">規則判斷不使用 LLM；告警後才觸發圍堵建議流程。</p>
      </div>
    </>
  );
}
