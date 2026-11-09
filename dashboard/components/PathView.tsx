"use client";
import { useState } from "react";

interface Path { id: string; nodes: string[]; assumption: string | null; steps: { from: string; to: string; kind: string; finding_ids: string[] }[] }
type Node = Record<string, any>;

const KIND: Record<string, string> = { exploit: "利用弱點", download: "下載安裝檔", read_secret: "取得金鑰", authorize: "以金鑰存取", api_data_access: "API 讀取資料" };

export default function PathView({ paths, nodes }: { paths: Path[]; nodes: Record<string, Node> }) {
  const [sel, setSel] = useState<string | null>(null);
  const node = sel ? nodes[sel] : null;
  return (
    <>
      {paths.map((p) => (
        <div key={p.id} className="panel">
          {p.assumption && <p className="muted">{p.assumption}</p>}
          <div className="chain">
            {p.nodes.map((n, i) => (
              <span key={`${p.id}-${i}`} style={{ display: "contents" }}>
                {i > 0 && <span className="arrow">→ <span className="muted">{KIND[p.steps.find((s) => s.to === n)?.kind ?? ""] ?? ""}</span> →</span>}
                <button type="button" className={`node ${nodes[n]?.crown_jewel ? "crown" : ""}`} onClick={() => setSel(n)}>{n}</button>
              </span>
            ))}
          </div>
          <p className="muted">必要步驟的發現：{[...new Set(p.steps.flatMap((s) => s.finding_ids))].join("、") || "—"}</p>
        </div>
      ))}
      {node && (
        <div className="panel">
          <h2 style={{ marginTop: 0 }}>{node.id}</h2>
          <ul>
            <li>類型：{node.type}；環境：{node.env ?? "—"}；負責人：{node.owner ?? "未登記"}</li>
            <li>已登記：{node.registered ? "是" : "否"}；經 CI/CD：{node.deployed_via_ci == null ? "不適用" : node.deployed_via_ci ? "是" : "否"}；對外：{node.exposed_to_internet ? "是" : "否"}</li>
            {node.crown_jewel && <li className="lv-high">核心資產</li>}
            {(node.components ?? []).length > 0 && <li>元件：{node.components.map((c: any) => `${c.name} ${c.version ?? "版本未知"}`).join("、")}</li>}
            {node.scope && <li>權限範圍：{node.scope}；狀態：{node.status}</li>}
          </ul>
        </div>
      )}
    </>
  );
}
