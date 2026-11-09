"use client";
import Link from "next/link";
import { useMemo, useState } from "react";
import type { EventSummary } from "@/lib/data";

const KIND: Record<string, string> = { live: "真實", archive: "真實・已收錄", demo: "示範", advisory: "公告" };
const STATUS: Record<string, string> = { open: "受影響", fixed: "已修復", not_affected: "不受影響", need_check: "需確認" };
const LEVEL: Record<string, string> = { high: "高", medium: "中", low: "低" };

export default function IntelList({ events, sourceQuery }: { events: EventSummary[]; sourceQuery: string }) {
  const [kind, setKind] = useState("all");
  const [status, setStatus] = useState("all");
  const rows = useMemo(() => events.filter((e) =>
    (kind === "all" || (kind === "demo" ? e.demo : !e.demo)) && (status === "all" || e.status === status)), [events, kind, status]);
  return (
    <>
      <p>
        <label>類型 <select value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="all">全部</option><option value="real">真實</option><option value="demo">示範</option></select></label>{" "}
        <label>結論 <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="all">全部</option><option value="open">受影響</option><option value="not_affected">不受影響</option>
          <option value="need_check">需確認</option><option value="fixed">已修復</option></select></label>
      </p>
      <div className="table-wrap"><table>
        <thead><tr><th>事件</th><th>類型</th><th>受影響項目</th><th>最高等級</th><th>處理狀態</th></tr></thead>
        <tbody>{rows.map((e) => (
          <tr key={e.id}>
            <td><Link href={`/intel/${e.id}${sourceQuery}`}>{e.title}</Link></td>
            <td><span className="tag">{KIND[e.kind] ?? e.kind}</span></td>
            <td>{e.affected_count}</td>
            <td>{e.max_level ? <span className={`lv-${e.max_level}`}>{LEVEL[e.max_level]}</span> : "—"}</td>
            <td>{STATUS[e.status] ?? e.status}</td>
          </tr>))}
        </tbody>
      </table></div>
      {rows.length === 0 && <p className="muted">沒有符合條件的事件。</p>}
    </>
  );
}
