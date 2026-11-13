"use client";

// 運作原理頁的整體架構圖：桌機橫向、手機直式，內容相同。
// 有 Subagent 的方塊右上角顯示數量，點一下（或 Enter／空白鍵）在方塊旁顯示 Subagent 清單。
// 顏色全走 globals.css 的 .arch-svg 類別（跟著淺色／深色主題）。

import { useEffect, useRef, useState, type CSSProperties, type KeyboardEvent } from "react";
import SubagentMap, { SubagentList } from "@/components/SubagentMap";
import { AGENT_SUBAGENTS, SDK_SUBAGENT_COUNT, type AgentKey } from "@/lib/subagents";

type Rect = { x: number; y: number; w: number; h: number };
type Variant = "w" | "n";
type Layout = { W: number; H: number; boxes: Record<AgentKey, Rect> };

// 流程：開工路由（程式）→ A0 →（只在 ③：每日情資）→ A1 → Orchestrator 派工（AI）→ A2、A3 → A4 → Orchestrator 驗收（AI）→ A5
const WIDE: Layout = {
  W: 1120, H: 560, boxes: {
    a0: { x: 290, y: 196, w: 96, h: 64 },
    a1: { x: 404, y: 196, w: 96, h: 64 },
    a2: { x: 520, y: 196, w: 84, h: 40 },
    a3: { x: 520, y: 244, w: 84, h: 40 },
    a4: { x: 628, y: 196, w: 92, h: 88 },
    a5: { x: 736, y: 196, w: 84, h: 88 },
    daily: { x: 350, y: 292, w: 150, h: 56 },
    incident: { x: 504, y: 460, w: 312, h: 56 },
  },
};

const NARROW: Layout = {
  W: 320, H: 828, boxes: {
    a0: { x: 20, y: 176, w: 280, h: 44 },
    daily: { x: 156, y: 236, w: 144, h: 44 },
    a1: { x: 20, y: 296, w: 128, h: 44 },
    a2: { x: 20, y: 356, w: 134, h: 44 },
    a3: { x: 166, y: 356, w: 134, h: 44 },
    a4: { x: 20, y: 416, w: 128, h: 44 },
    a5: { x: 20, y: 476, w: 156, h: 56 },
    incident: { x: 20, y: 548, w: 128, h: 44 },
  },
};

type Pick = { open: AgentKey | null; toggle: (k: AgentKey, el: Element) => void };

function Lines({ x, y, w, h, lines }: Rect & { lines: string[] }) {
  const cx = x + w / 2;
  const blockH = 14 + 20 * (lines.length - 1);
  const first = y + h / 2 - blockH / 2 + 12;
  return (
    <>
      {lines.map((line, i) => (
        <text key={i} className={i === 0 ? "t" : "s"} x={cx} y={first + i * 20} textAnchor="middle">
          {line}
        </text>
      ))}
    </>
  );
}

type BoxProps = Rect & { lines: string[]; cls?: string; rx?: number };

function Box({ cls = "box", rx = 8, ...p }: BoxProps) {
  return (
    <g>
      <rect className={cls} x={p.x} y={p.y} width={p.w} height={p.h} rx={rx} />
      <Lines {...p} />
    </g>
  );
}

/** 有 Subagent 的方塊：右上角數量徽章，可點擊展開 */
function AgentBox({ k, layout, variant, pick, lines, cls = "box" }: {
  k: AgentKey; layout: Layout; variant: Variant; pick: Pick; lines: string[]; cls?: string;
}) {
  const r = layout.boxes[k];
  const info = AGENT_SUBAGENTS[k];
  const on = pick.open === k;
  const onKey = (e: KeyboardEvent<SVGGElement>) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick.toggle(k, e.currentTarget); }
  };
  return (
    <g className={`hit${on ? " on" : ""}`} role="button" tabIndex={0} aria-expanded={on} aria-controls={`arch-pop-${variant}`}
      aria-label={`${info.id} ${info.title}：${info.subs.length} 個 Subagent`}
      onClick={(e) => pick.toggle(k, e.currentTarget)} onKeyDown={onKey}>
      <rect className={cls} x={r.x} y={r.y} width={r.w} height={r.h} rx={8} />
      <Lines {...r} lines={lines} />
      <circle className="badge" cx={r.x + r.w - 8} cy={r.y} r={9} />
      <text className="badge-t" x={r.x + r.w - 8} y={r.y + 4} textAnchor="middle">{info.subs.length}</text>
    </g>
  );
}

function Markers({ id }: { id: string }) {
  return (
    <defs>
      <marker id={`${id}-a`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
        <path className="head" d="M0 0L10 5L0 10z" />
      </marker>
      <marker id={`${id}-r`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5.5" markerHeight="5.5" orient="auto-start-reverse">
        <path className="head ro" d="M0 0L10 5L0 10z" />
      </marker>
    </defs>
  );
}

const CLAIM =
  "外部情資每小時比對、每天 08:00 全面評估：開工路由依觸發來源決定流程，盤點系統後，" +
  "每天 08:00 另由每日情資判讀當天新聞交給外部情資；驗證情資後，" +
  "由 Orchestrator（AI）依當天情資派工，接著找弱點、查早期訊號、推演入侵路徑並評分，" +
  "Orchestrator 再看結果驗收、追加後續，最後把燈號與建議發布到網站；分析流程只讀取電商平台、不修改。" +
  "部署、資料庫稽核、客訴等即時事件由網站規則直接判斷並告警，再觸發告警調查。有 Subagent 的方塊可以點開查看。";

/** 點開後的小卡：上半部的方塊往下開、下半部的往上開；桌機依方塊位置靠左或靠右，手機佔滿寬度 */
function Popover({ layout, variant, open, close }: { layout: Layout; variant: Variant; open: AgentKey | null; close: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { if (open) ref.current?.focus({ preventScroll: true }); }, [open]);
  if (!open) return <div id={`arch-pop-${variant}`} hidden />;
  const { W, H } = layout;
  const b = layout.boxes[open];
  const info = AGENT_SUBAGENTS[open];
  const style: CSSProperties = {};
  if (b.y + b.h / 2 < H * 0.55) style.top = `${((b.y + b.h + 10) / H) * 100}%`;
  else style.bottom = `${((H - b.y + 10) / H) * 100}%`;
  if (variant === "w") {
    if (b.x + b.w / 2 < W / 2) style.left = `${(b.x / W) * 100}%`;
    else style.right = `${((W - b.x - b.w) / W) * 100}%`;
  }
  return (
    <div id={`arch-pop-${variant}`} ref={ref} className="arch-pop" style={style} role="region" tabIndex={-1}
      aria-label={`${info.id} ${info.title} 的 Subagent`}>
      <div className="arch-pop-head">
        <span><span className="sa-id">{info.id}</span> {info.title}</span>
        <button type="button" className="arch-pop-close" aria-label="關閉" onClick={close}>×</button>
      </div>
      <SubagentList a={info} />
    </div>
  );
}

function Wide({ pick }: { pick: Pick }) {
  const A = "url(#arch-w-a)";
  const R = "url(#arch-w-r)";
  const L = WIDE;
  return (
    <svg className="arch-svg" viewBox="0 0 1120 560" role="group" aria-label={CLAIM}>
      <Markers id="arch-w" />

      {/* 左：外部情資、被評估的系統 */}
      <Box x={16} y={120} w={200} h={100} lines={["外部資安情資", "資安新聞、公告", "CISA KEV、NVD"]} />
      <rect className="box" x={16} y={300} width={200} height={170} rx={8} />
      <text className="t" x={116} y={330} textAnchor="middle">電商平台</text>
      <text className="s" x={116} y={350} textAnchor="middle">（被評估的系統）</text>
      <text className="s" x={116} y={372} textAnchor="middle">程式碼、部署紀錄</text>
      <Box x={32} y={392} w={168} h={60} cls="pill" lines={["① PR 把關", "擋下高風險變更"]} />

      {/* 中：分析流程 */}
      <rect className="zone" x={276} y={16} width={560} height={528} rx={12} />
      <text className="zone-title" x={296} y={44}>Sentinel 分析流程（GitHub Actions）</text>

      <Box x={290} y={60} w={96} h={30} rx={15} cls="pill" lines={["③ 每天 08:00"]} />
      <path className="edge" d="M338 90V110" markerEnd={A} />

      <path className="edge" d="M216 142H290" markerEnd={A} />
      <text className="lbl" x={253} y={132} textAnchor="middle">② 每小時</text>
      <text className="lbl" x={253} y={160} textAnchor="middle">比對公告</text>

      {/* 開工路由：純程式，不屬於 Orchestrator */}
      <Box x={290} y={110} w={96} h={64} lines={["開工路由", "程式（router）"]} />
      <path className="edge" d="M338 174V196" markerEnd={A} />
      <AgentBox k="a0" layout={L} variant="w" pick={pick} lines={["盤點系統", "A0 對帳"]} />
      <path className="edge" d="M386 228H404" markerEnd={A} />
      <AgentBox k="a1" layout={L} variant="w" pick={pick} lines={["外部情資", "A1 驗證比對"]} />

      {/* 每日情資：只在 ③ 每日例行執行，A0 之後、結果交給 A1 */}
      <path className="edge" d="M368 260V292" markerEnd={A} />
      <path className="edge" d="M452 292V260" markerEnd={A} />
      <AgentBox k="daily" layout={L} variant="w" pick={pick} lines={["每日情資・只在 ③", "判讀新聞，交給 A1"]} />

      {/* Orchestrator（AI 規劃＋程式政策）：派工與驗收，只能追加、排優先 */}
      <Box x={404} y={110} w={200} h={64} cls="orch" lines={["Orchestrator 派工（AI）", "依情資追加任務、排優先"]} />
      <path className="edge" d="M452 196V174" markerEnd={A} />
      <path className="edge" d="M562 174V196" markerEnd={A} />
      <path className="edge" d="M512 174V264H520" markerEnd={A} />
      <path className="edge" d="M596 174V186H674V196" markerEnd={A} />
      <AgentBox k="a2" layout={L} variant="w" pick={pick} lines={["弱點掃描 A2"]} />
      <AgentBox k="a3" layout={L} variant="w" pick={pick} lines={["早期訊號 A3"]} />
      <path className="edge" d="M604 216H616V240M604 264H616V240" />
      <path className="edge" d="M616 240H628" markerEnd={A} />

      <AgentBox k="a4" layout={L} variant="w" pick={pick} lines={["入侵路徑", "評分 · A4"]} />
      <Box x={620} y={110} w={200} h={64} cls="orch" lines={["Orchestrator 驗收（AI）", "看結果追加後續、寫摘要"]} />
      <path className="edge" d="M704 196V174" markerEnd={A} />
      <path className="edge" d="M778 174V196" markerEnd={A} />
      <AgentBox k="a5" layout={L} variant="w" pick={pick} lines={["報告與建議", "A5"]} />

      <text className="lbl" x={820} y={314} textAnchor="end">說明文字由 Claude 撰寫；分數與燈號一律由程式計算</text>

      <path className="edge ro" d="M216 330H306V260" markerEnd={R} />
      <text className="lbl ro" x={222} y={348}>唯讀讀取（不修改）</text>

      <path className="edge" d="M216 430H912" markerEnd={A} />
      <text className="lbl" x={290} y={420}>④ 部署、資料庫稽核、客訴（即時）</text>

      <AgentBox k="incident" layout={L} variant="w" pick={pick} lines={["告警調查", "推演入侵路徑 → 圍堵建議（留言到 Issue）"]} />

      {/* 右：網站 */}
      <rect className="zone" x={896} y={16} width={208} height={528} rx={12} />
      <text className="zone-title" x={912} y={44}>網站（Vercel）</text>

      <path className="edge" d="M820 240H912" markerEnd={A} />
      <text className="lbl" x={866} y={230} textAnchor="middle">每天發布</text>
      <Box x={912} y={200} w={176} h={80} lines={["今日重點、行動報告", "每天更新燈號與建議"]} />

      <Box x={912} y={400} w={176} h={60} lines={["即時告警", "④ 規則判斷，不用 AI"]} />
      <path className="edge" d="M1000 460V488H816" markerEnd={A} />
      <text className="lbl" x={866} y={480} textAnchor="middle">觸發調查</text>
    </svg>
  );
}

function Narrow({ pick }: { pick: Pick }) {
  const A = "url(#arch-n-a)";
  const R = "url(#arch-n-r)";
  const L = NARROW;
  return (
    <svg className="arch-svg" viewBox="0 0 320 828" role="group" aria-label={CLAIM}>
      <Markers id="arch-n" />

      <Box x={6} y={6} w={308} h={52} lines={["外部資安情資", "資安新聞、公告、CISA KEV、NVD"]} />
      <path className="edge" d="M84 58V116" markerEnd={A} />
      <text className="lbl" x={92} y={73}>② 每小時比對公告</text>

      <rect className="zone" x={6} y={80} width={308} height={540} rx={12} />
      <text className="zone-title" x={302} y={100} textAnchor="end">分析流程（GitHub Actions）</text>

      <Box x={20} y={116} w={128} h={44} lines={["開工路由", "程式"]} />
      <Box x={176} y={116} w={124} h={44} rx={22} cls="pill" lines={["③ 每天 08:00"]} />
      <path className="edge" d="M176 138H148" markerEnd={A} />

      <path className="edge" d="M84 160V176" markerEnd={A} />
      <AgentBox k="a0" layout={L} variant="n" pick={pick} lines={["盤點系統", "A0 對帳"]} />

      {/* 每日情資：只在 ③ 每日例行執行，結果交給 A1 */}
      <path className="edge" d="M228 220V236" markerEnd={A} />
      <AgentBox k="daily" layout={L} variant="n" pick={pick} lines={["每日情資", "只在 ③ 每天執行"]} />
      <path className="edge" d="M84 220V296" markerEnd={A} />
      <path className="edge" d="M228 280V288H120V296" markerEnd={A} />

      <AgentBox k="a1" layout={L} variant="n" pick={pick} lines={["外部情資", "A1"]} />
      <path className="edge" d="M148 318H156" markerEnd={A} />
      <Box x={156} y={296} w={144} h={44} cls="orch" lines={["Orchestrator", "派工（AI）"]} />

      <path className="edge" d="M180 340V348H87V356" markerEnd={A} />
      <path className="edge" d="M233 340V356" markerEnd={A} />
      <AgentBox k="a2" layout={L} variant="n" pick={pick} lines={["弱點掃描", "A2"]} />
      <AgentBox k="a3" layout={L} variant="n" pick={pick} lines={["早期訊號", "A3"]} />

      <path className="edge" d="M87 400V416" markerEnd={A} />
      <path className="edge" d="M233 400V408H120V416" markerEnd={A} />
      <AgentBox k="a4" layout={L} variant="n" pick={pick} lines={["入侵路徑與評分", "A4"]} />
      <path className="edge" d="M148 438H156" markerEnd={A} />
      <Box x={156} y={416} w={144} h={44} cls="orch" lines={["Orchestrator", "驗收（AI）"]} />

      <path className="edge" d="M228 460V468H98V476" markerEnd={A} />
      <AgentBox k="a5" layout={L} variant="n" pick={pick} lines={["報告與建議", "A5"]} />
      <text className="lbl" x={190} y={498}>說明由 Claude 撰寫</text>
      <text className="lbl" x={190} y={516}>分數、燈號由程式算</text>

      <AgentBox k="incident" layout={L} variant="n" pick={pick} lines={["告警調查", "→ 圍堵建議"]} />

      <path className="edge" d="M164 532V664" markerEnd={A} />
      <text className="lbl" x={172} y={580}>每天發布</text>

      <rect className="zone" x={6} y={632} width={308} height={100} rx={12} />
      <text className="zone-title" x={302} y={652} textAnchor="end">網站（Vercel）</text>
      <Box x={20} y={664} w={128} h={52} lines={["即時告警", "④ 規則判斷"]} />
      <Box x={156} y={664} w={144} h={52} lines={["今日重點、行動報告", "每天更新"]} />
      <path className="edge" d="M84 664V592" markerEnd={A} />
      <text className="lbl" x={92} y={628}>觸發調查</text>

      <Box x={6} y={760} w={308} h={60} lines={["電商平台（被評估的系統）", "① PR 把關 · 程式碼與部署紀錄"]} />
      <path className="edge" d="M84 760V716" markerEnd={A} />
      <text className="lbl" x={92} y={736}>④ 部署、資料庫稽核、客訴</text>
      <path className="edge ro" d="M308 760V198H300" markerEnd={R} />
      <text className="lbl ro" x={300} y={754} textAnchor="end">唯讀讀取（不修改）</text>
    </svg>
  );
}

export default function ArchitectureDiagram() {
  const [open, setOpen] = useState<AgentKey | null>(null);
  const trigger = useRef<Element | null>(null);

  const close = (refocus = true) => {
    setOpen(null);
    if (refocus) (trigger.current as SVGGElement | null)?.focus?.();
  };
  const pick: Pick = {
    open,
    toggle: (k, el) => { trigger.current = el; setOpen((cur) => (cur === k ? null : k)); },
  };

  useEffect(() => {
    if (!open) return;
    const onKey = (e: globalThis.KeyboardEvent) => { if (e.key === "Escape") close(); };
    const onDown = (e: PointerEvent) => {
      const t = e.target as Element | null;
      if (!t?.closest?.(".arch-pop, .hit")) close(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("pointerdown", onDown);
    return () => { document.removeEventListener("keydown", onKey); document.removeEventListener("pointerdown", onDown); };
  });

  return (
    <>
      <figure className="arch">
      <div className="arch-wide">
        <Wide pick={pick} />
        <Popover layout={WIDE} variant="w" open={open} close={() => close()} />
      </div>
      <div className="arch-narrow">
        <Narrow pick={pick} />
        <Popover layout={NARROW} variant="n" open={open} close={() => close()} />
      </div>
      <figcaption className="muted">
        {"①～④ 是四種觸發時機。藍色箭頭代表系統只「讀取」電商平台，不持有能修改它的權限。" +
          "橘框是 Orchestrator：由 AI 依當天情資派工、看結果驗收，只能追加任務與排優先，每一項都經程式核准；" +
          "開工路由是純程式，只依觸發來源決定流程。每日情資只在 ③ 每天 08:00 執行，由 Claude 判讀當天新聞後交給 A1；" +
          "Claude 只負責判讀新聞與撰寫白話說明，分數、燈號與結論一律由程式計算。" +
          "方塊右上角的藍色數字是它派發的 Subagent 數量，點一下就能查看。"}
      </figcaption>
    </figure>
      <details className="sa-all">
        <summary>列出全部 Subagent（A0～A5 與告警調查共 {SDK_SUBAGENT_COUNT} 個，每日情資 {AGENT_SUBAGENTS.daily.subs.length} 個）</summary>
        <p className="muted">
          {"每個 Agent 是一個 GitHub Actions Job，Job 內再派發 Subagent 分工（A0～A5 與告警調查由 Agent SDK 派發，每日情資由 Claude Code 派發）。" +
            "Subagent 只負責判讀與撰寫說明，不計分、不定燈號。"}
        </p>
        <SubagentMap />
      </details>
    </>
  );
}
