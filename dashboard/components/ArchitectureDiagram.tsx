// 運作原理頁的整體架構圖：桌機橫向、手機直式，內容相同。
// 顏色全走 globals.css 的 .arch-svg 類別（跟著淺色／深色主題）。

type BoxProps = { x: number; y: number; w: number; h: number; lines: string[]; cls?: string; rx?: number };

function Box({ x, y, w, h, lines, cls = "box", rx = 8 }: BoxProps) {
  const cx = x + w / 2;
  const blockH = 14 + 20 * (lines.length - 1);
  const first = y + h / 2 - blockH / 2 + 12;
  return (
    <g>
      <rect className={cls} x={x} y={y} width={w} height={h} rx={rx} />
      {lines.map((line, i) => (
        <text key={i} className={i === 0 ? "t" : "s"} x={cx} y={first + i * 20} textAnchor="middle">
          {line}
        </text>
      ))}
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
  "外部情資每小時比對、每天 08:00 全面評估，依序盤點系統、找弱點、推演入侵路徑並評分，再把燈號與建議發布到網站；" +
  "分析流程只讀取電商平台、不修改。部署通知等即時事件由網站規則直接判斷並告警，再觸發告警調查。";

function Wide() {
  const A = "url(#arch-w-a)";
  const R = "url(#arch-w-r)";
  return (
    <svg className="arch-svg arch-wide" viewBox="0 0 1120 560" role="img" aria-label={CLAIM}>
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
      <path className="edge" d="M338 90V130" markerEnd={A} />

      <path className="edge" d="M216 170H296" markerEnd={A} />
      <text className="lbl" x={256} y={160} textAnchor="middle">② 每小時</text>
      <text className="lbl" x={256} y={188} textAnchor="middle">比對公告</text>

      <Box x={296} y={130} w={84} h={80} lines={["派工", "程式決定"]} />
      <path className="edge" d="M380 170H400" markerEnd={A} />
      <Box x={400} y={130} w={84} h={80} lines={["盤點系統", "A0 對帳"]} />

      <path className="edge" d="M484 170H494V128H504" markerEnd={A} />
      <path className="edge" d="M484 170H504" markerEnd={A} />
      <path className="edge" d="M484 170H494V212H504" markerEnd={A} />
      <Box x={504} y={109} w={104} h={38} lines={["外部情資 A1"]} />
      <Box x={504} y={151} w={104} h={38} lines={["弱點掃描 A2"]} />
      <Box x={504} y={193} w={104} h={38} lines={["早期訊號 A3"]} />
      <path className="edge" d="M608 128H618V170M608 212H618V170" />
      <path className="edge" d="M608 170H628" markerEnd={A} />

      <Box x={628} y={130} w={92} h={80} lines={["入侵路徑", "評分 · A4"]} />
      <path className="edge" d="M720 170H736" markerEnd={A} />
      <Box x={736} y={130} w={80} h={80} lines={["報告與建議", "A5"]} />

      <path className="edge ai-link" d="M556 231V276M674 210V276M776 210V276" />
      <Box x={504} y={276} w={312} h={56} cls="ai" lines={["Claude AI：判讀新聞、撰寫白話說明", "分數與燈號一律由程式計算"]} />

      <path className="edge ro" d="M216 330H442V210" markerEnd={R} />
      <text className="lbl ro" x={290} y={320}>唯讀讀取（不修改）</text>

      <path className="edge" d="M216 430H912" markerEnd={A} />
      <text className="lbl" x={290} y={420}>④ 部署通知（即時）</text>

      <Box x={504} y={460} w={312} h={56} lines={["告警調查", "推演入侵路徑 → 圍堵建議（留言到 Issue）"]} />

      {/* 右：網站 */}
      <rect className="zone" x={896} y={16} width={208} height={528} rx={12} />
      <text className="zone-title" x={912} y={44}>網站（Vercel）</text>

      <path className="edge" d="M816 170H912" markerEnd={A} />
      <text className="lbl" x={866} y={160} textAnchor="middle">每天發布</text>
      <Box x={912} y={130} w={176} h={80} lines={["今日重點、行動報告", "每天更新燈號與建議"]} />

      <Box x={912} y={400} w={176} h={60} lines={["即時告警", "④ 規則判斷，不用 AI"]} />
      <path className="edge" d="M1000 460V488H816" markerEnd={A} />
      <text className="lbl" x={866} y={480} textAnchor="middle">觸發調查</text>
    </svg>
  );
}

function Narrow() {
  const A = "url(#arch-n-a)";
  const R = "url(#arch-n-r)";
  return (
    <svg className="arch-svg arch-narrow" viewBox="0 0 320 704" role="img" aria-label={CLAIM}>
      <Markers id="arch-n" />

      <Box x={6} y={6} w={308} h={52} lines={["外部資安情資", "資安新聞、公告、CISA KEV、NVD"]} />
      <path className="edge" d="M84 58V116" markerEnd={A} />
      <text className="lbl" x={92} y={73}>② 每小時比對公告</text>

      <rect className="zone" x={6} y={80} width={308} height={408} rx={12} />
      <text className="zone-title" x={302} y={100} textAnchor="end">分析流程（GitHub Actions）</text>

      <Box x={20} y={116} w={128} h={44} lines={["派工", "程式決定"]} />
      <Box x={176} y={116} w={124} h={44} rx={22} cls="pill" lines={["③ 每天 08:00"]} />
      <path className="edge" d="M176 138H148" markerEnd={A} />

      <path className="edge" d="M84 160V176" markerEnd={A} />
      <Box x={20} y={176} w={260} h={44} lines={["盤點系統", "A0 對帳"]} />

      <path className="edge" d="M64 220V236" markerEnd={A} />
      <path className="edge" d="M160 220V236" markerEnd={A} />
      <path className="edge" d="M256 220V236" markerEnd={A} />
      <Box x={20} y={236} w={88} h={44} lines={["外部情資", "A1"]} />
      <Box x={116} y={236} w={88} h={44} lines={["弱點掃描", "A2"]} />
      <Box x={212} y={236} w={88} h={44} lines={["早期訊號", "A3"]} />

      <path className="edge" d="M64 280V296" markerEnd={A} />
      <path className="edge" d="M160 280V296" markerEnd={A} />
      <path className="edge" d="M256 280V296" markerEnd={A} />
      <Box x={20} y={296} w={280} h={44} lines={["入侵路徑與評分", "A4"]} />

      <path className="edge" d="M98 340V356" markerEnd={A} />
      <Box x={20} y={356} w={156} h={56} lines={["報告與建議", "A5"]} />
      <path className="edge ai-link" d="M246 340V356M176 384H192" />
      <Box x={192} y={356} w={108} h={56} cls="ai" lines={["Claude AI", "只寫說明"]} />

      <Box x={20} y={428} w={128} h={44} lines={["告警調查", "→ 圍堵建議"]} />

      <path className="edge" d="M164 412V536" markerEnd={A} />
      <text className="lbl" x={172} y={452}>每天發布</text>

      <rect className="zone" x={6} y={504} width={308} height={100} rx={12} />
      <text className="zone-title" x={302} y={524} textAnchor="end">網站（Vercel）</text>
      <Box x={20} y={536} w={128} h={52} lines={["即時告警", "④ 規則判斷"]} />
      <Box x={156} y={536} w={144} h={52} lines={["今日重點、行動報告", "每天更新"]} />
      <path className="edge" d="M84 536V472" markerEnd={A} />
      <text className="lbl" x={92} y={526}>觸發調查</text>

      <Box x={6} y={636} w={308} h={60} lines={["電商平台（被評估的系統）", "① PR 把關 · 程式碼與部署紀錄"]} />
      <path className="edge" d="M84 636V588" markerEnd={A} />
      <text className="lbl" x={92} y={624}>④ 部署通知</text>
      <path className="edge ro" d="M308 636V198H280" markerEnd={R} />
      <text className="lbl ro" x={300} y={624} textAnchor="end">唯讀讀取（不修改）</text>
    </svg>
  );
}

export default function ArchitectureDiagram() {
  return (
    <figure className="arch">
      <Wide />
      <Narrow />
      <figcaption className="muted">
        ①～④ 是四種觸發時機。藍色箭頭代表系統只「讀取」電商平台，不持有能修改它的權限；
        Claude AI 只負責判讀新聞與撰寫白話說明，分數、燈號與結論一律由程式計算。各 Agent 底下的 Subagent 見下一段。
      </figcaption>
    </figure>
  );
}
