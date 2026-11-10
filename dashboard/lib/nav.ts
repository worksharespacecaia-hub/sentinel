// 網站導覽與頁面名稱的唯一來源：導覽列與各頁標題都從這裡取，名稱以 CEO 看得懂的白話為準。
// 主項只放 demo 會講的 3 頁，其他工程用頁面收在「工程細節」下拉。

export interface PageInfo { href: string; label: string }

export const PAGES = {
  brief: { href: "/brief", label: "今日重點" },
  report: { href: "/report", label: "行動報告" },
  live: { href: "/live", label: "異常行為偵測" },
  overview: { href: "/", label: "詳細總覽" },
  risks: { href: "/risks", label: "風險明細" },
  intel: { href: "/intel", label: "外部事件" },
  attackPaths: { href: "/attack-paths", label: "入侵路徑" },
  assets: { href: "/assets", label: "系統盤點" },
  appRisk: { href: "/app-risk", label: "App 風險" },
  runs: { href: "/runs", label: "AI 分析過程" },
  triggers: { href: "/triggers", label: "觸發紀錄" },
  architecture: { href: "/architecture", label: "運作原理" },
  weights: { href: "/weights", label: "燈號權重" },
  rules: { href: "/rules", label: "偵測規則" },
} as const satisfies Record<string, PageInfo>;

export const PRIMARY: PageInfo[] = [PAGES.brief, PAGES.report, PAGES.live];

export const ENGINEERING: PageInfo[] = [
  PAGES.overview, PAGES.risks, PAGES.intel, PAGES.attackPaths, PAGES.assets, PAGES.appRisk,
  PAGES.runs, PAGES.triggers, PAGES.architecture, PAGES.weights, PAGES.rules,
];

export const ENGINEERING_LABEL = "工程細節";

/** `/` 與 `/brief` 只比對完全相同的路徑；其他頁面也涵蓋子路徑（例如 /intel/abc 屬於外部事件）。 */
export function isActive(pathname: string | null | undefined, href: string): boolean {
  if (!pathname) return false;
  const p = pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
  if (href === "/" || href === "/brief") return p === href;
  return p === href || p.startsWith(`${href}/`);
}
