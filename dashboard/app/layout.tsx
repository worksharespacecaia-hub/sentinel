import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sentinel 資安哨兵（Demo）",
  description: "電商 SaaS 資安哨兵 Demo：虛構環境",
  robots: { index: false, follow: false },
};

const NAV = [
  ["/", "總覽"], ["/intel", "情資比對"], ["/runs", "Agent 執行"], ["/attack-paths", "攻擊鏈"], ["/risks", "風險清單"],
  ["/assets", "資產"], ["/live", "即時監控"], ["/app-risk", "App"], ["/triggers", "觸發紀錄"], ["/architecture", "架構說明"],
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh-Hant">
      <body>
        <div className="banner" role="note">虛構環境，非 91APP 或任何公司的實際系統。所有金鑰皆為 DEMO-FAKE 假值。</div>
        <header className="nav">
          <span className="brand">Sentinel 資安哨兵</span>
          {NAV.map(([href, label]) => <Link key={href} href={href}>{label}</Link>)}
        </header>
        <main>{children}</main>
      </body>
    </html>
  );
}
