import type { Metadata } from "next";
import Nav from "@/components/Nav";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sentinel 資安哨兵（Demo）",
  description: "電商 SaaS 資安哨兵 Demo：虛構環境",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh-Hant">
      <body>
        <div className="banner" role="note">虛構環境，非 91APP 或任何公司的實際系統。所有金鑰皆為 DEMO-FAKE 假值。</div>
        <Nav />
        <main>{children}</main>
      </body>
    </html>
  );
}
