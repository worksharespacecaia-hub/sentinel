"use client";
// 導覽列：3 個主項＋「工程細節」下拉；標示目前所在頁（aria-current），換頁後下拉自動收合。
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ENGINEERING, ENGINEERING_LABEL, PAGES, PRIMARY, isActive } from "@/lib/nav";

export default function Nav() {
  const pathname = usePathname();
  const inEngineering = ENGINEERING.some((p) => isActive(pathname, p.href));
  return (
    <header className="nav">
      <Link className="brand" href={PAGES.brief.href}>Sentinel 資安哨兵</Link>
      <nav aria-label="主要頁面" className="nav-main">
        {PRIMARY.map((p) => (
          <Link key={p.href} href={p.href} aria-current={isActive(pathname, p.href) ? "page" : undefined}>{p.label}</Link>
        ))}
      </nav>
      <details className="nav-more" key={pathname}>
        <summary className={inEngineering ? "current" : undefined}>{ENGINEERING_LABEL} <span aria-hidden="true">▾</span></summary>
        <ul>
          {ENGINEERING.map((p) => (
            <li key={p.href}>
              <Link href={p.href} aria-current={isActive(pathname, p.href) ? "page" : undefined}>{p.label}</Link>
            </li>
          ))}
        </ul>
      </details>
    </header>
  );
}
