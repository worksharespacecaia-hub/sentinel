"use client";
// 匯出 PDF：開啟瀏覽器列印視窗，選「另存為 PDF」。列印版面由 globals.css 的 @media print 控制。
export default function PrintButton() {
  return <button type="button" className="primary" onClick={() => window.print()}>匯出 PDF</button>;
}
