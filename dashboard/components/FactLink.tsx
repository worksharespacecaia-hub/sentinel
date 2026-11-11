"use client";
// 摘要數字：滑過或聚焦時顯示「這個數字包含哪幾項」的小卡；點擊仍跳到行動報告「數字從哪來」。
import { useRef, useState } from "react";

const TIP_WIDTH = 340;
const GUTTER = 16;

export default function FactLink({ href, text, label, lines, more }:
  { href: string; text: string; label: string; lines: string[]; more: number }) {
  const ref = useRef<HTMLAnchorElement>(null);
  const [shift, setShift] = useState(0);
  // 小卡預設對齊數字左緣；超出畫面時往左移，並保留左右 16px 邊距（手機窄畫面也不會被切掉）
  const place = () => {
    const a = ref.current;
    if (!a) return;
    const vw = document.documentElement.clientWidth;
    const width = Math.min(TIP_WIDTH, vw - GUTTER * 2);
    const left = a.getBoundingClientRect().left;
    const target = Math.max(GUTTER, Math.min(left, vw - GUTTER - width));
    setShift(Math.round(target - left));
  };

  return (
    <a ref={ref} className="fact-link" href={href} onMouseEnter={place} onFocus={place}>
      {text}
      <span className="fact-tip" style={{ left: shift }}>
        <strong>{label}：{text}</strong>
        {lines.length > 0 && <ul>{lines.map((l, i) => <li key={i}>{l}</li>)}</ul>}
        <span className="fact-tip-more">{more > 0 ? `還有 ${more} 項，` : ""}點數字看完整清單</span>
      </span>
    </a>
  );
}
