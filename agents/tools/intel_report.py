"""情資比對報告（第 7.8 節）。區塊 2、3、4、7 由程式產出、每次重算；區塊 1、5、6 先用範本，LLM 只能改寫文字。"""
from __future__ import annotations

from tools.templates import notice_draft, solution_for

KIND_LABEL = {"live": "真實", "archive": "真實・已收錄", "demo": "示範", "advisory": "公告"}
LEVEL_ZH = {"high": "高", "medium": "中", "low": "低"}
VERDICT_ZH = {"affected": "受影響", "not_affected": "不受影響", "need_check": "需確認"}
STATUS_ZH = {"open": "待處理", "fixed": "已修復", "not_affected": "不受影響", "need_check": "需確認"}


def build_report(match: dict, risks_by_id: dict[str, dict], graph_nodes: dict, *, verification: dict | None = None,
                 observed_at: str | None = None, llm_text: dict | None = None) -> dict:
    ev = match["event"]
    affected = [i for i in match["impacts"] if i["verdict"] == "affected"]
    need = [i for i in match["impacts"] if i["verdict"] == "need_check"]
    clean = [i for i in match["impacts"] if i["verdict"] == "not_affected"]
    levels = [risks_by_id[i["risk_id"]]["level"] for i in affected if i.get("risk_id") in risks_by_id]
    max_level = max(levels, key=lambda lv: {"low": 0, "medium": 1, "high": 2}[lv]) if levels else None
    rows = []
    for i in affected + need:
        r = risks_by_id.get(i.get("risk_id") or "")
        rows.append({"asset_id": i["asset_id"], "our_state": i["our_state"], "basis": i["basis"], "verdict": i["verdict"],
                     "reason": i.get("reason", ""), "risk_id": i.get("risk_id"),
                     "level": r["level"] if r else None, "score": r["score"] if r else None,
                     "breakdown": r["breakdown"] if r else [], "app_impact": i.get("app_impact"),
                     "to_verify": i.get("to_verify", []), "observed_at": observed_at})

    if affected:
        status = "open"
        if all((risks_by_id.get(i.get("risk_id") or "") or {}).get("status") == "fixed" for i in affected):
            status = "fixed"
    elif need:
        status = "need_check"
    else:
        status = match["status"] if match["status"] in ("not_affected", "need_check") else "not_affected"

    if affected:
        top = rows[0]
        conclusion = f"{len(affected)} 項受影響，最高風險為{LEVEL_ZH.get(max_level, '未評')}。{top['asset_id']}：{top['our_state']}。"
    elif need and all(i["asset_id"] == "*" for i in need):
        conclusion = f"無法自動判定：{need[0]['reason']}，需要人工確認。"
    elif need:
        conclusion = f"沒有確定受影響的項目，但有 {len(need)} 項需要人工確認。"
    else:
        reason = (match.get("notes") or ["沒有符合的資產"])[0]
        conclusion = f"不受影響：{reason}。"

    solutions = [] if not affected else [solution_for(risks_by_id[i["risk_id"]], graph_nodes)
                                         for i in affected if i.get("risk_id") in risks_by_id]
    pii_platform = any("資料敏感" in [b["factor"] for b in row["breakdown"]] and "影響範圍" in [b["factor"] for b in row["breakdown"]]
                       for row in rows if row["verdict"] == "affected")
    notice_needed = bool(affected) and (bool(ev.get("notice_required")) or pii_platform)
    text = llm_text or {}
    summary = text.get("summary") or ev.get("summary") or "；".join(ev.get("attack_chain", [])) or ev["title"]
    summary_source = text.get("source", "template")
    if not affected:
        summary_source = "template"   # 不受影響的事件不呼叫 LLM
    blocks = {
        "1_summary": {"title": ev["title"], "date": ev["date"], "industry": ev.get("industry"),
                      "attack_chain": ev.get("attack_chain", []), "attck": ev.get("attck", []), "cves": ev.get("cves", []),
                      "confidence": "已確認" if ev["confidence"] == "confirmed" else "暫定",
                      "label": KIND_LABEL.get(ev["kind"], ev["kind"]),
                      "sources": [{k: s.get(k) for k in ("url", "title", "quote", "fetch_status", "verification_basis", "verified_at")}
                                  for s in ev.get("sources", [])],
                      "verification": verification or {}, "summary": summary,
                      "summary_note": None if summary_source != "template" or not affected else "自動摘要未產生",
                      "fixture_note": ev.get("fixture_note")},
        "2_conclusion": {"text": conclusion, "affected_count": len(affected), "max_level": max_level},
        "3_affected": [r for r in rows if r["verdict"] == "affected"],
        "4_unaffected_and_check": {"not_affected": [{"asset_id": i["asset_id"], "our_state": i["our_state"], "reason": i.get("reason", "")}
                                                    for i in clean],
                                   "need_check": [r for r in rows if r["verdict"] == "need_check"],
                                   "notes": match.get("notes", [])},
        "5_solutions": text.get("solutions") or solutions,
        "6_notice": {"needed": notice_needed, "draft": text.get("notice") or (notice_draft(ev["title"]) if notice_needed else None)},
        "7_status": {"status": status, "label": STATUS_ZH[status]},
    }
    if not affected:
        blocks.pop("3_affected")
        blocks.pop("5_solutions")
        blocks.pop("6_notice")
    return {
        "event": {k: ev.get(k) for k in ("id", "kind", "title", "date", "industry", "attack_chain", "attck", "cves", "products",
                                         "revision", "controls", "confidence", "sources", "demo", "is_update_of", "proposed_controls")},
        "conclusion": conclusion, "affected_count": len(affected), "max_level": max_level,
        "impacts": match["impacts"], "solutions": blocks.get("5_solutions", []), "notice": blocks.get("6_notice"),
        "status": status, "evaluated_asset_ids": sorted({i["asset_id"] for i in match["impacts"]}),
        "complete": match.get("complete", False), "summary_source": summary_source, "summary": summary, "blocks": blocks,
    }


def to_markdown(rep: dict) -> str:
    b = rep["blocks"]
    s1 = b["1_summary"]
    tags = [f"`{s1['label']}`", f"`{s1['confidence']}`", *[f"`{c}`" for c in s1["cves"]]]
    lines = [f"# {s1['title']}", " ".join(tags), "", f"**結論：{b['2_conclusion']['text']}**", ""]
    if s1.get("fixture_note"):
        lines += [f"> {s1['fixture_note']}", ""]
    lines += ["## 事件摘要", s1["summary"], ""]
    if s1.get("summary_note"):
        lines += [f"_{s1['summary_note']}_", ""]
    up = rep.get("update_of")
    if up:
        lines += [f"> 這是「{up.get('title') or up['id']}」（{up['id']}）的新進度；比對時沿用原事件的產品、利用條件與控制項。", ""]
    if rep.get("updates"):
        lines.append("## 事件進度")
        lines += [f"- {u['date']} {u['title']}（{STATUS_ZH.get(u['status'], u['status'])}）：{u['conclusion']}"
                  for u in rep["updates"]]
        lines.append("")
    if "3_affected" in b:
        lines += ["## 受影響項目", "| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |", "|------|----------|---------|------|------|"]
        for r in b["3_affected"]:
            risk = f"{LEVEL_ZH.get(r['level'], '—')}（{r['score']} 分）" if r["level"] else "—"
            lines.append(f"| {r['asset_id']} | {r['our_state']} | {r['basis']} | {VERDICT_ZH[r['verdict']]} | {risk} |")
        lines.append("")
    u = b["4_unaffected_and_check"]
    if u["not_affected"] or u["need_check"] or u["notes"]:
        lines.append("## 不受影響與需確認")
        lines += [f"- {i['asset_id']}：{i['our_state']}，{i['reason']}" for i in u["not_affected"]]
        lines += [f"- 需確認：{i['asset_id']}：{'；'.join(i['to_verify']) or i['reason']}" for i in u["need_check"]]
        lines += [f"- {n}" for n in u["notes"]]
        lines.append("")
    for sol in b.get("5_solutions", []):
        lines += [f"## 可能的解法：{sol['risk_id']}", "| 選項 | 做法 | 代價 | 時效 |", "|------|------|------|------|"]
        lines += [f"| {o['name']} | {o['action']} | {o['cost']} | {o['timing']} |" for o in sol["options"]]
        lines += [f"建議負責團隊：{sol['suggested_owner']}；驗證方式：{sol['verify']}", ""]
    n = b.get("6_notice")
    if n and n["needed"]:
        lines += ["## 建議通知", n["draft"], ""]
    lines += ["## 處理狀態", b["7_status"]["label"], "", "## 來源"]
    for s in s1["sources"]:
        lines.append(f"- {s['title']}{'：' + s['url'] if s.get('url') else ''}")
    return "\n".join(lines) + "\n"
