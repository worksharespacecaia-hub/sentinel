"""燈號計算（第 7.5 節）。燈號必須附文字原因，不能只靠顏色。"""
from __future__ import annotations

from tools.reconcile import visibility_ok

LABEL = {"red": "紅燈：需要今天決策", "yellow": "黃燈：本週內處理", "green": "綠燈：目前沒有未處理的中高風險"}


def compute_light(*, risks: list[dict], signals: list[dict], open_alerts: list[dict], coverage: dict,
                  data_issues: list[dict]) -> tuple[str, list[str]]:
    reasons_red, reasons_yellow = [], []
    open_risks = [r for r in risks if r["status"] in ("open", "need_check")]
    highs = [r for r in open_risks if r["level"] == "high"]
    if highs:
        reasons_red.append(f"{len(highs)} 個未處理的高風險")
    breach = [s for s in signals if s.get("light") == "red" or s.get("suspected_breach")]
    if breach:
        reasons_red.append("早期訊號顯示疑似已發生外洩：" + "；".join(s["summary"] for s in breach))
    real_alerts = [a for a in open_alerts if not a.get("simulated") and a.get("status") != "closed" and a.get("level") == "high"]
    if real_alerts:
        reasons_red.append(f"{len(real_alerts)} 個未結案的即時高風險告警")
    if reasons_red:
        return "red", reasons_red
    meds = [r for r in open_risks if r["level"] == "medium"]
    if meds:
        reasons_yellow.append(f"{len(meds)} 個中風險")
    high_signals = [s for s in signals if s.get("level") in ("high", "medium")]
    if high_signals:
        reasons_yellow.append(f"{len(high_signals)} 個異常訊號待確認")
    ok, vis = visibility_ok(coverage)
    if not ok:
        reasons_yellow.append("可見度不足：" + "；".join(vis))
    bad = [i for i in data_issues if i.get("status") in ("missing", "failed", "stale") and i.get("required", True)]
    if bad:
        reasons_yellow.append("資料不足：" + "、".join(sorted({i["source"] for i in bad})))
    if reasons_yellow:
        return "yellow", reasons_yellow
    return "green", ["沒有未處理的中高風險，可見度達標，必要資料完整且未過期"]
