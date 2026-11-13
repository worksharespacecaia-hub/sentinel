"""產生 Orchestrator Skill 的核准政策 .claude/skills/orchestrator/references/policy.md（純程式，不呼叫 LLM）。

內容取自 agents/tools/orchestration.py 的選單、上限與拒絕原因，讓訂閱方案的 Claude 與程式核准使用同一份規則。
用法：python scripts/build-agent-plan-reference.py [--check]   （--check：內容不同時回傳非零，不改檔）
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents"))

from tools.orchestration import (DISPATCH_TASKS, MAX_A2_FINDINGS, MAX_A3_SYSTEMS, MAX_A4_BASELINE,  # noqa: E402
                                 MAX_A5_CEO, MAX_A5_REMEDIATION, MAX_CTRL_PER_EVENT, MAX_CTRL_TOTAL, MAX_DISPATCH_TASKS,
                                 MAX_EVENTS, MAX_PRIORITIES, MAX_REASON, MAX_REVIEW_TASKS, MAX_RISKS_PER_TASK, MAX_SUMMARY,
                                 REASON_HELP, REVIEW_TASKS)

OUT_PATH = ROOT / ".claude" / "skills" / "orchestrator" / "references" / "policy.md"
TARGET_ZH = {"event": "事件（event_id）", "risk": "風險（risk_id）"}


def _menu(menu: dict) -> str:
    return "\n".join(f"| {a} | {s} | {TARGET_ZH[v['target']]} | {v['what']} |" for (a, s), v in sorted(menu.items()))


def render() -> str:
    reasons = "\n".join(f"| {r} | {why} |" for r, why in REASON_HELP.items())
    return f"""# Orchestrator 核准政策（由 scripts/build-agent-plan-reference.py 依 agents/tools/orchestration.py 產生，請勿手改）

派工（dispatch）與驗收（review）的提案都是給程式核准的**建議**：必要任務一定照跑，只能追加任務與排優先，
不能要求跳過、停用或改變任何評估、分數與結論。程式依本次資料逐項檢查，不合規則的項目會被拒絕並記錄原因；
被拒絕的項目不佔配額。

共同規則：
- 提案是一個 JSON 物件；所有欄位都可以省略，沒有建議時寫 `{{}}`
- 只允許下面列出的欄位；頂層多寫的欄位各記一筆拒絕，某一項多寫欄位會讓整項被拒絕
- 每項理由 1 句，最多 {MAX_REASON} 字
- 只能使用輸入檔裡出現的事件 ID、風險 ID 與控制項 ID；候選清單是程式算的參考，最終資格以程式核准為準

## 派工（dispatch）

```json
{{"extra_controls": [{{"event_id": "事件 ID", "control_id": "C-...", "reason": "1 句理由"}}],
 "extra_tasks": [{{"agent": "a4", "subagent": "impact-analyst", "event_id": "事件 ID", "reason": "1 句理由"}}],
 "priorities": [{{"agent": "a4", "risk_id": "風險 ID", "reason": "1 句理由"}}]}}
```

- `extra_controls`：值得一併確認的控制項。只列出本次已算好的檢查結果，不影響判定；事件已直接對應的控制項不要重複
- `extra_tasks`：追加任務，對象由程式挑選（只挑輸入中有候選對象的事件）
- `priorities`：把 A4 必要任務中的風險移到說明順序最前面，不新增也不移除風險

可追加的任務：

| agent | subagent | 對象 | 用途 |
|---|---|---|---|
{_menu(DISPATCH_TASKS)}

上限：
- 只處理日期最新的 {MAX_EVENTS} 件新同業事件（公告調查只處理本次公告）
- 每件事件最多 {MAX_CTRL_PER_EVENT} 個加查控制項，總共最多 {MAX_CTRL_TOTAL} 個
- 追加任務總共最多 {MAX_DISPATCH_TASKS} 項（A2 每項最多 {MAX_A2_FINDINGS} 個項目、A3 最多 {MAX_A3_SYSTEMS} 個系統、A4 每件最多 {MAX_RISKS_PER_TASK} 個風險，由程式挑選）
- 排優先最多 {MAX_PRIORITIES} 項，只限 A4 必要任務的前 {MAX_A4_BASELINE} 個高風險

## 驗收（review）

```json
{{"extra_tasks": [{{"agent": "a5", "subagent": "intel-report-writer", "event_id": "事件 ID", "reason": "1 句理由"}},
                 {{"agent": "a5", "subagent": "key-rotation-advisor", "risk_id": "風險 ID", "reason": "1 句理由"}}],
 "priorities": [{{"agent": "a5", "risk_id": "風險 ID", "reason": "1 句理由"}}],
 "summary": "執行摘要"}}
```

- `extra_tasks`：A5 的後續任務。事件目標的任務給 `event_id`，風險目標的任務給 `risk_id`，不要兩個都給
- `priorities`：調整 A5 解法清單與 CEO 摘要參考清單的順序，不新增也不移除風險
- `summary`：給工程團隊的執行摘要，繁體中文，最多 {MAX_SUMMARY} 字；不寫金鑰、Token、個資、檔案路徑、IP、連接埠、設定鍵或控制項 ID，
  含這些內容會整段拒絕

可追加的任務：

| agent | subagent | 對象 | 用途 |
|---|---|---|---|
{_menu(REVIEW_TASKS)}

上限：
- 追加任務總共最多 {MAX_REVIEW_TASKS} 項
- 排優先最多 {MAX_PRIORITIES} 項，只限 A5 解法清單（前 {MAX_A5_REMEDIATION} 個）與 CEO 摘要參考清單（前 {MAX_A5_CEO} 個）中的風險

## 拒絕原因

| 原因 | 什麼時候 |
|---|---|
{reasons}
"""


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        current = OUT_PATH.read_text(encoding="utf-8") if OUT_PATH.is_file() else None
        if current != text:
            print(f"{OUT_PATH.relative_to(ROOT)} 已過期，請執行 python scripts/build-agent-plan-reference.py", file=sys.stderr)
            return 1
        print("policy.md 與程式一致")
        return 0
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
