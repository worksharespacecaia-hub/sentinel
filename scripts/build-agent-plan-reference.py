"""產生 daily-intel Skill 的動態派工規範 .claude/skills/daily-intel/references/agent-plan.md（純程式，不呼叫 LLM）。

內容取自 agents/tools/agent_plan.py 的可追加工作白名單與上限，讓訂閱方案的 Claude 與程式核准使用同一份規則。
用法：python scripts/build-agent-plan-reference.py [--check]   （--check：內容不同時回傳非零，不改檔）
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents"))

from tools.agent_plan import (MAX_CTRL_PER_EVENT, MAX_CTRL_TOTAL, MAX_EVENTS, MAX_REASON, MAX_TASKS,  # noqa: E402
                              TASK_MENU)

OUT_PATH = ROOT / ".claude" / "skills" / "daily-intel" / "references" / "agent-plan.md"


def render() -> str:
    rows = "\n".join(f"| {t['agent']} | {t['subagent']} | {t['what']} |" for t in sorted(TASK_MENU, key=lambda t: (t["agent"], t["subagent"])))
    return f"""# 動態派工建議（由 scripts/build-agent-plan-reference.py 依 agents/tools/agent_plan.py 產生，請勿手改）

`intel-daily.json` 頂層的 `agent_plan` 是給程式核准的**建議**：只能追加工作，不能要求跳過、停用或改變任何評估、分數與結論。
程式會逐項檢查，不合規則的建議會被拒絕並記錄原因。

## 格式

```json
{{"extra_controls": [{{"event_id": "事件 ID", "control_id": "C-...", "reason": "1 句理由"}}],
 "extra_tasks": [{{"agent": "a4", "subagent": "impact-analyst", "event_id": "事件 ID", "reason": "1 句理由"}}]}}
```

- 沒有建議時寫 `{{}}`；兩個陣列都可以省略
- `event_id`：本次 `events` 裡事件的 `id`（非空、唯一）；不要對 `seen.json` 的已知事件提出建議（新進度用自己的新 ID 可以）
- `extra_controls`：只放「值得一併確認」的控制項，ID 必須在 `references/controls.md`；事件能直接對應的控制項照舊寫在事件的 `controls`，兩者不要重複
- 只允許上面列出的欄位；多寫的欄位會讓整項建議被拒絕

## 上限

- 每件事件最多 {MAX_CTRL_PER_EVENT} 個加查控制項，總共最多 {MAX_CTRL_TOTAL} 個
- 追加工作總共最多 {MAX_TASKS} 項
- 只處理日期最新的 {MAX_EVENTS} 件新同業事件
- 每項理由 1 句，最多 {MAX_REASON} 字

## 可追加的工作

| agent | subagent | 用途 |
|---|---|---|
{rows}
"""


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        current = OUT_PATH.read_text(encoding="utf-8") if OUT_PATH.is_file() else None
        if current != text:
            print(f"{OUT_PATH.relative_to(ROOT)} 已過期，請執行 python scripts/build-agent-plan-reference.py", file=sys.stderr)
            return 1
        print("agent-plan.md 與程式一致")
        return 0
    OUT_PATH.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
