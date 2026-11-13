"""產生 daily-intel Skill 的可能破口 topic 清單 .claude/skills/daily-intel/references/check-topics.md（純程式，不呼叫 LLM）。

內容取自 rules/check-hints.json 的「被打到的地方」（target ID、名稱、關鍵字），讓訂閱方案的 Claude 寫 possible_entry_points.topic
時與程式的白名單（agents/tools/check_hints.topic_ids）使用同一份規則。
用法：python scripts/build-check-topics-reference.py [--check]   （--check：內容不同時回傳非零，不改檔）
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents"))

from tools.check_hints import CHECK_HINTS_FILE, load_rules  # noqa: E402

OUT_PATH = ROOT / ".claude" / "skills" / "daily-intel" / "references" / "check-topics.md"


def _cell(text: str) -> str:
    return str(text).replace("|", "／").replace("\n", " ")


def render(rules: dict) -> str:
    rows = "\n".join(f"| `{t['id']}` | {_cell(t['label'])} | {_cell('、'.join(t.get('keywords') or []) or '—')} |"
                     for t in rules["targets"])
    return f"""# 可能破口的 topic（由 scripts/build-check-topics-reference.py 依 rules/check-hints.json 產生，請勿手改）

事件的 `possible_entry_points[].topic` 只能填下表的 ID；對不到任何一項時省略 `topic`（或填 `null`）。
不在下表的 ID 會被程式移除（項目本身保留）。關鍵字只是說明這一類「被打到的地方」的範例，不必出現在事件文字中。

| ID | 名稱 | 關鍵字範例 |
|---|---|---|
{rows}
"""


def main(argv: list[str]) -> int:
    rules, issue = load_rules(CHECK_HINTS_FILE)
    if issue is not None:
        print("rules/check-hints.json 無效，無法產生 check-topics.md", file=sys.stderr)
        return 2
    text = render(rules)
    if "--check" in argv:
        current = OUT_PATH.read_text(encoding="utf-8") if OUT_PATH.is_file() else None
        if current != text:
            print(f"{OUT_PATH.relative_to(ROOT)} 已過期，請執行 python scripts/build-check-topics-reference.py", file=sys.stderr)
            return 1
        print("check-topics.md 與規則表一致")
        return 0
    OUT_PATH.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
