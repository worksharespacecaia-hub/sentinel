"""把 rules/realtime.yaml 與 rules/baselines.json 打包成 dashboard/lib/realtime-rules.json（第 7.6 節：建置時打包成 JSON）。

網站部署只包含 dashboard/，因此規則以 JSON 提交到 dashboard/lib；pytest 會檢查 JSON 與 YAML 一致，避免兩邊不同步。
用法：python scripts/build-rules.py [--check]
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
YAML_PATH = ROOT / "rules" / "realtime.yaml"
BASELINES_PATH = ROOT / "rules" / "baselines.json"
OUT_PATH = ROOT / "dashboard" / "lib" / "realtime-rules.json"

SOURCES = {"github.deployment", "db.audit", "support.complaint"}
ID_RE = re.compile(r"^RT-\d{3}$")


def validate(rules: list[dict], baselines: dict) -> None:
    seen = set()
    for r in rules:
        if not ID_RE.match(r.get("id", "")) or r["id"] in seen:
            raise ValueError(f"規則 ID 錯誤或重複：{r.get('id')}")
        seen.add(r["id"])
        if r.get("source") not in SOURCES:
            raise ValueError(f"{r['id']} 的 source 不支援")
        if r.get("level") not in ("high", "medium", "low"):
            raise ValueError(f"{r['id']} 的 level 錯誤")
        if not isinstance(r.get("dedup_minutes"), int) or r["dedup_minutes"] <= 0:
            raise ValueError(f"{r['id']} 的 dedup_minutes 必須是正整數")
        m = r.get("match") or {}
        if "text_regex" in m:
            if "(?" in m["text_regex"].replace("(?:", ""):
                raise ValueError(f"{r['id']}：JavaScript 不支援行內旗標，請改用 text_regex_flags")
            re.compile(m["text_regex"])
        if "event_hour_between" in m:
            a, b = m["event_hour_between"]
            if not (0 <= a < b <= 24):
                raise ValueError(f"{r['id']} 的 event_hour_between 錯誤")
        w = r.get("window")
        if w:
            if bool(w.get("minutes")) == bool(w.get("hours")):
                raise ValueError(f"{r['id']} 的時間窗需擇一指定 minutes 或 hours")
            if w.get("metric") == "rows_read_sum" and not w.get("over_baseline_multiplier"):
                raise ValueError(f"{r['id']} 缺少 over_baseline_multiplier")
            if w.get("distinct") and int(w.get("threshold", 0)) < 2:
                raise ValueError(f"{r['id']} 的 threshold 至少 2")
    if baselines.get("default", 0) <= 0 or any(v <= 0 for v in baselines.get("accounts", {}).values()):
        raise ValueError("baselines.json 的基準必須 > 0")


def build() -> str:
    text = YAML_PATH.read_text(encoding="utf-8")
    rules = yaml.safe_load(text) or []
    baselines = json.loads(BASELINES_PATH.read_text(encoding="utf-8"))
    validate(rules, baselines)
    digest = hashlib.sha256(text.encode("utf-8") + BASELINES_PATH.read_bytes()).hexdigest()[:16]
    data = {"generated_from": "rules/realtime.yaml + rules/baselines.json", "digest": digest, "rules": rules,
            "baselines": baselines}
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    out = build()
    if "--check" in argv:
        current = OUT_PATH.read_text(encoding="utf-8") if OUT_PATH.is_file() else ""
        if current != out:
            print("realtime-rules.json 與 YAML 不一致，請執行 python scripts/build-rules.py", file=sys.stderr)
            return 1
        return 0
    OUT_PATH.write_text(out, encoding="utf-8", newline="\n")
    print(f"已寫入 {OUT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
