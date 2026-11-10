#!/usr/bin/env bash
# intel-watch.json 語意狀態改變時才發布（只有 checked_at 改變不 commit）；實際發布交給 push-with-retry.sh。
# 用法：GH_TOKEN=... bash scripts/publish-intel-watch.sh
set -euo pipefail

STATE=dashboard/public/data/intel-watch.json
[[ -f "$STATE" ]] || { echo "沒有 $STATE，不 commit"; exit 0; }
# git diff 看不到未追蹤的檔案：第一次產生的 intel-watch.json 必須直接進入比對，否則永遠不會被 commit
if git ls-files --error-unmatch -- "$STATE" >/dev/null 2>&1 && git diff --quiet -- "$STATE"; then
  echo "狀態沒有變化，不 commit"; exit 0
fi
changed="$(python - "$STATE" <<'PY'
import json, subprocess, sys
path = sys.argv[1]
new = json.load(open(path, encoding="utf-8"))
old = subprocess.run(["git", "show", f"HEAD:{path}"], capture_output=True, text=True, encoding="utf-8")
prev = json.loads(old.stdout) if old.returncode == 0 else {}
strip = lambda d: {k: v for k, v in d.items() if k != "checked_at"}
print("1" if strip(new) != strip(prev) else "0")
PY
)"
if [[ "$changed" == "0" ]]; then echo "只有時間戳改變，不 commit"; exit 0; fi
scripts/push-with-retry.sh intel-watch
