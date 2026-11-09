#!/usr/bin/env bash
# 受信任的 publisher（第 10.1 節）：只發布允許的產物；遠端改變時重新取得最新 main、在乾淨工作樹重新合併，最多重試 3 次。
# 用法：GH_TOKEN=... scripts/push-with-retry.sh <output_dir>
# 不使用 git add .；只 stage 允許的資料、快取、索引與報告路徑。Repo ① 永遠不寫。
set -euo pipefail

OUTPUT_DIR="${1:?需要 output_dir}"
case "$OUTPUT_DIR" in
  daily|advisories/*|scenarios/*|failures/*) ALLOWED=(dashboard/public/data agents/cache/llm.json reports/intel) ;;
  intel-watch) ALLOWED=(dashboard/public/data/intel-watch.json) ;;
  *) echo "push-with-retry: 不允許的 output_dir：$OUTPUT_DIR" >&2; exit 2 ;;
esac
[[ "$OUTPUT_DIR" != *..* ]] || { echo "push-with-retry: 路徑含 .." >&2; exit 2; }
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

CANDIDATE="$(mktemp -d)"
trap 'rm -rf "$CANDIDATE"' EXIT
for p in "${ALLOWED[@]}"; do
  if [[ -e "$p" ]]; then mkdir -p "$CANDIDATE/$(dirname "$p")"; cp -R "$p" "$CANDIDATE/$p"; fi
done

if [[ -n "${PUBLISH_REMOTE_URL:-}" ]]; then
  REMOTE_URL="$PUBLISH_REMOTE_URL"          # 本機測試用（例如 bare repo 路徑）
else
  REMOTE_URL="https://x-access-token:${GH_TOKEN:?需要 GH_TOKEN}@github.com/${GITHUB_REPOSITORY:?需要 GITHUB_REPOSITORY}.git"
fi
git config user.name "sentinel-publisher[bot]"
git config user.email "sentinel-publisher@users.noreply.github.com"

for attempt in 1 2 3; do
  git fetch --quiet "$REMOTE_URL" main
  git reset --quiet --hard FETCH_HEAD
  git clean -fdq -- "${ALLOWED[@]}" 2>/dev/null || true
  python agents/tools/publish_merge.py --candidate "$CANDIDATE" --repo . --output-dir "$OUTPUT_DIR"
  git add -- "${ALLOWED[@]}"
  if git diff --cached --quiet; then
    echo "push-with-retry: 沒有內容變更，不 commit"
    exit 0
  fi
  git commit --quiet -m "sentinel: publish ${OUTPUT_DIR} (run ${GITHUB_RUN_ID:-local})"
  if git push --quiet "$REMOTE_URL" HEAD:main; then
    echo "push-with-retry: 第 ${attempt} 次發布成功"
    exit 0
  fi
  echo "push-with-retry: 第 ${attempt} 次推送失敗，重新合併後重試" >&2
  sleep $((attempt * 5))
done
echo "push-with-retry: 重試 3 次仍失敗；候選產物保留在 workflow artifact，未通知成功" >&2
exit 1
