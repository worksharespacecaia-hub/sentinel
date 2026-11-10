#!/usr/bin/env bash
# 從 Repo ① 的 baseline tag 匯出凍結測試資料到 agents/fixtures/target-baseline/。
# 假金鑰值一律換成 REDACTED（行號不變），sentinel Repo 不保存任何金鑰值。
# 用法：scripts/sync-target-fixture.sh <path-to-shopsaas-demo-platform> [ref=baseline]
set -euo pipefail
src="${1:?需要 Repo ① 路徑}"; ref="${2:-baseline}"
dest="$(cd "$(dirname "$0")/.." && pwd)/agents/fixtures/target-baseline"
rm -rf "$dest"; mkdir -p "$dest"
git -C "$src" archive --format=tar "$ref" -- ops config services infra .gitleaks.toml \
  | tar -x -C "$dest" --exclude='*/package-lock.json' --exclude='*/node_modules/*'
grep -rlE 'DEMO-FAKE-[A-Z0-9-]{4,}' "$dest" | while read -r f; do
  sed -i -E 's/DEMO-FAKE-[A-Z0-9-]{4,}/REDACTED/g' "$f"
done
sha="$(git -C "$src" rev-parse "$ref^{commit}")"
printf '{"source_repo": "shopsaas-demo-platform", "ref": "%s", "target_sha": "%s"}\n' "$ref" "$sha" > "$dest/.fixture.json"
echo "synced $ref ($sha) -> $dest"
