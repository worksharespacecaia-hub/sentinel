#!/usr/bin/env bash
# 以 Docker 執行 actionlint（含 shellcheck）。
# 例外：actionlint 1.7.4 尚未支援 concurrency.queue（GitHub 官方文件已支援 queue: single|max），只忽略這一條。
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
dir="$(pwd)"; command -v cygpath >/dev/null 2>&1 && dir="$(cygpath -w "$dir")"
MSYS_NO_PATHCONV=1 docker run --rm -v "$dir:/repo" --workdir /repo rhysd/actionlint:1.7.4 -color=false \
  -ignore 'unexpected key "queue" for "concurrency" section'
echo "actionlint: OK"
