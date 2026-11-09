#!/usr/bin/env bash
# 即時規則整合測試：啟動本機 Redis + Upstash REST 相容代理（只綁 127.0.0.1），執行 lib/*.itest.ts，結束後只移除本腳本建立的容器。
# 不連任何外部服務；GitHub API 在測試中以假的 fetch 回應。
set -euo pipefail
cd "$(dirname "$0")/.."

NET=sentinel-itest-net
REDIS=sentinel-itest-redis
SRH=sentinel-itest-srh
PORT="${ITEST_PORT:-18079}"
TOKEN=itest-token
REDIS_IMAGE=redis:7.4.2-alpine
SRH_IMAGE=hiett/serverless-redis-http@sha256:5b0bb9239fce53abf87b2018a7a0deb9ec7bd900c5360738fe5fbeeb426f9150

cleanup() {
  docker rm -f "$SRH" "$REDIS" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker network create "$NET" >/dev/null
docker run -d --name "$REDIS" --network "$NET" "$REDIS_IMAGE" >/dev/null
docker run -d --name "$SRH" --network "$NET" -p "127.0.0.1:${PORT}:80" \
  -e SRH_MODE=env -e SRH_TOKEN="$TOKEN" -e SRH_CONNECTION_STRING="redis://${REDIS}:6379" "$SRH_IMAGE" >/dev/null

for i in $(seq 1 30); do
  if curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:${PORT}/ping" >/dev/null 2>&1 \
     || curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -d '["PING"]' "http://127.0.0.1:${PORT}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

UPSTASH_REDIS_REST_URL="http://127.0.0.1:${PORT}" UPSTASH_REDIS_REST_TOKEN="$TOKEN" NODE_ENV=test \
  node --test --test-concurrency=1 --experimental-strip-types lib/*.itest.ts
