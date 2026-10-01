#!/usr/bin/env bash
# Reproducible end-to-end benchmark for res.
#
# Starts two local mock DNS upstreams (no external resolvers involved), starts
# the gateway in front of them, verifies it answers, then drives it with
# res-loadtest at several target rates. Results (with system info) are
# written to bench/results/.
#
# Usage: bench/run.sh [qps ...]        default: 1000 5000 10000
set -euo pipefail

cd "$(dirname "$0")/.."
BIN=target/release
RESULTS=bench/results
DURATION="${DURATION:-15}"
QPS_LEVELS=("$@")
[ ${#QPS_LEVELS[@]} -eq 0 ] && QPS_LEVELS=(1000 5000 10000)

mkdir -p "$RESULTS"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$RESULTS/$STAMP"
mkdir -p "$OUT"

cleanup() {
  jobs -p | xargs -r kill 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

if [ ! -x "$BIN/res" ] || [ ! -x "$BIN/mock-upstream" ] || [ ! -x "$BIN/res-loadtest" ]; then
  echo "missing release binaries; run: cargo build --release" >&2
  exit 1
fi

echo "== starting mock upstreams =="
"$BIN/mock-upstream" --listen 127.0.0.1:15300 >"$OUT/mock-1.log" 2>&1 &
"$BIN/mock-upstream" --listen 127.0.0.1:15301 >"$OUT/mock-2.log" 2>&1 &
sleep 0.3

echo "== starting gateway =="
"$BIN/res" --config bench/bench.toml serve >"$OUT/gateway.log" 2>&1 &
GATEWAY_PID=$!
sleep 0.7

if ! "$BIN/res" --config bench/bench.toml probe --server 127.0.0.1:15353 --require-ok; then
  echo "gateway probe failed; see $OUT/gateway.log" >&2
  exit 1
fi

echo "== hot-path microbenchmark =="
"$BIN/res-hotpath-bench" --iters 300000 | tee "$OUT/hotpath.txt"

for QPS in "${QPS_LEVELS[@]}"; do
  echo "== loadtest qps=$QPS duration=${DURATION}s =="
  "$BIN/res-loadtest" --server 127.0.0.1:15353 --qps "$QPS" --duration "$DURATION" \
    | tee "$OUT/loadtest-${QPS}.txt"
done

echo "== gateway stats snapshot =="
curl -s localhost:18080/api/stats | python3 -m json.tool >"$OUT/stats.json" || true
curl -s localhost:18080/api/diagnostics | python3 -m json.tool >"$OUT/diagnostics.json" || true

kill "$GATEWAY_PID" 2>/dev/null || true
echo "results written to $OUT/"
