#!/usr/bin/env bash
# Reproducible end-to-end benchmark for res.
#
# Starts two local mock DNS upstreams (no external resolvers involved), starts
# the gateway in front of them, verifies it answers, then drives it with
# res-loadtest at several target rates. Results (with system info) are
# written to bench/results/.
#
# Usage: bench/run.sh [qps ...]        default: 1000 5000 10000
#
# Environment overrides:
#   DURATION=15 TCP_FRAC=0.0 WORKERS=4 WINDOW=32
#   BENCH_UDP_PORT=15353 BENCH_API_PORT=18080
#   BENCH_UPSTREAM1_PORT=15300 BENCH_UPSTREAM2_PORT=15301
set -euo pipefail

cd "$(dirname "$0")/.."
BIN=target/release
RESULTS=bench/results
DURATION="${DURATION:-15}"
TCP_FRAC="${TCP_FRAC:-0}"
WORKERS="${WORKERS:-4}"
WINDOW="${WINDOW:-32}"
UDP_PORT="${BENCH_UDP_PORT:-15353}"
API_PORT="${BENCH_API_PORT:-18080}"
UP1_PORT="${BENCH_UPSTREAM1_PORT:-15300}"
UP2_PORT="${BENCH_UPSTREAM2_PORT:-15301}"
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

if [ ! -x "$BIN/res" ] || [ ! -x "$BIN/mock-upstream" ] \
  || [ ! -x "$BIN/res-loadtest" ] || [ ! -x "$BIN/res-hotpath-bench" ]; then
  echo "missing release binaries; run: cargo build --release" >&2
  exit 1
fi

CONFIG=bench/bench.toml
if [ "$UDP_PORT" != 15353 ] || [ "$API_PORT" != 18080 ] \
  || [ "$UP1_PORT" != 15300 ] || [ "$UP2_PORT" != 15301 ]; then
  CONFIG="$OUT/bench.toml"
  sed -e "s/127\\.0\\.0\\.1:15353/127.0.0.1:${UDP_PORT}/g" \
    -e "s/127\\.0\\.0\\.1:18080/127.0.0.1:${API_PORT}/g" \
    -e "s/port = 15300/port = ${UP1_PORT}/" \
    -e "s/port = 15301/port = ${UP2_PORT}/" \
    bench/bench.toml >"$CONFIG"
fi

echo "== starting mock upstreams =="
"$BIN/mock-upstream" --listen "127.0.0.1:${UP1_PORT}" >"$OUT/mock-1.log" 2>&1 &
"$BIN/mock-upstream" --listen "127.0.0.1:${UP2_PORT}" >"$OUT/mock-2.log" 2>&1 &
sleep 0.3

echo "== starting gateway =="
"$BIN/res" --config "$CONFIG" serve >"$OUT/gateway.log" 2>&1 &
GATEWAY_PID=$!
sleep 0.7

if ! "$BIN/res" --config "$CONFIG" probe --server "127.0.0.1:${UDP_PORT}" --require-ok; then
  echo "gateway probe failed; see $OUT/gateway.log" >&2
  exit 1
fi

echo "== hot-path microbenchmark =="
"$BIN/res-hotpath-bench" --iters 300000 | tee "$OUT/hotpath.txt"

TCP_LABEL="${TCP_FRAC//./_}"
for QPS in "${QPS_LEVELS[@]}"; do
  echo "== loadtest qps=$QPS tcp_frac=$TCP_FRAC duration=${DURATION}s =="
  "$BIN/res-loadtest" --server "127.0.0.1:${UDP_PORT}" --qps "$QPS" \
    --duration "$DURATION" --tcp-frac "$TCP_FRAC" --workers "$WORKERS" \
    --window "$WINDOW" --json | tee "$OUT/loadtest-${QPS}-tcp${TCP_LABEL}.json"
done

echo "== gateway stats snapshot =="
curl -s "localhost:${API_PORT}/api/stats" | python3 -m json.tool >"$OUT/stats.json" || true
curl -s "localhost:${API_PORT}/api/diagnostics" | python3 -m json.tool >"$OUT/diagnostics.json" || true

kill "$GATEWAY_PID" 2>/dev/null || true
echo "results written to $OUT/"
