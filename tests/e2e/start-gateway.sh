#!/usr/bin/env bash
# Start an isolated gateway for the browser smoke tests.
#
# Usage: tests/e2e/start-gateway.sh <res-binary> <work-dir> [dns-port] [api-port]
#
# * DNS binds 127.0.0.1 on an unprivileged test port (default 15353, UDP+TCP).
#   Never point this at port 53 of a machine that runs a resolver; on the
#   maintainers' servers the agreed test port is 153 (pass it as dns-port).
# * The config is a temporary copy of config/res.toml; the repository's
#   config is never modified.
# * Credentials: admin / adminpass12345 (test only).
set -euo pipefail
bin=${1:?res binary}
work=${2:?work dir}
dns_port=${3:-15353}
api_port=${4:-8099}
root=$(cd "$(dirname "$0")/../.." && pwd)

if [ "$dns_port" = "53" ]; then
  echo "refusing to bind DNS port 53 for tests" >&2
  exit 2
fi

mkdir -p "$work"
cp "$root/config/res.toml" "$work/res.toml"
sed -i \
  -e "s|^udp_addr.*|udp_addr = \"127.0.0.1:${dns_port}\"|" \
  -e "s|^tcp_addr.*|tcp_addr = \"127.0.0.1:${dns_port}\"|" \
  -e "s|^api_addr.*|api_addr = \"127.0.0.1:${api_port}\"|" \
  -e "s|^dashboard_dir.*|dashboard_dir = \"${root}/dashboard\"|" \
  "$work/res.toml"

RES_ADMIN_PASSWORD=adminpass12345 RES_VIEWER_PASSWORD=viewerpass12345 \
RES_METRICS_TOKEN=e2e-metrics \
  nohup "$bin" --config "$work/res.toml" serve >"$work/res.log" 2>&1 &
echo $! >"$work/res.pid"

for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:${api_port}/api/health" >/dev/null 2>&1; then
    echo "gateway up: dns=127.0.0.1:${dns_port} api=127.0.0.1:${api_port} pid=$(cat "$work/res.pid")"
    exit 0
  fi
  sleep 0.2
done
echo "gateway did not start; log:" >&2
cat "$work/res.log" >&2
exit 1
