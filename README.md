# OutisDNS

A production-oriented DNS gateway / forwarder in a **single Rust binary**.
OutisDNS owns the DNS data plane end to end — UDP/TCP :53 listening, packet
parsing, ACLs, rate limiting, caching, upstream selection, forwarding,
health checks, failover — and exposes a control plane (REST API, Prometheus
metrics, JSON dashboard). There is **no database anywhere in the stack**:
the single source of truth is one human-readable TOML file, written
atomically, with a last-known-good backup and a startup fallback chain.

```
client ──UDP/TCP 53──▶ outisdns ──(UDP/TCP)──▶ upstream resolvers (1.1.1.1, 8.8.8.8, …)
                          │
                          ├── Axum REST API   :8080  /api/...
                          ├── Prometheus      :8080  /metrics
                          └── JSON dashboard  :8080  /
```

## 1. Features

**Data plane (hot path — no file I/O, no blocking, bounded memory):**

* UDP and TCP DNS listeners (RFC 1035 parsing/serialization via `hickory-proto`)
* Fail-closed ACL (allowed/denied CIDR lists, pre-parsed into an immutable snapshot)
* Token-bucket rate limiting (per-client IP + global) with bounded client tracking
* Optional response cache (TTL-clamped, bounded entry count)
* Upstream selection strategies: `weighted_reliability`, `best_score`,
  `random_healthy`; strict priority tiers with weighted sharing inside a tier
* Bounded failover: total per-query deadline, per-attempt upstream timeout,
  `max_attempts` budget, one try per upstream, SERVFAIL retry policy
* Active health checks (UDP probes, optional TCP) with failure/recovery thresholds
* UDP truncation handling (TC=1 → TCP retry), EDNS-aware size limits
* Load shedding: `max_inflight_udp`, `max_tcp_connections`, per-connection query caps
* Per-query total deadline; SERVFAIL/REFUSED/NXDOMAIN pass through as final answers

**Control plane:**

* Axum REST API: health, status, stats, diagnostics, upstream CRUD + manual test,
  config export/import, bounded event rings (config/health/failover)
* Prometheus metrics (query/rcode/latency histograms, upstream counters, gauge
  exposition for in-flight, FDs/RSS, emergency state)
* Self-contained JSON dashboard (vanilla HTML/JS, no build step): overview,
  upstreams with health timeline, config editor with Apply/Reload, diagnostics,
  recent events, emergency banner, empty-state handling
* Structured logs (JSON or pretty) with event fields

**Configuration (no database, §"Configuration" below):**

* TOML with human duration strings (`"2s"`, `"500ms"`, `"1m"`)
* Atomic persistence: temp file → fsync → rename → dir fsync, previous valid
  version kept as `<file>.backup`
* Startup fallback chain: `file` → `backup` → built-in defaults, with the error
  surfaced in logs, `/api/status`, `/api/diagnostics` and the
  `outisdns_config_errors_total` counter
* Live hot-swap via `PUT /api/config`: parse + validate first, then swap an
  immutable `ArcSwap` snapshot (invalid input is rejected, runtime unchanged)
* Startup warnings for risky-but-valid settings (attempt budget exceeding the
  deadline, open-resolver ACL, health checks disabled, TCP fallback off)

## 2. Quick start

```console
$ cargo build --release
$ ./target/release/outisdns --config config/outisdns.toml serve
$ dig @127.0.0.1 -p 53 example.com        # from the host (needs root/CAP_NET_BIND_SERVICE for :53)
$ curl -s localhost:8080/api/status | python3 -m json.tool
$ ./target/release/outisdns --config config/outisdns.toml probe --server 127.0.0.1:53 --require-ok
```

Binaries: `outisdns` (serve/probe), `outisdns-loadtest` (traffic generator),
`outisdns-hotpath-bench` (stage microbenchmark), `mock-upstream` (local DNS
responder for reproducible benchmarks).

## 3. Configuration

`config/outisdns.toml` is the production sample. Sections: `[server]`
(listeners, packet/in-flight/connection limits), `[query]` (total deadline,
per-attempt timeout, attempt budget), `[acl]`, `[ratelimit]`, `[failover]`,
`[health]`, `[selection]`, `[cache]`, `[logging]`, `[[upstreams]]`.

Rules enforced by `validate()` (rejects the config with a precise message):

* `query.timeout >= query.upstream_timeout >= 1ms`, `max_attempts >= 1`
* `health.interval >= 100ms`, probes parse, thresholds `>= 1`
* upstream names unique, ports `!= 0`, addresses concrete (no `0.0.0.0`),
  priorities/weights `>= 1`
* deny/allow CIDRs parse; ratelimit/cache numbers positive

Keep `max_attempts * upstream_timeout <= timeout` so every configured attempt
can actually run; the startup warning (and `config.warnings` in `/api/status`)
points out when it does not.

Persistence protocol (`src/persist.rs::save_atomic`): round-trip validate →
copy current file to `.backup` only if it parses → write `.name.pid.tmp` in the
same directory → fsync → `rename` → fsync directory. The config directory must
therefore be a directory mount (compose mounts `./config:/etc/outisdns:rw`).

## 4. HTTP API (default `:8080`)

| Method & path | Purpose |
| --- | --- |
| `GET /api/health` | liveness (`{"status":"ok"}`) |
| `GET /api/status` | listeners, config (path/source/error/**warnings**), query, cache, upstream counts, emergency, in-flight, health-check settings |
| `GET /api/stats` | counters, qps, latency percentiles, rcode/failover/error breakdown, event counts |
| `GET /api/diagnostics` | PID, RSS, open FDs, config block, upstream list with last-state-change, resources, recent failovers/config events |
| `GET/POST /api/upstreams`, `PATCH/DELETE /api/upstreams/{id}` | CRUD; every mutation revalidates and persists atomically (flag `persisted` / `persist_error`) |
| `POST /api/upstreams/{id}/test` | one-shot manual probe |
| `GET /api/upstreams/{id}/health` | health history from the bounded ring |
| `GET /api/config` | export `{toml, path, source, error}` |
| `PUT /api/config` | import `{toml, persist?}` — invalid → `400`, runtime untouched |
| `GET /api/config/events` | configuration event ring |
| `GET /api/events?kind=&limit=` | merged/config/health/failover rings (`400` on unknown kind) |
| `GET /metrics` | Prometheus exposition |

## 5. Docker Compose (gateway + Prometheus + Grafana)

```console
$ docker-compose up -d --build      # DNS on :15353, API/dashboard :8080, Prometheus :9090, Grafana :3000 (admin/admin)
$ dig @127.0.0.1 -p 15353 example.com
```

No database service exists or is needed. `deploy/prometheus.yml` scrapes
`outisdns:8080/metrics`; Grafana provisions dashboards from
`deploy/grafana/`. The image health-checks itself with `outisdns probe`.

## 6. Benchmarks (measured, reproducible)

All numbers below were produced by the scripts in `bench/` on the machine
recorded in the output (`i5-6500, 4 cores, 15.5 GiB, Ubuntu 24.04, release
build, 2026-09-29`). Raw output lives in `bench/results/`.

**Reproduce:** `bench/run.sh [qps ...]` starts two local `mock-upstream`
instances + the gateway (`bench/bench.toml`), verifies with `probe`, runs
`outisdns-hotpath-bench` and `outisdns-loadtest` at each rate, and snapshots
`/api/stats`. No external DNS resolver is involved, so results do not depend
on the network path.

**Hot-path microbenchmark** (`outisdns-hotpath-bench`, ns/op):

| stage | ns/op | ops/sec |
| --- | ---: | ---: |
| packet parse | 226.3 | 4.42 M |
| ACL decision | 13.7 | 73.1 M |
| rate limit check | 59.0 | 16.9 M |
| upstream selection (8 candidates) | 189.2 | 5.29 M |
| admission control | 290.3 | 3.44 M |

**End-to-end through the gateway** (UDP, 15 s per point, local mock
upstreams):

| target qps | achieved qps | failures | p50 | p95 | p99 | avg |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 000 | 1 000.0 | 0.00% | 0.50 ms | 2.65 ms | 5.48 ms | 0.82 ms |
| 5 000 | 4 999.2 | 0.00% | 0.99 ms | 4.73 ms | 11.92 ms | 1.62 ms |
| 10 000 | 9 996.5 | 0.00% | 1.68 ms | 7.33 ms | 14.10 ms | 2.50 ms |
| 20 000 | 19 526.7 | 0.00% | 5.31 ms | 10.59 ms | 13.80 ms | 5.49 ms |
| 50 000 | ~19 500 (saturated) | 0.00% | 6.03 ms | 11.42 ms | 14.83 ms | 6.51 ms |

Readings:

* Up to ~19.5 k qps the gateway answers every query with **zero failures**;
  50 k qps is above capacity and simply queues (loss still 0%, latency grows).
* The same load generator sustained 44 k qps directly against the mock
  upstream (no gateway), so the **gateway is the binding component**, not the
  client; during saturation the gateway process used ~1.25 of 4 cores.
* Failover behaviour under real (throttled) external DNS was observed
  separately: timeout → retry → bounded deadline, with events recorded in the
  failover ring — external-resolver throughput is *not* quoted as a gateway
  number because this network throttles sustained foreign DNS traffic
  (a direct client run against 1.1.1.1 already showed p50 ≈ 193 ms and
  1.6 % loss at 1 k qps).

## 7. Tests

```console
$ cargo test        # 89 unit + 14 integration = 103 tests, all passing
$ cargo clippy --all-targets   # 0 warnings
$ cargo fmt --check
```

Integration tests boot the real gateway on ephemeral ports and cover: UDP/TCP
answering, ACL deny/REFUSED, rate limiting, cache, upstream CRUD +
persistence/backup behaviour, config export/import (round-trip and rejection
of invalid input), diagnostics + emergency visibility when every upstream is
down, failover event recording, metrics exposition.

## 8. Verification checklist (what was actually run)

Every item below was executed on 2026-09-29; nothing is inferred from code
reading alone.

* [x] `cargo fmt --check` — clean
* [x] `cargo clippy --all-targets` — 0 warnings
* [x] `cargo test` — 103/103 passing (89 unit, 14 integration)
* [x] `cargo build --release` — all four binaries built
* [x] `outisdns-hotpath-bench --iters 300000` — table in §6
* [x] `bench/run.sh 1000 5000 10000` and `bench/run.sh 20000 50000` —
      tables in §6, raw files in `bench/results/20260929-*`
* [x] Load generator ceiling test: 44 k qps direct to `mock-upstream`
      (proves the gateway, not the client, saturates at ~19.5 k qps)
* [x] `docker-compose up -d --build` — all three containers healthy; gateway
      container reports `healthy` via its own probe
* [x] `dig @127.0.0.1 -p 15353 example.com` over **UDP and TCP** — NOERROR
      with answers through the container
* [x] Dashboard `GET /` → HTTP 200; `GET /api/diagnostics` reports PID, RSS,
      open FDs, config warnings
* [x] `PUT /api/config` with modified TOML → `persisted: true`, file rewritten
      atomically, `outisdns.toml.backup` created, change visible live in
      `/api/status` (`per_ip_qps` 50 → 60) without restart
* [x] Corruption fallback: replaced the config file with invalid TOML and
      restarted → `/api/status` reports `source: "backup"` plus the exact parse
      error, `outisdns_config_errors_total 1`, DNS still answers NOERROR
* [x] Recovery: valid config re-persisted and restarted → `source: "file"`,
      `error: null`
* [x] Prometheus `activeTargets` → `health: up` scraping `outisdns:8080/metrics`
* [x] Grafana `/api/health` → `database: ok`; `/metrics` exposes
      `outisdns_config_errors_total`, `outisdns_resident_memory_bytes`
* [x] Emergency path (integration test): all upstreams down → diagnostics show
      `no_healthy_upstreams`, SERVFAIL answered, events recorded

## 9. Known limitations

* `GET /api/config` → `PUT /api/config` round-trips **values** but not
  comments (TOML is re-serialized on export); hand-edited files keep their
  comments as long as they are edited directly on disk.
* Single-instance UDP receive path saturates around 19–20 k qps on the
  reference machine; scale out horizontally for more.
* The compose file passes `network: host` + proxy build args so the image can
  be built behind a localhost-only HTTP proxy; both are no-ops without a proxy.
* Not yet implemented: DNSSEC validation, DoH/DoT listening, response rate
  limiting, zone transfers.
