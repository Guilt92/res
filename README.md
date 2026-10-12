# res

`res` is a lightweight DNS gateway/proxy: one Rust binary owns the DNS data
plane — UDP/TCP listeners, parsing, ACLs, rate limiting, optional caching,
upstream selection, health checks and bounded failover — and forwards queries
to configured upstream resolvers. Control plane: REST API, Prometheus
metrics, a built-in JSON dashboard and an optional Grafana stack.

**Forwarder, not a recursive resolver.** `res` never performs iterative
resolution, never queries root or authoritative servers and never walks the
DNS hierarchy: every query (cache misses included) is sent to a configured
upstream. DNS packets are parsed with `hickory-proto`; no resolver logic is
implemented.

## Capabilities

* UDP + TCP DNS listeners (RFC 1035 via `hickory-proto`), EDNS-aware size
  limits, TC=1 → TCP retry
* Fail-closed ACL (IPv4, IPv6 and IPv4-mapped clients), per-IP/global
  token-bucket rate limiting
* Response cache, enabled by default: TTLs are never extended beyond what the
  upstream advertised (they also decrement on every hit), RFC 2308 negative
  caching for NXDOMAIN/NODATA, bounded by entry count and TTL caps
* Upstream pools with priority tiers (strict by default, optional shared
  traffic to keep lower tiers warm), weighted sharing, three selection
  strategies, active health checks with hysteresis, selectable
  DEGRADED policy (always usable, or last resort)
* Bounded failover: total per-query deadline, per-attempt timeout, attempt
  budget, one try per upstream; failover latency is measured
  (`res_failover_latency_seconds`)
* Load shedding (max in-flight UDP, max TCP connections), packet counters
  with running maxima
* Prometheus metrics, structured logs, bounded event/history rings
* REST API: status, stats, diagnostics, upstream CRUD, config import/export,
  client/domain tables, timeseries
* Six Grafana dashboards (traffic, clients, upstreams, failures, packets,
  analytics) provisioned from `deploy/grafana/`

## Client ACLs

`[acl]` is fail-closed: an empty `allowed_cidrs` denies everyone, so an
unconfigured instance can never become an open resolver. Add your customer
networks explicitly — public CIDRs are fine:

```toml
[acl]
allowed_cidrs = ["127.0.0.0/8", "::1/128", "203.0.113.0/24", "2001:db8::/32"]
denied_cidrs  = []          # evaluated first, wins over allowed_cidrs
```

IPv4-mapped IPv6 clients (`::ffff:a.b.c.d`, as seen on dual-stack sockets)
are matched against both the IPv6 rules and the embedded IPv4 address.

## Quick start

Docker stack — DNS `:53` (UDP+TCP), dashboard/API `:8080`,
Prometheus `:9090`, Grafana `:3000`:

```console
$ docker-compose up -d --build
$ dig @127.0.0.1 -p 53 example.com
```

Local binary (the default config binds `:53`, so root or
`CAP_NET_BIND_SERVICE` is required):

```console
$ cargo build --release
$ sudo ./target/release/res --config config/res.toml serve
$ dig @127.0.0.1 example.com
```

Binaries: `res` (serve/probe), `res-loadtest`, `res-hotpath-bench`,
`mock-upstream` (test double).

## Configuration

Single TOML file `config/res.toml` — no database. Human durations (`"2s"`,
`"500ms"`); sections `[server]`, `[query]`, `[acl]`, `[ratelimit]`,
`[failover]`, `[health]`, `[selection]`, `[cache]`, `[logging]`,
`[monitoring]`, `[[upstreams]]`.

* The config directory must be writable: the API rewrites the file
  atomically (temp + fsync + rename) and keeps `res.toml.backup` as the last
  valid version, which is loaded automatically if the primary file is broken.
* `RES_PROMETHEUS_URL` overrides `[monitoring].prometheus_url`.
* Directories mounted into containers must be directory mounts (compose uses
  `./config:/etc/res:rw`).

## API & monitoring

| Endpoint | Purpose |
| --- | --- |
| `GET /` | JSON dashboard (live data only) |
| `GET /metrics` | Prometheus exposition |
| `GET /api/health`, `/api/status`, `/api/stats`, `/api/diagnostics` | liveness, runtime state, counters, host/config diagnostics |
| `GET/POST /api/upstreams`, `PATCH/DELETE /api/upstreams/{id}` | upstream CRUD, state, manual probes |
| `POST /api/upstreams/{id}/test` | on-demand connectivity/DNS probe of one upstream |
| `GET /api/config`, `PUT /api/config` | config export / validated hot import |
| `GET /api/events`, `/api/history`, `/api/timeseries` | event rings, bounded history, chart data |
| `GET /api/clients`, `/api/domains` | top client addresses, top queried names |

### Upstream management at runtime

Upstream DNS servers can be added, edited, enabled/disabled, probed and
removed **without restarting the service** — from the dashboard section
"Upstream DNS management" (`http://localhost:8080/`) or directly via the
API. Every change is validated as a complete configuration, applied
atomically via an `ArcSwap` snapshot (in-flight queries finish on the old
snapshot; new queries see the new pool immediately), then persisted with a
temp-file + fsync + rename write that keeps `res.toml.backup`.

Safety properties:

* **Admin token** — set `[server].api_token` (or `RES_API_TOKEN`) to require
  `Authorization: Bearer <token>` on every configuration-changing endpoint.
  Empty token keeps the open development posture (a startup warning is
  emitted). The dashboard stores the token in the browser only.
* **Optimistic concurrency** — mutations accept an optional `generation`
  (from `GET /api/upstreams`); a stale generation is rejected with `409`.
* **Last-upstream guard** — disabling or removing the last enabled upstream
  requires an explicit `confirm=true`, otherwise `409 confirm_required`.
* **Atomic persistence** — invalid changes never touch the running config
  or the file; a persist failure is reported in the response, audited
  (`persist_failed` / `applied_persist_failed` events) and visible in
  `/api/diagnostics`.
* **Audit trail** — every accepted and rejected change is recorded in the
  config event ring (`GET /api/config/events`) with action, timestamp and
  outcome.

Prometheus scrapes `res:8080/metrics` every 5 s (`deploy/prometheus.yml`).
Grafana (`:3000`, admin/admin; compose also enables anonymous Viewer)
provisions six dashboards in folder `res` from
`deploy/grafana/dashboards/` every 30 s; regenerate the JSON with:

```console
$ python3 deploy/grafana/generate_dashboards.py
```

## Development

```console
$ cargo fmt --check
$ cargo clippy --all-targets --all-features -- -D warnings
$ cargo test
```

Requires rustc 1.88+; Docker only for the full stack. MIT licensed.
