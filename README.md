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
* Fail-closed ACL, per-IP/global token-bucket rate limiting, optional
  TTL-clamped response cache
* Upstream pools with strict priority tiers and weighted sharing, three
  selection strategies, active health checks with hysteresis
* Bounded failover: total per-query deadline, per-attempt timeout, attempt
  budget, one try per upstream
* Load shedding (max in-flight UDP, max TCP connections), packet counters
  with running maxima
* Prometheus metrics, structured logs, bounded event/history rings
* REST API: status, stats, diagnostics, upstream CRUD, config import/export,
  client/domain tables, timeseries
* Six Grafana dashboards (traffic, clients, upstreams, failures, packets,
  analytics) provisioned from `deploy/grafana/`

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
| `GET /api/config`, `PUT /api/config` | config export / validated hot import |
| `GET /api/events`, `/api/history`, `/api/timeseries` | event rings, bounded history, chart data |
| `GET /api/clients`, `/api/domains` | top client addresses, top queried names |

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
