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
  caching for NXDOMAIN/NODATA, bounded by entry count and TTL caps. Queries
  carrying any EDNS option (ECS, COOKIE, padding, ...) bypass the shared cache
  and single-flight, because their upstream replies may be client-specific
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

This is an **application-layer ACL**, not a host firewall: it decides what
the gateway answers, not what reaches the machine. Keep the OS firewall
tight around port 53 as well.

## Quick start

Docker stack — DNS `:53` (UDP+TCP), dashboard/API `:8080`,
Prometheus `:9090` (localhost-only), Grafana `:3000` (auth required):

```console
$ docker compose up -d --build
$ dig @127.0.0.1 -p 53 example.com
$ open http://localhost:8080/        # log in as admin (password below)
```

All credentials are plain text in `docker-compose.yml` — intentional for
this deployment (no secrets manager), defined in exactly one place:

| Service | URL | User | Password (in the file named below) |
|---|---|---|---|
| Dashboard/API | `:8080` | `admin` (full), `viewer` (read-only) | `RES_ADMIN_PASSWORD` / `RES_VIEWER_PASSWORD` (`docker-compose.yml`) |
| Grafana | `:3000` | `admin` | `GF_SECURITY_ADMIN_PASSWORD` (`docker-compose.yml`) |
| Prometheus | `:9090` | `prom` | `deploy/prometheus/web.config.yml` (`--web.config.file`) |

Each application enforces its own credential: the gateway rejects
unauthenticated API requests with `401` (viewer mutations: `403`) and stores
only argon2 hashes in `config/res.credentials` (mode `0600`, gitignored);
Grafana applies its admin password on every start; Prometheus does **not**
read auth from environment variables — HTTP basic auth comes from the web
config file mounted in compose, so unauthenticated `/api/v1/*` and UI
requests get `401`. The gateway's Prometheus proxy and the Grafana datasource
both send the `prom` credentials automatically.

If the host already owns port 53 (systemd-resolved, another resolver),
do not edit the compose file — override the published port:

```console
$ RES_DNS_PUBLISH=5353 docker compose up -d --build
$ dig @127.0.0.1 -p 5353 example.com
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
`[failover]`, `[health]`, `[selection]`, `[cache]`, `[auth]`, `[logging]`,
`[monitoring]`, `[[upstreams]]`.

* The config directory must be writable: the API rewrites the file
  atomically (temp + fsync + rename) and keeps `res.toml.backup` as the last
  valid version, which is loaded automatically if the primary file is broken.
* `RES_PROMETHEUS_URL` overrides `[monitoring].prometheus_url`;
  `RES_PROMETHEUS_USERNAME` / `RES_PROMETHEUS_PASSWORD` (env-only, never in
  the TOML) are sent as HTTP basic auth on every proxy query when the
  Prometheus server requires it.
* Directories mounted into containers must be directory mounts (compose uses
  `./config:/etc/res:rw`).

### Authentication (dashboard & API)

Set by environment (`docker-compose.yml` sets them in plain text for this
deployment), hashed with argon2id at startup and persisted in
`res.credentials` (mode `0600`, next to the TOML config) — never written
into the TOML itself:

* `RES_ADMIN_PASSWORD` — `admin`, full access (login, mutations).
* `RES_VIEWER_PASSWORD` — `viewer`, read-only (all `GET`s; every mutation is
  rejected with 403).
* Optional `[server].api_token` / `RES_API_TOKEN` — legacy
  `Authorization: Bearer` auth for scripts; when set it is *also* required
  for mutations even for cookie sessions.

Behaviour: session cookie (`HttpOnly`, `SameSite=Strict`) plus a CSRF
double-submit token for cookie-authenticated mutations; `[auth]` section
controls session lifetime (`session_ttl`), lockout (`max_failed_attempts`
within `lockout_window`, held for `lockout_duration`), per-IP login
throttling (`login_rate_limit_per_minute`; `0` disables) and
`secure_cookies` (set `true` behind HTTPS). Password rotation
(`POST /api/auth/rotate-password`) re-hashes the credential **and revokes
every existing session**. With no passwords configured the gateway falls
back to the legacy open-read/token posture and warns loudly at startup.

## Exposing the dashboard (reverse proxy / HTTPS)

The binary speaks plain HTTP only — terminate TLS in front of it:

* Put nginx/Caddy/Traefik in front of `:8080` with a certificate; forward
  `X-Forwarded-*` only from a trusted hop.
* The gateway does **not** honour `X-Forwarded-For`: client-based limits
  (login throttle) see the proxy's address, so also rate-limit at the proxy
  (recommended anyway). DNS itself is not affected — it never goes through
  the proxy.
* Set `[auth].secure_cookies = true` (or restart with it) once HTTPS is in
  place so session cookies carry the `Secure` flag.
* API concurrency is bounded (256 in-flight, 5 s wait) and sheds load with
  `503`; a reverse proxy can add its own connection limits.
* `/metrics` is unauthenticated by default for Prometheus scrapes on the
  internal network; set `[auth].protect_metrics = true` (with an
  `api_token`) if it is reachable more widely — never expose it publicly.

## API & monitoring

| Endpoint | Purpose |
| --- | --- |
| `GET /` | dashboard (SPA; `/api/*` misses answer JSON 404) |
| `GET /metrics` | Prometheus exposition |
| `GET /api/health` | liveness (version) |
| `GET /api/status`, `/api/stats`, `/api/diagnostics` | runtime state, counters, host/config diagnostics |
| `GET/POST /api/upstreams`, `PATCH/DELETE /api/upstreams/{id}` | upstream CRUD, state, manual probes |
| `POST /api/upstreams/{id}/test` | on-demand connectivity/DNS probe of one upstream |
| `POST /api/auth/login`, `DELETE /api/auth/session`, `POST /api/auth/rotate-password` | login (cookie+CSRF), logout, password rotation (revokes all sessions) |
| `GET/PUT /api/acl`, `POST/PATCH/DELETE /api/acl/entries` | structured client ACL with `source` per entry |
| `GET/PUT /api/cache`, `POST /api/cache/clear` | TTL policy + byte/entry caps, live clear |
| `GET/PUT /api/health/config`, `GET/PUT /api/selection` | probing cadence/recovery policy, traffic-selection policy |
| `GET /api/config`, `PUT /api/config`, `POST /api/config/rollback` | export, validated hot import (`?generation=&confirm=`), backup restore |
| `GET /api/config/events`, `/api/events` | config audit ring, merged event ring |
| `GET /api/history`, `/api/timeseries`, `/api/monitoring` | bounded history, chart data, Prometheus fallback info |
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

Prometheus scrapes `res:8080/metrics` every 5 s (`deploy/prometheus.yml`,
15 days / 2 GB retention). Prometheus' own endpoints require HTTP basic auth
(user `prom`, from `deploy/prometheus/web.config.yml` mounted via
`--web.config.file` — Prometheus has no environment-variable auth;
unauthenticated API/UI requests get `401`). Grafana (`:3000`) requires
`admin` / `GF_SECURITY_ADMIN_PASSWORD`; anonymous access and sign-ups are
disabled, and its Prometheus datasource sends the same `prom` credentials
(`deploy/grafana/provisioning/datasources/prometheus.yml`). Six dashboards
are provisioned in folder `res` from
`deploy/grafana/dashboards/` every 30 s; regenerate the JSON with:

```console
$ python3 deploy/grafana/generate_dashboards.py
```

### Selection policy (`[selection]`)

Every query scores the usable upstreams and picks among them:
`strategy` (`weighted_reliability` default = weighted roulette over a
health × reliability × latency × probe score; `best_score` = always the
top scorer; `random_healthy` = uniform, for debugging), `tier_policy`
(`strict` keeps lower priority tiers cold; `shared` routes
`lower_tier_share` of traffic to them so they stay measured and warm),
`degraded_policy` (`usable` or `last_resort`) and `min_probe_samples`
(below this many completed probe rounds the probe term is neutral so a
fresh upstream is not penalised). The dashboard's "Health checks &
selection" panel edits both `[health]` and `[selection]` at runtime; the
upstreams table shows each candidate's score, rank and the factors behind
it (hover the score).

## Operational notes & known limitations

Deliberate scope decisions, so nothing here surprises an operator:

* **Compose credentials are plain text** — intentionally, per this
  deployment's requirement (no secrets manager). The gateway still stores
  only argon2 hashes at runtime; change the values by editing
  `docker-compose.yml` and `deploy/prometheus/web.config.yml` together.
* **No TLS in the binary** — plain HTTP/UDP/TCP; terminate HTTPS at a
  reverse proxy (see above) and set `secure_cookies`.
* **ACL is application-layer only** — pair it with a host firewall.
* **No DNSSEC validation** — `DO`/`CD` and DNSSEC records are passed through,
  and `DO` queries bypass the shared cache because the gateway cannot assert
  the authenticity of upstream data.
* **No Response Rate Limiting (RRL)** — per-IP/global token buckets and the
  fail-closed ACL are the only admission controls. A spoofed-source UDP flood
  can bypass the per-IP bucket, and the gateway is not safe as an open
  internet-facing resolver.
* **Upstream transaction ids are randomized per exchange**, but query-name
  case randomization (0x20) is not implemented; source-port entropy comes from
  the OS. Do not expose UDP service to untrusted networks without an upstream
  path you trust.
* **Zone transfers are not blocked** — `AXFR`/`IXFR` queries follow the same
  ACL/forwarding path. `ANY` follows `query.any_policy` (`forward` by default);
  set it to `refuse` on amplification-sensitive deployments.
* **`X-Forwarded-For` is not trusted** — API-side per-IP limits (login
  throttle) see the socket peer; rate-limit at the proxy for real client
  IPs. DNS is unaffected.
* **`/metrics` is open by default** (Prometheus scrape model);
  `protect_metrics` + `api_token` gate it when needed.
* **Top-clients/top-domains are bounded, not decaying** — capped by
  configured entry limits and evicted FIFO; entries do not age out over
  time on their own.
* **Duplicate OPT records on receive are not answered with FORMERR** —
  the serving path still emits exactly one OPT (duplicates are collapsed),
  which is what clients depend on; strict per-query FORMERR was skipped as
  not worth the hot-path cost.
* **Extended rcodes are classified as success in statistics** — a
  `BADVERS`-class reply passes through to the client but counts as `Ok`
  in success/failure rate classification (the standard rcode set is
  classified precisely).
* **API concurrency is bounded** (256 in-flight, ≤5 s wait, then `503`)
  and **no per-IP API rate limiter** exists beyond the login throttle —
  front it with a reverse proxy for public exposure.
* **No CSP header** — the dashboard ships an inline script by design;
  `nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`
  are set on every response.
* **Static-file fallback hardening** — unknown `/api/*` paths return JSON
  404 (never the SPA page), dotfiles and `..` are never served, missing
  assets 404 loudly.
* The API server holds a startup-time forwarder snapshot for the
  `/api/upstreams/{id}/test` button (probe *health checks* re-read the
  live config every round); only `tcp_fallback` could be stale there
  until the next restart — DNS data-plane selection always uses live
  config.

## Development

```console
$ cargo fmt --check
$ cargo clippy --all-targets --all-features -- -D warnings
$ cargo test
```
