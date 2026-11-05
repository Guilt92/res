# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **ACL deny always wins on every address form.** Client addresses are now
  canonicalized once at ingress (IPv4-mapped IPv6 `::ffff:a.b.c.d` → plain
  IPv4) and that same address is used for ACL evaluation, rate limiting, RRL
  and traffic statistics. Previously an IPv6 allow rule matching the mapped
  form (for example `::ffff:0:0/96`) could admit an embedded IPv4 address
  before its IPv4 deny rule was consulted.
- **ACL conflict detection ignores disabled entries.** A disabled entry is
  never evaluated, so it may overlap an enabled rule (or another disabled
  entry) without being rejected. This lets operators stage and disable rules
  before enabling them. Enabled entries still reject duplicates and
  allow/deny conflicts. Migration: no config change needed; the new rule only
  *permits* configurations that were previously rejected.

### Changed defaults

- **Management API binds loopback by default.** `server.api_addr` now
  defaults to `127.0.0.1:8080` instead of `0.0.0.0:8080`. The Docker stack
  already publishes the dashboard on the host loopback only
  (`127.0.0.1:8080:8080`, overridable with `RES_DASHBOARD_PUBLISH`). The
  container image must keep `api_addr = "0.0.0.0:8080"` inside the container
  for the published port to reach it (see `config/res.toml`).
  Migration: nothing breaks for existing explicit configs; bare-metal
  deployments relying on the old default of binding all interfaces must now
  set `api_addr` explicitly (and serve over HTTPS or a trusted reverse proxy).
- **Docker stack ships no default credentials.** `RES_ADMIN_PASSWORD` and
  `RES_METRICS_TOKEN` are now required variables (`${VAR:?}`): the stack
  refuses to start until the operator supplies them, instead of running with
  working `change-me-*` placeholders. Migration: set these variables (and
  match `RES_METRICS_TOKEN` in `deploy/prometheus.yml`) before starting.
- **Docker dashboard/API and Grafana publish loopback-only by default** (was
  all interfaces for the dashboard and Grafana). Override with
  `RES_DASHBOARD_PUBLISH` / `RES_GRAFANA_PUBLISH`.
- **`RES_SECURE_COOKIES` environment variable** forces the `Secure` flag on
  session/CSRF cookies (mirrors `RES_PROTECT_METRICS`). The Docker stack
  enables it.

### Added

- **Responsive dashboard with light/dark themes.** The control plane follows
  the operating system color scheme by default and can be pinned to Auto,
  Light, or Dark from the header (or the sign-in dialog). The preference is
  stored per browser in `localStorage` (`res-theme-pref`) and applied before
  first paint, so reloads do not flash the wrong theme. Charts, KPI cards,
  tables, forms and the sign-in dialog are fully themed with no new runtime
  dependencies. The layout is usable from 320 px upward: the sidebar becomes
  an off-canvas drawer on narrow screens and wide tables scroll inside their
  own panels instead of overflowing the page.
- **Multiple config backup generations.** Successful persistence writes now
  keep up to three generations of the last known-good configuration
  (`res.toml.backup`, `res.toml.backup.2`, `res.toml.backup.3`) instead of a
  single `.backup` file. `restore_backup` promotes a generation only after it
  parses as a complete configuration. Stale temp files left by a crashed
  writer are removed on the next save, and persistence failures are logged as
  structured `config_persist_failed` events.

### Fixed

- **Admin password rotation is persist-first.** The new password is written to
  the credentials file before it is published in memory, so a failed disk
  write leaves the old password active instead of diverging between memory and
  disk across a restart.

### Performance

- **DNS-over-TLS connection reuse.** Direct DoT upstreams now keep a bounded
  idle pool of established TLS sessions (2 per upstream identity, 32 total,
  30 s idle / 5 min age) keyed by target, SNI and CA bundle, and share rustls
  session resumption through the cached client config. Sequential queries no
  longer pay a full TCP+TLS handshake each time. Certificate validation is
  unchanged; proxied DoT is not pooled. Startup warns (`dot_short_timeout`)
  when a DoT upstream's timeout budget is under 1 s, since the first exchange
  still includes the handshake.
