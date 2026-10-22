# DNS Security and Panel Hardening Follow-up

Date: 2026-10-22
Repository: `/home/outis/work-github/res`
Branch: `main`

## Scope

This follow-up completes the hardening work started by the dashboard redesign
(`a8e91a8`). Changes are local commits; nothing was pushed. The production
Compose stack was intentionally not restarted.

## Commits

| Commit | Change |
|---|---|
| `7940035` | Separate metrics-only bearer authentication and fail closed |
| `b1e369b` | Optional policy requiring encrypted (TLS) upstreams |
| `f94cec7` | Bounded UDP response-rate limiting (RRL) |
| `c01b18b` | Strict dashboard CSP with external CSS/JS assets |
| `91d2732` | Non-root container with dropped capabilities |
| `a002b43` | IPv6 DNS/API test coverage and documentation |

## What Changed

### Metrics authentication

- `/metrics` accepts only the dedicated token from `RES_METRICS_TOKEN`
  (`AuthConfig.metrics_token`, environment-only and skipped by TOML
  serialization).
- When `protect_metrics = true` and the token is missing, scrapes fail closed
  with `401`; there is no fallback to the admin/API token or a browser session.
- The metrics token is not accepted by `/api/*`.
- Compose and Prometheus use `RES_METRICS_TOKEN`; the shared `api_token` was
  removed from `config/res.toml`.

### Encrypted upstream policy

- `server.require_encrypted_upstreams` (default `false`) rejects startup/config
  reload when any enabled upstream is not `protocol = "tls"`.
- Disabled plaintext entries are allowed, so staged migrations still work.
- A warning is emitted when the policy is off and enabled plaintext upstreams
  exist. DoT keeps its existing no-downgrade behavior on certificate/SNI
  failure.

### Response-rate limiting

- UDP responses are bucketed by `(canonical client IP, lowercased qname,
  qtype, rcode)`; TCP is exempt because it cannot carry spoofed-source
  amplification.
- Limits are bounded and sharded (64 shards, 30-second idle pruning,
  configurable `max_tracked_keys`). Excess responses return TC=1 by default,
  or are dropped with `action = "drop"`.
- New metrics: `res_rrl_truncated_total`, `res_rrl_dropped_total`; stats expose
  `rrl_truncated` and `rrl_dropped`; rate events are coalesced as
  `rrl_limited`.
- Defaults: enabled, 50 responses/s per key, burst 100, 65,536 keys,
  truncate. Validation rejects zero/negative/non-finite values and oversized
  key tables.

### Dashboard CSP

- Inline `<style>` and both inline `<script>` blocks moved to
  `dashboard/app.css`, `dashboard/boot.js`, and `dashboard/app.js`.
- Every response now carries:
  `default-src 'none'; script-src 'self'; style-src 'self';
  style-src-attr 'unsafe-inline'; img-src 'self' data:; font-src 'self';
  connect-src 'self'; base-uri 'none'; form-action 'self';
  frame-ancestors 'none'; object-src 'none'`.
- `style-src-attr 'unsafe-inline'` is retained for existing inline `style`
  attributes in chart/table markup; scripts allow no inline or `eval`.
- Static-file hardening tests now also verify CSP, asset MIME types, and the
  absence of inline style/script blocks in `index.html`.

### Non-root container

- The runtime image creates UID/GID 10001, makes `/etc/res` and `/app` owned by
  it, and uses `USER 10001:10001`.
- The entrypoint refuses an explicit root override.
- Compose runs as `${RES_UID:-1000}:${RES_GID:-1000}` so the host `./config`
  bind mount remains writable, drops all capabilities, keeps
  `no-new-privileges`, and sets
  `net.ipv4.ip_unprivileged_port_start=53` explicitly.
- The image is still read-only at runtime with only `/tmp` as tmpfs.

### IPv6

- DNS UDP/TCP and the management API work on IPv6 listeners (`[::]` or
  `[::1]`); ACLs already include `::1/128`.
- A new integration test covers DNS over IPv6 UDP/TCP and the IPv6 API. It
  skips only when the host has IPv6 disabled.

## Verification

- `cargo fmt --all`: clean.
- `cargo test`: 243 library tests and 80 integration tests passed; 0 failed.
- `cargo clippy --all-targets -- -D warnings`: clean.
- Docker image rebuilt from the repo and run in isolated containers with:
  read-only root filesystem, `--cap-drop ALL`, `no-new-privileges`, non-root
  UID, and the unprivileged-port sysctl.
  - DNS over UDP and TCP returned real upstream answers as UID 10001.
  - `/api/health` returned `200`; anonymous `/metrics` returned `401`, and the
    dedicated token returned `200`.
  - An explicit `--user 0` invocation was refused by the entrypoint.
  - A compose-style UID 1000 bind mount persisted `res.credentials` with mode
    `0600`.
  - The same image with `[::]:53` and `[::]:8080` answered IPv6 DNS over UDP
    and TCP on `[::1]`, and `GET http://[::1]:8080/api/health` returned
    `{"status":"ok","version":"0.1.0"}`.
- Dashboard exercised in Chromium 145, Firefox 146.0.1, and WebKit 26.0:
  login succeeded, `/app.css`, `/boot.js`, and `/app.js` loaded, 25 charts
  rendered, all 18 panels and 6 primary KPIs were present, no page errors, and
  zero CSP violations. The only 401 was the expected pre-login session probe.

## Residual Risks and Limitations

- RRL limits repeated responses, not traffic volume. A spoofed-source flood
  still reaches the host; pair it with network filtering and do not run as an
  open resolver. This work does not claim volumetric-DDoS protection.
- Enabled upstreams are still plaintext in the shipped config
  (`require_encrypted_upstreams = false`). Set it to `true` after migrating all
  enabled upstreams to DoT.
- CSP still permits inline `style` attributes (`style-src-attr`), though no
  inline scripts or `eval` are allowed.
- Non-root compose requires the `./config` bind mount to be writable by
  `RES_UID`/`RES_GID` (default 1000:1000). The image alone defaults to UID
  10001.
- The IPv6 integration test skips on this host because IPv6 is disabled
  (`disable_ipv6=1`); live IPv6 behavior was verified inside an isolated
  container instead.
- Browser checks live in `/tmp/res-panel-8081` and are not part of the Rust
  test suite. `cargo audit`/`cargo deny` are not installed, so dependency
  auditing remains a separate task.

## Deployment Notes

1. Rebuild and recreate the `res` service during a maintenance window:
   `docker-compose build res && docker-compose up -d --force-recreate res`.
2. Ensure `./config` is owned by `RES_UID`/`RES_GID`; the container must write
   `res.toml` atomically and persist `res.credentials` with mode `0600`.
3. Keep `RES_PROTECT_METRICS=true` and confirm Prometheus sends
   `RES_METRICS_TOKEN`; admin/session credentials will not work for `/metrics`.
4. To enforce transport encryption, migrate enabled upstreams to
   `protocol = "tls"` and set `require_encrypted_upstreams = true`.
5. Review RRL thresholds against real traffic before exposing the listener to
   untrusted networks.

## Relevant Files

- `src/ratelimit.rs`, `src/dns/pipeline.rs`, `src/dns/msg.rs`,
  `src/dns/forward.rs`, `src/shared.rs`: RRL serving path and truncation.
- `src/config.rs`, `config/res.toml`: metrics token, encrypted-upstream policy,
  RRL validation/defaults.
- `src/api/mod.rs`, `src/metrics.rs`: metrics guard, CSP/security headers,
  RRL stats and counters.
- `dashboard/index.html`, `dashboard/app.css`, `dashboard/boot.js`,
  `dashboard/app.js`: CSP-compatible dashboard assets.
- `Dockerfile`, `docker/entrypoint.sh`, `docker-compose.yml`: non-root runtime.
- `tests/gateway.rs`, `tests/common/mod.rs`: metrics auth, encrypted upstream,
  RRL, CSP/static assets, IPv6 tests.
- `README.md`: configuration, security model, IPv6, and container guidance.
