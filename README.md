# res

`res` is a lightweight, health-aware DNS gateway written in Rust. It accepts
DNS over UDP and TCP, forwards each query to configured upstream resolvers,
and exposes a REST API, a web dashboard, and Prometheus metrics.

`res` is a forwarder, not a recursive resolver: it never queries root or
authoritative servers and performs no iterative resolution or local DNSSEC
validation.

## Features

- UDP and TCP DNS listeners with EDNS-aware response limits and TC=1 retry
- Priority-tiered upstream pools, health checks, weighted selection, and
  bounded failover
- Response cache with RFC 2308 negative caching and TTL bounds
- Fail-closed ACLs, per-client and global rate limits, and response-rate
  limiting
- Optional SOCKS5 or HTTP CONNECT upstream proxy, including SOCKS5 UDP
  association
- DNS-over-TLS upstreams with certificate and SNI validation
- REST API, web dashboard, Prometheus metrics, and Grafana dashboards
- Authenticated control plane with admin/viewer roles and optional HTTPS
- TOML configuration with validation, atomic writes, and backup recovery

## Requirements

- Docker and Docker Compose for the container stack
- Rust 1.88 or newer for local builds

## Docker quick start

The stack is **secure by default**: it ships no default credentials (the
gateway fails closed at startup without an admin password) and the management
interfaces are bound to the host loopback. Set the required variables first:

```bash
export RES_ADMIN_PASSWORD='a-long-random-admin-password'
export RES_METRICS_TOKEN='a-long-random-metrics-token'
docker compose up -d --build
```

Then query the gateway and open the dashboard:

```bash
dig @127.0.0.1 -p 153 example.com
```

| Service | Address |
|---|---|
| DNS | `127.0.0.1:153` (UDP and TCP; see `RES_DNS_PUBLISH` below) |
| Dashboard/API | http://127.0.0.1:8080 (loopback only) |
| Prometheus | http://localhost:9090 (loopback only) |
| Grafana | http://127.0.0.1:3000 (loopback only) |

The gateway's DNS port is published as host port **153** by default (to avoid
clashing with systemd-resolved or another resolver on the standard :53).
Publish the standard port, or any other, without editing the Compose file:

```bash
RES_DNS_PUBLISH=53 docker compose up -d
dig @127.0.0.1 example.com
```

The management dashboard/API is bound to the host **loopback** by default so
it is never exposed to the network. Expose it explicitly (only over HTTPS or
a trusted reverse proxy, and keep `RES_SECURE_COOKIES=true`):

```bash
RES_DASHBOARD_PUBLISH=0.0.0.0 docker compose up -d
```

The Grafana and Prometheus monitoring services use the **development
placeholder** credentials in `docker-compose.yml`, `deploy/prometheus.yml`,
`deploy/prometheus/web.config.yml`, and the Grafana provisioning file.
They are loopback-only, but change them all before exposing the stack.
Prometheus passwords must be updated together with their bcrypt hash.

The gateway container runs unprivileged. The bind-mounted `./config`
directory must be writable by the container UID; override it with `RES_UID`
and `RES_GID` if needed.

### Configuration directory ownership

Runtime updates use a temp file, fsync, and atomic rename in the config
directory, and `res.credentials` is stored there too. The directory must
therefore be writable by the non-root UID that runs the process. Compose
defaults to UID/GID `1000`; align it with the host owner explicitly:

```bash
# Fresh checkout (never run the gateway as root)
mkdir -p config
sudo chown -R "$(id -u):$(id -g)" config
chmod 700 config
RES_UID="$(id -u)" RES_GID="$(id -g)" docker compose up -d --build
```

Existing deployments created before the ownership was aligned need a one-time
migration. Changing ownership does not require root inside the container:

```bash
sudo chown -R "$(id -u):$(id -g)" config
chmod 700 config
RES_UID="$(id -u)" RES_GID="$(id -g)" \
  docker compose up -d --build --force-recreate res
```

The entrypoint probes the config directory at startup and refuses to start
with an actionable message when it is not writable; this prevents a later
dashboard mutation from failing with `EACCES`. If persistence still fails at
runtime, the mutation is rejected with HTTP `500` / `persist_failed`, the
active configuration is left unchanged, and the dashboard shows the error.
Successful writes keep up to three generations of the previous valid
configuration, mode-`0600`: `res.toml.backup` (newest), `res.toml.backup.2`
and `res.toml.backup.3`. Restoring an older generation is validated: the file
must parse as a complete configuration before it replaces `res.toml` (use
`res`'s persisted backups through the config import API, which validates the
same way, or copy the backup over `res.toml` and let startup validation
decide). Temp files abandoned by a crashed writer are removed automatically
on the next save.

### Resource limits

Compose applies CPU, memory, PID and file-descriptor bounds to every service:

| Service | CPU | Memory | PIDs | Other |
|---|---|---|---|---|
| `res` | 1.0 | 512 MiB | 256 | `nofile` 65536, read-only rootfs |
| `prometheus` | 0.5 | 512 MiB | 512 | 2 GB / 15 day TSDB cap |
| `grafana` | 0.5 | 256 MiB | 512 | — |

Override them without editing the file, for example:

```bash
RES_CPU_LIMIT=2 RES_MEMORY_LIMIT=1G \
PROMETHEUS_MEMORY_LIMIT=1G GRAFANA_MEMORY_LIMIT=512M \
docker compose up -d
```

The memory alert thresholds in `deploy/alerts.yml` (warning at 384 MiB,
critical at 460 MiB) assume the default 512 MiB `res` limit. If you raise or
lower `RES_MEMORY_LIMIT`, adjust those rules to match.

## Configuration

The main configuration file is `config/res.toml`. It defines listeners,
upstreams, ACLs, rate limits, caching, health checks, selection, failover,
authentication, proxy, logging, and monitoring.

- The ACL is allow-list based. Add every client network explicitly; an empty
  allow list cannot serve DNS clients.
- DNS-over-TLS upstreams use `protocol = "tls"`, normally on port `853`, and
  require `tls_server_name`. Successful direct (non-proxied) exchanges return
  the TLS session to a small bounded idle pool (up to 2 per upstream, 32
  process-wide, 30 s idle / 5 min total age), and rustls session resumption is
  shared through the cached client config, so sequential queries do not pay a
  TCP+TLS handshake each time. Proxied DoT is not pooled.
- A DoT exchange must complete within the per-upstream timeout, which defaults
  to 500 ms (`query.upstream_timeout_ms` or `timeout_ms` per upstream). The
  first exchange and any reconnect include a TCP connect plus TLS handshake;
  on high-latency links raise `timeout_ms` for that upstream (startup logs a
  `dot_short_timeout` warning when a DoT upstream's budget is under 1 s).
- Set `require_encrypted_upstreams = true` to reject enabled plaintext
  upstreams.
- `[proxy]` routes upstream exchanges through SOCKS5 or HTTP CONNECT. SOCKS5
  supports TCP, DoT, and UDP (`UDP ASSOCIATE`); HTTP CONNECT is TCP-only.
  When enabled, a proxy failure is an upstream failure: traffic never falls
  back to a direct connection.
- The proxy password can be persisted in the TOML file for restart survival,
  but it is redacted from logs, API exports, diagnostics, and audit events.
- `monitoring.client_ip_privacy` defaults to `"full"`. Use `"masked"` to hide
  host bits or `"off"` to disable per-client tracking.
- The configuration directory must be writable by the runtime UID for runtime
  updates and backup recovery. The API persists before publishing: a failed
  write rejects the mutation and leaves the active configuration unchanged.
  Successful writes keep up to three backup generations of the last
  known-good configuration (`res.toml.backup`, `.backup.2`, `.backup.3`).

Control-plane credentials are supplied through environment variables or a
mode-0600 credentials file:

| Variable | Purpose |
|---|---|
| `RES_ADMIN_PASSWORD` | Admin login (full access; required to start, no default) |
| `RES_VIEWER_PASSWORD` | Optional read-only viewer login |
| `RES_API_TOKEN` | Optional API bearer token |
| `RES_METRICS_TOKEN` | Dedicated metrics-only bearer token |
| `RES_PROTECT_METRICS` | Require the metrics token for `/metrics` |
| `RES_SECURE_COOKIES` | Mark session/CSRF cookies `Secure` (set `true` when serving over HTTPS) |
| `RES_PROMETHEUS_URL` | Prometheus URL used by the dashboard |
| `RES_PROMETHEUS_USERNAME` / `RES_PROMETHEUS_PASSWORD` | Prometheus basic auth |

Startup fails closed when no admin password, API token, or persisted
credentials are available. Passwords are stored as argon2id hashes in
`config/res.credentials` (mode `0600`, ignored by Git). The management API
binds the loopback by default; expose it only over HTTPS (which also forces
`Secure` cookies) or a trusted reverse proxy.

## Local build

The default configuration binds port 53, so running it directly requires root
or `CAP_NET_BIND_SERVICE`. For development, change the listener addresses in
`config/res.toml`. The management API binds the loopback by default; bind it
to a network address only when serving over HTTPS or a trusted reverse proxy.

```bash
cargo build --release
sudo ./target/release/res --config config/res.toml serve
```

Additional binaries:

- `res-loadtest` — DNS load generator
- `res-hotpath-bench` — hot-path microbenchmark
- `mock-upstream` — local DNS test upstream

## Tests and checks

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

Integration tests start in-process loopback upstreams and do not require
external DNS access. The TLS fixtures under `tests/fixtures/tls/` are
self-signed, test-only credentials and must never be used in production.

## Benchmarks

Build the release binaries first, then run the reproducible benchmark:

```bash
cargo build --release
bench/run.sh
```

The script starts local mock upstreams, runs the gateway, and writes results
to `bench/results/` (ignored by Git).

## Monitoring

- `deploy/prometheus.yml` defines scrape jobs.
- `deploy/alerts.yml` contains Prometheus alert rules.
- `deploy/grafana/` contains provisioning files and generated dashboards.
- Regenerate dashboards after editing the generator:

```bash
python3 deploy/grafana/generate_dashboards.py
```

Critical rules cover a missing gateway scrape, Prometheus itself being down,
zero enabled upstreams, zero usable upstreams, and imminent container OOM.
The stack evaluates rules in Prometheus but does not ship Alertmanager or a
notification destination: connect an existing Alertmanager/PagerDuty/Slack
integration, or scrape the rules from your central monitoring system.

## Security notes

- Restrict DNS access with ACLs and a host firewall. Never expose an
  unrestricted DNS gateway.
- Application rate limits bound in-process work but do not stop volumetric
  DDoS traffic; add network-level protection where needed.
- The management API/dashboard binds the host loopback by default and ships
  no default credentials. Expose it only over HTTPS (which marks cookies
  `Secure`) or a trusted reverse proxy, and change every monitoring
  placeholder credential first.
- Keep the configuration directory private; it may contain an API token or a
  proxy password.

## Limitations

- No recursive resolution or local DNSSEC validation.
- No native DNS-over-HTTPS (DoH) upstream transport.
- ACLs, rate limits, caching, and health state are per-process; multi-instance
  deployments need consistent configuration and edge-level protection.
- The application layer cannot absorb a volumetric DDoS attack.

## License

MIT. See [LICENSE](LICENSE).
