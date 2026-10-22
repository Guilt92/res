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

```bash
docker compose up -d --build
dig @127.0.0.1 example.com
```

| Service | Address |
|---|---|
| DNS | `127.0.0.1:53` (UDP and TCP) |
| Dashboard/API | http://localhost:8080 |
| Prometheus | http://localhost:9090 (loopback only) |
| Grafana | http://localhost:3000 |

The credentials in `docker-compose.yml`, `deploy/prometheus.yml`,
`deploy/prometheus/web.config.yml`, and the Grafana provisioning file are
**development placeholders**. Change all of them before exposing the stack.
Prometheus passwords must be updated together with their bcrypt hash.

If port 53 is already in use, publish a different host port without editing
the Compose file:

```bash
RES_DNS_PUBLISH=5353 docker compose up -d --build
dig @127.0.0.1 -p 5353 example.com
```

The gateway container runs unprivileged. The bind-mounted `./config`
directory must be writable by the container UID; override it with `RES_UID`
and `RES_GID` if needed.

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
  require `tls_server_name`.
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
- The configuration directory must be writable for runtime updates and backup
  recovery. The API writes atomically and keeps `res.toml.backup` as the last
  known-good configuration.

Control-plane credentials are supplied through environment variables or a
mode-0600 credentials file:

| Variable | Purpose |
|---|---|
| `RES_ADMIN_PASSWORD` | Admin login (full access) |
| `RES_VIEWER_PASSWORD` | Optional read-only viewer login |
| `RES_API_TOKEN` | Optional API bearer token |
| `RES_METRICS_TOKEN` | Dedicated metrics-only bearer token |
| `RES_PROTECT_METRICS` | Require the metrics token for `/metrics` |
| `RES_PROMETHEUS_URL` | Prometheus URL used by the dashboard |
| `RES_PROMETHEUS_USERNAME` / `RES_PROMETHEUS_PASSWORD` | Prometheus basic auth |

Startup fails closed when no admin password, API token, or persisted
credentials are available. Passwords are stored as argon2id hashes in
`config/res.credentials` (mode `0600`, ignored by Git).

## Local build

The default configuration binds port 53, so running it directly requires root
or `CAP_NET_BIND_SERVICE`. For development, change the listener addresses in
`config/res.toml`.

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
- Change all example credentials and use HTTPS or a trusted reverse proxy for
  the management interface before exposing it.
- Keep the configuration directory private; it may contain an API token or a
  proxy password.

## Limitations

- No recursive resolution or local DNSSEC validation.
- No native DNS-over-HTTPS (DoH) upstream transport.
- The application layer cannot absorb a volumetric DDoS attack.

## License

MIT. See [LICENSE](LICENSE).
