# res

`res` is a lightweight DNS gateway written in Rust. It forwards DNS queries to configured upstream resolvers and provides runtime configuration, health checks, monitoring, and a web dashboard.

**It is a forwarder, not a recursive resolver.**

## Features

- UDP/TCP DNS forwarding
- Configurable upstreams, health checks, selection, and failover
- IPv4/IPv6 ACLs and rate limiting
- Optional DNS cache with TTL-aware expiry
- Bounded concurrency and response-rate limiting
- REST API and web dashboard
- Prometheus metrics and Grafana dashboards
- Authentication, HTTPS, and optional DNS-over-TLS (DoT)
- Optional SOCKS5 or HTTP CONNECT upstream proxy with write-only credentials
- Full client IPs in the dashboard by default; prefix masking is opt-in
- TOML configuration with validation, atomic updates, and backup recovery

## Requirements

- Docker and Docker Compose, or
- Rust toolchain for local builds

## Quick Start

```bash
docker compose up -d --build
dig @127.0.0.1 example.com
```

Dashboard/API: http://localhost:8080

Prometheus: `localhost:9090`  
Grafana: `localhost:3000`

Configure credentials in `docker-compose.yml` before deployment.

If port 53 is already in use:

```bash
RES_DNS_PUBLISH=5353 docker compose up -d --build
dig @127.0.0.1 -p 5353 example.com
```

## Configuration

The main configuration file is `config/res.toml`.

It defines listeners, upstreams, ACLs, rate limits, caching, health checks, selection policies, failover, authentication, and monitoring.

- An empty `allowed_cidrs` denies all DNS clients.
- DNS-over-TLS upstreams use `protocol = "tls"` and typically port `853`.
- Set `require_encrypted_upstreams = true` to reject enabled plaintext upstreams.
- `[proxy]` can route every upstream exchange through a SOCKS5 or HTTP CONNECT
  proxy. SOCKS5 supports TCP, DoT and UDP (`UDP ASSOCIATE`); HTTP CONNECT is
  TCP-only, so validation rejects it while any enabled upstream uses UDP.
  Proxying is mandatory when enabled: a proxy failure becomes an upstream
  failure and never falls back to a direct connection.
- The proxy password is stored in the TOML file for restart survival but is
  redacted from `Debug`, API/diagnostics/events and configuration exports.
- `monitoring.client_ip_privacy` defaults to `"full"` so the dashboard and
  Prometheus agree. Use `"masked"` to hide host bits or `"off"` to disable
  per-client tracking.
- The configuration directory must be writable for runtime updates and backup recovery.

See `config/res.toml` for available options. Security-sensitive deployments
should terminate/rate-limit at the network edge as well: application controls
bound in-process memory and CPU, but cannot absorb a volumetric DDoS.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

## Limitations

- No recursive resolution or local DNSSEC validation.
- No native DNS-over-HTTPS (DoH) upstream transport.
- Application-level rate limiting does not prevent volumetric DDoS attacks; network-level protection is required.
- Restrict DNS access using ACLs and a host firewall. Do not expose an unrestricted DNS gateway.
