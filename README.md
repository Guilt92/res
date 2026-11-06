# res

**res** is a lightweight, health-aware DNS gateway written in Rust. It forwards DNS queries over UDP and TCP to configured upstream resolvers, with support for caching, failover, access control, and monitoring.

It is a DNS forwarder, not a recursive resolver.

## Features

- UDP and TCP DNS forwarding
- Health-aware upstream selection and failover
- Response caching with TTL and negative caching support
- Client ACLs and rate limiting
- SOCKS5 and HTTP CONNECT proxy support
- DNS-over-TLS (DoT) with certificate validation
- REST API and web dashboard
- Admin and read-only viewer authentication
- Prometheus metrics and Grafana dashboards
- TOML-based configuration with validation and backup recovery

## Requirements

- Docker and Docker Compose
- Rust 1.88+ (for local builds)

## Quick Start

Set the required credentials:

```bash
export RES_ADMIN_PASSWORD='your-secure-password'
export RES_METRICS_TOKEN='your-metrics-token'

docker compose up -d --build
```

## Services

| Service | Address |
|---|---|
| DNS | `127.0.0.1:153` |
| Dashboard / API | `http://127.0.0.1:8080` |
| Prometheus | `http://127.0.0.1:9090` |
| Grafana | `http://127.0.0.1:3000` |

Management and monitoring interfaces are bound to loopback by default.

## Configuration

Main configuration file:

```text
config/res.toml
```

Configure upstream resolvers, ACLs, caching, rate limits, health checks, authentication, and proxy settings through this file or the management dashboard.

The configuration directory must be writable by the container runtime user.

## Development

```bash
cargo build --release
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

