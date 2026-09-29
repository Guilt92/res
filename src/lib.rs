//! # OutisDNS
//!
//! A lightweight, health-aware **DNS gateway/proxy** written in Rust.
//!
//! OutisDNS owns the complete DNS data plane: UDP/TCP listeners on port 53,
//! packet parsing (via `hickory-proto`), validation, ACLs, rate limiting,
//! upstream selection, forwarding, retries/failover, active health checking
//! and latency measurement. It is **not** a recursive resolver, an
//! authoritative server, or a wrapper around any external DNS daemon — no
//! dnsdist, PowerDNS, Unbound, BIND or CoreDNS is involved anywhere.
//!
//! ## Architecture
//!
//! * `dns` – listeners + per-query pipeline + upstream exchange
//! * `upstream` – runtime state, health hysteresis, latency windows, registry
//! * `selection` – replaceable upstream selection strategies
//! * `failover` – bounded retry engine
//! * `acl`, `ratelimit`, `cache` – request admission and optional caching
//! * `api` – Axum control plane (never on the DNS request path)
//! * `events` – bounded in-memory event rings (config / health / failover)
//! * `persist` – atomic file-based configuration persistence
//! * `shared` – atomically swappable configuration + shared state
//! * `runtime` – orchestration and graceful shutdown

pub mod acl;
pub mod api;
pub mod cache;
pub mod config;
pub mod dns;
pub mod events;
pub mod failover;
pub mod logging;
pub mod metrics;
pub mod persist;
pub mod ratelimit;
pub mod runtime;
pub mod selection;
pub mod shared;
pub mod sysinfo;
pub mod upstream;
