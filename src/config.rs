//! Configuration: file format, validation and the atomically swappable runtime view.
//!
//! The persisted format is a single human-readable TOML file. It is parsed
//! **once** at startup (and on explicit reload); the DNS data plane only ever
//! reads the derived [`RuntimeConfig`] through `ArcSwap`, so a reload is atomic
//! from the perspective of a request: it observes either the complete old
//! configuration or the complete new one — never a partially updated view.
//!
//! Runtime state (queries, latency, health samples, counters) is never written
//! back to this file.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::acl::{AclConfig, AclRules};
use crate::ratelimit::RateLimitConfig;

/// Serde helpers for human-friendly durations stored as milliseconds.
///
/// Accepts `"1500ms"`, `"2s"`, `"5m"`, a bare integer (milliseconds) or a
/// float with a unit (`"1.5s"`). Serialisation emits the compact unit form
/// (`"2s"`, `"1500ms"`), keeping the TOML file readable.
pub mod duration_ms {
    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(ms: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format(*ms))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = u64;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(r#"a duration like "1500ms", "2s", "5m" or milliseconds as an integer"#)
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<u64, E> {
                parse(v).map_err(E::custom)
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
                Ok(v)
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
                u64::try_from(v).map_err(E::custom)
            }
        }
        d.deserialize_any(V)
    }

    /// Render milliseconds using the largest exact unit.
    pub fn format(ms: u64) -> String {
        if ms >= 60_000 && ms.is_multiple_of(60_000) {
            format!("{}m", ms / 60_000)
        } else if ms >= 1_000 && ms.is_multiple_of(1_000) {
            format!("{}s", ms / 1_000)
        } else {
            format!("{ms}ms")
        }
    }

    /// Parse `"1500ms"`, `"2s"`, `"5m"`, `"1.5s"` or a bare integer (ms).
    pub fn parse(text: &str) -> Result<u64, String> {
        let t = text.trim();
        if t.is_empty() {
            return Err("empty duration".into());
        }
        if let Ok(ms) = t.parse::<u64>() {
            return Ok(ms);
        }
        let split = t
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .ok_or_else(|| format!("invalid duration '{text}'"))?;
        let (num, unit) = t.split_at(split);
        let value: f64 = num
            .parse()
            .map_err(|_| format!("invalid duration number '{num}' in '{text}'"))?;
        if !value.is_finite() || value < 0.0 {
            return Err(format!("invalid duration '{text}'"));
        }
        let ms = match unit {
            "ms" => value,
            "s" => value * 1_000.0,
            "m" => value * 60_000.0,
            _ => return Err(format!("unknown duration unit '{unit}' in '{text}'")),
        };
        Ok(ms.round() as u64)
    }
}

/// Transport used to talk to an upstream (and, for health checks, to probe it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Udp,
    Tcp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Udp => f.write_str("udp"),
            Protocol::Tcp => f.write_str("tcp"),
        }
    }
}

/// A single upstream DNS server definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamConfig {
    /// Stable identifier assigned by the configuration manager. Not intended
    /// to be set by hand (defaults to 0 and is assigned on load).
    pub id: i64,
    /// Human readable, unique name.
    pub name: String,
    /// Upstream IP address (no hostname resolution: the gateway must never
    /// depend on a resolver to find its resolvers).
    pub address: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub enabled: bool,
    /// Lower value = higher preference. Selection never crosses priority tiers.
    pub priority: u32,
    /// Relative share of traffic inside a priority tier.
    pub weight: u32,
    /// Optional per-upstream timeout override (milliseconds).
    pub timeout_ms: Option<u64>,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            id: 0,
            name: String::new(),
            address: IpAddr::from([0, 0, 0, 0]),
            port: 53,
            protocol: Protocol::Udp,
            enabled: true,
            priority: 1,
            weight: 1,
            timeout_ms: None,
        }
    }
}

impl UpstreamConfig {
    pub fn timeout(&self, fallback_ms: u64) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(fallback_ms))
    }

    /// Cheap validation of a single upstream definition.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("upstream name must not be empty".into());
        }
        if self.name.len() > 64 {
            return Err(format!(
                "upstream name '{}' longer than 64 characters",
                self.name
            ));
        }
        if self.port == 0 {
            return Err(format!("upstream '{}' has port 0", self.name));
        }
        if self.address.is_unspecified() {
            return Err(format!(
                "upstream '{}' has an unspecified address",
                self.name
            ));
        }
        if self.address.is_multicast() {
            return Err(format!("upstream '{}' uses a multicast address", self.name));
        }
        if self.priority == 0 {
            return Err(format!("upstream '{}' priority must be >= 1", self.name));
        }
        if self.weight == 0 {
            return Err(format!("upstream '{}' weight must be >= 1", self.name));
        }
        if let Some(t) = self.timeout_ms {
            if t == 0 || t > 60_000 {
                return Err(format!(
                    "upstream '{}' timeout_ms must be in 1..=60000",
                    self.name
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// UDP DNS listener address.
    #[serde(rename = "udp_addr")]
    pub udp_addr: SocketAddr,
    /// TCP DNS listener address.
    #[serde(rename = "tcp_addr")]
    pub tcp_addr: SocketAddr,
    /// HTTP API / metrics / dashboard listener address.
    #[serde(rename = "api_addr")]
    pub api_addr: SocketAddr,
    /// Directory containing the dashboard assets (index.html).
    pub dashboard_dir: Option<PathBuf>,
    /// Maximum accepted UDP datagram size (bytes).
    pub max_udp_packet_size: usize,
    /// Maximum concurrent in-flight UDP queries before shedding load.
    pub max_inflight_udp: usize,
    /// Maximum simultaneous TCP DNS connections.
    pub max_tcp_connections: usize,
    /// Maximum queries served on a single TCP connection before it is closed.
    pub max_queries_per_tcp_conn: u32,
    /// Idle timeout for an established TCP DNS connection.
    pub tcp_idle_timeout_ms: u64,
    /// If an upstream UDP response is truncated (TC=1), retry over TCP.
    pub upstream_tcp_fallback: bool,
    /// Grace period for draining in-flight work on shutdown.
    pub shutdown_grace_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            udp_addr: "0.0.0.0:53".parse().expect("default udp addr"),
            tcp_addr: "0.0.0.0:53".parse().expect("default tcp addr"),
            api_addr: "0.0.0.0:8080".parse().expect("default api addr"),
            dashboard_dir: Some(PathBuf::from("dashboard")),
            max_udp_packet_size: 4096,
            max_inflight_udp: 4096,
            max_tcp_connections: 512,
            max_queries_per_tcp_conn: 100,
            tcp_idle_timeout_ms: 10_000,
            upstream_tcp_fallback: true,
            shutdown_grace_ms: 5_000,
        }
    }
}

/// Query timeouts and attempt budget for one client request (§36: every
/// attempt shares a single overall deadline).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct QueryConfig {
    /// Overall deadline for the whole client query across all attempts.
    #[serde(rename = "timeout", with = "duration_ms")]
    pub timeout_ms: u64,
    /// Cap for a single upstream attempt (never exceeds the remaining
    /// overall deadline).
    #[serde(rename = "upstream_timeout", with = "duration_ms")]
    pub upstream_timeout_ms: u64,
    /// Maximum upstream attempts for one client query (including the first).
    pub max_attempts: u32,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 2_000,
            upstream_timeout_ms: 500,
            max_attempts: 3,
        }
    }
}

impl QueryConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_millis(self.upstream_timeout_ms)
    }
}

/// Failover *policy* (the budgets live in [`QueryConfig`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FailoverConfig {
    /// Retry a different upstream after a SERVFAIL. Off by default: SERVFAIL
    /// is a valid DNS response and retries add latency (§37).
    pub retry_on_servfail: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HealthConfig {
    /// Enabled/disabled active health checking.
    pub enabled: bool,
    /// Interval between check rounds.
    #[serde(rename = "interval", with = "duration_ms")]
    pub interval_ms: u64,
    /// Timeout per probe.
    #[serde(rename = "timeout", with = "duration_ms")]
    pub timeout_ms: u64,
    /// Consecutive failed rounds before an upstream is considered DOWN.
    pub failure_threshold: u32,
    /// Consecutive successful rounds required to return to UP.
    pub recovery_threshold: u32,
    /// Minimum number of probes in a round that must succeed.
    pub min_successes: usize,
    /// Also probe TCP even when the upstream protocol is UDP.
    pub tcp_probes: bool,
    /// Probe queries, e.g. `A example.com`.
    pub probes: Vec<HealthProbe>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HealthProbe {
    pub name: String,
    #[serde(rename = "type")]
    pub query_type: String,
}

impl Default for HealthProbe {
    fn default() -> Self {
        Self {
            name: "example.com".into(),
            query_type: "A".into(),
        }
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: 5_000,
            timeout_ms: 2_000,
            failure_threshold: 3,
            recovery_threshold: 2,
            min_successes: 1,
            tcp_probes: false,
            probes: vec![
                HealthProbe {
                    name: "example.com".into(),
                    query_type: "A".into(),
                },
                HealthProbe {
                    name: "example.com".into(),
                    query_type: "AAAA".into(),
                },
                HealthProbe {
                    name: ".".into(),
                    query_type: "NS".into(),
                },
            ],
        }
    }
}

/// Selection strategy identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionStrategy {
    /// Weighted roulette over a composite reliability/latency/health score.
    #[default]
    WeightedReliability,
    /// Deterministic: always the highest scoring candidate.
    BestScore,
    /// Uniform random among healthy candidates (useful for debugging).
    RandomHealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SelectionConfig {
    pub strategy: SelectionStrategy,
    /// Latency score reference in milliseconds: a candidate at exactly this
    /// latency scores 0.5 on the latency term.
    pub latency_reference_ms: f64,
}

impl Default for SelectionConfig {
    fn default() -> Self {
        Self {
            strategy: SelectionStrategy::WeightedReliability,
            latency_reference_ms: 50.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CacheConfig {
    pub enabled: bool,
    /// Hard cap on cached entries (bounded memory).
    pub max_entries: usize,
    /// Lower TTL bound applied to cached responses (seconds).
    pub min_ttl_secs: u64,
    /// Upper TTL bound applied to cached responses (seconds).
    pub max_ttl_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_entries: 4096,
            min_ttl_secs: 0,
            max_ttl_secs: 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingConfig {
    /// `json` (production) or `pretty` (development).
    pub format: LogFormat,
    /// tracing filter, e.g. `info,outisdns=debug`.
    pub filter: String,
    /// Log a warning for every Nth SERVFAIL response (0 = never).
    pub servfail_sample_every: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Json,
            filter: "info".into(),
            servfail_sample_every: 0,
        }
    }
}

/// The full persisted configuration (file + API mutations).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub query: QueryConfig,
    pub acl: AclConfig,
    pub ratelimit: RateLimitConfig,
    pub failover: FailoverConfig,
    pub health: HealthConfig,
    pub selection: SelectionConfig,
    pub cache: CacheConfig,
    pub logging: LoggingConfig,
    pub upstreams: Vec<UpstreamConfig>,
}

/// Which file the active configuration came from and why.
#[derive(Debug, Clone, Serialize)]
pub struct LoadedConfig {
    pub config: AppConfig,
    /// `file`, `backup` or `defaults`.
    pub source: &'static str,
    /// Why the primary file was rejected (None when `source == "file"`).
    pub error: Option<String>,
}

impl AppConfig {
    /// Strict load: any parse/validation problem is an error.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| anyhow::anyhow!("invalid config {}: {e}", path.display()))
    }

    /// Parse + validate a TOML document.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut cfg: Self = toml::from_str(text).map_err(|e| format!("parse error: {e}"))?;
        cfg.normalize_upstream_ids();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Startup loader with a last-known-good fallback chain:
    ///
    /// ```text
    /// config.toml  →  config.toml.backup  →  built-in defaults
    /// ```
    ///
    /// A malformed configuration file must never keep the gateway from
    /// starting: the problem is reported (`source`, `error`) and surfaced via
    /// `/api/status` and `outisdns_config_errors_total`.
    pub fn load_with_fallback(path: &Path) -> LoadedConfig {
        match Self::load(path) {
            Ok(config) => LoadedConfig {
                config,
                source: "file",
                error: None,
            },
            Err(primary_err) => {
                let backup = backup_path(path);
                match Self::load(&backup) {
                    Ok(config) => LoadedConfig {
                        config,
                        source: "backup",
                        error: Some(primary_err.to_string()),
                    },
                    Err(backup_err) => LoadedConfig {
                        config: Self::default(),
                        source: "defaults",
                        error: Some(format!("primary: {primary_err}; backup: {backup_err}")),
                    },
                }
            }
        }
    }

    /// Where the last-known-good copy of `path` lives.
    pub fn backup_path(path: &Path) -> PathBuf {
        backup_path(path)
    }

    /// Seed upstreams default to `id = 0`; the registry is keyed by id, so
    /// every unassigned upstream must receive a unique positive id.
    pub fn normalize_upstream_ids(&mut self) {
        let mut next = self
            .upstreams
            .iter()
            .map(|u| u.id)
            .max()
            .unwrap_or(0)
            .max(0)
            + 1;
        for u in &mut self.upstreams {
            if u.id == 0 {
                u.id = next;
                next += 1;
            }
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.server.max_udp_packet_size < 512 || self.server.max_udp_packet_size > 65_535 {
            return Err("server.max_udp_packet_size must be in 512..=65535".into());
        }
        if self.server.max_inflight_udp == 0 {
            return Err("server.max_inflight_udp must be > 0".into());
        }
        if self.server.max_tcp_connections == 0 {
            return Err("server.max_tcp_connections must be > 0".into());
        }
        // Port 0 is allowed: the OS assigns an ephemeral port (used by the
        // integration tests); the bound addresses are reported via /api/status.
        AclRules::parse(&self.acl)?;

        if self.ratelimit.enabled {
            if self.ratelimit.per_ip_qps <= 0.0 || self.ratelimit.per_ip_burst == 0 {
                return Err("ratelimit.per_ip_qps/per_ip_burst must be > 0".into());
            }
            if self.ratelimit.global_qps <= 0.0 || self.ratelimit.global_burst == 0 {
                return Err("ratelimit.global_qps/global_burst must be > 0".into());
            }
            if self.ratelimit.max_tracked_clients == 0 {
                return Err("ratelimit.max_tracked_clients must be > 0".into());
            }
        }

        if self.query.max_attempts == 0 {
            return Err("query.max_attempts must be >= 1".into());
        }
        if self.query.upstream_timeout_ms == 0 {
            return Err("query.upstream_timeout must be > 0".into());
        }
        if self.query.timeout_ms < self.query.upstream_timeout_ms {
            return Err("query.timeout must be >= query.upstream_timeout".into());
        }

        if self.health.enabled {
            if self.health.interval_ms < 100 {
                return Err("health.interval must be >= 100ms".into());
            }
            if self.health.timeout_ms == 0 {
                return Err("health.timeout must be > 0".into());
            }
            if self.health.failure_threshold == 0 || self.health.recovery_threshold == 0 {
                return Err("health failure/recovery thresholds must be >= 1".into());
            }
            if self.health.probes.is_empty() {
                return Err(
                    "health.probes must not be empty when health checks are enabled".into(),
                );
            }
            for p in &self.health.probes {
                crate::dns::msg::parse_record_type(&p.query_type)
                    .map_err(|e| format!("health probe type '{}': {e}", p.query_type))?;
            }
        }

        if self.selection.latency_reference_ms <= 0.0 {
            return Err("selection.latency_reference_ms must be > 0".into());
        }

        if self.cache.enabled {
            if self.cache.max_entries == 0 {
                return Err("cache.max_entries must be > 0".into());
            }
            if self.cache.max_ttl_secs < self.cache.min_ttl_secs {
                return Err("cache.max_ttl_secs must be >= min_ttl_secs".into());
            }
        }

        let mut names = HashSet::new();
        let mut ids = HashSet::new();
        for u in &self.upstreams {
            u.validate()?;
            if !names.insert(u.name.clone()) {
                return Err(format!("duplicate upstream name '{}'", u.name));
            }
            if u.id != 0 && !ids.insert(u.id) {
                return Err(format!("duplicate upstream id {}", u.id));
            }
        }
        Ok(())
    }

    /// Non-fatal configuration issues worth surfacing at startup and in
    /// `/api/diagnostics`. Validation passed if this is called.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        let attempt_budget = self
            .query
            .upstream_timeout_ms
            .saturating_mul(self.query.max_attempts as u64);
        if attempt_budget > self.query.timeout_ms {
            out.push(format!(
                "query.max_attempts ({}) x query.upstream_timeout ({}ms) exceeds query.timeout ({}ms): \
                 later failover attempts will be cut short by the deadline",
                self.query.max_attempts, self.query.upstream_timeout_ms, self.query.timeout_ms
            ));
        }
        let open = self.acl.allowed_cidrs.iter().any(|s| {
            s.parse::<ipnet::IpNet>()
                .map(|n| n.prefix_len() == 0)
                .unwrap_or(false)
        });
        if open {
            out.push(
                "acl.allowed_cidrs contains a /0 network: this gateway is an open resolver".into(),
            );
        }
        if !self.health.enabled {
            out.push(
                "health checks are disabled: upstream failures are only detected per query".into(),
            );
        }
        if !self.server.upstream_tcp_fallback {
            out.push(
                "server.upstream_tcp_fallback is off: truncated (TC=1) answers are passed through"
                    .into(),
            );
        }
        out
    }

    /// Serialize back to the TOML file format (used by export).
    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string_pretty(self).map_err(|e| format!("serialize error: {e}"))
    }

    /// Returns a copy with the given upstream list, validated.
    pub fn with_upstreams(&self, upstreams: Vec<UpstreamConfig>) -> Result<Self, String> {
        let mut next = self.clone();
        next.upstreams = upstreams;
        next.validate()?;
        Ok(next)
    }
}

/// `<file>.backup` next to the primary configuration file.
pub fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".backup");
    PathBuf::from(name)
}

/// The subset of configuration the DNS data plane reads on the hot path.
///
/// `acl` is pre-parsed so requests never parse CIDR strings.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub udp_addr: SocketAddr,
    pub tcp_addr: SocketAddr,
    pub max_udp_packet_size: usize,
    pub max_inflight_udp: usize,
    pub max_tcp_connections: usize,
    pub max_queries_per_tcp_conn: u32,
    pub tcp_idle_timeout: Duration,
    pub upstream_tcp_fallback: bool,
    pub acl: AclRules,
    pub ratelimit: RateLimitConfig,
    pub query: QueryConfig,
    pub failover: FailoverConfig,
    pub selection: SelectionConfig,
    pub cache: CacheConfig,
}

impl RuntimeConfig {
    pub fn from_app(app: &AppConfig) -> Result<Self, String> {
        Ok(Self {
            udp_addr: app.server.udp_addr,
            tcp_addr: app.server.tcp_addr,
            max_udp_packet_size: app.server.max_udp_packet_size,
            max_inflight_udp: app.server.max_inflight_udp,
            max_tcp_connections: app.server.max_tcp_connections,
            max_queries_per_tcp_conn: app.server.max_queries_per_tcp_conn,
            tcp_idle_timeout: Duration::from_millis(app.server.tcp_idle_timeout_ms),
            upstream_tcp_fallback: app.server.upstream_tcp_fallback,
            acl: AclRules::parse(&app.acl)?,
            ratelimit: app.ratelimit.clone(),
            query: app.query.clone(),
            failover: app.failover.clone(),
            selection: app.selection.clone(),
            cache: app.cache.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::AclDecision;

    fn base() -> AppConfig {
        AppConfig {
            upstreams: vec![UpstreamConfig {
                id: 1,
                name: "cf".into(),
                address: "1.1.1.1".parse().unwrap(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn default_config_is_valid() {
        base().validate().unwrap();
        assert!(base().warnings().is_empty(), "{:?}", base().warnings());
    }

    #[test]
    fn warns_when_attempt_budget_exceeds_deadline() {
        let mut cfg = base();
        cfg.query.timeout_ms = 1_000;
        cfg.query.upstream_timeout_ms = 800;
        cfg.query.max_attempts = 3;
        cfg.validate().unwrap();
        let warnings = cfg.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("cut short by the deadline"),
            "{warnings:?}"
        );
    }

    #[test]
    fn warns_on_open_resolver_acl() {
        let mut cfg = base();
        cfg.acl.allowed_cidrs = vec!["0.0.0.0/0".into()];
        cfg.validate().unwrap();
        let warnings = cfg.warnings();
        assert!(
            warnings.iter().any(|w| w.contains("open resolver")),
            "{warnings:?}"
        );
    }

    #[test]
    fn rejects_duplicate_upstream_names() {
        let mut cfg = base();
        cfg.upstreams.push(UpstreamConfig {
            id: 2,
            name: "cf".into(),
            address: "8.8.8.8".parse().unwrap(),
            ..Default::default()
        });
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("duplicate upstream name"), "{err}");
    }

    #[test]
    fn rejects_bad_cidr() {
        let mut cfg = base();
        cfg.acl.allowed_cidrs = vec!["not-a-cidr".into()];
        assert!(cfg.validate().unwrap_err().contains("invalid allowed CIDR"));
    }

    #[test]
    fn rejects_zero_priority_and_weight() {
        let mut cfg = base();
        cfg.upstreams[0].priority = 0;
        assert!(cfg.validate().unwrap_err().contains("priority"));
        cfg.upstreams[0].priority = 1;
        cfg.upstreams[0].weight = 0;
        assert!(cfg.validate().unwrap_err().contains("weight"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let res: Result<AppConfig, _> = toml::from_str("bogus_key = 1");
        assert!(res.is_err());
    }

    #[test]
    fn parses_example_shaped_config() {
        let cfg = AppConfig::parse(
            r#"
            [server]
            udp_addr = "127.0.0.1:5300"
            tcp_addr = "127.0.0.1:5300"
            api_addr = "127.0.0.1:9999"

            [query]
            timeout = "1500ms"
            max_attempts = 2

            [health]
            interval = "5s"
            timeout = "2s"
            failure_threshold = 3
            recovery_threshold = 2

            [acl]
            allowed_cidrs = ["10.0.0.0/8"]

            [[upstreams]]
            name = "cloudflare-1"
            address = "1.1.1.1"
            port = 53
            protocol = "udp"
            enabled = true
            priority = 10
            weight = 100
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.udp_addr.port(), 5300);
        assert_eq!(cfg.server.api_addr.port(), 9999);
        assert_eq!(cfg.query.timeout_ms, 1500);
        assert_eq!(cfg.query.upstream_timeout_ms, 500); // default retained
        assert_eq!(cfg.health.interval_ms, 5_000);
        assert_eq!(cfg.health.timeout_ms, 2_000);
        assert_eq!(cfg.acl.allowed_cidrs, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(cfg.upstreams[0].priority, 10);
        assert_eq!(cfg.upstreams[0].weight, 100);
        assert_eq!(cfg.upstreams[0].id, 1); // assigned on load
    }

    #[test]
    fn round_trips_human_durations() {
        let text = r#"
            [query]
            timeout = "2s"
            upstream_timeout = "1500ms"
            [health]
            interval = "1m"
            timeout = "3s"
        "#;
        let cfg = AppConfig::parse(text).unwrap();
        assert_eq!(cfg.query.timeout_ms, 2_000);
        assert_eq!(cfg.query.upstream_timeout_ms, 1_500);
        assert_eq!(cfg.health.interval_ms, 60_000);
        assert_eq!(cfg.health.timeout_ms, 3_000);

        let out = cfg.to_toml().unwrap();
        assert!(out.contains(r#"timeout = "2s""#), "{out}");
        assert!(out.contains(r#"interval = "1m""#), "{out}");
        let reparsed = AppConfig::parse(&out).unwrap();
        assert_eq!(reparsed.query.timeout_ms, 2_000);
        assert_eq!(reparsed.health.interval_ms, 60_000);
    }

    #[test]
    fn duration_parser_accepts_units_and_integers() {
        assert_eq!(duration_ms::parse("1500ms").unwrap(), 1500);
        assert_eq!(duration_ms::parse("2s").unwrap(), 2000);
        assert_eq!(duration_ms::parse("1m").unwrap(), 60_000);
        assert_eq!(duration_ms::parse("1.5s").unwrap(), 1500);
        assert_eq!(duration_ms::parse("250").unwrap(), 250);
        assert!(duration_ms::parse("fast").is_err());
        assert!(duration_ms::parse("10x").is_err());
        assert_eq!(duration_ms::format(2_000), "2s");
        assert_eq!(duration_ms::format(1_500), "1500ms");
    }

    #[test]
    fn rejects_invalid_query_budget() {
        let mut cfg = base();
        cfg.query.timeout_ms = 500;
        cfg.query.upstream_timeout_ms = 1_000;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("query.timeout"), "{err}");
    }

    #[test]
    fn runtime_config_derives_from_app() {
        let mut app = base();
        app.acl.allowed_cidrs = vec!["10.1.0.0/16".into()];
        app.acl.denied_cidrs = vec!["10.1.5.0/24".into()];
        let rt = RuntimeConfig::from_app(&app).unwrap();
        assert_eq!(
            rt.acl.decide("10.1.2.3".parse().unwrap()),
            AclDecision::Allow
        );
        assert_eq!(
            rt.acl.decide("10.1.5.9".parse().unwrap()),
            AclDecision::Deny
        );
        assert_eq!(rt.acl.decide("8.8.8.8".parse().unwrap()), AclDecision::Deny);
    }

    #[test]
    fn upstream_timeout_override() {
        let mut u = UpstreamConfig::default();
        assert_eq!(u.timeout(2000), Duration::from_millis(2000));
        u.timeout_ms = Some(500);
        assert_eq!(u.timeout(2000), Duration::from_millis(500));
    }

    #[test]
    fn example_config_loads() {
        let cfg = AppConfig::load(Path::new("config/outisdns.toml")).expect("example config");
        assert_eq!(cfg.upstreams.len(), 6);
        assert_eq!(cfg.query.timeout_ms, 2000);
        assert_eq!(cfg.query.upstream_timeout_ms, 500);
        assert_eq!(cfg.query.max_attempts, 3);
        assert_eq!(cfg.health.interval_ms, 5_000);
        assert_eq!(cfg.server.udp_addr.port(), 53);
        assert!(cfg.upstreams.iter().all(|u| u.id >= 1));
        let mut ids: Vec<i64> = cfg.upstreams.iter().map(|u| u.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), cfg.upstreams.len(), "ids must be unique");
    }

    #[test]
    fn fallback_uses_backup_then_defaults() {
        let dir = std::env::temp_dir().join(format!("outisdns-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cfg.toml");

        // Broken primary + missing backup -> defaults with an error.
        std::fs::write(&path, "this is not toml {{{").unwrap();
        let loaded = AppConfig::load_with_fallback(&path);
        assert_eq!(loaded.source, "defaults");
        assert!(loaded.error.is_some());

        // Working backup wins over the broken primary.
        std::fs::write(AppConfig::backup_path(&path), "[query]\ntimeout = \"3s\"\n").unwrap();
        let loaded = AppConfig::load_with_fallback(&path);
        assert_eq!(loaded.source, "backup");
        assert_eq!(loaded.config.query.timeout_ms, 3_000);
        assert!(loaded.error.is_some());

        // Healthy primary wins.
        std::fs::write(&path, "[query]\ntimeout = \"4s\"\n").unwrap();
        let loaded = AppConfig::load_with_fallback(&path);
        assert_eq!(loaded.source, "file");
        assert!(loaded.error.is_none());
        assert_eq!(loaded.config.query.timeout_ms, 4_000);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
