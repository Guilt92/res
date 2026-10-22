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
    /// DNS-over-TLS (RFC 7858). Requires `tls_server_name` for certificate
    /// validation; the TCP port is usually 853.
    Tls,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Udp => f.write_str("udp"),
            Protocol::Tcp => f.write_str("tcp"),
            Protocol::Tls => f.write_str("tls"),
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
    /// Optional per-upstream health-check interval override (milliseconds).
    /// When set, this upstream is probed on its own schedule instead of the
    /// global `[health].interval`.
    pub probe_interval_ms: Option<u64>,
    /// Optional per-upstream health-probe timeout override (milliseconds).
    pub probe_timeout_ms: Option<u64>,
    /// Optional per-upstream probe queries. When set, replaces the global
    /// `[health].probes` list for this upstream only.
    pub probes: Option<Vec<HealthProbe>>,
    /// Optional required rcode for a probe to count as success (e.g.
    /// "NOERROR"). When unset, both NOERROR and NXDOMAIN count as success.
    pub expect_rcode: Option<String>,
    /// TLS SNI and certificate name for `protocol = "tls"`. Required for DoT;
    /// the certificate must match this name (or an IP SAN for an IP literal).
    /// Never silently falls back to plaintext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
    /// Optional PEM CA bundle used to verify this upstream's DoT certificate.
    /// When unset, the bundled public WebPKI roots are used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca_file: Option<PathBuf>,
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
            probe_interval_ms: None,
            probe_timeout_ms: None,
            probes: None,
            expect_rcode: None,
            tls_server_name: None,
            tls_ca_file: None,
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
        if let Some(t) = self.probe_interval_ms {
            if !(100..=600_000).contains(&t) {
                return Err(format!(
                    "upstream '{}' probe_interval_ms must be in 100..=600000",
                    self.name
                ));
            }
        }
        if let Some(t) = self.probe_timeout_ms {
            if t == 0 || t > 60_000 {
                return Err(format!(
                    "upstream '{}' probe_timeout_ms must be in 1..=60000",
                    self.name
                ));
            }
        }
        if let Some(probes) = &self.probes {
            if probes.is_empty() {
                return Err(format!(
                    "upstream '{}' probes must not be empty when set",
                    self.name
                ));
            }
            for p in probes {
                crate::dns::msg::parse_record_type(&p.query_type).map_err(|e| {
                    format!(
                        "upstream '{}' probe type '{}': {e}",
                        self.name, p.query_type
                    )
                })?;
            }
        }
        if let Some(rc) = &self.expect_rcode {
            if crate::dns::msg::parse_rcode(rc).is_none() {
                return Err(format!(
                    "upstream '{}' expect_rcode '{rc}' is not a known rcode (NOERROR, NXDOMAIN, SERVFAIL, REFUSED, ...)",
                    self.name
                ));
            }
        }
        let tls_name = self.tls_server_name.as_deref().map(str::trim);
        if self.protocol == Protocol::Tls {
            match tls_name {
                Some(n) if !n.is_empty() && n.len() <= 253 => {}
                _ => {
                    return Err(format!(
                        "upstream '{}' uses protocol tls but has no valid tls_server_name",
                        self.name
                    ))
                }
            }
            if tls_name.is_some_and(|n| n.ends_with('.')) {
                return Err(format!(
                    "upstream '{}' tls_server_name must not end with a dot",
                    self.name
                ));
            }
        } else if self.tls_server_name.is_some() || self.tls_ca_file.is_some() {
            return Err(format!(
                "upstream '{}' sets TLS options but protocol is not tls",
                self.name
            ));
        }
        if let Some(path) = &self.tls_ca_file {
            if path.as_os_str().is_empty() {
                return Err(format!("upstream '{}' has an empty tls_ca_file", self.name));
            }
        }
        Ok(())
    }

    /// Effective probe list: per-upstream override, else the global default.
    pub fn effective_probes(&self, global: &[HealthProbe]) -> Vec<HealthProbe> {
        match &self.probes {
            Some(p) if !p.is_empty() => p.clone(),
            _ => global.to_vec(),
        }
    }

    /// Effective probe interval: per-upstream override, else the global value.
    pub fn effective_probe_interval_ms(&self, global_ms: u64) -> u64 {
        self.probe_interval_ms.unwrap_or(global_ms)
    }

    /// Effective probe timeout: per-upstream override, else the global value.
    pub fn effective_probe_timeout_ms(&self, global_ms: u64) -> u64 {
        self.probe_timeout_ms.unwrap_or(global_ms)
    }

    /// Required rcode for probe success (`None` = NOERROR or NXDOMAIN).
    pub fn expected_probe_rcode(&self) -> Option<crate::dns::msg::Rcode> {
        self.expect_rcode
            .as_deref()
            .and_then(crate::dns::msg::parse_rcode)
    }
}

/// Control-plane authentication policy (passwords themselves live in the
/// environment or a mode-0600 credentials file — never in this struct's
/// serialized form).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthConfig {
    /// Username of the full-privilege account.
    pub username: String,
    /// Username of the read-only account.
    pub viewer_username: String,
    /// Session lifetime; expired sessions are rejected and dropped.
    #[serde(rename = "session_ttl", with = "duration_ms")]
    pub session_ttl_ms: u64,
    /// Failed logins per account within `lockout_window` before lockout.
    pub max_failed_attempts: u32,
    /// Sliding window over which failures are counted.
    #[serde(rename = "lockout_window", with = "duration_ms")]
    pub lockout_window_ms: u64,
    /// How long a locked account rejects logins.
    #[serde(rename = "lockout_duration", with = "duration_ms")]
    pub lockout_duration_ms: u64,
    /// Require authentication for the Prometheus /metrics endpoint (default:
    /// open, since Prometheus scrapes without session cookies). When enabled,
    /// only `RES_METRICS_TOKEN` is accepted: administrator bearer tokens and
    /// dashboard sessions deliberately cannot scrape metrics.
    pub protect_metrics: bool,
    /// Dedicated metrics-only bearer credential. Environment-only
    /// (`RES_METRICS_TOKEN`): it is never loaded from or written to TOML, so
    /// config exports and persistence cannot leak it. It grants access to
    /// `/metrics` and nothing else. When `protect_metrics` is enabled and this
    /// is empty, `/metrics` fails closed with 401.
    #[serde(skip)]
    pub metrics_token: String,
    /// Mark session/CSRF cookies `Secure` (HTTPS-only). Enable when the
    /// management API is served over TLS; leave off for plain-HTTP LAN
    /// deployments (a startup warning is emitted when auth is enabled on a
    /// non-loopback address without this flag).
    pub secure_cookies: bool,
    /// Explicit development-only escape hatch: allow the control plane to run
    /// without any password or API token. Disabled by default; when credentials
    /// are missing the gateway refuses to start instead of silently exposing
    /// administrative read/write routes. Never enable this in production.
    pub allow_open_mode: bool,
    /// Maximum login attempts per client IP per minute (0 disables the
    /// per-IP limiter; per-username lockout still applies).
    pub login_rate_limit_per_minute: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            username: "admin".into(),
            viewer_username: "viewer".into(),
            session_ttl_ms: 12 * 60 * 60 * 1000,
            max_failed_attempts: 5,
            lockout_window_ms: 15 * 60 * 1000,
            lockout_duration_ms: 15 * 60 * 1000,
            protect_metrics: false,
            metrics_token: String::new(),
            secure_cookies: false,
            allow_open_mode: false,
            login_rate_limit_per_minute: 30,
        }
    }
}

impl AuthConfig {
    pub fn session_ttl(&self) -> Duration {
        Duration::from_millis(self.session_ttl_ms)
    }

    pub fn lockout_window_ms_duration(&self) -> Duration {
        Duration::from_millis(self.lockout_window_ms)
    }

    pub fn lockout_duration_ms_duration(&self) -> Duration {
        Duration::from_millis(self.lockout_duration_ms)
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
    /// Bearer token required for configuration-changing API operations
    /// (upstream create/update/delete/test, config import). Empty string
    /// keeps the control plane open (development default; a warning is
    /// emitted at startup). May be supplied via `RES_API_TOKEN`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub api_token: String,
    /// PEM certificate chain for the management API. Setting this and
    /// `tls_key` serves the API, dashboard, and `/metrics` over HTTPS; there
    /// is no plaintext fallback. Reverse-proxy TLS remains supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<PathBuf>,
    /// PEM private key matching `tls_cert`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<PathBuf>,
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
            api_token: String::new(),
            tls_cert: None,
            tls_key: None,
        }
    }
}

impl ServerConfig {
    /// True when the management API is configured for direct HTTPS.
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }
}

/// Policy for `ANY` (type 255) questions. RFC 8482: a resolver may refuse
/// `ANY` with NOTIMP or a minimal response instead of amplifying traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnyPolicy {
    /// Forward `ANY` queries to upstreams like any other type. Not the
    /// default because `ANY` is amplification-friendly and rarely needed.
    Forward,
    /// Refuse `ANY` locally with NOTIMP (RFC 8482). This is the default.
    #[default]
    Refuse,
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
    /// How to handle `ANY` queries: refuse locally with NOTIMP per RFC 8482
    /// (default, anti-amplification) or forward them upstream.
    pub any_policy: AnyPolicy,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 2_000,
            upstream_timeout_ms: 500,
            max_attempts: 3,
            any_policy: AnyPolicy::default(),
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
    /// Anti-flap: after a transition to a worse state, improvements are held
    /// back for this long (probes still run, metrics still update). Worsening
    /// transitions are never delayed. `0` disables the cooldown.
    #[serde(rename = "dwell", with = "duration_ms")]
    pub dwell_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
            // Default anti-flap: hold improvements for 5s after a worsening
            // transition; failures are never delayed.
            dwell_ms: 5_000,
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

/// How priority tiers interact during selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierPolicy {
    /// Classic strict tiers: only the best (lowest) priority tier that has
    /// usable upstreams receives traffic. Lower tiers stay cold.
    #[default]
    Strict,
    /// Share traffic across all usable tiers: the best tier keeps almost all
    /// traffic, while lower tiers receive approximately `lower_tier_share`
    /// of selections (weighted by their scores). Keeps lower tiers measured
    /// and warm for failover.
    Shared,
}

/// When DEGRADED upstreams may receive traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedPolicy {
    /// Degraded upstreams are selectable at any time (scored 0.4x).
    #[default]
    Usable,
    /// Degraded upstreams are used only when no UP upstream is available.
    LastResort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SelectionConfig {
    pub strategy: SelectionStrategy,
    /// Latency score reference in milliseconds: a candidate at exactly this
    /// latency scores 0.5 on the latency term.
    pub latency_reference_ms: f64,
    /// Strict tiers (default) or shared traffic across tiers.
    pub tier_policy: TierPolicy,
    /// Approximate traffic share for lower tiers when `tier_policy` is
    /// `shared` (0.0–1.0; 0.05 = ~5% of selections keep lower tiers warm).
    pub lower_tier_share: f64,
    /// Degraded upstreams are always usable, or only a last resort.
    pub degraded_policy: DegradedPolicy,
    /// Minimum completed health-check rounds before the probe success rate
    /// enters the score. Below this the probe term is neutral (1.0) so a
    /// freshly started upstream is not penalised for having no probe history.
    pub min_probe_samples: u32,
}

impl Default for SelectionConfig {
    fn default() -> Self {
        Self {
            strategy: SelectionStrategy::WeightedReliability,
            latency_reference_ms: 50.0,
            tier_policy: TierPolicy::Strict,
            lower_tier_share: 0.0,
            degraded_policy: DegradedPolicy::Usable,
            min_probe_samples: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CacheConfig {
    /// Response cache on/off (on by default).
    pub enabled: bool,
    /// Hard cap on cached entries (bounded memory).
    pub max_entries: usize,
    /// Hard cap on cached payload bytes (entries + per-entry overhead).
    /// Count-only bounding cannot bound memory: `max_entries` × up-to-64KiB
    /// responses could otherwise grow to hundreds of MiB.
    pub max_memory_bytes: usize,
    /// Cacheability threshold: responses whose minimum TTL is *below* this
    /// value are not cached at all (TTLs are never extended upwards).
    pub min_ttl_secs: u64,
    /// Upper cap: cached TTLs longer than this are clamped down.
    pub max_ttl_secs: u64,
    /// Cap for RFC 2308 negative caching (NXDOMAIN / NODATA), seconds.
    pub negative_max_ttl_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 4096,
            max_memory_bytes: 33_554_432, // 32 MiB
            min_ttl_secs: 0,
            max_ttl_secs: 3600,
            negative_max_ttl_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingConfig {
    /// `json` (production) or `pretty` (development).
    pub format: LogFormat,
    /// tracing filter, e.g. `info,res=debug`.
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

/// How client IP addresses are exposed in events, logs, the API and the
/// dashboard.
///
/// DNS client addresses are operationally useful (abuse, ACL and rate-limit
/// troubleshooting) but are personal data, so the default is to keep the
/// network prefix and drop the host part.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientIpPrivacy {
    /// Show the network part only: IPv4 → `10.0.0.x`, IPv6 → `2001:db8::x`
    /// (default). Aggregates are still per real address internally.
    #[default]
    Masked,
    /// Expose the full address everywhere.
    Full,
    /// Do not track client addresses at all (no top-client table, no address
    /// in events or logs).
    Off,
}

impl ClientIpPrivacy {
    pub fn as_str(self) -> &'static str {
        match self {
            ClientIpPrivacy::Masked => "masked",
            ClientIpPrivacy::Full => "full",
            ClientIpPrivacy::Off => "off",
        }
    }
}

/// Monitoring integration (dashboard time-series source + traffic introspection).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MonitoringConfig {
    /// Base URL of a Prometheus server (`http://prometheus:9090`) used by
    /// `GET /api/timeseries?source=prometheus|auto`. Empty string (default)
    /// disables the proxy and the dashboard falls back to the gateway's own
    /// native history.
    ///
    /// The `RES_PROMETHEUS_URL` environment variable overrides this
    /// value (applied on every parse).
    pub prometheus_url: String,
    /// Username for HTTP basic auth when the Prometheus server enforces it
    /// (`--web.config.file` `basic_auth`). Empty (default) sends no
    /// `Authorization` header. `RES_PROMETHEUS_USERNAME` overrides this.
    pub prometheus_username: String,
    /// Password for HTTP basic auth against Prometheus. Environment-only
    /// (`RES_PROMETHEUS_PASSWORD`): `#[serde(skip)]` keeps it out of the
    /// TOML file entirely — it can neither be loaded from nor persisted or
    /// serialized back into the config (same rule as the dashboard
    /// credentials, which never live in the TOML either).
    #[serde(skip)]
    pub prometheus_password: String,
    /// Client-address exposure (see [`ClientIpPrivacy`]). `off` disables the
    /// top-client table entirely.
    pub client_ip_privacy: ClientIpPrivacy,
    /// Maximum tracked client addresses (bounded memory; `0` disables).
    pub top_clients_max: usize,
    /// Maximum tracked queried names (bounded memory; `0` disables).
    pub top_domains_max: usize,
    /// How many top clients are exported as Prometheus series
    /// (`res_client_*`, masked labels by default). `0` disables the
    /// export. Kept small so per-client metrics cannot explode in cardinality.
    pub client_metrics_max: usize,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            prometheus_url: String::new(),
            prometheus_username: String::new(),
            prometheus_password: String::new(),
            client_ip_privacy: ClientIpPrivacy::default(),
            top_clients_max: 4_096,
            top_domains_max: 8_192,
            client_metrics_max: 100,
        }
    }
}

impl MonitoringConfig {
    pub fn enabled(&self) -> bool {
        !self.prometheus_url.trim().is_empty()
    }

    /// Whether per-client request counting is active at all.
    pub fn track_clients(&self) -> bool {
        self.client_ip_privacy != ClientIpPrivacy::Off && self.top_clients_max > 0
    }

    /// Whether per-name request counting is active.
    pub fn track_domains(&self) -> bool {
        self.top_domains_max > 0
    }

    /// Effective top-client table capacity (`0` = disabled by privacy).
    pub fn client_table_cap(&self) -> usize {
        if self.track_clients() {
            self.top_clients_max
        } else {
            0
        }
    }

    /// Effective top-domain table capacity (`0` = disabled).
    pub fn domain_table_cap(&self) -> usize {
        if self.track_domains() {
            self.top_domains_max
        } else {
            0
        }
    }
}

/// The full persisted configuration (file + API mutations).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub query: QueryConfig,
    pub acl: AclConfig,
    pub ratelimit: RateLimitConfig,
    pub failover: FailoverConfig,
    pub health: HealthConfig,
    pub selection: SelectionConfig,
    pub cache: CacheConfig,
    pub logging: LoggingConfig,
    pub monitoring: MonitoringConfig,
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
        cfg.apply_env_overrides();
        cfg.normalize_upstream_ids();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Environment overrides (highest precedence, applied on every parse so
    /// reloads and API imports keep them).
    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("RES_PROMETHEUS_URL") {
            if !v.trim().is_empty() {
                self.monitoring.prometheus_url = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("RES_PROMETHEUS_USERNAME") {
            if !v.trim().is_empty() {
                self.monitoring.prometheus_username = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("RES_PROMETHEUS_PASSWORD") {
            if !v.is_empty() {
                self.monitoring.prometheus_password = v;
            }
        }
        if let Ok(v) = std::env::var("RES_API_TOKEN") {
            // Explicit empty value is ignored so an unset variable cannot
            // silently open a token-protected control plane.
            if !v.is_empty() {
                self.server.api_token = v;
            }
        }
        if let Ok(v) = std::env::var("RES_METRICS_TOKEN") {
            // Environment-only, like the Prometheus password: the scrape
            // credential is never accepted from TOML and never serialized.
            if !v.is_empty() {
                self.auth.metrics_token = v;
            }
        }
        if let Ok(v) = std::env::var("RES_PROTECT_METRICS") {
            match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => self.auth.protect_metrics = true,
                "0" | "false" | "no" | "off" => self.auth.protect_metrics = false,
                other => tracing::warn!(
                    event = "invalid_env_override",
                    variable = "RES_PROTECT_METRICS",
                    value = other,
                    "ignoring invalid boolean"
                ),
            }
        }
    }

    /// Startup loader with a last-known-good fallback chain:
    ///
    /// ```text
    /// config.toml  →  config.toml.backup  →  built-in defaults
    /// ```
    ///
    /// A malformed configuration file must never keep the gateway from
    /// starting: the problem is reported (`source`, `error`) and surfaced via
    /// `/api/status` and `res_config_errors_total`.
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
                    Err(backup_err) => {
                        let mut config = Self::default();
                        config.apply_env_overrides();
                        LoadedConfig {
                            config,
                            source: "defaults",
                            error: Some(format!("primary: {primary_err}; backup: {backup_err}")),
                        }
                    }
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
        if self.server.tls_cert.is_some() != self.server.tls_key.is_some() {
            return Err("server.tls_cert and server.tls_key must be configured together".into());
        }
        if self
            .server
            .tls_cert
            .as_ref()
            .is_some_and(|p| p.as_os_str().is_empty())
            || self
                .server
                .tls_key
                .as_ref()
                .is_some_and(|p| p.as_os_str().is_empty())
        {
            return Err("server.tls_cert/server.tls_key must not be empty paths".into());
        }
        if self.server.max_udp_packet_size < 512 || self.server.max_udp_packet_size > 65_535 {
            return Err("server.max_udp_packet_size must be in 512..=65535".into());
        }
        if self.server.max_inflight_udp == 0 {
            return Err("server.max_inflight_udp must be > 0".into());
        }
        if self.server.max_tcp_connections == 0 {
            return Err("server.max_tcp_connections must be > 0".into());
        }
        // Bounded scale: each upstream carries runtime state, probe tasks,
        // metric vectors and selector entries — an accidental 10k-entry list
        // (or a hostile config push) must fail validation, not OOM.
        const MAX_UPSTREAMS: usize = 1024;
        if self.upstreams.len() > MAX_UPSTREAMS {
            return Err(format!(
                "too many upstreams: {} (max {MAX_UPSTREAMS})",
                self.upstreams.len()
            ));
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
        if self.monitoring.top_clients_max > 1_000_000 {
            return Err("monitoring.top_clients_max must be <= 1000000".into());
        }
        if self.monitoring.top_domains_max > 1_000_000 {
            return Err("monitoring.top_domains_max must be <= 1000000".into());
        }
        if self.monitoring.client_metrics_max > 10_000 {
            return Err("monitoring.client_metrics_max must be <= 10000".into());
        }
        if self.query.upstream_timeout_ms == 0 {
            return Err("query.upstream_timeout must be > 0".into());
        }
        if self.query.timeout_ms < self.query.upstream_timeout_ms {
            return Err("query.timeout must be >= query.upstream_timeout".into());
        }

        // Health bounds hold even while checks are off: nonsense must
        // never be persisted, then bite the moment someone flips
        // `enabled` (same reasoning as the cache bounds below).
        if self.health.interval_ms < 100 {
            return Err("health.interval must be >= 100ms".into());
        }
        if self.health.timeout_ms == 0 {
            return Err("health.timeout must be > 0".into());
        }
        if self.health.failure_threshold == 0 || self.health.recovery_threshold == 0 {
            return Err("health failure/recovery thresholds must be >= 1".into());
        }
        // Probe *types* are validated whenever probes are present; only
        // the "non-empty" requirement depends on checks being enabled
        // (a disabled section may legitimately have no probes).
        for p in &self.health.probes {
            crate::dns::msg::parse_record_type(&p.query_type)
                .map_err(|e| format!("health probe type '{}': {e}", p.query_type))?;
        }
        if self.health.enabled && self.health.probes.is_empty() {
            return Err("health.probes must not be empty when health checks are enabled".into());
        }

        if self.selection.latency_reference_ms <= 0.0 {
            return Err("selection.latency_reference_ms must be > 0".into());
        }
        if !self.selection.lower_tier_share.is_finite()
            || !(0.0..=1.0).contains(&self.selection.lower_tier_share)
        {
            return Err("selection.lower_tier_share must be within 0.0..=1.0".into());
        }

        // TTL bound consistency and a non-zero capacity are independent of
        // `enabled`: nonsense must never be persisted, even if the cache is
        // currently off.
        if self.cache.max_ttl_secs < self.cache.min_ttl_secs {
            return Err("cache.max_ttl_secs must be >= min_ttl_secs".into());
        }
        if self.cache.max_entries == 0 {
            return Err("cache.max_entries must be > 0".into());
        }
        if self.cache.max_entries > 1_000_000 {
            return Err("cache.max_entries must be <= 1000000".into());
        }
        if self.cache.max_memory_bytes == 0 {
            return Err("cache.max_memory_bytes must be > 0".into());
        }
        if self.cache.negative_max_ttl_secs > 86_400 {
            return Err("cache.negative_max_ttl_secs must be <= 86400".into());
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
        let open = self.acl.effective_entries().iter().any(|e| {
            e.action == crate::acl::AclAction::Allow
                && crate::acl::normalize_cidr(&e.cidr)
                    .map(|n| n.prefix_len() == 0)
                    .unwrap_or(false)
        });
        if open {
            out.push(
                "the ACL allow list contains a /0 network: this gateway is an open resolver".into(),
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
        if self.server.api_token.is_empty() {
            out.push(
                "server.api_token is empty: API clients must sign in with a password \
                 session; startup fails unless password auth or explicit \
                 [auth].allow_open_mode is configured"
                    .into(),
            );
        }
        if self.auth.protect_metrics && self.auth.metrics_token.is_empty() {
            out.push(
                "auth.protect_metrics is enabled but RES_METRICS_TOKEN is empty: \
                 /metrics will reject every request (fail closed); set a dedicated \
                 metrics token rather than reusing the admin credential"
                    .into(),
            );
        }
        if !self.auth.protect_metrics && !self.auth.metrics_token.is_empty() {
            out.push(
                "RES_METRICS_TOKEN is configured but auth.protect_metrics is false: \
                 /metrics remains unauthenticated"
                    .into(),
            );
        }
        if self.auth.allow_open_mode {
            out.push(
                "auth.allow_open_mode is enabled: the control plane may run without any \
                 authentication; use only for isolated development and never expose it \
                 to untrusted networks"
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
    /// Client-address exposure on the data plane (events + top-client table).
    pub client_ip_privacy: ClientIpPrivacy,
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
            client_ip_privacy: app.monitoring.client_ip_privacy,
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
        let mut cfg = base();
        cfg.server.api_token = "test-token".into();
        cfg.validate().unwrap();
        assert!(cfg.warnings().is_empty(), "{:?}", cfg.warnings());
    }

    #[test]
    fn api_token_is_optional_and_never_serialized_when_empty() {
        let mut cfg = base();
        cfg.server.api_token = String::new();
        let toml_text = cfg.to_toml().expect("serialize");
        assert!(
            !toml_text.contains("api_token"),
            "empty token must not appear in exports: {toml_text}"
        );
        let reloaded: AppConfig = toml::from_str(&toml_text).expect("parse");
        assert_eq!(reloaded.server.api_token, "");
        assert!(reloaded
            .warnings()
            .iter()
            .any(|w| w.contains("api_token is empty")));

        cfg.server.api_token = "sekrit".into();
        let toml_text = cfg.to_toml().expect("serialize");
        assert!(toml_text.contains("api_token"));
        let reloaded: AppConfig = toml::from_str(&toml_text).expect("parse");
        assert_eq!(reloaded.server.api_token, "sekrit");
        assert!(!reloaded
            .warnings()
            .iter()
            .any(|w| w.contains("api_token is empty")));
    }

    #[test]
    fn warns_when_attempt_budget_exceeds_deadline() {
        let mut cfg = base();
        cfg.server.api_token = "test-token".into();
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
        assert!(cfg.validate().unwrap_err().contains("invalid CIDR or IP"));
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
    fn lower_tier_share_must_be_a_probability() {
        let mut cfg = base();
        cfg.selection.lower_tier_share = 0.05;
        cfg.validate().unwrap();
        cfg.selection.lower_tier_share = 0.0;
        cfg.validate().unwrap();
        cfg.selection.lower_tier_share = 1.0;
        cfg.validate().unwrap();
        cfg.selection.lower_tier_share = 1.5;
        assert!(cfg.validate().unwrap_err().contains("lower_tier_share"));
        cfg.selection.lower_tier_share = -0.1;
        assert!(cfg.validate().unwrap_err().contains("lower_tier_share"));
        cfg.selection.lower_tier_share = f64::NAN;
        assert!(cfg.validate().unwrap_err().contains("lower_tier_share"));
    }

    #[test]
    fn cache_defaults_are_enabled_with_negative_caching() {
        let cache = CacheConfig::default();
        assert!(cache.enabled, "cache is on by default");
        assert_eq!(cache.negative_max_ttl_secs, 30);
        // Config files without the new key still parse (serde default).
        let toml = r#"
            [server]
            udp_addr = "127.0.0.1:0"
            tcp_addr = "127.0.0.1:0"
            api_addr = "127.0.0.1:0"
            [cache]
            enabled = true
            max_entries = 100
            min_ttl_secs = 0
            max_ttl_secs = 60
        "#;
        let cfg = AppConfig::parse(toml).expect("legacy cache section parses");
        assert_eq!(cfg.cache.negative_max_ttl_secs, 30);
        assert_eq!(cfg.cache.max_ttl_secs, 60);
        // Selection keys are also optional.
        let toml = r#"
            [server]
            udp_addr = "127.0.0.1:0"
            tcp_addr = "127.0.0.1:0"
            api_addr = "127.0.0.1:0"
            [selection]
            strategy = "best_score"
        "#;
        let cfg = AppConfig::parse(toml).expect("legacy selection section parses");
        assert_eq!(cfg.selection.tier_policy, TierPolicy::Strict);
        assert_eq!(cfg.selection.degraded_policy, DegradedPolicy::Usable);
        assert_eq!(cfg.selection.lower_tier_share, 0.0);
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

    /// The Prometheus basic-auth password is environment-only: `serde(skip)`
    /// keeps it out of every serialization (persistence, config export), and
    /// a stray TOML key is rejected loudly by `deny_unknown_fields` instead
    /// of being silently accepted into the file-backed config.
    #[test]
    fn prometheus_password_is_env_only() {
        let m = MonitoringConfig {
            prometheus_url: "http://prometheus:9090".into(),
            prometheus_username: "prom".into(),
            prometheus_password: "sekrit".into(),
            ..Default::default()
        };
        let out = toml::to_string(&m).expect("serialize");
        assert!(!out.contains("sekrit"), "password leaked: {out}");
        assert!(
            out.contains("prometheus_username"),
            "username is allowed in TOML: {out}"
        );

        // Username round-trips from TOML (non-secret) …
        let m: MonitoringConfig =
            toml::from_str("prometheus_url = \"http://p:9090\"\nprometheus_username = \"prom\"")
                .expect("username + url parse");
        assert_eq!(m.prometheus_username, "prom");
        assert_eq!(m.prometheus_password, "");

        // … but the password may not appear in TOML at all.
        let err = toml::from_str::<MonitoringConfig>("prometheus_password = \"x\"")
            .expect_err("password key must be rejected")
            .to_string();
        assert!(err.contains("prometheus_password"), "{err}");
    }

    /// The metrics scrape credential is env-only for the same reason as the
    /// Prometheus password: an admin config export must never contain it.
    #[test]
    fn metrics_token_is_env_only() {
        let auth = AuthConfig {
            protect_metrics: true,
            metrics_token: "metrics-sekrit".into(),
            ..Default::default()
        };
        let out = toml::to_string(&auth).expect("serialize");
        assert!(!out.contains("metrics-sekrit"), "token leaked: {out}");
        assert!(!out.contains("metrics_token"), "token field leaked: {out}");

        let err = toml::from_str::<AuthConfig>("metrics_token = \"x\"")
            .expect_err("TOML metrics token must be rejected")
            .to_string();
        assert!(err.contains("metrics_token"), "{err}");
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
        let cfg = AppConfig::load(Path::new("config/res.toml")).expect("example config");
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
        let dir = std::env::temp_dir().join(format!("res-cfg-{}", std::process::id()));
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

    #[test]
    fn default_privacy_is_masked_with_bounded_tables() {
        let m = MonitoringConfig::default();
        assert_eq!(m.client_ip_privacy, ClientIpPrivacy::Masked);
        assert_eq!(m.client_table_cap(), 4_096);
        assert_eq!(m.domain_table_cap(), 8_192);
        assert!(m.track_clients());
        assert!(m.track_domains());
        assert_eq!(m.client_metrics_max, 100, "bounded per-client export");
    }

    #[test]
    fn rejects_unbounded_client_metrics_export() {
        let mut cfg = base();
        cfg.monitoring.client_metrics_max = 10_001;
        assert!(
            cfg.validate().is_err(),
            "client metrics export must be cardinality-bounded"
        );
        cfg.monitoring.client_metrics_max = 10_000;
        assert!(cfg.validate().is_ok());
        cfg.monitoring.client_metrics_max = 0;
        assert!(cfg.validate().is_ok(), "0 disables the export");
    }

    #[test]
    fn privacy_off_disables_client_tracking_but_not_domains() {
        let mut cfg = base();
        cfg.monitoring.client_ip_privacy = ClientIpPrivacy::Off;
        assert_eq!(cfg.monitoring.client_table_cap(), 0);
        assert!(!cfg.monitoring.track_clients());
        assert!(
            cfg.monitoring.domain_table_cap() > 0,
            "domains still tracked"
        );
    }

    #[test]
    fn rejects_unbounded_traffic_tables() {
        let mut cfg = base();
        cfg.monitoring.top_clients_max = 1_000_001;
        assert!(cfg.validate().is_err(), "client cap must be bounded");
        cfg.monitoring.top_clients_max = 4_096;
        cfg.monitoring.top_domains_max = 1_000_001;
        assert!(cfg.validate().is_err(), "domain cap must be bounded");
    }

    #[test]
    fn privacy_round_trips_through_toml_and_reaches_the_hot_path() {
        let mut cfg = base();
        cfg.monitoring.client_ip_privacy = ClientIpPrivacy::Full;
        cfg.monitoring.top_clients_max = 128;

        let text = cfg.to_toml().expect("serialize");
        assert!(
            text.contains("client_ip_privacy = \"full\""),
            "privacy must be visible in the exported config:\n{text}"
        );
        let parsed = AppConfig::parse(&text).expect("parse");
        assert_eq!(parsed.monitoring.client_ip_privacy, ClientIpPrivacy::Full);
        assert_eq!(parsed.monitoring.top_clients_max, 128);

        let rt = RuntimeConfig::from_app(&parsed).expect("runtime");
        assert_eq!(rt.client_ip_privacy, ClientIpPrivacy::Full);
        let rt = RuntimeConfig::from_app(&base()).expect("runtime");
        assert_eq!(rt.client_ip_privacy, ClientIpPrivacy::Masked);
    }

    #[test]
    fn per_upstream_probe_overrides_validate_and_resolve() {
        let mut cfg = base();
        cfg.upstreams[0].probe_interval_ms = Some(2_000);
        cfg.upstreams[0].probe_timeout_ms = Some(1_000);
        cfg.upstreams[0].probes = Some(vec![HealthProbe {
            name: "health.example.".into(),
            query_type: "A".into(),
        }]);
        cfg.upstreams[0].expect_rcode = Some("NOERROR".into());
        cfg.validate().expect("valid per-upstream probes");

        let up = &cfg.upstreams[0];
        assert_eq!(up.effective_probe_interval_ms(5_000), 2_000);
        assert_eq!(up.effective_probe_timeout_ms(2_000), 1_000);
        assert_eq!(
            up.expected_probe_rcode(),
            Some(crate::dns::msg::Rcode::NoError)
        );
        let probes = up.effective_probes(&cfg.health.probes);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].name, "health.example.");
    }

    #[test]
    fn per_upstream_probe_overrides_fall_back_to_global() {
        let cfg = base();
        let up = &cfg.upstreams[0];
        assert_eq!(up.effective_probe_interval_ms(5_000), 5_000);
        assert_eq!(up.effective_probe_timeout_ms(2_000), 2_000);
        assert_eq!(up.expected_probe_rcode(), None);
        assert_eq!(up.effective_probes(&cfg.health.probes), cfg.health.probes);
    }

    #[test]
    fn rejects_invalid_expect_rcode() {
        let mut cfg = base();
        cfg.upstreams[0].expect_rcode = Some("NOT_A_RCODE".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("expect_rcode"), "{err}");
    }

    #[test]
    fn rejects_zero_cache_memory_budget() {
        let mut cfg = base();
        cfg.cache.max_memory_bytes = 0;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("max_memory_bytes"), "{err}");
    }

    #[test]
    fn rejects_too_many_upstreams() {
        let mut cfg = base();
        let proto = cfg.upstreams[0].clone();
        cfg.upstreams = (0..1025u32)
            .map(|i| {
                let mut u = proto.clone();
                u.id = i64::from(i);
                u.name = format!("up{i}");
                u
            })
            .collect();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("too many upstreams"), "{err}");
    }

    #[test]
    fn rejects_empty_per_upstream_probes() {
        let mut cfg = base();
        cfg.upstreams[0].probes = Some(vec![]);
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("probes must not be empty"), "{err}");
    }

    #[test]
    fn rejects_out_of_range_per_upstream_probe_interval() {
        let mut cfg = base();
        cfg.upstreams[0].probe_interval_ms = Some(50);
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("probe_interval_ms"), "{err}");
        cfg.upstreams[0].probe_interval_ms = Some(600_001);
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("probe_interval_ms"), "{err}");
    }

    #[test]
    fn dot_upstream_requires_tls_server_name() {
        let mut cfg = base();
        cfg.upstreams[0].protocol = Protocol::Tls;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("tls_server_name"), "{err}");

        cfg.upstreams[0].tls_server_name = Some("resolver.example".into());
        cfg.validate().expect("DoT with SNI is valid");
    }

    #[test]
    fn tls_options_are_rejected_on_plain_transports() {
        let mut cfg = base();
        cfg.upstreams[0].tls_server_name = Some("resolver.example".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("protocol is not tls"), "{err}");
    }

    #[test]
    fn management_tls_requires_both_files() {
        let mut cfg = base();
        cfg.server.tls_cert = Some(std::path::PathBuf::from("cert.pem"));
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("configured together"), "{err}");
        cfg.server.tls_key = Some(std::path::PathBuf::from("key.pem"));
        cfg.validate().expect("paired TLS files are valid");
    }
}
