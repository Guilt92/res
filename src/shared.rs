//! Shared in-memory state: configuration, upstream registry, metrics, cache,
//! event rings.
//!
//! Everything the DNS data plane needs lives here and is reachable without
//! file, network or blocking I/O. Reconfiguration swaps complete `Arc`s, so a
//! request observes a consistent old or new configuration.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;

use crate::cache::DnsCache;
use crate::config::{AppConfig, RuntimeConfig, UpstreamConfig};
use crate::dns::listener::Counter;
use crate::events::{Event, EventLogs};
use crate::metrics::Metrics;
use crate::ratelimit::RateLimiter;
use crate::selection::{build_selector, SelectorHandle, UpstreamSelector};
use crate::upstream::latency::{LatencyStats, LatencyWindow};
use crate::upstream::Registry;

const GLOBAL_LATENCY_WINDOW: usize = 2048;

pub struct Shared {
    /// Full configuration (management view, includes upstreams).
    pub app: ArcSwap<AppConfig>,
    /// Data-plane configuration (pre-parsed ACL, limits, failover, ...).
    pub rt: ArcSwap<RuntimeConfig>,
    /// Active selection strategy (`UpstreamSelector: Send + Sync` supertrait).
    pub selector: ArcSwap<SelectorHandle>,
    /// Upstream runtime registry (health, latency, counters).
    pub registry: Registry,
    pub metrics: Arc<Metrics>,
    pub cache: DnsCache,
    pub ratelimit: RateLimiter,
    /// Bounded in-memory event rings (config / health / failover).
    pub events: Arc<EventLogs>,
    /// Where the active configuration came from and any startup error
    /// (surfaced by `/api/status` and `/api/diagnostics`).
    pub config_state: std::sync::RwLock<ConfigState>,
    /// End-to-end latency of forwarded queries (dashboard percentiles).
    pub global_latency: std::sync::Mutex<LatencyWindow>,
    pub qps: QpsMeter,
    pub started_at: Instant,
    pub config_path: std::sync::OnceLock<PathBuf>,
    /// In-flight / connection counters used by the listeners and status API.
    pub udp_inflight: Arc<Counter>,
    pub tcp_connections: Arc<Counter>,
    /// Actual bound listener addresses (filled in at startup; differs from
    /// the configured address when port 0 is used, e.g. in tests).
    pub bound: std::sync::RwLock<BoundAddrs>,
}

/// Where the running configuration came from and whether anything is wrong
/// with it (surfaced by the API instead of blocking startup).
#[derive(Debug, Clone)]
pub struct ConfigState {
    /// `file`, `backup`, `defaults`, `inline` (tests / programmatic start).
    pub source: String,
    /// Last configuration problem (startup fallback or persist failure).
    pub error: Option<String>,
}

impl Default for ConfigState {
    fn default() -> Self {
        Self {
            source: "inline".into(),
            error: None,
        }
    }
}

/// Addresses the listeners actually bound to.
#[derive(Debug, Clone, Default)]
pub struct BoundAddrs {
    pub udp: Option<std::net::SocketAddr>,
    pub tcp: Option<std::net::SocketAddr>,
    pub api: Option<std::net::SocketAddr>,
}

impl Shared {
    pub fn new(mut app: AppConfig) -> anyhow::Result<Arc<Self>> {
        app.normalize_upstream_ids();
        app.validate()
            .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;
        let rt = RuntimeConfig::from_app(&app).map_err(|e| anyhow::anyhow!(e))?;
        let selector: Arc<dyn UpstreamSelector> = Arc::from(build_selector(&app.selection));
        let registry = Registry::new();
        registry.reconcile(&app.upstreams);

        Ok(Arc::new(Self {
            app: ArcSwap::from_pointee(app),
            rt: ArcSwap::from_pointee(rt),
            selector: ArcSwap::from(Arc::new(SelectorHandle::new(selector))),
            registry,
            metrics: Metrics::new(),
            cache: DnsCache::new(),
            ratelimit: RateLimiter::new(),
            events: Arc::new(EventLogs::new()),
            config_state: std::sync::RwLock::new(ConfigState::default()),
            global_latency: std::sync::Mutex::new(LatencyWindow::new(GLOBAL_LATENCY_WINDOW)),
            qps: QpsMeter::new(),
            started_at: Instant::now(),
            config_path: std::sync::OnceLock::new(),
            udp_inflight: Arc::new(Counter::default()),
            tcp_connections: Arc::new(Counter::default()),
            bound: std::sync::RwLock::new(BoundAddrs::default()),
        }))
    }

    /// Owned handle to the active selector. The internal guard is dropped
    /// before this returns, so the `Arc` can be held across `.await` points.
    pub fn current_selector(&self) -> Arc<dyn UpstreamSelector> {
        self.selector.load().0.clone()
    }

    /// Atomically install a new configuration (validated first).
    ///
    /// The DNS request path either sees the previous complete configuration
    /// or the new complete configuration.
    pub fn replace_config(&self, mut next: AppConfig) -> Result<(), String> {
        next.normalize_upstream_ids();
        next.validate()?;
        let rt = RuntimeConfig::from_app(&next)?;
        let selector: Arc<dyn UpstreamSelector> = Arc::from(build_selector(&next.selection));

        // Drop metric series for upstreams that disappeared.
        let old_names: std::collections::HashSet<String> = self
            .registry
            .snapshot()
            .iter()
            .map(|u| u.config().name)
            .collect();
        let new_names: std::collections::HashSet<String> =
            next.upstreams.iter().map(|u| u.name.clone()).collect();
        for name in old_names.difference(&new_names) {
            self.metrics.drop_upstream(name);
        }

        self.registry.reconcile(&next.upstreams);
        self.selector.store(Arc::new(SelectorHandle::new(selector)));
        self.rt.store(Arc::new(rt));
        self.app.store(Arc::new(next));
        self.metrics.config_reloads_total.inc();
        tracing::info!(event = "configuration_reloaded");
        Ok(())
    }

    /// Replace the upstream list (keeping the rest of the configuration).
    pub fn apply_upstreams(&self, upstreams: Vec<UpstreamConfig>) -> Result<(), String> {
        let next = self.app.load().with_upstreams(upstreams)?;
        self.replace_config(next)
    }

    /// Record a configuration change in the bounded config event ring.
    pub fn record_config_event(&self, action: &str, detail: serde_json::Value) {
        self.events.config.push(Event::config(action, detail));
    }

    /// Record a health state change / probe result (rare, bounded).
    #[allow(clippy::too_many_arguments)]
    pub fn record_health_event(
        &self,
        action: &str,
        upstream_id: i64,
        upstream: &str,
        from: Option<&str>,
        to: Option<&str>,
        reason: Option<String>,
        detail: serde_json::Value,
    ) {
        self.events.health.push(Event::health(
            action,
            upstream_id,
            upstream,
            from,
            to,
            reason,
            detail,
        ));
    }

    /// Persist the active configuration to its file (atomic, last-known-good
    /// backup). No-op when no configuration path is set (pure in-memory use,
    /// e.g. tests). Failures are recorded but never interrupt the data plane.
    pub fn persist_config(&self) -> Result<(), String> {
        let Some(path) = self.config_path.get() else {
            return Ok(());
        };
        let app = self.app.load();
        match crate::persist::save_atomic(path, &app) {
            Ok(()) => {
                self.clear_config_error();
                Ok(())
            }
            Err(e) => {
                self.metrics.config_errors_total.inc();
                self.record_config_event(
                    "persist_failed",
                    serde_json::json!({ "path": path.display().to_string(), "error": e }),
                );
                tracing::warn!(event = "config_persist_failed", error = %e);
                self.set_config_error(format!("persist failed: {e}"));
                Err(e)
            }
        }
    }

    pub fn set_config_state(&self, source: &str, error: Option<String>) {
        let mut st = self.config_state.write().unwrap_or_else(|e| e.into_inner());
        st.source = source.to_string();
        st.error = error;
    }

    pub fn set_config_error(&self, error: String) {
        let mut st = self.config_state.write().unwrap_or_else(|e| e.into_inner());
        st.error = Some(error);
    }

    pub fn clear_config_error(&self) {
        let mut st = self.config_state.write().unwrap_or_else(|e| e.into_inner());
        st.error = None;
    }

    pub fn config_state(&self) -> ConfigState {
        self.config_state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn global_latency_stats(&self) -> LatencyStats {
        self.global_latency
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stats()
    }

    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }
}

/// Samples total query counters once per second to derive QPS.
pub struct QpsMeter {
    inner: std::sync::Mutex<QpsInner>,
}

struct QpsInner {
    last_total: u64,
    last_at: Instant,
    qps: f64,
}

impl QpsMeter {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(QpsInner {
                last_total: 0,
                last_at: Instant::now(),
                qps: 0.0,
            }),
        }
    }

    pub fn sample(&self, total: u64) {
        let mut i = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let dt = i.last_at.elapsed().as_secs_f64();
        if dt >= 0.2 {
            i.qps = (total.saturating_sub(i.last_total)) as f64 / dt;
            i.last_total = total;
            i.last_at = Instant::now();
        }
    }

    /// Most recent per-second rate; 0.0 when sampling has stalled.
    pub fn current(&self) -> f64 {
        let i = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if i.last_at.elapsed() > Duration::from_secs(5) {
            0.0
        } else {
            i.qps
        }
    }
}

impl Default for QpsMeter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_with_upstreams() -> AppConfig {
        AppConfig {
            upstreams: vec![UpstreamConfig {
                id: 1,
                name: "one".into(),
                address: "1.1.1.1".parse().unwrap(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn new_builds_registry_and_validates() {
        let shared = Shared::new(app_with_upstreams()).unwrap();
        assert_eq!(shared.registry.len(), 1);
        assert!(shared.registry.get(1).is_some());
    }

    #[test]
    fn new_rejects_invalid_config() {
        let mut bad = app_with_upstreams();
        bad.upstreams[0].priority = 0;
        assert!(Shared::new(bad).is_err());
    }

    #[test]
    fn replace_config_swaps_atomically() {
        let shared = Shared::new(app_with_upstreams()).unwrap();
        assert_eq!(shared.registry.len(), 1);

        let mut next = app_with_upstreams();
        next.upstreams.push(UpstreamConfig {
            id: 2,
            name: "two".into(),
            address: "8.8.8.8".parse().unwrap(),
            ..Default::default()
        });
        shared.replace_config(next).unwrap();
        assert_eq!(shared.registry.len(), 2);
        assert_eq!(shared.app.load().upstreams.len(), 2);
        assert_eq!(shared.rt.load().query.max_attempts, 3);
    }

    #[test]
    fn replace_config_rejects_invalid_without_applying() {
        let shared = Shared::new(app_with_upstreams()).unwrap();
        let mut bad = app_with_upstreams();
        bad.upstreams[0].name = String::new();
        assert!(shared.replace_config(bad).is_err());
        // Old configuration intact.
        assert_eq!(shared.registry.len(), 1);
        assert_eq!(shared.registry.snapshot()[0].config().name, "one");
    }

    #[test]
    fn apply_upstreams_validates_duplicates() {
        let shared = Shared::new(app_with_upstreams()).unwrap();
        let dup = vec![
            UpstreamConfig {
                id: 5,
                name: "x".into(),
                address: "9.9.9.9".parse().unwrap(),
                ..Default::default()
            },
            UpstreamConfig {
                id: 6,
                name: "x".into(),
                address: "8.8.4.4".parse().unwrap(),
                ..Default::default()
            },
        ];
        assert!(shared.apply_upstreams(dup).is_err());
        assert_eq!(shared.registry.len(), 1);
    }

    #[test]
    fn qps_meter_samples_and_decays() {
        let m = QpsMeter::new();
        assert_eq!(m.current(), 0.0);
        std::thread::sleep(Duration::from_millis(250));
        m.sample(100);
        std::thread::sleep(Duration::from_millis(250));
        m.sample(200);
        let q = m.current();
        assert!(q > 0.0, "expected positive qps, got {q}");
    }
}
