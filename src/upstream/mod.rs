//! Upstream runtime state: health, latency, counters and the atomic registry.
//!
//! The registry maps upstream ids to shared runtime objects. Reconfiguration
//! builds a complete new map and swaps it under a write lock, so the DNS data
//! plane always observes either the old or the new upstream set, never a
//! partially updated one.

pub mod health;
pub mod latency;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::config::UpstreamConfig;
use crate::dns::msg::Rcode;
use latency::{LatencyStats, LatencyWindow};

/// Rolling outcome window size (bounded memory per upstream).
const OUTCOME_WINDOW: usize = 256;
/// Forwarding latency window size.
const FORWARD_LATENCY_WINDOW: usize = 512;
/// Health-check latency window size.
const HEALTH_LATENCY_WINDOW: usize = 128;

/// Health state of an upstream (hysteresis state machine, see [`health`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Up,
    Degraded,
    Down,
}

impl HealthStatus {
    pub fn is_usable(self) -> bool {
        matches!(self, HealthStatus::Up | HealthStatus::Degraded)
    }

    /// Numeric encoding for Prometheus (`res_upstream_state`).
    pub fn state_value(self) -> i64 {
        match self {
            HealthStatus::Down => 0,
            HealthStatus::Degraded => 1,
            HealthStatus::Up => 2,
        }
    }
}

/// Classification of one upstream attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeKind {
    /// A valid DNS response with a usable rcode (NOERROR / NXDOMAIN).
    Ok,
    /// Upstream SERVFAIL.
    ServFail,
    /// Upstream REFUSED.
    Refused,
    /// Timeout (no response within the per-upstream deadline).
    Timeout,
    /// Connection / socket error.
    Network,
    /// Response could not be correlated with the query.
    Invalid,
}

impl OutcomeKind {
    pub fn is_success(self) -> bool {
        matches!(self, OutcomeKind::Ok)
    }
}

/// Rolling success/timeout/failure samples for rate computations.
#[derive(Debug, Default)]
struct OutcomeWindow {
    samples: VecDeque<OutcomeKind>,
}

impl OutcomeWindow {
    fn push(&mut self, kind: OutcomeKind) {
        if self.samples.len() >= OUTCOME_WINDOW {
            self.samples.pop_front();
        }
        self.samples.push_back(kind);
    }

    /// Rolling success rate over the recent outcome window.
    ///
    /// `None` while no client query has been forwarded yet — an idle upstream
    /// has no success rate, and reporting one (e.g. `1.0`) would be a
    /// fabricated measurement on the dashboard.
    fn success_rate(&self) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }
        let ok = self.samples.iter().filter(|k| k.is_success()).count();
        Some(ok as f64 / self.samples.len() as f64)
    }

    /// Laplace-smoothed success rate used by the selector: an upstream with a
    /// short history is not immediately trusted, and a single late failure in
    /// a long clean history does not dominate.
    fn smoothed_reliability(&self) -> f64 {
        let n = self.samples.len() as f64;
        if n == 0.0 {
            return 1.0;
        }
        let ok = self.samples.iter().filter(|k| k.is_success()).count() as f64;
        (ok + 1.0) / (n + 2.0)
    }

    /// Share of windowed outcomes matching `pred`; `None` with no outcomes.
    fn rate(&self, pred: impl Fn(&OutcomeKind) -> bool) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }
        let n = self.samples.iter().filter(|k| pred(k)).count();
        Some(n as f64 / self.samples.len() as f64)
    }
}

#[derive(Debug)]
struct Inner {
    status: HealthStatus,
    consec_failures: u32,
    consec_successes: u32,
    last_check: Option<Instant>,
    last_success: Option<Instant>,
    last_failure: Option<Instant>,
    state_changed: Option<Instant>,
    last_error: Option<String>,
    // Lifetime counters (monotonic, exported as metrics / stats).
    queries: u64,
    ok: u64,
    failures: u64,
    timeouts: u64,
    servfail: u64,
    refused: u64,
    health_rounds: u64,
    health_failures: u64,
    /// Attempts that failed and caused a retry on another upstream.
    failovers: u64,
    /// Result of the most recent health check (None before the first one).
    last_health_ok: Option<bool>,
    outcomes: OutcomeWindow,
    forward_latency: LatencyWindow,
    health_latency: LatencyWindow,
    // Sampled once per second by the runtime sampler (honest rates: measured
    // over the previous interval, never derived from config).
    prev_queries: u64,
    prev_sample: Option<Instant>,
    qps: f64,
}

impl Inner {
    fn new() -> Self {
        Self {
            status: HealthStatus::Up,
            consec_failures: 0,
            consec_successes: 0,
            last_check: None,
            last_success: None,
            last_failure: None,
            state_changed: None,
            last_error: None,
            queries: 0,
            ok: 0,
            failures: 0,
            timeouts: 0,
            servfail: 0,
            refused: 0,
            health_rounds: 0,
            health_failures: 0,
            failovers: 0,
            last_health_ok: None,
            outcomes: OutcomeWindow::default(),
            forward_latency: LatencyWindow::new(FORWARD_LATENCY_WINDOW),
            health_latency: LatencyWindow::new(HEALTH_LATENCY_WINDOW),
            prev_queries: 0,
            prev_sample: None,
            qps: 0.0,
        }
    }
}

/// A health state transition, emitted for logging/metrics/persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthTransition {
    pub from: HealthStatus,
    pub to: HealthStatus,
}

/// Allocation-free snapshot of the selector inputs for one upstream.
#[derive(Debug, Clone, Copy)]
pub struct ViewInputs {
    pub status: HealthStatus,
    pub priority: u32,
    pub weight: u32,
    /// Laplace-smoothed reliability over the rolling outcome window.
    pub reliability: f64,
    pub p95_ms: f64,
    pub avg_ms: f64,
    pub has_latency: bool,
}

/// Shared, mutable runtime state of a single upstream.
pub struct UpstreamRuntime {
    id: i64,
    cfg: RwLock<UpstreamConfig>,
    inner: Mutex<Inner>,
}

impl UpstreamRuntime {
    pub fn new(cfg: UpstreamConfig) -> Arc<Self> {
        Arc::new(Self {
            id: cfg.id,
            cfg: RwLock::new(cfg),
            inner: Mutex::new(Inner::new()),
        })
    }

    pub fn id(&self) -> i64 {
        self.id
    }

    /// Current configuration (cloned; cheap, never held across I/O).
    pub fn config(&self) -> UpstreamConfig {
        self.cfg.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Whether this upstream participates in forwarding (no cloning).
    pub fn is_enabled(&self) -> bool {
        self.cfg.read().unwrap_or_else(|e| e.into_inner()).enabled
    }

    /// Update mutable fields (priority, weight, enabled, timeout) in place.
    pub fn update_config(&self, cfg: UpstreamConfig) {
        debug_assert_eq!(cfg.id, self.id);
        *self.cfg.write().unwrap_or_else(|e| e.into_inner()) = cfg;
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn health_status(&self) -> HealthStatus {
        self.lock_inner().status
    }

    /// Record that a failed attempt on this upstream triggered a retry on
    /// another one (incremented from the failover loop).
    pub fn record_failover(&self) {
        self.lock_inner().failovers += 1;
    }

    /// Record the result of a forwarded client query attempt.
    pub fn record_forward(&self, kind: OutcomeKind, latency: Duration) {
        let mut inner = self.lock_inner();
        // Start the rate window at the first attempt (not at process start),
        // so the first measured interval already covers real traffic.
        if inner.prev_sample.is_none() {
            inner.prev_sample = Some(Instant::now());
            inner.prev_queries = inner.queries;
        }
        inner.queries += 1;
        match kind {
            OutcomeKind::Ok => {
                inner.ok += 1;
                inner.forward_latency.push(latency);
                inner.last_success = Some(Instant::now());
                inner.last_error = None;
            }
            OutcomeKind::Timeout => {
                inner.timeouts += 1;
                inner.failures += 1;
                inner.last_failure = Some(Instant::now());
            }
            OutcomeKind::ServFail => {
                inner.servfail += 1;
                inner.failures += 1;
                inner.last_failure = Some(Instant::now());
            }
            OutcomeKind::Refused => {
                inner.refused += 1;
                inner.failures += 1;
                inner.last_failure = Some(Instant::now());
            }
            OutcomeKind::Network | OutcomeKind::Invalid => {
                inner.failures += 1;
                inner.last_failure = Some(Instant::now());
            }
        }
        inner.outcomes.push(kind);
    }

    /// Record one health-check round. Returns a transition when the state
    /// machine changed state.
    pub fn record_health_round(
        &self,
        ok: bool,
        latency: Option<Duration>,
        error: Option<String>,
        thresholds: &health::Hysteresis,
    ) -> Option<HealthTransition> {
        let mut inner = self.lock_inner();
        inner.health_rounds += 1;
        inner.last_check = Some(Instant::now());
        inner.last_health_ok = Some(ok);
        if let Some(l) = latency {
            inner.health_latency.push(l);
        }
        if ok {
            inner.last_success = Some(Instant::now());
            inner.last_error = None;
        } else {
            inner.health_failures += 1;
            inner.last_failure = Some(Instant::now());
            if let Some(e) = error {
                inner.last_error = Some(e);
            }
        }
        let from = inner.status;
        let step = health::step(
            from,
            inner.consec_failures,
            inner.consec_successes,
            ok,
            thresholds,
        );
        inner.status = step.status;
        inner.consec_failures = step.consec_failures;
        inner.consec_successes = step.consec_successes;
        if from != step.status {
            inner.state_changed = Some(Instant::now());
            Some(HealthTransition {
                from,
                to: step.status,
            })
        } else {
            None
        }
    }

    /// Lightweight, allocation-free inputs for the selector hot path.
    pub fn view_inputs(&self) -> ViewInputs {
        let cfg = self.config();
        let inner = self.lock_inner();
        let fwd = inner.forward_latency.stats();
        ViewInputs {
            status: inner.status,
            priority: cfg.priority,
            weight: cfg.weight,
            reliability: inner.outcomes.smoothed_reliability(),
            p95_ms: fwd.p95_ms,
            avg_ms: fwd.avg_ms,
            has_latency: fwd.count > 0,
        }
    }

    /// Refresh the measured requests/second over the last sample interval
    /// (called from the runtime sampler once per second).
    pub fn sample_rate(&self) {
        let mut inner = self.lock_inner();
        let now = Instant::now();
        let Some(prev) = inner.prev_sample else {
            // No attempt yet: rate is not measured, never guessed.
            inner.qps = 0.0;
            return;
        };
        let delta = inner.queries.saturating_sub(inner.prev_queries);
        let dt = now
            .saturating_duration_since(prev)
            .as_secs_f64()
            .max(f64::MIN_POSITIVE);
        inner.qps = delta as f64 / dt;
        inner.prev_queries = inner.queries;
        inner.prev_sample = Some(now);
    }

    /// Snapshot for the API / dashboard.
    pub fn stats(&self) -> UpstreamStats {
        let cfg = self.config();
        let inner = self.lock_inner();
        let fwd = inner.forward_latency.stats();
        let hea = inner.health_latency.stats();
        UpstreamStats {
            id: cfg.id,
            name: cfg.name.clone(),
            address: cfg.address.to_string(),
            port: cfg.port,
            protocol: cfg.protocol.to_string(),
            enabled: cfg.enabled,
            priority: cfg.priority,
            weight: cfg.weight,
            health: inner.status,
            latency: LatencySnapshot::from(fwd),
            health_latency: if hea.count > 0 {
                Some(hea.avg_ms)
            } else {
                None
            },
            success_rate: inner.outcomes.success_rate(),
            timeout_rate: inner.outcomes.rate(|k| matches!(k, OutcomeKind::Timeout)),
            servfail_rate: inner.outcomes.rate(|k| matches!(k, OutcomeKind::ServFail)),
            // Lifetime failure share of attempts (`None` before the first
            // attempt — a denominator of zero must not read as 0%).
            failure_rate: if inner.queries == 0 {
                None
            } else {
                Some(inner.failures as f64 / inner.queries as f64)
            },
            qps: round3(inner.qps),
            in_use: inner.qps > 0.0,
            queries: inner.queries,
            ok: inner.ok,
            failures: inner.failures,
            timeouts: inner.timeouts,
            servfail: inner.servfail,
            refused: inner.refused,
            health_rounds: inner.health_rounds,
            health_failures: inner.health_failures,
            failovers: inner.failovers,
            last_health_ok: inner.last_health_ok,
            consecutive_failures: inner.consec_failures,
            consecutive_successes: inner.consec_successes,
            last_check_ago_secs: ago_secs(inner.last_check),
            last_success_ago_secs: ago_secs(inner.last_success),
            last_failure_ago_secs: ago_secs(inner.last_failure),
            last_state_change_ago_secs: ago_secs(inner.state_changed),
            last_error: inner.last_error.clone(),
        }
    }
}

fn ago_secs(at: Option<Instant>) -> Option<u64> {
    at.map(|t| t.elapsed().as_secs())
}

/// Point-in-time latency view exposed by the API.
///
/// Every field is `null` until the upstream has actually answered at least one
/// client query — an unmeasured percentile must never look like a measurement
/// of `0 ms`.
#[derive(Debug, Clone, Serialize)]
pub struct LatencySnapshot {
    pub last_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub samples: u64,
}

impl From<LatencyStats> for LatencySnapshot {
    fn from(s: LatencyStats) -> Self {
        let measured = s.count > 0;
        let f = |v: f64| if measured { Some(round3(v)) } else { None };
        Self {
            last_ms: f(s.last_ms),
            avg_ms: f(s.avg_ms),
            min_ms: f(s.min_ms),
            max_ms: f(s.max_ms),
            p50_ms: f(s.p50_ms),
            p95_ms: f(s.p95_ms),
            p99_ms: f(s.p99_ms),
            samples: s.count,
        }
    }
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// API representation of an upstream (configuration + runtime statistics).
#[derive(Debug, Clone, Serialize)]
pub struct UpstreamStats {
    pub id: i64,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub protocol: String,
    pub enabled: bool,
    pub priority: u32,
    pub weight: u32,
    pub health: HealthStatus,
    pub latency: LatencySnapshot,
    pub health_latency: Option<f64>,
    /// `null` until the outcome window holds at least one client query.
    pub success_rate: Option<f64>,
    pub timeout_rate: Option<f64>,
    pub servfail_rate: Option<f64>,
    /// Lifetime share of attempts that failed (`null` before any attempt).
    pub failure_rate: Option<f64>,
    /// Measured queries/second over the last sampler interval.
    pub qps: f64,
    /// `true` when traffic was seen in the last sampler interval.
    pub in_use: bool,
    pub queries: u64,
    pub ok: u64,
    pub failures: u64,
    pub timeouts: u64,
    pub servfail: u64,
    pub refused: u64,
    pub health_rounds: u64,
    pub health_failures: u64,
    /// Attempts on this upstream that failed and forced a retry elsewhere.
    pub failovers: u64,
    /// Result of the most recent health check (`null` before the first one).
    pub last_health_ok: Option<bool>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_check_ago_secs: Option<u64>,
    pub last_success_ago_secs: Option<u64>,
    pub last_failure_ago_secs: Option<u64>,
    pub last_state_change_ago_secs: Option<u64>,
    pub last_error: Option<String>,
}

/// Map an upstream response code to an outcome classification.
pub fn classify_rcode(rcode: Rcode) -> OutcomeKind {
    match rcode {
        Rcode::NoError | Rcode::NXDomain => OutcomeKind::Ok,
        Rcode::ServFail => OutcomeKind::ServFail,
        Rcode::Refused => OutcomeKind::Refused,
        _ => OutcomeKind::Ok,
    }
}

/// Atomic map of upstream id -> shared runtime state.
#[derive(Default)]
pub struct Registry {
    map: RwLock<HashMap>,
}

type HashMap = std::collections::HashMap<i64, Arc<UpstreamRuntime>>;

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the upstream set atomically.
    ///
    /// Existing runtime objects are reused for unchanged ids so health and
    /// latency history survive reconfiguration. Removed ids disappear from
    /// every subsequent snapshot.
    pub fn reconcile(&self, upstreams: &[UpstreamConfig]) {
        let mut next = HashMap::with_capacity(upstreams.len());
        let mut old = self.map.write().unwrap_or_else(|e| e.into_inner());
        for cfg in upstreams {
            if let Some(existing) = old.get(&cfg.id) {
                if existing.config() != *cfg {
                    existing.update_config(cfg.clone());
                }
                next.insert(cfg.id, Arc::clone(existing));
            } else {
                next.insert(cfg.id, UpstreamRuntime::new(cfg.clone()));
            }
        }
        *old = next;
    }

    /// Snapshot of all upstreams (stable id order).
    pub fn snapshot(&self) -> Vec<Arc<UpstreamRuntime>> {
        let map = self.map.read().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<_> = map.values().cloned().collect();
        v.sort_by_key(|r| r.id());
        v
    }

    /// Snapshot of enabled upstreams only (hot path: no config cloning).
    pub fn enabled_snapshot(&self) -> Vec<Arc<UpstreamRuntime>> {
        let map = self.map.read().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<_> = map.values().filter(|r| r.is_enabled()).cloned().collect();
        v.sort_by_key(|r| r.id());
        v
    }

    pub fn get(&self, id: i64) -> Option<Arc<UpstreamRuntime>> {
        self.map
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .cloned()
    }

    /// Refresh the measured qps of every upstream (runtime sampler, 1 Hz).
    pub fn sample_rates(&self) {
        for r in self.snapshot() {
            r.sample_rate();
        }
    }

    pub fn len(&self) -> usize {
        self.map.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(id: i64, name: &str) -> UpstreamConfig {
        UpstreamConfig {
            id,
            name: name.into(),
            address: "1.1.1.1".parse().unwrap(),
            ..Default::default()
        }
    }

    #[test]
    fn reconcile_reuses_runtime_objects() {
        let reg = Registry::new();
        reg.reconcile(&[cfg(1, "a"), cfg(2, "b")]);
        let first = reg.get(1).unwrap();
        first.record_forward(OutcomeKind::Ok, Duration::from_millis(5));
        assert_eq!(first.stats().queries, 1);

        // Same ids, different weight: state must survive.
        let mut changed = cfg(1, "a");
        changed.weight = 9;
        let mut changed2 = cfg(2, "b");
        changed2.enabled = false;
        reg.reconcile(&[changed, changed2]);

        let again = reg.get(1).unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        assert_eq!(again.stats().queries, 1);
        assert_eq!(again.config().weight, 9);
        assert!(!reg.get(2).unwrap().config().enabled);
    }

    #[test]
    fn reconcile_removes_deleted_upstreams() {
        let reg = Registry::new();
        reg.reconcile(&[cfg(1, "a"), cfg(2, "b")]);
        assert_eq!(reg.len(), 2);
        reg.reconcile(&[cfg(2, "b")]);
        assert_eq!(reg.len(), 1);
        assert!(reg.get(1).is_none());
        assert!(reg.get(2).is_some());
    }

    #[test]
    fn counters_and_rates() {
        let rt = UpstreamRuntime::new(cfg(1, "a"));
        rt.record_forward(OutcomeKind::Ok, Duration::from_millis(10));
        rt.record_forward(OutcomeKind::Timeout, Duration::from_millis(0));
        rt.record_forward(OutcomeKind::Ok, Duration::from_millis(20));
        let s = rt.stats();
        assert_eq!(s.queries, 3);
        assert_eq!(s.ok, 2);
        assert_eq!(s.timeouts, 1);
        assert!((s.success_rate.expect("measured") - 2.0 / 3.0).abs() < 1e-9);
        assert!((s.timeout_rate.expect("measured") - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(s.latency.p50_ms, Some(15.0));
    }

    #[test]
    fn idle_upstream_reports_no_rates_instead_of_defaults() {
        let rt = UpstreamRuntime::new(cfg(1, "a"));
        let s = rt.stats();
        assert_eq!(s.queries, 0);
        // No client query has been forwarded: nothing may be reported as a
        // measurement (the old behaviour invented 100% success / 0 ms).
        assert_eq!(s.success_rate, None);
        assert_eq!(s.timeout_rate, None);
        assert_eq!(s.servfail_rate, None);
        assert_eq!(s.latency.samples, 0);
        assert_eq!(s.latency.p50_ms, None);
        assert_eq!(s.latency.p95_ms, None);
        assert_eq!(s.latency.p99_ms, None);
        assert_eq!(s.latency.avg_ms, None);
        assert_eq!(s.latency.last_ms, None);
        // Health probes are not client traffic and must not create a sample.
        let hyst = health::Hysteresis {
            failure_threshold: 3,
            recovery_threshold: 3,
        };
        rt.record_health_round(true, Some(Duration::from_millis(2)), None, &hyst);
        let s = rt.stats();
        assert_eq!(s.success_rate, None);
        assert_eq!(s.latency.p50_ms, None);
        assert!(s.health_latency.is_some(), "probe latency is measured");
    }

    #[test]
    fn health_status_serializes_lowercase() {
        let json = serde_json::to_string(&HealthStatus::Degraded).unwrap();
        assert_eq!(json, "\"degraded\"");
    }
}
