//! Active DNS health checking with hysteresis.
//!
//! Health checks are real DNS queries sent through the same
//! [`Forwarder`](crate::dns::forward::Forwarder) used for normal forwarding —
//! no ICMP, no external probing tool.
//!
//! State machine (see `Hysteresis`):
//!
//! ```text
//! UP --first failed round--> DEGRADED --failure_threshold--> DOWN
//! UP/DEGRADED/DOWN --recovery_threshold consecutive successes--> UP
//! ```

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::config::{HealthConfig, Protocol};
use crate::dns::forward::Forwarder;
use crate::dns::msg::{self, Rcode};
use crate::metrics::Metrics;
use crate::shared::Shared;
use crate::upstream::{HealthStatus, HealthTransition, UpstreamRuntime};

/// Thresholds for the health state machine.
#[derive(Debug, Clone, Copy)]
pub struct Hysteresis {
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
}

/// Result of feeding one check round into the state machine.
#[derive(Debug, Clone, Copy)]
pub struct Step {
    pub status: HealthStatus,
    pub consec_failures: u32,
    pub consec_successes: u32,
}

/// Pure hysteresis transition function (unit tested independently).
///
/// * a failed round from `UP` moves to `DEGRADED` immediately (fast protection),
/// * further consecutive failures up to `failure_threshold` move to `DOWN`,
/// * `recovery_threshold` consecutive successful rounds are required to return
///   to `UP` from any degraded/down state.
pub fn step(
    state: HealthStatus,
    consec_failures: u32,
    consec_successes: u32,
    ok: bool,
    hyst: &Hysteresis,
) -> Step {
    if ok {
        let successes = consec_successes.saturating_add(1);
        let status = if state != HealthStatus::Up && successes >= hyst.recovery_threshold {
            HealthStatus::Up
        } else {
            state
        };
        Step {
            status,
            consec_failures: 0,
            consec_successes: successes,
        }
    } else {
        let failures = consec_failures.saturating_add(1);
        let status = match state {
            HealthStatus::Up => HealthStatus::Degraded,
            HealthStatus::Degraded if failures >= hyst.failure_threshold => HealthStatus::Down,
            other => other,
        };
        Step {
            status,
            consec_failures: failures,
            consec_successes: 0,
        }
    }
}

/// Background health-check loop.
pub async fn run_health_checker(
    shared: Arc<Shared>,
    forwarder: Forwarder,
    mut shutdown: watch::Receiver<bool>,
) {
    tracing::debug!(event = "health_checker_started");
    loop {
        let hc: HealthConfig = shared.app.load().health.clone();
        let base = hc.interval_ms.max(100);
        // +/-10% jitter so many gateway instances do not synchronise.
        let jitter_ms = fastrand::u64(0..(base / 10).max(1));
        let sleep = Duration::from_millis(base + jitter_ms);

        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(sleep) => {}
        }

        if !hc.enabled {
            continue;
        }
        run_round(&shared, &forwarder, &hc).await;
        refresh_gauges(&shared, &shared.metrics);
    }
    tracing::debug!(event = "health_checker_stopped");
}

async fn run_round(shared: &Arc<Shared>, forwarder: &Forwarder, hc: &HealthConfig) {
    let upstreams: Vec<Arc<UpstreamRuntime>> = shared
        .registry
        .snapshot()
        .into_iter()
        .filter(|u| u.config().enabled)
        .collect();
    if upstreams.is_empty() {
        return;
    }

    let hyst = Hysteresis {
        failure_threshold: hc.failure_threshold,
        recovery_threshold: hc.recovery_threshold,
    };

    let mut set = tokio::task::JoinSet::new();
    for up in upstreams {
        let shared = Arc::clone(shared);
        let forwarder = *forwarder;
        let hc = hc.clone();
        set.spawn(async move {
            check_upstream(&shared, &forwarder, &up, &hc, &hyst).await;
        });
    }
    while let Some(res) = set.join_next().await {
        if let Err(e) = res {
            tracing::warn!(event = "health_task_failed", error = %e);
        }
    }
}

async fn check_upstream(
    shared: &Arc<Shared>,
    forwarder: &Forwarder,
    up: &Arc<UpstreamRuntime>,
    hc: &HealthConfig,
    hyst: &Hysteresis,
) {
    let cfg = up.config();
    let timeout = Duration::from_millis(hc.timeout_ms);
    let pre_state = up.health_status();

    let mut successes = 0usize;
    let mut attempts = 0usize;
    let mut latencies: Vec<Duration> = Vec::new();
    let mut last_error: Option<String> = None;

    'probes: for probe in &hc.probes {
        let raw = match msg::build_query(&probe.name, &probe.query_type) {
            Ok(r) => r,
            Err(e) => {
                last_error = Some(format!("probe build failed: {e}"));
                continue;
            }
        };
        let parsed = match msg::parse_query(&raw) {
            Ok(p) => p,
            Err(e) => {
                last_error = Some(format!("probe parse failed: {e:?}"));
                continue;
            }
        };

        let mut transports = vec![cfg.protocol];
        if hc.tcp_probes && cfg.protocol == Protocol::Udp {
            transports.push(Protocol::Tcp);
        }

        for proto in transports {
            attempts += 1;
            match forwarder
                .exchange_with(&cfg, &parsed, &raw, timeout, proto)
                .await
            {
                Ok(ok) => match ok.view.rcode {
                    Rcode::NoError | Rcode::NXDomain => {
                        successes += 1;
                        latencies.push(ok.latency);
                    }
                    other => {
                        last_error = Some(format!("rcode {}", other.as_str()));
                    }
                },
                Err(e) => last_error = Some(e.to_string()),
            }
            if successes >= hc.min_successes {
                break 'probes;
            }
        }
    }

    let ok = successes >= hc.min_successes && attempts > 0;
    let latency = if latencies.is_empty() {
        None
    } else {
        let sum: Duration = latencies.iter().sum();
        Some(sum / latencies.len() as u32)
    };
    let error = if ok {
        None
    } else {
        last_error.or_else(|| Some("no successful probe".into()))
    };

    let transition = up.record_health_round(ok, latency, error.clone(), hyst);
    record_check_metrics(shared, &cfg.name, ok, latency, transition.is_some());

    if let Some(t) = &transition {
        log_transition(&cfg.name, *t, &error);
        shared
            .metrics
            .set_upstream_health(&cfg.name, t.to == HealthStatus::Up, t.to.state_value());
    }

    // Record: state transitions, plus failed rounds while the upstream is
    // still in play (bounded volume; steady-state DOWN failures are not
    // recorded every round).
    let should_record = transition.is_some() || (!ok && pre_state != HealthStatus::Down);
    if should_record {
        shared.record_health_event(
            if transition.is_some() {
                "transition"
            } else {
                "round_failed"
            },
            cfg.id,
            &cfg.name,
            Some(state_str(pre_state)),
            Some(state_str(up.health_status())),
            error.clone(),
            serde_json::json!({
                "success": ok,
                "latency_ms": latency.map(|d| (d.as_secs_f64() * 1000.0 * 100.0).round() / 100.0),
                "transition": transition.is_some(),
            }),
        );
    }
}

fn state_str(s: HealthStatus) -> &'static str {
    match s {
        HealthStatus::Up => "up",
        HealthStatus::Degraded => "degraded",
        HealthStatus::Down => "down",
    }
}

/// Export the result of one health-check round (or on-demand probe) to
/// Prometheus: round result, probe latency (when measured), last-success
/// timestamp and state transitions. Called from the checker loop and from
/// the API-triggered probe, never from the query hot path.
fn record_check_metrics(
    shared: &Arc<Shared>,
    name: &str,
    ok: bool,
    latency: Option<Duration>,
    transitioned: bool,
) {
    let m = &shared.metrics;
    m.healthcheck_total
        .with_label_values(&[name, if ok { "success" } else { "failure" }])
        .inc();
    if ok {
        if let Ok(elapsed) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            m.healthcheck_last_success_timestamp_seconds
                .with_label_values(&[name])
                .set(elapsed.as_secs() as i64);
        }
    }
    if let Some(l) = latency {
        m.healthcheck_duration_seconds
            .with_label_values(&[name])
            .observe(l.as_secs_f64());
    }
    if transitioned {
        m.upstream_state_changes_total
            .with_label_values(&[name])
            .inc();
    }
}

fn log_transition(name: &str, t: HealthTransition, error: &Option<String>) {
    let from = state_str(t.from);
    let to = state_str(t.to);
    match t.to {
        HealthStatus::Down => tracing::warn!(
            event = "upstream_marked_down",
            upstream = %name,
            from,
            to,
            error = error.as_deref().unwrap_or(""),
        ),
        HealthStatus::Degraded => tracing::warn!(
            event = "upstream_degraded",
            upstream = %name,
            from,
            to,
            error = error.as_deref().unwrap_or(""),
        ),
        HealthStatus::Up => tracing::info!(
            event = "upstream_recovered",
            upstream = %name,
            from,
            to,
        ),
    }
}

/// Refresh the derived gauges (active / healthy counts + per-upstream state)
/// and emit a system event when the pool enters/leaves total failure.
pub fn refresh_gauges(shared: &Arc<Shared>, metrics: &Arc<Metrics>) {
    let snapshot = shared.registry.snapshot();
    let mut active = 0i64;
    let mut healthy = 0i64;
    let total = snapshot.len() as i64;
    for up in &snapshot {
        let cfg = up.config();
        if cfg.enabled {
            active += 1;
        }
        let status = up.health_status();
        if status == HealthStatus::Up {
            healthy += 1;
        }
        metrics.set_upstream_health(&cfg.name, status == HealthStatus::Up, status.state_value());
    }
    metrics.active_upstreams.set(active);
    metrics.healthy_upstreams.set(healthy);

    // Emergency: every upstream is DOWN while at least one exists — clients
    // are receiving SERVFAIL. Emit exactly once per transition (the sampler
    // calls this every second, so no cooldown is needed).
    let emergency = total > 0 && healthy == 0;
    let was = shared.emergency.load(std::sync::atomic::Ordering::Relaxed);
    if emergency != was {
        shared
            .emergency
            .store(emergency, std::sync::atomic::Ordering::Relaxed);
        if emergency {
            shared.push_system_event(
                "all_upstreams_down",
                serde_json::json!({
                    "active": active,
                    "total": total,
                    "detail": "no healthy upstream remains - clients are getting SERVFAIL",
                }),
                None,
                None,
            );
            tracing::error!(event = "emergency_no_healthy_upstreams", active, total);
        } else {
            shared.push_system_event(
                "all_upstreams_recovered",
                serde_json::json!({ "active": active, "healthy": healthy }),
                None,
                None,
            );
            tracing::info!(event = "emergency_cleared", healthy, total);
        }
    }
}

/// Run a single on-demand health check (API `POST /upstreams/:id/test`).
pub async fn probe_once(
    shared: &Arc<Shared>,
    forwarder: &Forwarder,
    up: &Arc<UpstreamRuntime>,
) -> ProbeResult {
    let app = shared.app.load();
    let hc = app.health.clone();
    let cfg = up.config();
    let timeout = Duration::from_millis(hc.timeout_ms.max(500));

    let probe = hc.probes.first().cloned().unwrap_or_default();
    let started = std::time::Instant::now();
    let raw = match msg::build_query(&probe.name, &probe.query_type) {
        Ok(r) => r,
        Err(e) => {
            return ProbeResult {
                success: false,
                latency_ms: None,
                rcode: None,
                error: Some(e),
            }
        }
    };
    let parsed = msg::parse_query(&raw).expect("built query parses");

    let result = forwarder.exchange(&cfg, &parsed, &raw, timeout).await;
    let out = match result {
        Ok(ok) => {
            let rcode = ok.view.rcode;
            let success = matches!(rcode, Rcode::NoError | Rcode::NXDomain);
            ProbeResult {
                success,
                latency_ms: Some(ok.latency.as_secs_f64() * 1000.0),
                rcode: Some(rcode.as_str().to_string()),
                error: if success {
                    None
                } else {
                    Some(format!("rcode {}", rcode.as_str()))
                },
            }
        }
        Err(e) => ProbeResult {
            success: false,
            latency_ms: None,
            rcode: None,
            error: Some(e.to_string()),
        },
    };

    // Feed the result into the state machine as an extra round so an operator
    // test can observe (and recover) an upstream immediately.
    let hyst = Hysteresis {
        failure_threshold: hc.failure_threshold,
        recovery_threshold: hc.recovery_threshold,
    };
    let pre = up.health_status();
    let transition = up.record_health_round(
        out.success,
        out.latency_ms.map(|ms| Duration::from_millis(ms as u64)),
        out.error.clone(),
        &hyst,
    );
    record_check_metrics(
        shared,
        &cfg.name,
        out.success,
        out.latency_ms.map(|ms| Duration::from_millis(ms as u64)),
        transition.is_some(),
    );
    if let Some(t) = &transition {
        log_transition(&cfg.name, *t, &out.error);
        shared
            .metrics
            .set_upstream_health(&cfg.name, t.to == HealthStatus::Up, t.to.state_value());
    }
    shared.record_health_event(
        "probe",
        cfg.id,
        &cfg.name,
        Some(state_str(pre)),
        Some(state_str(up.health_status())),
        out.error.clone(),
        serde_json::json!({
            "success": out.success,
            "latency_ms": out.latency_ms,
            "rcode": out.rcode,
            "transition": transition.is_some(),
        }),
    );
    tracing::debug!(
        event = "on_demand_probe",
        upstream = %cfg.name,
        success = out.success,
        latency_ms = out.latency_ms.unwrap_or(0.0),
        elapsed_ms = started.elapsed().as_millis() as u64,
    );
    out
}

/// Result of an on-demand health probe.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeResult {
    pub success: bool,
    pub latency_ms: Option<f64>,
    pub rcode: Option<String>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hyst(f: u32, r: u32) -> Hysteresis {
        Hysteresis {
            failure_threshold: f,
            recovery_threshold: r,
        }
    }

    #[test]
    fn first_failure_degrades_immediately() {
        let h = hyst(3, 2);
        let s = step(HealthStatus::Up, 0, 5, false, &h);
        assert_eq!(s.status, HealthStatus::Degraded);
        assert_eq!(s.consec_failures, 1);
        assert_eq!(s.consec_successes, 0);
    }

    #[test]
    fn failure_threshold_takes_it_down() {
        let h = hyst(3, 2);
        let mut state = HealthStatus::Up;
        let mut f = 0;
        let mut s = 0;
        for i in 1..=3 {
            let st = step(state, f, s, false, &h);
            state = st.status;
            f = st.consec_failures;
            s = st.consec_successes;
            if i == 1 {
                assert_eq!(state, HealthStatus::Degraded);
            }
        }
        assert_eq!(state, HealthStatus::Down);
        // Stays down on further failures.
        let st = step(state, f, s, false, &h);
        assert_eq!(st.status, HealthStatus::Down);
        assert_eq!(st.consec_failures, 4);
    }

    #[test]
    fn recovery_requires_threshold_consecutive_successes() {
        let h = hyst(3, 2);
        let mut state = HealthStatus::Down;
        let mut f = 5;
        let mut s = 0;

        let st = step(state, f, s, true, &h);
        assert_eq!(st.status, HealthStatus::Down, "one success is not enough");
        state = st.status;
        f = st.consec_failures;
        s = st.consec_successes;

        let st = step(state, f, s, true, &h);
        assert_eq!(st.status, HealthStatus::Up, "two successes recover");
        assert_eq!(st.consec_failures, 0);
    }

    #[test]
    fn failure_resets_recovery_progress() {
        let h = hyst(3, 2);
        let st = step(HealthStatus::Down, 4, 0, true, &h);
        assert_eq!(st.status, HealthStatus::Down);
        assert_eq!(st.consec_successes, 1);
        // A failure wipes the success streak.
        let st2 = step(
            st.status,
            st.consec_failures,
            st.consec_successes,
            false,
            &h,
        );
        assert_eq!(st2.consec_successes, 0);
        assert_eq!(st2.status, HealthStatus::Down);
    }

    #[test]
    fn success_while_up_keeps_up_and_resets_failures() {
        let h = hyst(3, 2);
        let st = step(HealthStatus::Up, 2, 0, true, &h);
        assert_eq!(st.status, HealthStatus::Up);
        assert_eq!(st.consec_failures, 0);
    }

    #[test]
    fn degraded_recovered_after_threshold() {
        let h = hyst(3, 2);
        let st = step(HealthStatus::Degraded, 1, 0, true, &h);
        assert_eq!(st.status, HealthStatus::Degraded);
        let st = step(st.status, st.consec_failures, st.consec_successes, true, &h);
        assert_eq!(st.status, HealthStatus::Up);
    }
}
