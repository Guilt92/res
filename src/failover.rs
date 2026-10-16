//! Bounded retry / failover across the upstream pool.
//!
//! Guarantees:
//! * at most `query.max_attempts` upstreams are tried for one client query,
//! * each attempt is capped by `query.upstream_timeout` (or the upstream's
//!   own timeout override),
//! * the whole query is capped by `query.timeout`,
//! * an upstream is never tried twice for the same query,
//! * SERVFAIL responses are retried on another upstream only when
//!   `retry_on_servfail` is enabled; REFUSED / NXDOMAIN / NOERROR are final.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{FailoverConfig, QueryConfig};
use crate::dns::forward::{ExchangeError, Forwarder};
use crate::dns::msg::{ParsedQuery, Rcode};
use crate::events::EventLogs;
use crate::metrics::Metrics;
use crate::selection::{StateView, UpstreamSelector};
use crate::upstream::{classify_rcode, OutcomeKind, UpstreamRuntime};

#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("no usable upstream candidates")]
    NoCandidates,
    #[error("all upstream attempts failed ({attempts} attempts)")]
    AllFailed { attempts: u32 },
    #[error("total query deadline exceeded after {attempts} attempts")]
    DeadlineExceeded { attempts: u32 },
}

impl ForwardError {
    pub fn reason(&self) -> &'static str {
        match self {
            ForwardError::NoCandidates => "no_upstreams",
            ForwardError::AllFailed { .. } => "upstream_failure",
            ForwardError::DeadlineExceeded { .. } => "deadline",
        }
    }
}

pub struct ForwardSuccess {
    pub upstream_id: i64,
    pub upstream_name: String,
    pub response: Vec<u8>,
    /// Number of upstream attempts used (1 = no failover).
    pub attempts: u32,
    pub latency: Duration,
    pub rcode: Rcode,
    pub truncated: bool,
}

/// Forward one query through the pool with selection + failover.
///
/// `pool` must contain only enabled upstreams (see `Registry::snapshot`).
/// `started` is the instant the *client's query* entered the pipeline: the
/// failover deadline is `started + query_cfg.timeout()`, so coalesced
/// followers and retries can never extend a single query past the operator's
/// configured budget.
#[allow(clippy::too_many_arguments)]
pub async fn forward(
    forwarder: &Forwarder,
    selector: &(dyn UpstreamSelector + Send + Sync),
    metrics: &Metrics,
    query_cfg: &QueryConfig,
    failover: &FailoverConfig,
    query: &ParsedQuery,
    raw: &[u8],
    pool: &[Arc<UpstreamRuntime>],
    events: &EventLogs,
    started: Instant,
    min_probe_samples: u32,
) -> Result<ForwardSuccess, ForwardError> {
    let call_started = Instant::now();
    let deadline = started + query_cfg.timeout();

    let mut tried: Vec<i64> = Vec::with_capacity(query_cfg.max_attempts as usize);
    let mut attempts: u32 = 0;
    let mut failover_counted = false;
    // Cumulative time burned in *failed* attempts (the extra latency the
    // client paid because of failover).
    let mut failed_attempt_time = Duration::ZERO;
    // Why the previous attempt gave up:
    // (upstream id, upstream name, reason, elapsed ms).
    let mut last_failure: Option<(i64, String, &'static str, u64)> = None;

    loop {
        if attempts >= query_cfg.max_attempts {
            break;
        }
        let remaining_total = deadline.saturating_duration_since(Instant::now());
        if remaining_total.is_zero() {
            return Err(ForwardError::DeadlineExceeded { attempts });
        }

        let candidates: Vec<StateView> = pool
            .iter()
            .filter(|u| !tried.contains(&u.id()))
            .map(|u| StateView::from_runtime(u, min_probe_samples))
            .collect();

        let Some(pick) = selector.select(&candidates) else {
            break;
        };
        let Some(runtime) = pool.iter().find(|u| u.id() == pick) else {
            break;
        };

        let up = runtime.config();
        let name = up.name.clone();
        attempts += 1;
        if attempts > 1 && !failover_counted {
            failover_counted = true;
            metrics.failovers_total.inc();
            tracing::debug!(
                event = "failover",
                upstream = %name,
                attempt = attempts,
                tried = tried.len(),
            );
        }
        if let Some((failed_id, failed_up, reason, extra_ms)) = last_failure.take() {
            // Bounded ring; only written when a retry actually happens.
            events.failover.push(crate::events::Event::failover(
                &failed_up, reason, attempts, &name, extra_ms,
            ));
            metrics
                .upstream_failovers_total
                .with_label_values(&[&failed_up])
                .inc();
            metrics
                .failover_reason_total
                .with_label_values(&[reason])
                .inc();
            if let Some(failed) = pool.iter().find(|u| u.id() == failed_id) {
                failed.record_failover();
            }
        }

        let budget = up
            .timeout(query_cfg.upstream_timeout_ms)
            .min(remaining_total);

        metrics
            .upstream_queries_total
            .with_label_values(&[&name])
            .inc();
        let started_attempt = Instant::now();

        match forwarder.exchange(&up, query, raw, budget).await {
            Ok(ok) => {
                let kind = classify_rcode(ok.view.rcode);
                runtime.record_forward(kind, ok.latency);
                metrics
                    .upstream_rcode_total
                    .with_label_values(&[&name, ok.view.rcode.as_str()])
                    .inc();
                metrics
                    .upstream_latency
                    .with_label_values(&[&name])
                    .observe(ok.latency.as_secs_f64());

                let retryable_servfail =
                    kind == OutcomeKind::ServFail && failover.retry_on_servfail;
                if retryable_servfail {
                    failed_attempt_time += started_attempt.elapsed();
                    metrics
                        .upstream_failures_total
                        .with_label_values(&[&name])
                        .inc();
                    tracing::debug!(
                        event = "upstream_servfail_retry",
                        upstream = %name,
                        attempt = attempts,
                    );
                    last_failure = Some((
                        up.id,
                        name.clone(),
                        "servfail",
                        started_attempt.elapsed().as_millis() as u64,
                    ));
                    tried.push(pick);
                    continue;
                }

                if !kind.is_success() {
                    metrics
                        .upstream_failures_total
                        .with_label_values(&[&name])
                        .inc();
                }

                if attempts > 1 {
                    // Client-visible extra latency caused by earlier failed
                    // attempts (bounded, histogram).
                    metrics
                        .failover_latency
                        .observe(failed_attempt_time.as_secs_f64());
                }
                return Ok(ForwardSuccess {
                    upstream_id: up.id,
                    upstream_name: name,
                    response: ok.response,
                    attempts,
                    latency: call_started.elapsed(),
                    rcode: ok.view.rcode,
                    truncated: ok.view.truncated,
                });
            }
            Err(e) => {
                let kind = match &e {
                    ExchangeError::Timeout => OutcomeKind::Timeout,
                    ExchangeError::Network(_) => OutcomeKind::Network,
                    ExchangeError::Invalid(_) => OutcomeKind::Invalid,
                };
                runtime.record_forward(kind, Duration::ZERO);
                metrics
                    .upstream_failures_total
                    .with_label_values(&[&name])
                    .inc();
                if matches!(e, ExchangeError::Timeout) {
                    metrics
                        .upstream_timeouts_total
                        .with_label_values(&[&name])
                        .inc();
                }
                tracing::debug!(
                    event = "upstream_attempt_failed",
                    upstream = %name,
                    attempt = attempts,
                    error = %e,
                    elapsed_ms = started_attempt.elapsed().as_millis() as u64,
                );
                let reason: &'static str = match &e {
                    ExchangeError::Timeout => "timeout",
                    ExchangeError::Network(_) => "network",
                    ExchangeError::Invalid(_) => "invalid",
                };
                failed_attempt_time += started_attempt.elapsed();
                last_failure = Some((
                    up.id,
                    name.clone(),
                    reason,
                    started_attempt.elapsed().as_millis() as u64,
                ));
                tried.push(pick);
                continue;
            }
        }
    }

    if attempts == 0 {
        // Either no enabled upstreams at all, or every usable upstream was
        // already excluded (all DOWN). Fail fast instead of hanging.
        Err(ForwardError::NoCandidates)
    } else {
        Err(ForwardError::AllFailed { attempts })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::{rdata, RData, Record};

    use crate::config::{SelectionConfig, SelectionStrategy, UpstreamConfig};
    use crate::dns::msg;
    use crate::selection::build_selector;
    use crate::upstream::health::Hysteresis;
    use crate::upstream::HealthStatus;

    /// Behaviour of a minimal fake UDP upstream.
    #[derive(Clone, Copy)]
    enum Mode {
        /// Receive the query but never answer (dead upstream).
        Silent,
        /// Answer with an A record (NOERROR).
        Answer,
        /// Answer with SERVFAIL.
        ServFail,
    }

    struct FakeUpstream {
        addr: SocketAddr,
        hits: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl FakeUpstream {
        async fn start(mode: Mode) -> Self {
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind fake upstream");
            let addr = sock.local_addr().expect("fake upstream addr");
            let hits = Arc::new(AtomicUsize::new(0));
            let h = Arc::clone(&hits);
            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                        break;
                    };
                    let Ok(query) = Message::from_vec(&buf[..n]) else {
                        continue;
                    };
                    h.fetch_add(1, Ordering::SeqCst);
                    match mode {
                        Mode::Silent => {}
                        Mode::Answer => {
                            let resp = response_for(&query, ResponseCode::NoError);
                            let _ = sock.send_to(&resp, peer).await;
                        }
                        Mode::ServFail => {
                            let resp = response_for(&query, ResponseCode::ServFail);
                            let _ = sock.send_to(&resp, peer).await;
                        }
                    }
                }
            });
            Self { addr, hits, task }
        }

        fn config(&self, id: i64, name: &str) -> UpstreamConfig {
            UpstreamConfig {
                id,
                name: name.to_string(),
                address: self.addr.ip(),
                port: self.addr.port(),
                ..Default::default()
            }
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    impl Drop for FakeUpstream {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn response_for(query: &Message, rcode: ResponseCode) -> Vec<u8> {
        let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
        resp.metadata.recursion_desired = query.metadata.recursion_desired;
        resp.metadata.recursion_available = true;
        resp.metadata.response_code = rcode;
        resp.queries = query.queries.clone();
        if rcode == ResponseCode::NoError {
            if let Some(question) = query.queries.first() {
                resp.answers.push(Record::from_rdata(
                    question.name().clone(),
                    60,
                    RData::A(rdata::A::from(std::net::Ipv4Addr::new(192, 0, 2, 53))),
                ));
            }
        }
        resp.to_vec().expect("encode fake response")
    }

    /// Deterministic selector: highest score, ties broken by lowest id, so
    /// tests always try upstream `1` before upstream `2`.
    fn best_selector() -> Box<dyn UpstreamSelector> {
        build_selector(&SelectionConfig {
            strategy: SelectionStrategy::BestScore,
            ..SelectionConfig::default()
        })
    }

    async fn run_forward(
        selector: &(dyn UpstreamSelector + Send + Sync),
        query_cfg: &QueryConfig,
        failover_cfg: &FailoverConfig,
        raw: &[u8],
        pool: &[Arc<UpstreamRuntime>],
    ) -> (
        Result<ForwardSuccess, ForwardError>,
        Arc<Metrics>,
        EventLogs,
    ) {
        let metrics = Metrics::new();
        let events = EventLogs::new();
        let query = msg::parse_query(raw).expect("parse test query");
        let forwarder = Forwarder::new(false);
        let result = forward(
            &forwarder,
            selector,
            &metrics,
            query_cfg,
            failover_cfg,
            &query,
            raw,
            pool,
            &events,
            Instant::now(),
            3,
        )
        .await;
        (result, metrics, events)
    }

    fn expect_err(result: Result<ForwardSuccess, ForwardError>) -> ForwardError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("expected forward to fail"),
        }
    }

    fn expect_ok(result: Result<ForwardSuccess, ForwardError>) -> ForwardSuccess {
        match result {
            Ok(ok) => ok,
            Err(e) => panic!("expected forward to succeed, got {e}"),
        }
    }

    #[tokio::test]
    async fn empty_pool_fails_fast_with_no_candidates() {
        let sel = best_selector();
        let raw = msg::build_query("example.com", "A").unwrap();
        let (result, metrics, events) = run_forward(
            sel.as_ref(),
            &QueryConfig::default(),
            &FailoverConfig::default(),
            &raw,
            &[],
        )
        .await;

        let err = expect_err(result);
        assert!(matches!(err, ForwardError::NoCandidates));
        assert_eq!(err.reason(), "no_upstreams");
        assert_eq!(metrics.failovers_total.get(), 0);
        assert_eq!(events.failover.len(), 0);
    }

    #[tokio::test]
    async fn silent_upstream_is_tried_exactly_once() {
        let up = FakeUpstream::start(Mode::Silent).await;
        let pool = vec![UpstreamRuntime::new(up.config(1, "silent"))];
        let sel = best_selector();
        let raw = msg::build_query("example.com", "A").unwrap();

        let (result, metrics, events) = run_forward(
            sel.as_ref(),
            &QueryConfig::default(),
            &FailoverConfig::default(),
            &raw,
            &pool,
        )
        .await;

        let err = expect_err(result);
        assert!(
            matches!(err, ForwardError::AllFailed { attempts: 1 }),
            "a lone upstream must not be retried, got {err}"
        );
        assert_eq!(err.reason(), "upstream_failure");
        assert_eq!(up.hits(), 1, "dead upstream must be probed exactly once");
        assert_eq!(
            metrics.failovers_total.get(),
            0,
            "a single attempt is not a failover"
        );
        assert_eq!(events.failover.len(), 0);
    }

    #[tokio::test]
    async fn timeout_fails_over_to_the_second_upstream() {
        let a = FakeUpstream::start(Mode::Silent).await;
        let b = FakeUpstream::start(Mode::Answer).await;
        let ra = UpstreamRuntime::new(a.config(1, "one"));
        let rb = UpstreamRuntime::new(b.config(2, "two"));
        let pool = vec![Arc::clone(&ra), Arc::clone(&rb)];
        let sel = best_selector();
        let raw = msg::build_query("example.com", "A").unwrap();
        let query = msg::parse_query(&raw).unwrap();

        let (result, metrics, events) = run_forward(
            sel.as_ref(),
            &QueryConfig::default(),
            &FailoverConfig::default(),
            &raw,
            &pool,
        )
        .await;

        let ok = expect_ok(result);
        assert_eq!(ok.attempts, 2, "one failed attempt plus one retry");
        assert_eq!(ok.upstream_id, 2);
        assert_eq!(ok.upstream_name, "two");
        assert_eq!(ok.rcode, Rcode::NoError);

        // The response is the second upstream's answer, correlated to the
        // client's transaction id.
        let view = msg::parse_response(&ok.response).expect("parse response");
        assert_eq!(view.id, query.id);
        assert_eq!(view.rcode, Rcode::NoError);

        // Failover accounting: metrics, per-upstream counters, event ring.
        assert_eq!(metrics.failovers_total.get(), 1);
        assert_eq!(
            metrics
                .failover_reason_total
                .with_label_values(&["timeout"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .upstream_failovers_total
                .with_label_values(&["one"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .upstream_failures_total
                .with_label_values(&["one"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .upstream_timeouts_total
                .with_label_values(&["one"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .upstream_queries_total
                .with_label_values(&["two"])
                .get(),
            1
        );
        assert_eq!(ra.stats().failovers, 1);
        assert_eq!(rb.stats().failovers, 0);
        assert_eq!(events.failover.len(), 1);
        let recent = events.failover.recent(10);
        let ev = &recent[0];
        assert_eq!(ev.action, "retry");
        assert_eq!(ev.reason.as_deref(), Some("timeout"));
        assert_eq!(ev.upstream.as_deref(), Some("one"));
        assert_eq!(ev.fallback.as_deref(), Some("two"));
        assert_eq!(ev.attempts, Some(2));
    }

    #[tokio::test]
    async fn servfail_is_final_when_retry_is_disabled() {
        let up = FakeUpstream::start(Mode::ServFail).await;
        let pool = vec![UpstreamRuntime::new(up.config(1, "sf"))];
        let sel = best_selector();
        let raw = msg::build_query("example.com", "A").unwrap();

        let (result, metrics, events) = run_forward(
            sel.as_ref(),
            &QueryConfig::default(),
            &FailoverConfig::default(),
            &raw,
            &pool,
        )
        .await;

        let ok = expect_ok(result);
        assert_eq!(ok.rcode, Rcode::ServFail);
        assert_eq!(ok.attempts, 1, "SERVFAIL is a valid response, not a retry");
        assert_eq!(metrics.failovers_total.get(), 0);
        assert_eq!(events.failover.len(), 0);
        assert_eq!(
            metrics
                .upstream_failures_total
                .with_label_values(&["sf"])
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn servfail_retried_when_retry_is_enabled() {
        let a = FakeUpstream::start(Mode::ServFail).await;
        let b = FakeUpstream::start(Mode::Answer).await;
        let ra = UpstreamRuntime::new(a.config(1, "sf"));
        let rb = UpstreamRuntime::new(b.config(2, "good"));
        let pool = vec![Arc::clone(&ra), Arc::clone(&rb)];
        let sel = best_selector();
        let raw = msg::build_query("example.com", "A").unwrap();

        let (result, metrics, events) = run_forward(
            sel.as_ref(),
            &QueryConfig::default(),
            &FailoverConfig {
                retry_on_servfail: true,
            },
            &raw,
            &pool,
        )
        .await;

        let ok = expect_ok(result);
        assert_eq!(ok.rcode, Rcode::NoError);
        assert_eq!(ok.attempts, 2);
        assert_eq!(ok.upstream_id, 2);
        assert_eq!(metrics.failovers_total.get(), 1);
        assert_eq!(
            metrics
                .failover_reason_total
                .with_label_values(&["servfail"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .upstream_failovers_total
                .with_label_values(&["sf"])
                .get(),
            1
        );
        assert_eq!(ra.stats().failovers, 1);
        assert_eq!(events.failover.len(), 1);
    }

    #[tokio::test]
    async fn overall_deadline_stops_further_attempts() {
        let up = FakeUpstream::start(Mode::Silent).await;
        let pool = vec![UpstreamRuntime::new(up.config(1, "slow"))];
        let sel = best_selector();
        let raw = msg::build_query("example.com", "A").unwrap();
        let query_cfg = QueryConfig {
            timeout_ms: 150,
            upstream_timeout_ms: 5_000,
            max_attempts: 3,
            any_policy: crate::config::AnyPolicy::Forward,
        };

        let (result, metrics, _) = run_forward(
            sel.as_ref(),
            &query_cfg,
            &FailoverConfig::default(),
            &raw,
            &pool,
        )
        .await;

        let err = expect_err(result);
        assert!(
            matches!(err, ForwardError::DeadlineExceeded { .. }),
            "expected deadline, got {err}"
        );
        assert_eq!(err.reason(), "deadline");
        assert!(
            up.hits() <= 2,
            "deadline must stop retries, upstream saw {} queries",
            up.hits()
        );
        assert_eq!(metrics.failovers_total.get(), 0);
    }

    #[tokio::test]
    async fn all_unhealthy_upstreams_yield_no_candidates() {
        // The fake never has to answer: an unhealthy upstream is excluded
        // before any exchange is attempted.
        let up = FakeUpstream::start(Mode::Answer).await;
        let rt = UpstreamRuntime::new(up.config(1, "down"));
        let hyst = Hysteresis {
            failure_threshold: 1,
            recovery_threshold: 1,
        };
        // Two failed rounds: HEALTHY -> DEGRADED -> UNHEALTHY.
        rt.record_health_round(
            false,
            None,
            Some("probe failed".into()),
            &hyst,
            Duration::ZERO,
        );
        rt.record_health_round(
            false,
            None,
            Some("probe failed".into()),
            &hyst,
            Duration::ZERO,
        );
        assert_eq!(rt.health_status(), HealthStatus::Unhealthy);

        let pool = vec![rt];
        let sel = best_selector();
        let raw = msg::build_query("example.com", "A").unwrap();
        let (result, _, events) = run_forward(
            sel.as_ref(),
            &QueryConfig::default(),
            &FailoverConfig::default(),
            &raw,
            &pool,
        )
        .await;

        let err = expect_err(result);
        assert!(matches!(err, ForwardError::NoCandidates));
        assert_eq!(err.reason(), "no_upstreams");
        assert_eq!(up.hits(), 0, "unhealthy upstreams must not be probed");
        assert_eq!(events.failover.len(), 0);
    }
}
