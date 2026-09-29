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
) -> Result<ForwardSuccess, ForwardError> {
    let started = Instant::now();
    let deadline = started + query_cfg.timeout();

    let mut tried: Vec<i64> = Vec::with_capacity(query_cfg.max_attempts as usize);
    let mut attempts: u32 = 0;
    let mut failover_counted = false;
    // Why the previous attempt gave up: (upstream name, reason, elapsed ms).
    let mut last_failure: Option<(String, &'static str, u64)> = None;

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
            .map(|u| StateView::from_runtime(u))
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
        if let Some((failed_up, reason, extra_ms)) = last_failure.take() {
            // Bounded ring; only written when a retry actually happens.
            events.failover.push(crate::events::Event::failover(
                &failed_up, reason, attempts, &name, extra_ms,
            ));
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

                return Ok(ForwardSuccess {
                    upstream_id: up.id,
                    upstream_name: name,
                    response: ok.response,
                    attempts,
                    latency: started.elapsed(),
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
                last_failure = Some((
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
