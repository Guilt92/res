//! Per-query pipeline.
//!
//! ```text
//! receive → parse/validate → ACL → rate limit → cache → select →
//! forward (bounded failover) → correlate → respond
//! ```
//!
//! No database, no HTTP, no unbounded work: the hot path only touches
//! in-memory, already-validated configuration.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::Message;

use crate::acl::AclDecision;
use crate::cache::CacheKey;
use crate::config::{CacheConfig, FailoverConfig, QueryConfig};
use crate::dns::forward::{enforce_client_udp_limit, Forwarder};
use crate::dns::msg::{self, ParsedQuery, QueryReject, Rcode};
use crate::dns::Transport;
use crate::failover::{self, ForwardError};
use crate::shared::Shared;

pub struct Pipeline {
    pub shared: Arc<Shared>,
    pub forwarder: Forwarder,
    /// Sequence used to sample SERVFAIL warnings (never log every one).
    servfail_seq: AtomicU64,
}

/// Configuration snapshot taken during the synchronous phase of a request so
/// that no lock/guard is held across `.await`.
struct Prepared {
    parsed: ParsedQuery,
    query: QueryConfig,
    failover: FailoverConfig,
    cache_key: Option<CacheKey>,
    cache_cfg: CacheConfig,
}

enum Precheck {
    /// Answer immediately (REFUSED, cache hit, NOTIMP, ...).
    Reply(Vec<u8>),
    /// Drop silently (malformed, rate limited).
    Drop,
    Proceed(Prepared),
}

impl Pipeline {
    pub fn new(shared: Arc<Shared>, forwarder: Forwarder) -> Arc<Self> {
        Arc::new(Self {
            shared,
            forwarder,
            servfail_seq: AtomicU64::new(0),
        })
    }

    /// Handle one client query; `None` means "send nothing back".
    pub async fn handle(
        &self,
        client: SocketAddr,
        transport: Transport,
        raw: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let started = Instant::now();
        let metrics = &self.shared.metrics;
        metrics
            .queries_total
            .with_label_values(&[transport.as_str()])
            .inc();

        let prepared = match self.precheck(client, transport, &raw, started) {
            Precheck::Reply(resp) => return Some(resp),
            Precheck::Drop => return None,
            Precheck::Proceed(p) => p,
        };

        // Everything below is async; no configuration guard is held.
        let selector = self.shared.current_selector();
        let pool = self.shared.registry.enabled_snapshot();

        let result = failover::forward(
            &self.forwarder,
            selector.as_ref(),
            metrics,
            &prepared.query,
            &prepared.failover,
            &prepared.parsed,
            &raw,
            &pool,
            &self.shared.events,
        )
        .await;

        let elapsed = started.elapsed();
        metrics.query_duration.observe(elapsed.as_secs_f64());
        self.shared
            .global_latency
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(elapsed);

        match result {
            Ok(success) => {
                metrics
                    .client_rcode_total
                    .with_label_values(&[success.rcode.as_str()])
                    .inc();

                if success.rcode == Rcode::ServFail {
                    self.maybe_log_servfail(&success.upstream_name, success.attempts, elapsed);
                }

                let response = enforce_client_udp_limit(
                    success.response,
                    transport == Transport::Udp,
                    prepared.parsed.has_edns,
                );

                if let Some(key) = &prepared.cache_key {
                    if success.rcode == Rcode::NoError && !success.truncated {
                        if let Some(ttl) = msg::cacheable_ttl(
                            &response,
                            prepared.cache_cfg.min_ttl_secs,
                            prepared.cache_cfg.max_ttl_secs,
                        ) {
                            self.shared.cache.put(
                                key.clone(),
                                response.clone(),
                                Duration::from_secs(ttl),
                                &prepared.cache_cfg,
                            );
                            metrics.cache_entries.set(self.shared.cache.len() as i64);
                        }
                    }
                }
                Some(response)
            }
            Err(e) => {
                metrics
                    .query_errors_total
                    .with_label_values(&[e.reason()])
                    .inc();
                metrics
                    .client_rcode_total
                    .with_label_values(&["SERVFAIL"])
                    .inc();
                tracing::warn!(
                    event = "dns_query_failed",
                    transport = transport.as_str(),
                    reason = e.reason(),
                    error = %e,
                    attempts = attempts_of(&e),
                    elapsed_ms = elapsed.as_millis() as u64,
                );
                Some(msg::error_response(&prepared.parsed, Rcode::ServFail))
            }
        }
    }

    /// Synchronous admission phase (parse, ACL, rate limit, cache).
    fn precheck(
        &self,
        client: SocketAddr,
        transport: Transport,
        raw: &[u8],
        started: Instant,
    ) -> Precheck {
        let shared = &self.shared;
        let metrics = &shared.metrics;
        let rt = shared.rt.load();

        let parsed = match msg::parse_query(raw) {
            Ok(q) => q,
            Err(QueryReject::UnsupportedOpcode) => {
                let resp = match Message::from_vec(raw) {
                    Ok(m) => {
                        let mut out = Message::error_msg(
                            m.metadata.id,
                            m.metadata.op_code,
                            hickory_proto::op::ResponseCode::NotImp,
                        );
                        out.metadata.recursion_desired = m.metadata.recursion_desired;
                        out.metadata.recursion_available = true;
                        out.queries = m.queries;
                        out.to_vec().ok()
                    }
                    Err(_) => None,
                };
                match resp {
                    Some(resp) => {
                        metrics
                            .query_errors_total
                            .with_label_values(&["notimp"])
                            .inc();
                        metrics
                            .client_rcode_total
                            .with_label_values(&["NOTIMP"])
                            .inc();
                        metrics
                            .query_duration
                            .observe(started.elapsed().as_secs_f64());
                        return Precheck::Reply(resp);
                    }
                    None => {
                        metrics.malformed_total.inc();
                        return Precheck::Drop;
                    }
                }
            }
            Err(_) => {
                metrics.malformed_total.inc();
                tracing::debug!(
                    event = "malformed_packet",
                    transport = transport.as_str(),
                    len = raw.len(),
                );
                return Precheck::Drop;
            }
        };

        // ---- ACL (before any forwarding work) ----
        if rt.acl.decide(client.ip()) == AclDecision::Deny {
            metrics.acl_denied_total.inc();
            tracing::debug!(
                event = "acl_denied",
                transport = transport.as_str(),
                client = %client,
            );
            metrics
                .query_duration
                .observe(started.elapsed().as_secs_f64());
            return Precheck::Reply(msg::error_response(&parsed, Rcode::Refused));
        }

        // ---- Rate limiting ----
        if !shared.ratelimit.check(client.ip(), &rt.ratelimit) {
            metrics.rate_limit_dropped_total.inc();
            tracing::debug!(
                event = "rate_limit_triggered",
                transport = transport.as_str()
            );
            return Precheck::Drop;
        }

        // ---- Cache (optional, off by default) ----
        let cache_key = msg::question_key(parsed.question());
        let use_cache = rt.cache.enabled && !parsed.dnssec_ok;
        if use_cache {
            if let Some(resp) = shared.cache.get(&cache_key, parsed.id, &rt.cache) {
                metrics.cache_hits_total.inc();
                metrics
                    .client_rcode_total
                    .with_label_values(&["NOERROR"])
                    .inc();
                let elapsed = started.elapsed();
                metrics.query_duration.observe(elapsed.as_secs_f64());
                shared
                    .global_latency
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(elapsed);
                return Precheck::Reply(resp);
            }
            metrics.cache_misses_total.inc();
        }

        Precheck::Proceed(Prepared {
            parsed,
            query: rt.query.clone(),
            failover: rt.failover.clone(),
            cache_key: use_cache.then_some(cache_key),
            cache_cfg: rt.cache.clone(),
        })
    }

    fn maybe_log_servfail(&self, upstream: &str, attempts: u32, elapsed: Duration) {
        let every = self.shared.app.load().logging.servfail_sample_every;
        if every == 0 {
            return;
        }
        let n = self.servfail_seq.fetch_add(1, Ordering::Relaxed);
        if n.is_multiple_of(u64::from(every)) {
            tracing::warn!(
                event = "servfail_response",
                upstream = %upstream,
                attempt = attempts,
                latency = elapsed.as_millis() as u64,
            );
        }
    }
}

fn attempts_of(e: &ForwardError) -> u32 {
    match e {
        ForwardError::NoCandidates => 0,
        ForwardError::AllFailed { attempts } | ForwardError::DeadlineExceeded { attempts } => {
            *attempts
        }
    }
}
