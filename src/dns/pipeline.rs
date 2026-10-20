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
use hickory_proto::rr::RecordType;
use serde_json::json;

use crate::acl::AclDecision;
use crate::cache::{CacheKey, FlightOutcome, FlightRole, FlightWait};
use crate::config::{CacheConfig, FailoverConfig, QueryConfig};
use crate::dns::forward::{enforce_client_udp_limit, Forwarder};
use crate::dns::msg::{self, ParsedQuery, QueryReject, Rcode};
use crate::dns::Transport;
use crate::failover::{self, ForwardError};
use crate::shared::Shared;

pub struct Pipeline {
    pub shared: Arc<Shared>,
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
    min_probe_samples: u32,
    /// `server.upstream_tcp_fallback` as of *this* query (hot-reloaded; a
    /// Forwarder baked at process start would never see a config swap).
    tcp_fallback: bool,
    /// `server.max_udp_packet_size` as of this query: egress ceiling.
    udp_cap: u16,
}

enum Precheck {
    /// Answer immediately (REFUSED, cache hit, NOTIMP, ...).
    Reply(Vec<u8>),
    /// Drop silently (malformed, rate limited).
    Drop,
    Proceed(Prepared),
}

impl Pipeline {
    pub fn new(shared: Arc<Shared>) -> Arc<Self> {
        Arc::new(Self {
            shared,
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
        // Traffic introspection: every received request is attributed to its
        // client (masked on output unless the operator opted out of privacy).
        self.shared
            .traffic
            .record_request(client.ip(), transport == Transport::Tcp, raw.len());

        let prepared = match self.precheck(client, transport, &raw, started) {
            Precheck::Reply(resp) => return Some(resp),
            Precheck::Drop => return None,
            Precheck::Proceed(p) => p,
        };

        // Everything below is async; no configuration guard is held.
        let selector = self.shared.current_selector();
        let pool = self.shared.registry.enabled_snapshot();
        // tcp_fallback is re-read from the config snapshot taken for *this*
        // query so a config swap applies without a process restart.
        let forwarder = Forwarder::new(prepared.tcp_fallback);

        // ---- Single-flight (cache-miss coalescing) ----
        // When the cache is enabled and this question missed, concurrent
        // identical misses coalesce onto one upstream query. The first
        // arrival is the leader and performs the forward; later arrivals
        // wait for the leader's outcome instead of duplicating the query.
        // DO-bit and EDNS-option queries (and disabled caches) skip this
        // entirely: their responses may be client-specific and must not be
        // shared through the cache or single-flight.
        if let Some(key) = &prepared.cache_key {
            match self.shared.singleflight.join(key) {
                FlightRole::Leader(leader) => {
                    let result = failover::forward(
                        &forwarder,
                        selector.as_ref(),
                        metrics,
                        &prepared.query,
                        &prepared.failover,
                        &prepared.parsed,
                        &raw,
                        &pool,
                        &self.shared.events,
                        started,
                        prepared.min_probe_samples,
                    )
                    .await;
                    // Snapshot the flight payload while `result` is still
                    // borrowed, but complete the flight *after* the cache
                    // put inside finish_forward: a follower must never wake
                    // onto an entry that is not yet coherent.
                    let outcome = match &result {
                        Ok(success) => FlightOutcome::Success {
                            response: Arc::new(success.response.clone()),
                            rcode: success.rcode,
                        },
                        Err(e) => FlightOutcome::Failed { reason: e.reason() },
                    };
                    let reply = self
                        .finish_forward(client, transport, &prepared, result, &raw, started)
                        .await;
                    leader.complete(outcome);
                    return reply;
                }
                FlightRole::Follower(rx) => {
                    // Wait only for what remains of the *client's* overall
                    // query budget (started at admission): waiting a full
                    // timeout from here — plus our own forward afterwards —
                    // could hold the client for twice the configured budget.
                    let budget = prepared.query.timeout().saturating_sub(started.elapsed());
                    match crate::cache::wait_for_flight(rx, budget).await {
                        FlightWait::Outcome(FlightOutcome::Success { response, rcode }) => {
                            metrics.cache_coalesced_total.inc();
                            let mut bytes = (*response).clone();
                            if msg::align_response_to_query(&mut bytes, &prepared.parsed, &raw) {
                                let elapsed = started.elapsed();
                                metrics.query_duration.observe(elapsed.as_secs_f64());
                                self.shared
                                    .global_latency
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .push(elapsed);
                                metrics
                                    .client_rcode_total
                                    .with_label_values(&[rcode.as_str()])
                                    .inc();
                                let outcome = if rcode == Rcode::ServFail {
                                    crate::traffic::Outcome::Failed
                                } else {
                                    crate::traffic::Outcome::Ok
                                };
                                self.shared.traffic.record_outcome(
                                    client.ip(),
                                    outcome,
                                    Some(elapsed),
                                );
                                return Some(enforce_client_udp_limit(
                                    bytes,
                                    transport == Transport::Udp,
                                    prepared.parsed.has_edns,
                                    prepared.parsed.edns_payload,
                                    prepared.udp_cap,
                                    &prepared.parsed,
                                ));
                            }
                            // Leader's bytes cannot be aligned to this query
                            // (malformed): fall through to a direct forward
                            // instead of sending an unaligned packet.
                        }
                        FlightWait::Outcome(FlightOutcome::Failed { reason }) => {
                            metrics.cache_coalesced_total.inc();
                            let elapsed = started.elapsed();
                            metrics.query_duration.observe(elapsed.as_secs_f64());
                            self.shared
                                .global_latency
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push(elapsed);
                            self.note_forward_failure(client, transport, reason, 0, elapsed);
                            return Some(msg::error_response(&prepared.parsed, Rcode::ServFail));
                        }
                        // Timeout, cancelled, or the leader vanished: fall
                        // through to a direct forward so the client still gets
                        // an answer (worst case one extra upstream query in a
                        // rare race).
                        FlightWait::Timeout | FlightWait::Cancelled => {}
                    }
                }
            }
        }

        let result = failover::forward(
            &forwarder,
            selector.as_ref(),
            metrics,
            &prepared.query,
            &prepared.failover,
            &prepared.parsed,
            &raw,
            &pool,
            &self.shared.events,
            started,
            prepared.min_probe_samples,
        )
        .await;

        self.finish_forward(client, transport, &prepared, result, &raw, started)
            .await
    }

    /// Shared tail of the forward path: observe latency, cache the response
    /// (when cacheable), align it to the client's query, apply per-client
    /// UDP limits, and record metrics.
    async fn finish_forward(
        &self,
        client: SocketAddr,
        transport: Transport,
        prepared: &Prepared,
        result: Result<failover::ForwardSuccess, ForwardError>,
        query_raw: &[u8],
        started: Instant,
    ) -> Option<Vec<u8>> {
        let metrics = &self.shared.metrics;
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
                    self.shared.traffic.record_outcome(
                        client.ip(),
                        crate::traffic::Outcome::Failed,
                        Some(elapsed),
                    );
                } else {
                    self.shared.traffic.record_outcome(
                        client.ip(),
                        crate::traffic::Outcome::Ok,
                        Some(elapsed),
                    );
                }

                // Cache the *raw* upstream bytes before any per-client
                // adaptation: what one client is allowed to receive (UDP
                // size limits, EDNS presence) must not define what every
                // later client reads out of the shared cache.
                if let Some(key) = &prepared.cache_key {
                    // Positive caching (NOERROR with answers) and RFC 2308
                    // negative caching (NXDOMAIN / NODATA with an SOA).
                    let entry = if success.rcode == Rcode::NoError && !success.truncated {
                        msg::cacheable_ttl(
                            &success.response,
                            prepared.cache_cfg.min_ttl_secs,
                            prepared.cache_cfg.max_ttl_secs,
                        )
                        .map(|t| (t, Rcode::NoError))
                        .or_else(|| {
                            msg::negative_ttl(
                                &success.response,
                                prepared.cache_cfg.negative_max_ttl_secs,
                            )
                            .map(|t| (t, success.rcode))
                        })
                    } else if success.rcode == Rcode::NXDomain && !success.truncated {
                        msg::negative_ttl(
                            &success.response,
                            prepared.cache_cfg.negative_max_ttl_secs,
                        )
                        .map(|t| (t, Rcode::NXDomain))
                    } else {
                        None
                    };
                    if let Some((ttl, rcode)) = entry {
                        let evicted = self.shared.cache.put(
                            key.clone(),
                            success.response.clone(),
                            Duration::from_secs(ttl),
                            rcode,
                            &prepared.cache_cfg,
                        );
                        if evicted > 0 {
                            metrics.cache_evictions_total.inc_by(u64::from(evicted));
                        }
                        metrics.cache_entries.set(self.shared.cache.len() as i64);
                        metrics
                            .cache_memory_bytes
                            .set(self.shared.cache.memory_bytes() as i64);
                    }
                }

                // Serve-path adaptation: align the bytes to *this* client's
                // query (id/RD/CD/question-case/OPT), then apply UDP size
                // limits. An unalignable packet is answered with SERVFAIL
                // rather than forwarded mis-wired (traffic already recorded
                // above — this stays one query).
                let mut response = success.response;
                if !msg::align_response_to_query(&mut response, &prepared.parsed, query_raw) {
                    tracing::debug!(event = "response_align_failed");
                    return Some(msg::error_response(&prepared.parsed, Rcode::ServFail));
                }
                let response = enforce_client_udp_limit(
                    response,
                    transport == Transport::Udp,
                    prepared.parsed.has_edns,
                    prepared.parsed.edns_payload,
                    prepared.udp_cap,
                    &prepared.parsed,
                );
                Some(response)
            }
            Err(e) => {
                self.note_forward_failure(client, transport, e.reason(), attempts_of(&e), elapsed);
                Some(msg::error_response(&prepared.parsed, Rcode::ServFail))
            }
        }
    }

    /// Record metrics/events for a failed forward (shared by the leader's
    /// error path and coalesced followers that received `FlightOutcome::Failed`).
    fn note_forward_failure(
        &self,
        client: SocketAddr,
        transport: Transport,
        reason: &'static str,
        attempts: u32,
        elapsed: Duration,
    ) {
        let metrics = &self.shared.metrics;
        metrics
            .query_errors_total
            .with_label_values(&[reason])
            .inc();
        metrics
            .client_rcode_total
            .with_label_values(&["SERVFAIL"])
            .inc();
        let client_outcome = if reason == "deadline" {
            crate::traffic::Outcome::Timeout
        } else {
            crate::traffic::Outcome::Failed
        };
        self.shared
            .traffic
            .record_outcome(client.ip(), client_outcome, Some(elapsed));
        if reason == "deadline" {
            self.shared.note_system_event(
                "query_deadline",
                json!({ "transport": transport.as_str(), "attempts": attempts }),
            );
        }
        tracing::warn!(
            event = "dns_query_failed",
            transport = transport.as_str(),
            reason,
            attempts,
            elapsed_ms = elapsed.as_millis() as u64,
        );
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
                        // Echo the client's OPT (RFC 6891: NOTIMP replies to
                        // EDNS queries must carry an OPT as well).
                        out.edns = m.edns;
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
                        let elapsed = started.elapsed();
                        metrics.query_duration.observe(elapsed.as_secs_f64());
                        shared.traffic.record_outcome(
                            client.ip(),
                            crate::traffic::Outcome::Failed,
                            Some(elapsed),
                        );
                        return Precheck::Reply(resp);
                    }
                    None => {
                        metrics.malformed_total.inc();
                        shared.traffic.record_outcome(
                            client.ip(),
                            crate::traffic::Outcome::Failed,
                            None,
                        );
                        return Precheck::Drop;
                    }
                }
            }
            Err(_) => {
                metrics.malformed_total.inc();
                shared
                    .traffic
                    .record_outcome(client.ip(), crate::traffic::Outcome::Failed, None);
                tracing::debug!(
                    event = "malformed_packet",
                    transport = transport.as_str(),
                    len = raw.len(),
                );
                return Precheck::Drop;
            }
        };

        // ---- Question-type + domain accounting (before any rejection so
        // traffic reflects what clients actually asked for) ----
        let cache_key = msg::question_key(
            parsed.question(),
            parsed.checking_disabled,
            parsed.recursion_desired,
        );
        metrics
            .query_type_total
            .with_label_values(&[msg::qtype_label(parsed.qtype())])
            .inc();
        shared.traffic.record_domain(&cache_key.name);

        // ---- ACL (before any forwarding work) ----
        if rt.acl.decide(client.ip()) == AclDecision::Deny {
            metrics.acl_denied_total.inc();
            shared.note_system_event(
                "acl_denied",
                json!({
                    "client_ip": shared.client_label(client.ip()),
                    "transport": transport.as_str(),
                }),
            );
            tracing::debug!(
                event = "acl_denied",
                transport = transport.as_str(),
                client = %shared.client_label(client.ip()),
            );
            let elapsed = started.elapsed();
            metrics.query_duration.observe(elapsed.as_secs_f64());
            shared.traffic.record_outcome(
                client.ip(),
                crate::traffic::Outcome::AclDenied,
                Some(elapsed),
            );
            return Precheck::Reply(msg::error_response(&parsed, Rcode::Refused));
        }

        // ---- Rate limiting ----
        if !shared.ratelimit.check(client.ip(), &rt.ratelimit) {
            metrics.rate_limit_dropped_total.inc();
            shared.note_system_event(
                "rate_limited",
                json!({
                    "client_ip": shared.client_label(client.ip()),
                    "transport": transport.as_str(),
                }),
            );
            tracing::debug!(
                event = "rate_limit_triggered",
                transport = transport.as_str(),
                client = %shared.client_label(client.ip()),
            );
            shared
                .traffic
                .record_outcome(client.ip(), crate::traffic::Outcome::RateLimited, None);
            return Precheck::Drop;
        }

        // ---- ANY policy (RFC 8482): refuse locally with NOTIMP ----
        // After ACL and rate limiting so a denied or throttled client
        // cannot use cheap local ANY replies to bypass those gates (and
        // does not get served *after* consuming an admission token it was
        // never entitled to).
        if parsed.qtype() == RecordType::ANY
            && rt.query.any_policy == crate::config::AnyPolicy::Refuse
        {
            metrics
                .query_errors_total
                .with_label_values(&["any_refused"])
                .inc();
            metrics
                .client_rcode_total
                .with_label_values(&["NOTIMP"])
                .inc();
            let elapsed = started.elapsed();
            metrics.query_duration.observe(elapsed.as_secs_f64());
            shared.traffic.record_outcome(
                client.ip(),
                crate::traffic::Outcome::Failed,
                Some(elapsed),
            );
            return Precheck::Reply(msg::error_response(&parsed, Rcode::NotImp));
        }

        // ---- Cache (enabled by default; client-specific queries always miss) ----
        // DO-bit queries need DNSSEC records, and any EDNS option (ECS,
        // COOKIE, ...) can make the upstream response client-specific. Both
        // bypass the shared cache and single-flight to prevent cross-client
        // data leakage or cache poisoning.
        let use_cache = rt.cache.enabled && !parsed.dnssec_ok && !parsed.has_edns_options;
        if use_cache {
            match shared.cache.get(&cache_key, parsed.id, &rt.cache) {
                crate::cache::CacheLookup::Hit { mut bytes, rcode } => {
                    // Align to *this* query before counting the hit: the
                    // stored bytes carry the casing/EDNS of whichever client
                    // populated the entry and must never be served verbatim.
                    if !msg::align_response_to_query(&mut bytes, &parsed, raw) {
                        tracing::debug!(event = "cache_entry_unaligned");
                        metrics.cache_misses_total.inc();
                    } else {
                        metrics.cache_hits_total.inc();
                        metrics
                            .client_rcode_total
                            .with_label_values(&[rcode.as_str()])
                            .inc();
                        let elapsed = started.elapsed();
                        metrics.query_duration.observe(elapsed.as_secs_f64());
                        shared
                            .global_latency
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(elapsed);
                        shared.traffic.record_outcome(
                            client.ip(),
                            crate::traffic::Outcome::Ok,
                            Some(elapsed),
                        );
                        // Same transport limits as the forward path.
                        let resp = enforce_client_udp_limit(
                            bytes,
                            transport == Transport::Udp,
                            parsed.has_edns,
                            parsed.edns_payload,
                            rt.max_udp_packet_size as u16,
                            &parsed,
                        );
                        return Precheck::Reply(resp);
                    }
                }
                crate::cache::CacheLookup::Miss => {
                    metrics.cache_misses_total.inc();
                }
                crate::cache::CacheLookup::Expired => {
                    metrics.cache_misses_total.inc();
                    metrics.cache_expirations_total.inc();
                }
            }
        }

        Precheck::Proceed(Prepared {
            parsed,
            query: rt.query.clone(),
            failover: rt.failover.clone(),
            cache_key: use_cache.then_some(cache_key),
            cache_cfg: rt.cache.clone(),
            min_probe_samples: rt.selection.min_probe_samples,
            tcp_fallback: rt.upstream_tcp_fallback,
            udp_cap: rt.max_udp_packet_size as u16,
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

#[cfg(test)]
mod tests {
    use super::*;

    use hickory_proto::op::{MessageType, OpCode, Query as HQuery};
    use hickory_proto::rr::{rdata, Name, RData, Record};

    use crate::config::{AnyPolicy, AppConfig};
    use crate::ratelimit::RateLimitConfig;

    fn client() -> SocketAddr {
        "127.0.0.1:54321".parse().expect("client addr")
    }

    fn pipeline_with(app: AppConfig) -> Arc<Pipeline> {
        let shared = crate::shared::Shared::new(app).expect("shared state");
        Pipeline::new(shared)
    }

    fn query_bytes(name: &str, qtype: &str) -> Vec<u8> {
        msg::build_query(name, qtype).expect("build query")
    }

    fn reply_rcode(pipeline: &Pipeline, raw: &[u8]) -> Rcode {
        match pipeline.precheck(client(), Transport::Udp, raw, Instant::now()) {
            Precheck::Reply(bytes) => {
                msg::parse_response(&bytes)
                    .expect("parse local reply")
                    .rcode
            }
            Precheck::Drop => panic!("expected a reply, got drop"),
            Precheck::Proceed(_) => panic!("expected a reply, got proceed"),
        }
    }

    #[test]
    fn malformed_packet_is_dropped() {
        let p = pipeline_with(AppConfig::default());
        let raw = vec![0u8; 4];
        let out = p.precheck(client(), Transport::Udp, &raw, Instant::now());
        assert!(matches!(out, Precheck::Drop));
        assert_eq!(p.shared.metrics.malformed_total.get(), 1);
    }

    #[test]
    fn acl_deny_replies_refused_before_any_forwarding() {
        let mut app = AppConfig::default();
        app.acl.allowed_cidrs = vec!["10.0.0.0/8".to_string()];
        let p = pipeline_with(app);
        let raw = query_bytes("example.com", "A");

        let out = p.precheck(client(), Transport::Udp, &raw, Instant::now());
        match out {
            Precheck::Reply(bytes) => {
                let view = msg::parse_response(&bytes).expect("parse REFUSED");
                assert_eq!(view.rcode, Rcode::Refused);
            }
            _ => panic!("expected REFUSED reply"),
        }
        assert_eq!(p.shared.metrics.acl_denied_total.get(), 1);
    }

    #[test]
    fn second_query_from_same_client_is_rate_limited() {
        let app = AppConfig {
            ratelimit: RateLimitConfig {
                enabled: true,
                per_ip_qps: 1.0,
                per_ip_burst: 1,
                max_tracked_clients: 1_000,
                global_qps: 10_000.0,
                global_burst: 10_000,
            },
            ..AppConfig::default()
        };
        let p = pipeline_with(app);
        let raw = query_bytes("example.com", "A");

        let first = p.precheck(client(), Transport::Udp, &raw, Instant::now());
        assert!(
            matches!(first, Precheck::Proceed(_)),
            "first query must pass the limiter"
        );
        let second = p.precheck(client(), Transport::Udp, &raw, Instant::now());
        assert!(matches!(second, Precheck::Drop));
        assert_eq!(p.shared.metrics.rate_limit_dropped_total.get(), 1);
    }

    #[test]
    fn any_policy_refuse_answers_notimp_locally() {
        let mut app = AppConfig::default();
        app.query.any_policy = AnyPolicy::Refuse;
        let p = pipeline_with(app);
        let raw = query_bytes("example.com", "ANY");

        assert_eq!(reply_rcode(&p, &raw), Rcode::NotImp);
        assert_eq!(
            p.shared
                .metrics
                .query_errors_total
                .with_label_values(&["any_refused"])
                .get(),
            1
        );
        assert_eq!(
            p.shared
                .metrics
                .client_rcode_total
                .with_label_values(&["NOTIMP"])
                .get(),
            1
        );
    }

    #[test]
    fn unsupported_opcode_answers_notimp() {
        let p = pipeline_with(AppConfig::default());
        let mut m = Message::new(7, MessageType::Query, OpCode::Update);
        m.queries.push(HQuery::query(
            Name::from_ascii("example.com").unwrap(),
            RecordType::A,
        ));
        let raw = m.to_vec().expect("encode UPDATE query");

        let out = p.precheck(client(), Transport::Udp, &raw, Instant::now());
        match out {
            Precheck::Reply(bytes) => {
                let view = msg::parse_response(&bytes).expect("parse NOTIMP");
                assert_eq!(view.rcode, Rcode::NotImp);
                assert_eq!(view.id, 7);
            }
            _ => panic!("expected NOTIMP reply"),
        }
        assert_eq!(
            p.shared
                .metrics
                .query_errors_total
                .with_label_values(&["notimp"])
                .get(),
            1
        );
        assert_eq!(
            p.shared
                .metrics
                .client_rcode_total
                .with_label_values(&["NOTIMP"])
                .get(),
            1
        );
    }

    #[test]
    fn cache_hit_short_circuits_the_forward_path() {
        let p = pipeline_with(AppConfig::default());
        let raw = query_bytes("example.com", "A");
        let parsed = msg::parse_query(&raw).expect("parse query");
        let key = msg::question_key(
            parsed.question(),
            parsed.checking_disabled,
            parsed.recursion_desired,
        );

        // Store a response under a *different* transaction id: the cache must
        // rewrite it to the client's id on the way out.
        let mut stored = Message::response(999, OpCode::Query);
        stored.metadata.recursion_available = true;
        stored.queries = parsed.queries.clone();
        stored.answers.push(Record::from_rdata(
            parsed.question().name().clone(),
            300,
            RData::A(rdata::A::from(std::net::Ipv4Addr::new(192, 0, 2, 53))),
        ));
        let bytes = stored.to_vec().expect("encode cached response");
        let cache_cfg = p.shared.rt.load().cache.clone();
        let evicted = p.shared.cache.put(
            key,
            bytes,
            Duration::from_secs(300),
            Rcode::NoError,
            &cache_cfg,
        );
        assert_eq!(evicted, 0);

        match p.precheck(client(), Transport::Udp, &raw, Instant::now()) {
            Precheck::Reply(out) => {
                let view = msg::parse_response(&out).expect("parse cached reply");
                assert_eq!(view.rcode, Rcode::NoError);
                assert_eq!(view.id, parsed.id, "cached response id must be rewritten");
            }
            _ => panic!("expected cache-hit reply"),
        }
        assert_eq!(p.shared.metrics.cache_hits_total.get(), 1);
    }

    #[test]
    fn edns_option_queries_bypass_the_shared_cache() {
        use hickory_proto::op::Edns;
        use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};

        let mut app = AppConfig::default();
        app.cache.enabled = true;
        app.ratelimit.enabled = false;
        let p = pipeline_with(app);

        let raw = query_bytes("example.com", "A");
        let parsed = msg::parse_query(&raw).expect("parse query");
        let key = msg::question_key(
            parsed.question(),
            parsed.checking_disabled,
            parsed.recursion_desired,
        );
        let mut stored = Message::response(999, OpCode::Query);
        stored.queries = parsed.queries.clone();
        stored.answers.push(Record::from_rdata(
            parsed.question().name().clone(),
            300,
            RData::A(rdata::A::from(std::net::Ipv4Addr::new(192, 0, 2, 53))),
        ));
        let cache_cfg = p.shared.rt.load().cache.clone();
        p.shared.cache.put(
            key,
            stored.to_vec().expect("encode cached response"),
            Duration::from_secs(300),
            Rcode::NoError,
            &cache_cfg,
        );

        // The plain query is served from the shared cache...
        assert!(matches!(
            p.precheck(client(), Transport::Udp, &raw, Instant::now()),
            Precheck::Reply(_)
        ));
        assert_eq!(p.shared.metrics.cache_hits_total.get(), 1);

        // ...but an otherwise identical ECS query must never read that entry:
        // the upstream answer may be specific to another client's subnet.
        let mut m = Message::query();
        m.metadata.id = parsed.id;
        m.queries = parsed.queries.clone();
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "198.51.100.0".parse().unwrap(),
                24,
                0,
            )));
        m.set_edns(edns);
        let ecs_raw = m.to_vec().expect("encode ECS query");
        let ecs = msg::parse_query(&ecs_raw).expect("parse ECS query");
        assert!(ecs.has_edns_options);

        match p.precheck(client(), Transport::Udp, &ecs_raw, Instant::now()) {
            Precheck::Proceed(prepared) => assert!(
                prepared.cache_key.is_none(),
                "option-bearing queries must not join cache/single-flight"
            ),
            Precheck::Reply(_) => panic!("ECS query must not be served from the shared cache"),
            Precheck::Drop => panic!("ECS query must be forwarded"),
        }
        assert_eq!(
            p.shared.metrics.cache_hits_total.get(),
            1,
            "the ECS query must not consume the plain entry"
        );
    }

    #[tokio::test]
    async fn query_without_upstreams_returns_servfail() {
        let p = pipeline_with(AppConfig::default());
        let raw = query_bytes("example.com", "A");
        let id = msg::parse_query(&raw).expect("parse query").id;

        let out = p
            .handle(client(), Transport::Udp, raw)
            .await
            .expect("SERVFAIL reply");
        let view = msg::parse_response(&out).expect("parse SERVFAIL");
        assert_eq!(view.rcode, Rcode::ServFail);
        assert_eq!(view.id, id);

        let m = &p.shared.metrics;
        assert_eq!(
            m.query_errors_total
                .with_label_values(&["no_upstreams"])
                .get(),
            1
        );
        assert_eq!(
            m.client_rcode_total.with_label_values(&["SERVFAIL"]).get(),
            1
        );
        assert_eq!(m.queries_total.with_label_values(&["udp"]).get(), 1);
        assert_eq!(m.query_type_total.with_label_values(&["A"]).get(), 1);
    }
}
