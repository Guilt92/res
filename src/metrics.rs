//! Prometheus metrics.
//!
//! All instruments live in a dedicated [`Metrics`] registry (never the global
//! default registry, so tests can build independent gateways).
//!
//! Label cardinality is deliberately bounded: upstream names are
//! administrator-defined and bounded, rcodes and query types use fixed
//! enum-like sets, and domain names are never labels. The only per-client
//! labels come from the top-N client-metrics collector, which exports at most
//! `monitoring.client_metrics_max` addresses per scrape, masked by default.

use prometheus::core::{Collector, Desc};
use prometheus::{
    proto, Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Opts, Registry, TextEncoder,
};
use std::sync::Arc;

use crate::config::ClientIpPrivacy;

/// Upper bounds (seconds) of `res_query_duration_seconds`, in ascending
/// order (no `+Inf` — it is implied as `sample_count`).
pub const DURATION_BUCKETS: &[f64] = &[
    0.000_5, 0.001, 0.002_5, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Upper bounds (seconds) of `res_upstream_latency_seconds`.
pub const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0,
];

pub struct Metrics {
    pub registry: Registry,

    // Client-facing query metrics.
    pub queries_total: IntCounterVec,
    pub query_errors_total: IntCounterVec,
    pub query_duration: Histogram,
    pub client_rcode_total: IntCounterVec,
    pub malformed_total: IntCounter,
    pub acl_denied_total: IntCounter,
    pub rate_limit_dropped_total: IntCounter,
    pub overload_dropped_total: IntCounter,
    /// Bounded query-type counters (`qtype` label from [`QTYPES`]).
    pub query_type_total: IntCounterVec,

    // Wire-level counters (packets and payload bytes actually seen).
    pub udp_packets_received_total: IntCounter,
    pub udp_packets_sent_total: IntCounter,
    pub request_bytes_total: IntCounter,
    pub response_bytes_total: IntCounter,
    /// Packets larger than `server.max_udp_packet_size` (dropped before parse).
    pub oversized_packets_total: IntCounter,
    /// Largest request/response payload observed since start (real maximums,
    /// not the configured limit).
    pub max_request_bytes: IntGauge,
    pub max_response_bytes: IntGauge,

    // Upstream metrics.
    pub upstream_queries_total: IntCounterVec,
    pub upstream_failures_total: IntCounterVec,
    pub upstream_timeouts_total: IntCounterVec,
    pub upstream_failovers_total: IntCounterVec,
    pub upstream_rcode_total: IntCounterVec,
    pub upstream_latency: HistogramVec,
    pub upstream_health: IntGaugeVec,
    pub upstream_state: IntGaugeVec,
    /// Health-check probe rounds by result (`success` / `failure`).
    pub healthcheck_total: IntCounterVec,
    /// Latency of successful health-check probe rounds.
    pub healthcheck_duration_seconds: HistogramVec,
    /// Unix timestamp of the last successful health check per upstream
    /// (absent until the first success — never faked with epoch 0).
    pub healthcheck_last_success_timestamp_seconds: IntGaugeVec,
    /// Health-state transitions per upstream (up/degraded/down changes).
    pub upstream_state_changes_total: IntCounterVec,
    pub active_upstreams: IntGauge,
    pub healthy_upstreams: IntGauge,
    pub failovers_total: IntCounter,

    // Cache.
    pub cache_hits_total: IntCounter,
    pub cache_misses_total: IntCounter,
    pub cache_entries: IntGauge,

    // TCP / operational.
    pub tcp_connections_total: IntCounter,
    pub tcp_connections_rejected_total: IntCounter,
    pub config_reloads_total: IntCounter,
    pub config_errors_total: IntCounter,
    pub udp_inflight: IntGauge,
    pub tcp_connections: IntGauge,
    pub resident_memory_bytes: IntGauge,
    /// Process CPU utilisation in percent (0–100 * cores), sampled by the
    /// runtime sampler (not on the query path).
    pub cpu_percent: IntGauge,
    /// Open file descriptors of this process, sampled by the runtime sampler.
    pub open_fds: IntGauge,
}

/// The bounded rcode label set (every value [`crate::dns::msg::Rcode`] can
/// produce as a client-facing response code).
pub const RCODES: &[&str] = &[
    "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "OTHER",
];

/// Bounded query-type label set: every common type plus `OTHER`, so the
/// metric cardinality cannot grow with exotic RR types.
pub const QTYPES: &[&str] = &[
    "A", "AAAA", "NS", "CNAME", "SOA", "PTR", "MX", "TXT", "SRV", "CAA", "ANY", "OTHER",
];

/// Aliased histogram vec (kept as its own type for convenience).
pub type HistogramVec = prometheus::HistogramVec;

impl Metrics {
    pub fn new() -> Arc<Self> {
        let registry = Registry::new();

        let mk =
            |name: &str, help: &str| IntCounter::with_opts(Opts::new(name, help)).expect("metric");
        let mk1 = |name: &str, help: &str, l: &[&str]| {
            IntCounterVec::new(Opts::new(name, help), l).expect("metric")
        };

        let queries_total = mk1(
            "res_queries_total",
            "DNS queries received, by transport",
            &["transport"],
        );
        let query_errors_total = mk1(
            "res_query_errors_total",
            "Client queries that ended in a gateway error response, by reason",
            &["reason"],
        );
        let query_duration = Histogram::with_opts(
            HistogramOpts::new(
                "res_query_duration_seconds",
                "End-to-end client query handling duration",
            )
            .buckets(DURATION_BUCKETS.to_vec()),
        )
        .expect("metric");
        let client_rcode_total = mk1(
            "res_response_rcode_total",
            "Response codes returned to clients",
            &["rcode"],
        );
        let malformed_total = mk(
            "res_malformed_packets_total",
            "Packets dropped because they could not be parsed as DNS queries",
        );
        let acl_denied_total = mk("res_acl_denied_total", "Queries denied by ACL");
        let rate_limit_dropped_total = mk(
            "res_rate_limit_dropped_total",
            "Queries dropped by rate limiting",
        );
        let overload_dropped_total = mk(
            "res_overload_dropped_total",
            "Queries dropped because the in-flight limit was reached",
        );
        let query_type_total = mk1(
            "res_query_type_total",
            "Parsed DNS queries by question type",
            &["qtype"],
        );

        // Wire-level accounting: what actually crossed the socket.
        let udp_packets_received_total = mk(
            "res_udp_packets_received_total",
            "UDP packets received (including oversized/malformed ones)",
        );
        let udp_packets_sent_total = mk(
            "res_udp_packets_sent_total",
            "UDP packets successfully sent to clients",
        );
        let request_bytes_total = mk(
            "res_request_bytes_total",
            "DNS request payload bytes received from clients",
        );
        let response_bytes_total = mk(
            "res_response_bytes_total",
            "DNS response payload bytes sent to clients",
        );
        let oversized_packets_total = mk(
            "res_oversized_packets_total",
            "UDP packets larger than server.max_udp_packet_size (dropped)",
        );
        let max_request_bytes = IntGauge::with_opts(Opts::new(
            "res_max_request_bytes",
            "Largest DNS request payload seen since start",
        ))
        .expect("metric");
        let max_response_bytes = IntGauge::with_opts(Opts::new(
            "res_max_response_bytes",
            "Largest DNS response payload sent since start",
        ))
        .expect("metric");

        let upstream_queries_total = mk1(
            "res_upstream_queries_total",
            "Queries forwarded to an upstream",
            &["upstream"],
        );
        let upstream_failures_total = mk1(
            "res_upstream_failures_total",
            "Upstream attempts that failed (network error, timeout, servfail)",
            &["upstream"],
        );
        let upstream_timeouts_total = mk1(
            "res_upstream_timeouts_total",
            "Upstream attempts that timed out",
            &["upstream"],
        );
        let upstream_failovers_total = mk1(
            "res_upstream_failovers_total",
            "Upstream attempts that failed and caused a retry on another upstream",
            &["upstream"],
        );
        let upstream_rcode_total = mk1(
            "res_upstream_rcode_total",
            "Response codes received from upstreams",
            &["upstream", "rcode"],
        );
        let upstream_latency = HistogramVec::new(
            HistogramOpts::new(
                "res_upstream_latency_seconds",
                "Upstream response latency for forwarded queries",
            )
            .buckets(LATENCY_BUCKETS.to_vec()),
            &["upstream"],
        )
        .expect("metric");
        let upstream_health = IntGaugeVec::new(
            Opts::new(
                "res_upstream_health",
                "1 when the upstream is UP, 0 otherwise",
            ),
            &["upstream"],
        )
        .expect("metric");
        let upstream_state = IntGaugeVec::new(
            Opts::new(
                "res_upstream_state",
                "Upstream health state: 0=DOWN, 1=DEGRADED, 2=UP",
            ),
            &["upstream"],
        )
        .expect("metric");
        let healthcheck_total = mk1(
            "res_healthcheck_total",
            "Health-check probe rounds by result",
            &["upstream", "result"],
        );
        let healthcheck_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "res_healthcheck_duration_seconds",
                "Latency of successful health-check probe rounds",
            )
            .buckets(LATENCY_BUCKETS.to_vec()),
            &["upstream"],
        )
        .expect("metric");
        let healthcheck_last_success_timestamp_seconds = IntGaugeVec::new(
            Opts::new(
                "res_healthcheck_last_success_timestamp_seconds",
                "Unix time of the last successful health check",
            ),
            &["upstream"],
        )
        .expect("metric");
        let upstream_state_changes_total = mk1(
            "res_upstream_state_changes_total",
            "Upstream health-state transitions (up/degraded/down)",
            &["upstream"],
        );
        let active_upstreams = IntGauge::with_opts(Opts::new(
            "res_active_upstreams",
            "Enabled upstreams currently in the pool",
        ))
        .expect("metric");
        let healthy_upstreams = IntGauge::with_opts(Opts::new(
            "res_healthy_upstreams",
            "Upstreams in the UP state",
        ))
        .expect("metric");
        let failovers_total = mk(
            "res_failovers_total",
            "Client queries that needed more than one upstream attempt",
        );

        let cache_hits_total = mk("res_cache_hits_total", "Cache hits");
        let cache_misses_total = mk("res_cache_misses_total", "Cache misses");
        let cache_entries = IntGauge::with_opts(Opts::new(
            "res_cache_entries",
            "Current number of cached responses",
        ))
        .expect("metric");

        let tcp_connections_total = mk("res_tcp_connections_total", "Accepted TCP DNS connections");
        let tcp_connections_rejected_total = mk(
            "res_tcp_connections_rejected_total",
            "TCP DNS connections rejected because the connection limit was reached",
        );
        let config_reloads_total = mk(
            "res_config_reloads_total",
            "Successful configuration reloads applied to the data plane",
        );
        let config_errors_total = mk(
            "res_config_errors_total",
            "Configuration parse/persistence failures",
        );
        let udp_inflight = IntGauge::with_opts(Opts::new(
            "res_udp_inflight",
            "UDP queries currently in flight",
        ))
        .expect("metric");
        let tcp_connections = IntGauge::with_opts(Opts::new(
            "res_tcp_connections",
            "TCP DNS connections currently open",
        ))
        .expect("metric");
        let resident_memory_bytes = IntGauge::with_opts(Opts::new(
            "res_resident_memory_bytes",
            "Resident memory (RSS) of this process in bytes",
        ))
        .expect("metric");
        let cpu_percent = IntGauge::with_opts(Opts::new(
            "res_cpu_percent",
            "Process CPU utilisation in percent (rounded, 100 = one core saturated)",
        ))
        .expect("metric");
        let open_fds = IntGauge::with_opts(Opts::new(
            "res_open_fds",
            "Open file descriptors of this process",
        ))
        .expect("metric");

        for c in [
            &queries_total,
            &query_errors_total,
            &client_rcode_total,
            &query_type_total,
            &upstream_queries_total,
            &upstream_failures_total,
            &upstream_timeouts_total,
            &upstream_failovers_total,
            &upstream_rcode_total,
            &healthcheck_total,
            &upstream_state_changes_total,
        ] {
            registry.register(Box::new(c.clone())).expect("register");
        }
        for c in [
            &malformed_total,
            &acl_denied_total,
            &rate_limit_dropped_total,
            &overload_dropped_total,
            &failovers_total,
            &cache_hits_total,
            &cache_misses_total,
            &tcp_connections_total,
            &tcp_connections_rejected_total,
            &config_reloads_total,
            &config_errors_total,
            &udp_packets_received_total,
            &udp_packets_sent_total,
            &request_bytes_total,
            &response_bytes_total,
            &oversized_packets_total,
        ] {
            registry.register(Box::new(c.clone())).expect("register");
        }
        {
            let h = &query_duration;
            registry.register(Box::new(h.clone())).expect("register");
        }
        {
            let h = &upstream_latency;
            registry.register(Box::new(h.clone())).expect("register");
        }
        {
            let h = &healthcheck_duration_seconds;
            registry.register(Box::new(h.clone())).expect("register");
        }
        for g in [
            &upstream_health,
            &upstream_state,
            &healthcheck_last_success_timestamp_seconds,
        ] {
            registry.register(Box::new(g.clone())).expect("register");
        }
        for g in [
            &active_upstreams,
            &healthy_upstreams,
            &cache_entries,
            &udp_inflight,
            &tcp_connections,
            &resident_memory_bytes,
            &cpu_percent,
            &open_fds,
            &max_request_bytes,
            &max_response_bytes,
        ] {
            registry.register(Box::new(g.clone())).expect("register");
        }

        // Warm up canonical series (at zero) so dashboards and health checks
        // see the metrics before the first real traffic arrives.
        let _ = queries_total.with_label_values(&["udp"]);
        let _ = queries_total.with_label_values(&["tcp"]);
        for rcode in RCODES {
            let _ = client_rcode_total.with_label_values(&[rcode]);
        }
        for qtype in QTYPES {
            let _ = query_type_total.with_label_values(&[qtype]);
        }

        Arc::new(Self {
            registry,
            queries_total,
            query_errors_total,
            query_duration,
            client_rcode_total,
            malformed_total,
            acl_denied_total,
            rate_limit_dropped_total,
            overload_dropped_total,
            query_type_total,
            udp_packets_received_total,
            udp_packets_sent_total,
            request_bytes_total,
            response_bytes_total,
            oversized_packets_total,
            max_request_bytes,
            max_response_bytes,
            upstream_queries_total,
            upstream_failures_total,
            upstream_timeouts_total,
            upstream_failovers_total,
            upstream_rcode_total,
            upstream_latency,
            upstream_health,
            upstream_state,
            healthcheck_total,
            healthcheck_duration_seconds,
            healthcheck_last_success_timestamp_seconds,
            upstream_state_changes_total,
            active_upstreams,
            healthy_upstreams,
            failovers_total,
            cache_hits_total,
            cache_misses_total,
            cache_entries,
            tcp_connections_total,
            tcp_connections_rejected_total,
            config_reloads_total,
            config_errors_total,
            udp_inflight,
            tcp_connections,
            resident_memory_bytes,
            cpu_percent,
            open_fds,
        })
    }

    /// Encode every metric in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut buf = Vec::with_capacity(8 * 1024);
        let encoder = TextEncoder::new();
        if let Err(e) = encoder.encode(&self.registry.gather(), &mut buf) {
            tracing::error!(event = "metrics_encode_failed", error = %e);
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Record the health-state gauges for one upstream. Also materialises
    /// every per-upstream counter series (at a measured zero) so dashboards
    /// show real `0` rates from process start instead of gaps.
    pub fn set_upstream_health(&self, name: &str, healthy: bool, state_value: i64) {
        self.upstream_health
            .with_label_values(&[name])
            .set(if healthy { 1 } else { 0 });
        self.upstream_state
            .with_label_values(&[name])
            .set(state_value);
        let _ = self.upstream_queries_total.with_label_values(&[name]);
        let _ = self.upstream_failures_total.with_label_values(&[name]);
        let _ = self.upstream_timeouts_total.with_label_values(&[name]);
        let _ = self.upstream_failovers_total.with_label_values(&[name]);
        let _ = self.upstream_latency.with_label_values(&[name]);
        let _ = self.upstream_state_changes_total.with_label_values(&[name]);
        let _ = self.healthcheck_duration_seconds.with_label_values(&[name]);
        for result in ["success", "failure"] {
            let _ = self.healthcheck_total.with_label_values(&[name, result]);
        }
        for rcode in RCODES {
            let _ = self.upstream_rcode_total.with_label_values(&[name, rcode]);
        }
    }

    /// Remove every per-upstream series for a deleted upstream (bounded rcode
    /// label set — the only values [`crate::dns::msg::Rcode`] can produce).
    pub fn drop_upstream(&self, name: &str) {
        let _ = self.upstream_health.remove_label_values(&[name]);
        let _ = self.upstream_state.remove_label_values(&[name]);
        let _ = self.upstream_queries_total.remove_label_values(&[name]);
        let _ = self.upstream_failures_total.remove_label_values(&[name]);
        let _ = self.upstream_timeouts_total.remove_label_values(&[name]);
        let _ = self.upstream_failovers_total.remove_label_values(&[name]);
        let _ = self.upstream_latency.remove_label_values(&[name]);
        let _ = self
            .upstream_state_changes_total
            .remove_label_values(&[name]);
        let _ = self
            .healthcheck_duration_seconds
            .remove_label_values(&[name]);
        let _ = self
            .healthcheck_last_success_timestamp_seconds
            .remove_label_values(&[name]);
        for result in ["success", "failure"] {
            let _ = self.healthcheck_total.remove_label_values(&[name, result]);
        }
        for rcode in RCODES {
            let _ = self
                .upstream_rcode_total
                .remove_label_values(&[name, rcode]);
        }
    }

    /// Account one request payload (total bytes + running observed maximum).
    pub fn observe_request_bytes(&self, n: usize) {
        self.request_bytes_total.inc_by(n as u64);
        let n = n as i64;
        if n > self.max_request_bytes.get() {
            self.max_request_bytes.set(n);
        }
    }

    /// Account one response payload (total bytes + running observed maximum).
    pub fn observe_response_bytes(&self, n: usize) {
        self.response_bytes_total.inc_by(n as u64);
        let n = n as i64;
        if n > self.max_response_bytes.get() {
            self.max_response_bytes.set(n);
        }
    }
}

/// Exports the current top-N client addresses (by request count) as
/// Prometheus counter series at scrape time.
///
/// * **Bounded** — at most `monitoring.client_metrics_max` clients, selected
///   from the already-bounded traffic table on every scrape.
/// * **Privacy-preserving** — labels follow the configured policy: `masked`
///   (default) aggregates by masked address, `full` uses real addresses,
///   `off` exports nothing at all.
/// * **Real counters** — every value is the cumulative count kept by the
///   traffic table; results are only exported once they actually occurred
///   (an outcome with a count of 0 is omitted instead of padded with zeros).
///
/// The families are rebuilt from scratch on each `collect()` so concurrent
/// scrapes never observe a half-updated state.
pub struct ClientMetricsCollector {
    traffic: Arc<crate::traffic::TrafficStats>,
    desc_queries: IntCounterVec,
    desc_results: IntCounterVec,
    desc_bytes: IntCounterVec,
}

impl ClientMetricsCollector {
    pub fn new(traffic: Arc<crate::traffic::TrafficStats>) -> Self {
        let mk = |name: &str, help: &str, labels: &[&str]| {
            IntCounterVec::new(Opts::new(name, help), labels).expect("metric")
        };
        Self {
            traffic,
            desc_queries: mk(
                "res_client_queries_total",
                "DNS requests received per client address (top-N export)",
                &["client"],
            ),
            desc_results: mk(
                "res_client_query_result_total",
                "Per-client request outcomes: ok/failed/timeout/rate_limited/acl_denied",
                &["client", "result"],
            ),
            desc_bytes: mk(
                "res_client_request_bytes_total",
                "DNS request payload bytes received per client address",
                &["client"],
            ),
        }
    }
}

impl Collector for ClientMetricsCollector {
    fn desc(&self) -> Vec<&Desc> {
        let mut v = Vec::with_capacity(3);
        v.extend(self.desc_queries.desc());
        v.extend(self.desc_results.desc());
        v.extend(self.desc_bytes.desc());
        v
    }

    fn collect(&self) -> Vec<proto::MetricFamily> {
        let (cap, privacy) = self.traffic.prom_export();
        if cap == 0 || privacy == ClientIpPrivacy::Off {
            return Vec::new();
        }
        let rows = self
            .traffic
            .client_rows(cap, crate::traffic::ClientSort::Requests, privacy);
        if rows.is_empty() {
            return Vec::new();
        }
        let queries = IntCounterVec::new(
            Opts::new(
                "res_client_queries_total",
                "DNS requests received per client address (top-N export)",
            ),
            &["client"],
        )
        .expect("metric");
        let results = IntCounterVec::new(
            Opts::new(
                "res_client_query_result_total",
                "Per-client request outcomes: ok/failed/timeout/rate_limited/acl_denied",
            ),
            &["client", "result"],
        )
        .expect("metric");
        let bytes = IntCounterVec::new(
            Opts::new(
                "res_client_request_bytes_total",
                "DNS request payload bytes received per client address",
            ),
            &["client"],
        )
        .expect("metric");

        for row in &rows {
            queries
                .with_label_values(&[row.client.as_str()])
                .inc_by(row.requests);
            bytes
                .with_label_values(&[row.client.as_str()])
                .inc_by(row.bytes);
            for (result, n) in [
                ("ok", row.ok),
                ("failed", row.failed),
                ("timeout", row.timeouts),
                ("rate_limited", row.rate_limited),
                ("acl_denied", row.acl_denied),
            ] {
                if n > 0 {
                    results
                        .with_label_values(&[row.client.as_str(), result])
                        .inc_by(n);
                }
            }
        }

        let mut fams = queries.collect();
        fams.extend(results.collect());
        fams.extend(bytes.collect());
        fams
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_exposes_required_metric_names() {
        let m = Metrics::new();
        // Touched series (an unused MetricVec renders nothing at all).
        m.query_errors_total.with_label_values(&["timeout"]).inc();
        m.upstream_queries_total
            .with_label_values(&["warmup"])
            .inc();
        m.upstream_failures_total
            .with_label_values(&["warmup"])
            .inc();
        m.upstream_timeouts_total
            .with_label_values(&["warmup"])
            .inc();
        m.upstream_failovers_total
            .with_label_values(&["warmup"])
            .inc();
        m.upstream_rcode_total
            .with_label_values(&["warmup", "NOERROR"])
            .inc();
        m.upstream_latency
            .with_label_values(&["warmup"])
            .observe(0.001);
        m.upstream_health.with_label_values(&["warmup"]).set(1);
        m.upstream_state.with_label_values(&["warmup"]).set(2);
        m.set_upstream_health("warmup", true, 2);
        m.healthcheck_total
            .with_label_values(&["warmup", "success"])
            .inc();
        m.healthcheck_duration_seconds
            .with_label_values(&["warmup"])
            .observe(0.01);
        m.upstream_state_changes_total
            .with_label_values(&["warmup"])
            .inc();
        let text = m.render();
        for name in [
            "res_queries_total",
            "res_query_errors_total",
            "res_query_duration_seconds",
            "res_upstream_queries_total",
            "res_upstream_failures_total",
            "res_upstream_timeouts_total",
            "res_upstream_failovers_total",
            "res_upstream_latency_seconds",
            "res_upstream_health",
            "res_cache_hits_total",
            "res_cache_misses_total",
            "res_active_upstreams",
            "res_failovers_total",
            "res_acl_denied_total",
            "res_rate_limit_dropped_total",
            "res_udp_inflight",
            "res_tcp_connections",
            "res_resident_memory_bytes",
            "res_cpu_percent",
            "res_open_fds",
            "res_config_errors_total",
            "res_healthcheck_total",
            "res_healthcheck_duration_seconds",
            "res_upstream_state_changes_total",
        ] {
            assert!(text.contains(name), "missing metric {name}");
        }
    }

    #[test]
    fn client_metrics_collector_exports_real_top_client_counters() {
        use crate::traffic::{Outcome, TrafficStats};
        let m = Metrics::new();
        let t = Arc::new(TrafficStats::new(16, 16));
        t.set_prom_export(10, ClientIpPrivacy::Masked);
        m.registry
            .register(Box::new(ClientMetricsCollector::new(t.clone())))
            .expect("register collector");

        // Idle: no clients → no series (Grafana shows "No data", never 0).
        assert!(
            !m.render().contains("res_client_queries_total"),
            "no invented client series before traffic"
        );

        let ip: std::net::IpAddr = "10.1.2.3".parse().expect("ip");
        t.record_request(ip, false, 40);
        t.record_outcome(ip, Outcome::Ok, None);
        t.record_request(ip, true, 60);
        t.record_outcome(ip, Outcome::Timeout, None);
        let text = m.render();
        assert!(
            text.contains("res_client_queries_total{client=\"10.x.x.x\"} 2"),
            "masked label, real count:\n{text}"
        );
        assert!(
            text.contains("res_client_request_bytes_total{client=\"10.x.x.x\"} 100"),
            "real bytes:\n{text}"
        );
        assert!(
            text.contains("res_client_query_result_total{client=\"10.x.x.x\",result=\"ok\"} 1"),
            "outcome counters:\n{text}"
        );
        assert!(
            text.contains(
                "res_client_query_result_total{client=\"10.x.x.x\",result=\"timeout\"} 1"
            ),
            "timeout counter:\n{text}"
        );
        assert!(
            !text.contains("result=\"failed\""),
            "outcomes that never happened must not be padded with zeros"
        );

        // Privacy off: the export must disappear entirely.
        t.set_prom_export(10, ClientIpPrivacy::Off);
        assert!(
            !m.render().contains("res_client_queries_total"),
            "privacy off disables the client export"
        );
        // Re-enable to prove the counters are still real, not reset.
        t.set_prom_export(10, ClientIpPrivacy::Masked);
        assert!(
            m.render()
                .contains("res_client_queries_total{client=\"10.x.x.x\"} 2"),
            "counters survive a privacy toggle"
        );
    }

    #[test]
    fn counters_increment() {
        let m = Metrics::new();
        m.queries_total.with_label_values(&["udp"]).inc();
        let text = m.render();
        assert!(text.contains("res_queries_total{transport=\"udp\"} 1"));
    }
}

#[cfg(test)]
mod collect_tests {
    use super::*;

    #[test]
    fn gather_is_cumulative_for_histograms() {
        // Regression: the runtime sampler reads histograms every second via
        // gather(); a draining collect would silently destroy /metrics data.
        let m = Metrics::new();
        m.query_duration.observe(0.01);
        let count = |m: &Arc<Metrics>| -> f64 {
            let fams = m.registry.gather();
            for f in fams {
                if f.name() == "res_query_duration_seconds" {
                    return f.get_metric()[0].get_histogram().get_sample_count() as f64;
                }
            }
            0.0
        };
        let a = count(&m);
        m.query_duration.observe(0.01);
        m.query_duration.observe(0.5);
        let b = count(&m);
        eprintln!("a={a} b={b}");
        assert_eq!(a, 1.0);
        assert_eq!(b, 3.0, "collect must not reset histogram data");
    }
}
