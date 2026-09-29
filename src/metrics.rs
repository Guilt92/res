//! Prometheus metrics.
//!
//! All instruments live in a dedicated [`Metrics`] registry (never the global
//! default registry, so tests can build independent gateways).
//!
//! Label cardinality is deliberately bounded: upstream names are
//! administrator-defined and bounded, rcodes use a fixed enum-like set, and no
//! domain names, client IPs or query names are ever used as labels.

use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};
use std::sync::Arc;

const DURATION_BUCKETS: &[f64] = &[
    0.000_5, 0.001, 0.002_5, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

const LATENCY_BUCKETS: &[f64] = &[
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

    // Upstream metrics.
    pub upstream_queries_total: IntCounterVec,
    pub upstream_failures_total: IntCounterVec,
    pub upstream_timeouts_total: IntCounterVec,
    pub upstream_rcode_total: IntCounterVec,
    pub upstream_latency: HistogramVec,
    pub upstream_health: IntGaugeVec,
    pub upstream_state: IntGaugeVec,
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
}

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
            "outisdns_queries_total",
            "DNS queries received, by transport",
            &["transport"],
        );
        let query_errors_total = mk1(
            "outisdns_query_errors_total",
            "Client queries that ended in a gateway error response, by reason",
            &["reason"],
        );
        let query_duration = Histogram::with_opts(
            HistogramOpts::new(
                "outisdns_query_duration_seconds",
                "End-to-end client query handling duration",
            )
            .buckets(DURATION_BUCKETS.to_vec()),
        )
        .expect("metric");
        let client_rcode_total = mk1(
            "outisdns_response_rcode_total",
            "Response codes returned to clients",
            &["rcode"],
        );
        let malformed_total = mk(
            "outisdns_malformed_packets_total",
            "Packets dropped because they could not be parsed as DNS queries",
        );
        let acl_denied_total = mk("outisdns_acl_denied_total", "Queries denied by ACL");
        let rate_limit_dropped_total = mk(
            "outisdns_rate_limit_dropped_total",
            "Queries dropped by rate limiting",
        );
        let overload_dropped_total = mk(
            "outisdns_overload_dropped_total",
            "Queries dropped because the in-flight limit was reached",
        );

        let upstream_queries_total = mk1(
            "outisdns_upstream_queries_total",
            "Queries forwarded to an upstream",
            &["upstream"],
        );
        let upstream_failures_total = mk1(
            "outisdns_upstream_failures_total",
            "Upstream attempts that failed (network error, timeout, servfail)",
            &["upstream"],
        );
        let upstream_timeouts_total = mk1(
            "outisdns_upstream_timeouts_total",
            "Upstream attempts that timed out",
            &["upstream"],
        );
        let upstream_rcode_total = mk1(
            "outisdns_upstream_rcode_total",
            "Response codes received from upstreams",
            &["upstream", "rcode"],
        );
        let upstream_latency = HistogramVec::new(
            HistogramOpts::new(
                "outisdns_upstream_latency_seconds",
                "Upstream response latency for forwarded queries",
            )
            .buckets(LATENCY_BUCKETS.to_vec()),
            &["upstream"],
        )
        .expect("metric");
        let upstream_health = IntGaugeVec::new(
            Opts::new(
                "outisdns_upstream_health",
                "1 when the upstream is UP, 0 otherwise",
            ),
            &["upstream"],
        )
        .expect("metric");
        let upstream_state = IntGaugeVec::new(
            Opts::new(
                "outisdns_upstream_state",
                "Upstream health state: 0=DOWN, 1=DEGRADED, 2=UP",
            ),
            &["upstream"],
        )
        .expect("metric");
        let active_upstreams = IntGauge::with_opts(Opts::new(
            "outisdns_active_upstreams",
            "Enabled upstreams currently in the pool",
        ))
        .expect("metric");
        let healthy_upstreams = IntGauge::with_opts(Opts::new(
            "outisdns_healthy_upstreams",
            "Upstreams in the UP state",
        ))
        .expect("metric");
        let failovers_total = mk(
            "outisdns_failovers_total",
            "Client queries that needed more than one upstream attempt",
        );

        let cache_hits_total = mk("outisdns_cache_hits_total", "Cache hits");
        let cache_misses_total = mk("outisdns_cache_misses_total", "Cache misses");
        let cache_entries = IntGauge::with_opts(Opts::new(
            "outisdns_cache_entries",
            "Current number of cached responses",
        ))
        .expect("metric");

        let tcp_connections_total = mk(
            "outisdns_tcp_connections_total",
            "Accepted TCP DNS connections",
        );
        let tcp_connections_rejected_total = mk(
            "outisdns_tcp_connections_rejected_total",
            "TCP DNS connections rejected because the connection limit was reached",
        );
        let config_reloads_total = mk(
            "outisdns_config_reloads_total",
            "Successful configuration reloads applied to the data plane",
        );
        let config_errors_total = mk(
            "outisdns_config_errors_total",
            "Configuration parse/persistence failures",
        );
        let udp_inflight = IntGauge::with_opts(Opts::new(
            "outisdns_udp_inflight",
            "UDP queries currently in flight",
        ))
        .expect("metric");
        let tcp_connections = IntGauge::with_opts(Opts::new(
            "outisdns_tcp_connections",
            "TCP DNS connections currently open",
        ))
        .expect("metric");
        let resident_memory_bytes = IntGauge::with_opts(Opts::new(
            "outisdns_resident_memory_bytes",
            "Resident memory (RSS) of this process in bytes",
        ))
        .expect("metric");

        for c in [
            &queries_total,
            &query_errors_total,
            &client_rcode_total,
            &upstream_queries_total,
            &upstream_failures_total,
            &upstream_timeouts_total,
            &upstream_rcode_total,
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
        for g in [&upstream_health, &upstream_state] {
            registry.register(Box::new(g.clone())).expect("register");
        }
        for g in [
            &active_upstreams,
            &healthy_upstreams,
            &cache_entries,
            &udp_inflight,
            &tcp_connections,
            &resident_memory_bytes,
        ] {
            registry.register(Box::new(g.clone())).expect("register");
        }

        // Warm up canonical series (at zero) so dashboards and health checks
        // see the metrics before the first real traffic arrives.
        let _ = queries_total.with_label_values(&["udp"]);
        let _ = queries_total.with_label_values(&["tcp"]);
        for rcode in [
            "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "OTHER",
        ] {
            let _ = client_rcode_total.with_label_values(&[rcode]);
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
            upstream_queries_total,
            upstream_failures_total,
            upstream_timeouts_total,
            upstream_rcode_total,
            upstream_latency,
            upstream_health,
            upstream_state,
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

    /// Record the health-state gauges for one upstream.
    pub fn set_upstream_health(&self, name: &str, healthy: bool, state_value: i64) {
        self.upstream_health
            .with_label_values(&[name])
            .set(if healthy { 1 } else { 0 });
        self.upstream_state
            .with_label_values(&[name])
            .set(state_value);
    }

    /// Remove every per-upstream series for a deleted upstream (bounded rcode
    /// label set — the only values [`crate::dns::msg::Rcode`] can produce).
    pub fn drop_upstream(&self, name: &str) {
        let _ = self.upstream_health.remove_label_values(&[name]);
        let _ = self.upstream_state.remove_label_values(&[name]);
        let _ = self.upstream_queries_total.remove_label_values(&[name]);
        let _ = self.upstream_failures_total.remove_label_values(&[name]);
        let _ = self.upstream_timeouts_total.remove_label_values(&[name]);
        let _ = self.upstream_latency.remove_label_values(&[name]);
        for rcode in [
            "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "OTHER",
        ] {
            let _ = self
                .upstream_rcode_total
                .remove_label_values(&[name, rcode]);
        }
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
        m.upstream_rcode_total
            .with_label_values(&["warmup", "NOERROR"])
            .inc();
        m.upstream_latency
            .with_label_values(&["warmup"])
            .observe(0.001);
        m.upstream_health.with_label_values(&["warmup"]).set(1);
        m.upstream_state.with_label_values(&["warmup"]).set(2);
        let text = m.render();
        for name in [
            "outisdns_queries_total",
            "outisdns_query_errors_total",
            "outisdns_query_duration_seconds",
            "outisdns_upstream_queries_total",
            "outisdns_upstream_failures_total",
            "outisdns_upstream_timeouts_total",
            "outisdns_upstream_latency_seconds",
            "outisdns_upstream_health",
            "outisdns_cache_hits_total",
            "outisdns_cache_misses_total",
            "outisdns_active_upstreams",
            "outisdns_failovers_total",
            "outisdns_acl_denied_total",
            "outisdns_rate_limit_dropped_total",
            "outisdns_udp_inflight",
            "outisdns_tcp_connections",
            "outisdns_resident_memory_bytes",
            "outisdns_config_errors_total",
        ] {
            assert!(text.contains(name), "missing metric {name}");
        }
    }

    #[test]
    fn counters_increment() {
        let m = Metrics::new();
        m.queries_total.with_label_values(&["udp"]).inc();
        let text = m.render();
        assert!(text.contains("outisdns_queries_total{transport=\"udp\"} 1"));
    }
}
