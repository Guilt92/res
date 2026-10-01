//! Axum control plane: REST API, Prometheus endpoint, dashboard hosting.
//!
//! The API is strictly a management plane: DNS query processing never calls
//! into it, never touches the file system or the network on its own, and
//! keeps working when this HTTP server is down. Configuration persistence is
//! a single atomic file write per mutation — there is no database anywhere.

mod prom;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tower_http::services::{ServeDir, ServeFile};

use crate::config::{AppConfig, Protocol, UpstreamConfig};
use crate::dns::forward::Forwarder;
use crate::dns::msg::Rcode;
use crate::events::Event;
use crate::shared::Shared;
use crate::upstream::{health::probe_once, HealthStatus};

#[derive(Clone)]
pub struct ApiState {
    pub shared: Arc<Shared>,
    pub forwarder: Forwarder,
    /// Serialises configuration mutations (create/update/delete/import).
    pub mutation: Arc<tokio::sync::Mutex<()>>,
    /// Cached Prometheus reachability probe (refreshed at most every 10 s).
    probe: Arc<std::sync::Mutex<Option<ProbeState>>>,
}

#[derive(Clone)]
struct ProbeState {
    at: Instant,
    url: String,
    reachable: bool,
    error: Option<String>,
}

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    Conflict(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

pub fn router(shared: Arc<Shared>, forwarder: Forwarder) -> Router {
    let state = ApiState {
        shared,
        forwarder,
        mutation: Arc::new(tokio::sync::Mutex::new(())),
        probe: Arc::new(std::sync::Mutex::new(None)),
    };

    let dashboard = state
        .shared
        .app
        .load()
        .server
        .dashboard_dir
        .clone()
        .filter(|d| d.exists());

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/status", get(status))
        .route("/api/stats", get(stats))
        .route("/api/diagnostics", get(diagnostics))
        .route("/api/upstreams", get(list_upstreams).post(create_upstream))
        .route(
            "/api/upstreams/{id}",
            get(get_upstream)
                .patch(patch_upstream)
                .delete(delete_upstream),
        )
        .route("/api/upstreams/{id}/test", post(test_upstream))
        .route("/api/upstreams/{id}/health", get(upstream_events))
        .route("/api/config", get(export_config).put(import_config))
        .route("/api/config/events", get(config_events))
        .route("/api/events", get(all_events))
        .route("/api/history", get(history))
        .route("/api/timeseries", get(timeseries))
        .route("/api/clients", get(top_clients))
        .route("/api/domains", get(top_domains))
        .route("/api/monitoring", get(monitoring_info))
        .route("/metrics", get(metrics_endpoint))
        .with_state(state);

    match dashboard {
        Some(dir) => {
            let index = dir.join("index.html");
            app.fallback_service(ServeDir::new(dir).fallback(ServeFile::new(index)))
        }
        None => app,
    }
}

// ---------------------------------------------------------------------------
// Health / status / stats / diagnostics
// ---------------------------------------------------------------------------

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn status(State(st): State<ApiState>) -> Json<Value> {
    let app = st.shared.app.load();
    let rt = st.shared.rt.load();
    let bound = st
        .shared
        .bound
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let (total, enabled, healthy, degraded, down) = upstream_counts(&st);
    let cfg_state = st.shared.config_state();

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": st.shared.uptime().as_secs(),
        "listeners": {
            "udp": bound.udp.map(|a| a.to_string()),
            "tcp": bound.tcp.map(|a| a.to_string()),
            "api": bound.api.map(|a| a.to_string()),
            "configured_udp": app.server.udp_addr.to_string(),
            "configured_tcp": app.server.tcp_addr.to_string(),
            "configured_api": app.server.api_addr.to_string(),
        },
        "config": {
            "path": st.shared.config_path.get().map(|p| p.display().to_string()),
            "source": cfg_state.source,
            "error": cfg_state.error,
            "warnings": app.warnings(),
        },
        "selector": {
            "strategy": st.shared.current_selector().describe(),
            "latency_reference_ms": rt.selection.latency_reference_ms,
        },
        "acl": {
            "allowed_networks": rt.acl.allowed_count(),
            "denied_networks": rt.acl.denied_count(),
        },
        "privacy": {
            "client_ip": rt.client_ip_privacy.as_str(),
            "top_clients_max": app.monitoring.top_clients_max,
            "top_domains_max": app.monitoring.top_domains_max,
            "client_metrics_max": app.monitoring.client_metrics_max,
        },
        "rate_limit": {
            "enabled": rt.ratelimit.enabled,
            "per_ip_qps": rt.ratelimit.per_ip_qps,
            "global_qps": rt.ratelimit.global_qps,
            "tracked_clients": st.shared.ratelimit.tracked_clients(),
        },
        "query": {
            "timeout_ms": rt.query.timeout_ms,
            "upstream_timeout_ms": rt.query.upstream_timeout_ms,
            "max_attempts": rt.query.max_attempts,
            "retry_on_servfail": rt.failover.retry_on_servfail,
        },
        "cache": {
            "enabled": rt.cache.enabled,
            "entries": st.shared.cache.len(),
            "max_entries": rt.cache.max_entries,
        },
        "upstreams": {
            "total": total,
            "enabled": enabled,
            "healthy": healthy,
            "degraded": degraded,
            "down": down,
        },
        "emergency": {
            "no_healthy_upstreams": total > 0 && healthy == 0,
        },
        "inflight": {
            "udp": st.shared.udp_inflight.current(),
            "tcp_connections": st.shared.tcp_connections.current(),
        },
        "health_check": {
            "enabled": app.health.enabled,
            "interval_ms": app.health.interval_ms,
            "failure_threshold": app.health.failure_threshold,
            "recovery_threshold": app.health.recovery_threshold,
            "probes": app.health.probes.len(),
        },
        "log_format": match app.logging.format {
            crate::config::LogFormat::Json => "json",
            crate::config::LogFormat::Pretty => "pretty",
        },
    }))
}

async fn stats(State(st): State<ApiState>) -> Json<Value> {
    Json(build_stats(&st))
}

fn build_stats(st: &ApiState) -> Value {
    let metrics = &st.shared.metrics;
    let queries_udp = metrics.queries_total.with_label_values(&["udp"]).get();
    let queries_tcp = metrics.queries_total.with_label_values(&["tcp"]).get();
    let queries_total = queries_udp + queries_tcp;

    let rcode = |name: &str| metrics.client_rcode_total.with_label_values(&[name]).get();
    let responses = [
        Rcode::NoError,
        Rcode::NXDomain,
        Rcode::ServFail,
        Rcode::Refused,
        Rcode::FormErr,
        Rcode::NotImp,
        Rcode::Other,
    ]
    .iter()
    .map(|r| rcode(r.as_str()))
    .sum::<u64>();
    let success = rcode("NOERROR") + rcode("NXDOMAIN");
    let errors = responses.saturating_sub(success);

    let lat = st.shared.global_latency_stats();
    let (total, enabled, healthy, degraded, down) = upstream_counts(st);

    let hits = metrics.cache_hits_total.get();
    let misses = metrics.cache_misses_total.get();
    let cache_reads = hits + misses;

    // A rate that has no denominator is not zero — it is *unmeasured*. Emit
    // `null` so the dashboard can render "N/A" instead of inventing a value
    // (a fake 100% success rate on an idle gateway is worse than no number).
    let ratio = |num: u64, den: u64| -> Value {
        if den == 0 {
            Value::Null
        } else {
            json!(num as f64 / den as f64)
        }
    };
    // Latency percentiles only exist once at least one query was answered.
    let ms = |v: f64| -> Value {
        if lat.count == 0 {
            Value::Null
        } else {
            json!(round2(v))
        }
    };

    // Question-type histogram (bounded label set) + traffic introspection.
    let privacy = st.shared.rt.load().client_ip_privacy;
    let mut qtypes = serde_json::Map::new();
    for t in crate::metrics::QTYPES {
        qtypes.insert(
            (*t).to_string(),
            json!(metrics.query_type_total.with_label_values(&[t]).get()),
        );
    }

    json!({
        "uptime_seconds": st.shared.uptime().as_secs(),
        "qps": round2(st.shared.qps.current()),
        "queries_total": queries_total,
        "queries_udp": queries_udp,
        "queries_tcp": queries_tcp,
        "responses_total": responses,
        "success_count": success,
        "error_count": errors,
        "success_rate": ratio(success, responses),
        "error_rate": ratio(errors, responses),
        "latency": {
            "samples": lat.count,
            "last_ms": ms(lat.last_ms),
            "avg_ms": ms(lat.avg_ms),
            "p50_ms": ms(lat.p50_ms),
            "p95_ms": ms(lat.p95_ms),
            "p99_ms": ms(lat.p99_ms),
        },
        "cache": {
            "enabled": st.shared.rt.load().cache.enabled,
            "entries": st.shared.cache.len(),
            "hits": hits,
            "misses": misses,
            "hit_ratio": ratio(hits, cache_reads),
        },
        "upstreams": {
            "total": total,
            "enabled": enabled,
            "healthy": healthy,
            "degraded": degraded,
            "down": down,
        },
        "failovers": metrics.failovers_total.get(),
        "timeout_count": metrics.query_errors_total.with_label_values(&["deadline"]).get(),
        "timeout_rate": ratio(
            metrics.query_errors_total.with_label_values(&["deadline"]).get(),
            queries_total,
        ),
        "failover_rate": ratio(metrics.failovers_total.get(), queries_total),
        "acl_denied": metrics.acl_denied_total.get(),
        "rate_limited": metrics.rate_limit_dropped_total.get(),
        "overload_dropped": metrics.overload_dropped_total.get(),
        "malformed": metrics.malformed_total.get(),
        "config_errors": metrics.config_errors_total.get(),
        "tcp": {
            "connections": metrics.tcp_connections_total.get(),
            "rejected": metrics.tcp_connections_rejected_total.get(),
        },
        "rcode": {
            "NOERROR": rcode("NOERROR"),
            "NXDOMAIN": rcode("NXDOMAIN"),
            "SERVFAIL": rcode("SERVFAIL"),
            "REFUSED": rcode("REFUSED"),
            "FORMERR": rcode("FORMERR"),
            "NOTIMP": rcode("NOTIMP"),
            "OTHER": rcode("OTHER"),
        },
        "query_errors": {
            "no_upstreams": metrics.query_errors_total.with_label_values(&["no_upstreams"]).get(),
            "upstream_failure": metrics.query_errors_total.with_label_values(&["upstream_failure"]).get(),
            "deadline": metrics.query_errors_total.with_label_values(&["deadline"]).get(),
            "notimp": metrics.query_errors_total.with_label_values(&["notimp"]).get(),
        },
        "traffic": {
            "udp_packets_received": metrics.udp_packets_received_total.get(),
            "udp_packets_sent": metrics.udp_packets_sent_total.get(),
            "request_bytes": metrics.request_bytes_total.get(),
            "response_bytes": metrics.response_bytes_total.get(),
            "avg_request_bytes": ratio(metrics.request_bytes_total.get(), queries_total),
            "avg_response_bytes": ratio(metrics.response_bytes_total.get(), responses),
            "max_request_bytes": metrics.max_request_bytes.get(),
            "max_response_bytes": metrics.max_response_bytes.get(),
            "oversized_packets": metrics.oversized_packets_total.get(),
            "query_type": Value::Object(qtypes),
            "client_ip_privacy": privacy.as_str(),
            "clients": json!(st.shared.traffic.client_stats()),
            "domains": json!(st.shared.traffic.domain_stats()),
            "top_clients": st
                .shared
                .traffic
                .client_rows(10, crate::traffic::ClientSort::Requests, privacy),
            "top_domains": crate::traffic::domain_rows(st.shared.traffic.top_domains(10)),
        },
        "events": st.shared.events.counts(),
    })
}

/// One-shot troubleshooting view: everything needed to answer "why is DNS
/// slow / failing here?" without shelling into the box.
async fn diagnostics(State(st): State<ApiState>) -> Json<Value> {
    let app = st.shared.app.load();
    let rt = st.shared.rt.load();
    let bound = st
        .shared
        .bound
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let cfg_state = st.shared.config_state();

    let upstreams: Vec<Value> = st
        .shared
        .registry
        .snapshot()
        .iter()
        .map(|u| serde_json::to_value(u.stats()).expect("serializable"))
        .collect();
    let (total, enabled, healthy, degraded, down) = upstream_counts(&st);

    let metrics = &st.shared.metrics;
    let bound_addr = |a: Option<std::net::SocketAddr>| a.map(|x| x.to_string());

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
        "uptime_seconds": st.shared.uptime().as_secs(),
        "listeners": {
            "udp": bound_addr(bound.udp),
            "tcp": bound_addr(bound.tcp),
            "api": bound_addr(bound.api),
            "configured_udp": app.server.udp_addr.to_string(),
            "configured_tcp": app.server.tcp_addr.to_string(),
            "configured_api": app.server.api_addr.to_string(),
        },
        "config": {
            "path": st.shared.config_path.get().map(|p| p.display().to_string()),
            "source": cfg_state.source,
            "error": cfg_state.error,
            "upstreams": app.upstreams.len(),
            "warnings": app.warnings(),
        },
        "query": {
            "timeout_ms": rt.query.timeout_ms,
            "upstream_timeout_ms": rt.query.upstream_timeout_ms,
            "max_attempts": rt.query.max_attempts,
            "retry_on_servfail": rt.failover.retry_on_servfail,
        },
        "upstreams": {
            "total": total,
            "enabled": enabled,
            "healthy": healthy,
            "degraded": degraded,
            "down": down,
            "list": upstreams,
        },
        "health_check": {
            "enabled": app.health.enabled,
            "interval_ms": app.health.interval_ms,
            "timeout_ms": app.health.timeout_ms,
            "probes": app.health.probes.len(),
        },
        "cache": {
            "enabled": rt.cache.enabled,
            "entries": st.shared.cache.len(),
            "max_entries": rt.cache.max_entries,
        },
        "inflight": {
            "udp": st.shared.udp_inflight.current(),
            "tcp_connections": st.shared.tcp_connections.current(),
        },
        "ratelimit": {
            "enabled": rt.ratelimit.enabled,
            "tracked_clients": st.shared.ratelimit.tracked_clients(),
        },
        "qps": round2(st.shared.qps.current()),
        "failovers_total": metrics.failovers_total.get(),
        "config_errors_total": metrics.config_errors_total.get(),
        "emergency": {
            "no_healthy_upstreams": total > 0 && healthy == 0,
        },
        "events": st.shared.events.counts(),
        "resources": {
            "resident_memory_bytes": metrics.resident_memory_bytes.get(),
            "cpu_percent": metrics.cpu_percent.get(),
            "open_fds": crate::sysinfo::open_fd_count(),
        },
        "recent_failovers": st.shared.events.failover.recent(10),
        "recent_config_events": st.shared.events.config.recent(10),
        "recent_system_events": st.shared.events.system.recent(10),
    }))
}

fn upstream_counts(st: &ApiState) -> (usize, usize, usize, usize, usize) {
    let snap = st.shared.registry.snapshot();
    let total = snap.len();
    let mut enabled = 0;
    let mut healthy = 0;
    let mut degraded = 0;
    let mut down = 0;
    for u in &snap {
        if u.is_enabled() {
            enabled += 1;
        }
        match u.health_status() {
            HealthStatus::Up => healthy += 1,
            HealthStatus::Degraded => degraded += 1,
            HealthStatus::Down => down += 1,
        }
    }
    (total, enabled, healthy, degraded, down)
}

async fn metrics_endpoint(State(st): State<ApiState>) -> Response {
    let body = st.shared.metrics.render();
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Configuration export / import / events
// ---------------------------------------------------------------------------

async fn export_config(State(st): State<ApiState>) -> Result<Json<Value>, ApiError> {
    let app = st.shared.app.load();
    let toml_text = app.to_toml().map_err(ApiError::Internal)?;
    Ok(Json(json!({
        "toml": toml_text,
        "path": st.shared.config_path.get().map(|p| p.display().to_string()),
        "source": st.shared.config_state().source,
        "error": st.shared.config_state().error,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportConfigRequest {
    toml: String,
    /// Also write the imported configuration to disk (default true).
    #[serde(default = "default_true")]
    persist: bool,
}

fn default_true() -> bool {
    true
}

async fn import_config(
    State(st): State<ApiState>,
    Json(req): Json<ImportConfigRequest>,
) -> Result<Json<Value>, ApiError> {
    let _guard = st.mutation.lock().await;

    // Parse + validate BEFORE touching runtime state: an invalid import must
    // leave the running configuration completely unchanged.
    let next = AppConfig::parse(&req.toml).map_err(ApiError::BadRequest)?;

    st.shared
        .replace_config(next)
        .map_err(ApiError::BadRequest)?;

    let (persisted, persist_error) = if req.persist {
        persist_or_report(&st)
    } else {
        (false, None)
    };

    st.shared.record_config_event(
        "import",
        json!({
            "upstreams": st.shared.app.load().upstreams.len(),
            "persisted": persisted,
            "persist_error": persist_error,
        }),
    );

    Ok(Json(json!({
        "status": "ok",
        "persisted": persisted,
        "persist_error": persist_error,
        "upstreams": st.shared.app.load().upstreams.len(),
    })))
}

#[derive(Deserialize)]
struct EventsQuery {
    /// `config`, `health`, `failover` or `system` (default: all merged).
    kind: Option<String>,
    limit: Option<usize>,
}

async fn config_events(State(st): State<ApiState>) -> Json<Value> {
    let events = st.shared.events.config.recent(100);
    Json(json!({ "events": events }))
}

async fn all_events(
    State(st): State<ApiState>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 256);
    let mut events: Vec<Event> = match q.kind.as_deref() {
        Some("config") => st.shared.events.config.recent(limit),
        Some("health") => st.shared.events.health.recent(limit),
        Some("failover") => st.shared.events.failover.recent(limit),
        Some("system") => st.shared.events.system.recent(limit),
        Some(other) => {
            return Err(ApiError::BadRequest(format!(
                "unknown kind '{other}' (expected config|health|failover|system)"
            )))
        }
        None => merge_event_shares(
            [
                st.shared.events.config.recent(limit),
                st.shared.events.health.recent(limit),
                st.shared.events.failover.recent(limit),
                st.shared.events.system.recent(limit),
            ],
            limit,
        ),
    };
    events.sort_by_key(|e| std::cmp::Reverse(e.ts_ms));
    Ok(Json(json!({ "events": events })))
}

/// Merge per-kind event pools (each newest-first) into one newest-first
/// window of at most `limit` events.
///
/// Every kind first gets `ceil(limit / kinds)` slots (minimum 4 while the
/// limit allows), so a flood in one ring cannot evict the other kinds; the
/// remaining slots go to whatever is newest across all pools.
fn merge_event_shares(mut pools: [Vec<Event>; 4], limit: usize) -> Vec<Event> {
    let kinds = pools.len() as f64;
    let share = ((limit as f64 / kinds).ceil() as usize).max(4.min(limit));
    let mut out: Vec<Event> = Vec::with_capacity(limit);
    for pool in &mut pools {
        let take = share.min(pool.len()).min(limit.saturating_sub(out.len()));
        for _ in 0..take {
            if pool.is_empty() {
                break;
            }
            out.push(pool.remove(0));
        }
        if out.len() >= limit {
            break;
        }
    }
    // Top up with the globally newest leftovers.
    while out.len() < limit {
        let mut best: Option<usize> = None;
        for (i, pool) in pools.iter().enumerate() {
            if let Some(e) = pool.first() {
                if best.is_none()
                    || pools[best.unwrap()]
                        .first()
                        .is_some_and(|b| e.ts_ms > b.ts_ms)
                {
                    best = Some(i);
                }
            }
        }
        match best {
            Some(i) => out.push(pools[i].remove(0)),
            None => break,
        }
    }
    out.truncate(limit);
    out.sort_by_key(|e| std::cmp::Reverse(e.ts_ms));
    out
}

// ---------------------------------------------------------------------------
// Time series (native history + Prometheus proxy)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct HistoryQuery {
    range: Option<String>,
}

#[derive(Deserialize)]
struct TimeseriesQuery {
    range: Option<String>,
    /// `auto` (default), `native` or `prometheus`.
    source: Option<String>,
}

/// Gateway-native time series (always available, no external dependency).
async fn history(
    State(st): State<ApiState>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Value>, ApiError> {
    let range = q.range.unwrap_or_else(|| "5m".into());
    crate::history::range_secs(&range).map_err(ApiError::BadRequest)?;
    let v = st
        .shared
        .history
        .query(&range)
        .map_err(ApiError::Internal)?;
    Ok(Json(v))
}

/// Normalized time series from the requested source.
async fn timeseries(
    State(st): State<ApiState>,
    Query(q): Query<TimeseriesQuery>,
) -> Result<Json<Value>, ApiError> {
    let range = q.range.unwrap_or_else(|| "5m".into());
    crate::history::range_secs(&range).map_err(ApiError::BadRequest)?;
    let source = q.source.as_deref().unwrap_or("auto");
    let prom_enabled = st.shared.app.load().monitoring.enabled();

    match source {
        "native" => {
            let v = st
                .shared
                .history
                .query(&range)
                .map_err(ApiError::Internal)?;
            Ok(Json(v))
        }
        "prometheus" => {
            if !prom_enabled {
                return Err(ApiError::BadRequest(
                    "prometheus source not configured (set [monitoring].prometheus_url or RES_PROMETHEUS_URL)"
                        .into(),
                ));
            }
            fetch_prometheus(&st, &range)
                .await
                .map(Json)
                .map_err(ApiError::Internal)
        }
        "auto" => {
            if prom_enabled {
                match fetch_prometheus(&st, &range).await {
                    Ok(v) => Ok(Json(v)),
                    Err(e) => {
                        let mut v = st
                            .shared
                            .history
                            .query(&range)
                            .map_err(ApiError::Internal)?;
                        v["fallback_reason"] = json!(e);
                        Ok(Json(v))
                    }
                }
            } else {
                let mut v = st
                    .shared
                    .history
                    .query(&range)
                    .map_err(ApiError::Internal)?;
                v["fallback_reason"] = json!("prometheus_not_configured");
                Ok(Json(v))
            }
        }
        other => Err(ApiError::BadRequest(format!(
            "unknown source '{other}' (expected auto|native|prometheus)"
        ))),
    }
}

/// Top client addresses and top queried names (traffic introspection).
/// Addresses follow the configured `client_ip_privacy` policy (masked by
/// default); tables are bounded, so `tracked.skipped_requests` reports
/// requests that could not be attributed instead of hiding them.
#[derive(Deserialize)]
struct TopQuery {
    limit: Option<usize>,
    /// Sort key for the client table: `requests` (default), `bytes`,
    /// `failed`, `timeouts`, `rps`, `latency`.
    sort: Option<String>,
}

fn clamp_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(10).clamp(1, 100)
}

async fn top_clients(State(st): State<ApiState>, Query(q): Query<TopQuery>) -> Json<Value> {
    let privacy = st.shared.rt.load().client_ip_privacy;
    let stats = st.shared.traffic.client_stats();
    let sort = q
        .sort
        .as_deref()
        .and_then(crate::traffic::ClientSort::parse)
        .unwrap_or_default();
    let rows = st
        .shared
        .traffic
        .client_rows(clamp_limit(q.limit), sort, privacy);
    Json(json!({
        "privacy": privacy.as_str(),
        "sort": sort.as_str(),
        "tracked": stats,
        "rows": rows,
    }))
}

async fn top_domains(State(st): State<ApiState>, Query(q): Query<TopQuery>) -> Json<Value> {
    let stats = st.shared.traffic.domain_stats();
    let rows = st.shared.traffic.top_domains(clamp_limit(q.limit));
    Json(json!({
        "tracked": stats,
        "rows": crate::traffic::domain_rows(rows),
    }))
}

/// Prometheus reachability + configuration (for the dashboard source chip).
async fn monitoring_info(State(st): State<ApiState>) -> Json<Value> {
    let cfg = st.shared.app.load().monitoring.clone();
    if !cfg.enabled() {
        return Json(json!({
            "prometheus": { "configured": false, "url": Value::Null, "reachable": false },
        }));
    }
    let (reachable, error) = cached_probe(&st, &cfg.prometheus_url).await;
    Json(json!({
        "prometheus": {
            "configured": true,
            "url": cfg.prometheus_url,
            "reachable": reachable,
            "error": error,
        },
    }))
}

async fn cached_probe(st: &ApiState, url: &str) -> (bool, Option<String>) {
    const TTL: Duration = Duration::from_secs(10);
    {
        let g = st.probe.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = g.as_ref() {
            if p.url == url && p.at.elapsed() < TTL {
                return (p.reachable, p.error.clone());
            }
        }
    }
    let (reachable, error) = match prom::PromClient::new(url) {
        Ok(c) => match c.probe().await {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e)),
        },
        Err(e) => (false, Some(e)),
    };
    let mut g = st.probe.lock().unwrap_or_else(|e| e.into_inner());
    *g = Some(ProbeState {
        at: Instant::now(),
        url: url.to_string(),
        reachable,
        error: error.clone(),
    });
    (reachable, error)
}

/// Fetch every canonical series from Prometheus in parallel and normalize
/// into the same payload shape as the native history endpoint.
async fn fetch_prometheus(st: &ApiState, range: &str) -> Result<Value, String> {
    let url = st.shared.app.load().monitoring.prometheus_url.clone();
    let url = url.trim().to_string();
    if url.is_empty() {
        return Err("prometheus not configured".into());
    }
    let client = prom::PromClient::new(&url)?;
    let range_secs = crate::history::range_secs(range)?;

    let step = (range_secs / 300).max(5);
    let w = format!("{}s", step.max(15));
    let end = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let start = end - range_secs as f64;

    let mut jobs: Vec<(String, &'static str, String)> = Vec::new();
    for (key, expr) in prom::global_exprs(&w) {
        jobs.push(("__global__".into(), key, expr));
    }
    let up_names: Vec<String> = st
        .shared
        .registry
        .snapshot()
        .iter()
        .map(|u| u.config().name)
        .collect();
    for name in up_names {
        for (key, expr) in prom::upstream_exprs(&name, &w) {
            jobs.push((name.clone(), key, expr));
        }
    }

    let mut set = tokio::task::JoinSet::new();
    let jobs_total = jobs.len();
    for (scope, key, expr) in jobs {
        let c = client.clone();
        set.spawn(async move {
            let r = c.query_range(&expr, start, end, step).await;
            (scope, key, r)
        });
    }

    let mut results: HashMap<(String, &'static str), Result<Value, String>> = HashMap::new();
    let mut errors: Vec<String> = Vec::new();
    let mut ok_count = 0usize;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((scope, key, Ok(v))) => {
                ok_count += 1;
                results.insert((scope, key), Ok(v));
            }
            Ok((scope, key, Err(e))) => {
                results.insert((scope, key), Err(e.clone()));
                errors.push(e);
            }
            Err(e) => errors.push(format!("task join failed: {e}")),
        }
    }
    if ok_count == 0 {
        return Err(errors
            .into_iter()
            .next()
            .unwrap_or_else(|| "no data from Prometheus".into()));
    }

    // Deterministic timestamp axis: always the requested window's step grid.
    // Deriving it from "whichever matrix happens to come out of the HashMap
    // first" made the axis — and therefore every chart — depend on iteration
    // order, so identical requests could return 301 points or 1.
    let ts = prom::step_axis(start, end, step);

    let mut series = serde_json::Map::new();
    for key in prom::GLOBAL_SERIES {
        let pts = results
            .get(&("__global__".to_string(), *key))
            .map(|r| match r {
                Ok(v) => prom::matrix_to_points(v, &ts),
                Err(_) => vec![None; ts.len()],
            })
            .unwrap_or_else(|| vec![None; ts.len()]);
        series.insert((*key).to_string(), points_json(&ts, &pts));
    }

    let mut upstreams = serde_json::Map::new();
    let mut names: Vec<String> = results
        .keys()
        .map(|(scope, _)| scope.clone())
        .filter(|s| s != "__global__")
        .collect();
    names.sort();
    names.dedup();
    for name in names {
        let mut us = serde_json::Map::new();
        for key in prom::UPSTREAM_SERIES {
            let pts = results
                .get(&(name.clone(), *key))
                .map(|r| match r {
                    Ok(v) => prom::matrix_to_points(v, &ts),
                    Err(_) => vec![None; ts.len()],
                })
                .unwrap_or_else(|| vec![None; ts.len()]);
            us.insert((*key).to_string(), points_json(&ts, &pts));
        }
        upstreams.insert(name, Value::Object(us));
    }

    errors.sort();
    errors.dedup();
    errors.truncate(8);
    Ok(json!({
        "source": "prometheus",
        "prometheus_url": url,
        "range": range,
        "start_ms": (start * 1000.0).round() as u64,
        "end_ms": (end * 1000.0).round() as u64,
        "step_seconds": step,
        "generated_ms": (end * 1000.0).round() as u64,
        "points": ts.len(),
        "queries_ok": ok_count,
        "queries_total": jobs_total,
        "partial_errors": errors,
        "series": Value::Object(series),
        "upstreams": Value::Object(upstreams),
    }))
}

fn points_json(ts: &[u64], vals: &[Option<f64>]) -> Value {
    let mut arr = Vec::with_capacity(ts.len());
    for (t, v) in ts.iter().zip(vals) {
        let v = match v {
            Some(v) if v.is_finite() => json!((v * 100.0).round() / 100.0),
            _ => Value::Null,
        };
        arr.push(json!([t, v]));
    }
    Value::Array(arr)
}

// ---------------------------------------------------------------------------
// Upstream CRUD
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUpstreamRequest {
    pub name: String,
    pub address: String,
    pub port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub enabled: Option<bool>,
    pub priority: Option<u32>,
    pub weight: Option<u32>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateUpstreamRequest {
    pub name: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub enabled: Option<bool>,
    pub priority: Option<u32>,
    pub weight: Option<u32>,
    pub timeout_ms: Option<u64>,
    /// Explicitly clear the timeout override.
    pub clear_timeout: Option<bool>,
}

fn parse_address(s: &str) -> Result<IpAddr, ApiError> {
    s.trim()
        .parse()
        .map_err(|e| ApiError::BadRequest(format!("invalid address '{s}': {e}")))
}

async fn list_upstreams(State(st): State<ApiState>) -> Json<Value> {
    use crate::upstream::HealthStatus;

    let rows: Vec<crate::upstream::UpstreamStats> = st
        .shared
        .registry
        .snapshot()
        .iter()
        .map(|u| u.stats())
        .collect();

    // Selection semantics (mirrors `selection.rs`): a DOWN upstream is scored
    // 0 while any upstream is UP, so it is *kept* as a fallback but not used.
    let any_up = rows.iter().any(|r| r.health == HealthStatus::Up);
    let mut eligible = Vec::new();
    let mut in_use = Vec::new();
    let mut idle = Vec::new();
    let mut avoided = Vec::new();
    let mut disabled = Vec::new();
    let (mut up, mut degraded, mut down) = (0usize, 0usize, 0usize);
    let mut sum_qps = 0.0f64;

    let upstreams: Vec<Value> = rows
        .iter()
        .map(|r| {
            let mut v = serde_json::to_value(r).expect("serializable");
            if !r.enabled {
                disabled.push(r.name.clone());
                v["eligible"] = Value::Bool(false);
                return v;
            }
            match r.health {
                HealthStatus::Up => up += 1,
                HealthStatus::Degraded => degraded += 1,
                HealthStatus::Down => down += 1,
            }
            let is_eligible = !(r.health == HealthStatus::Down && any_up);
            v["eligible"] = Value::Bool(is_eligible);
            sum_qps += r.qps;
            if is_eligible {
                eligible.push(r.name.clone());
                if r.in_use {
                    in_use.push(r.name.clone());
                } else {
                    idle.push(r.name.clone());
                }
            } else {
                avoided.push(r.name.clone());
            }
            v
        })
        .collect();

    Json(json!({
        "upstreams": upstreams,
        "state": {
            "total": rows.len(),
            "up": up,
            "degraded": degraded,
            "down": down,
            "disabled": disabled.len(),
            "eligible": eligible,
            "in_use": in_use,
            "idle": idle,
            "avoided": avoided,
            "disabled_names": disabled,
            "total_qps": round2(sum_qps),
            // Same rule as /api/status: no UP upstream while any exists.
            "emergency": !rows.is_empty() && up == 0,
        },
    }))
}

async fn get_upstream(
    State(st): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    st.shared
        .registry
        .get(id)
        .map(|u| Json(json!({ "upstream": serde_json::to_value(u.stats()).unwrap() })))
        .ok_or_else(|| ApiError::NotFound(format!("upstream {id} not found")))
}

async fn create_upstream(
    State(st): State<ApiState>,
    Json(req): Json<CreateUpstreamRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let _guard = st.mutation.lock().await;
    let current: AppConfig = (**st.shared.app.load()).clone();

    let mut candidate = UpstreamConfig {
        id: 0,
        name: req.name.trim().to_string(),
        address: parse_address(&req.address)?,
        port: req.port.unwrap_or(53),
        protocol: req.protocol.unwrap_or(Protocol::Udp),
        enabled: req.enabled.unwrap_or(true),
        priority: req.priority.unwrap_or(1),
        weight: req.weight.unwrap_or(1),
        timeout_ms: req.timeout_ms,
    };
    candidate.validate().map_err(ApiError::BadRequest)?;
    if current.upstreams.iter().any(|u| u.name == candidate.name) {
        return Err(ApiError::Conflict(format!(
            "upstream name '{}' already exists",
            candidate.name
        )));
    }

    let mut list = current.upstreams.clone();
    let next_id = list.iter().map(|u| u.id).max().unwrap_or(0).max(0) + 1;
    candidate.id = next_id;
    list.push(candidate.clone());

    st.shared
        .apply_upstreams(list)
        .map_err(ApiError::Internal)?;

    let (persisted, persist_error) = persist_or_report(&st);
    st.shared.record_config_event(
        "create",
        json!({ "id": next_id, "name": candidate.name, "persisted": persisted }),
    );

    let stats = st
        .shared
        .registry
        .get(next_id)
        .map(|u| serde_json::to_value(u.stats()).unwrap())
        .unwrap_or(Value::Null);
    Ok((
        StatusCode::CREATED,
        Json(json!({ "upstream": stats, "persisted": persisted, "persist_error": persist_error })),
    ))
}

async fn patch_upstream(
    State(st): State<ApiState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateUpstreamRequest>,
) -> Result<Json<Value>, ApiError> {
    let _guard = st.mutation.lock().await;
    let current: AppConfig = (**st.shared.app.load()).clone();

    let existing = current
        .upstreams
        .iter()
        .find(|u| u.id == id)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("upstream {id} not found")))?;

    let mut updated = existing.clone();
    if let Some(name) = &req.name {
        updated.name = name.trim().to_string();
    }
    if let Some(addr) = &req.address {
        updated.address = parse_address(addr)?;
    }
    if let Some(port) = req.port {
        updated.port = port;
    }
    if let Some(proto) = req.protocol {
        updated.protocol = proto;
    }
    if let Some(enabled) = req.enabled {
        updated.enabled = enabled;
    }
    if let Some(priority) = req.priority {
        updated.priority = priority;
    }
    if Some(true) == req.clear_timeout {
        updated.timeout_ms = None;
    } else if let Some(t) = req.timeout_ms {
        updated.timeout_ms = Some(t);
    }
    updated.validate().map_err(ApiError::BadRequest)?;
    if current
        .upstreams
        .iter()
        .any(|u| u.id != id && u.name == updated.name)
    {
        return Err(ApiError::Conflict(format!(
            "upstream name '{}' already exists",
            updated.name
        )));
    }

    let list: Vec<UpstreamConfig> = current
        .upstreams
        .iter()
        .map(|u| {
            if u.id == id {
                updated.clone()
            } else {
                u.clone()
            }
        })
        .collect();
    st.shared
        .apply_upstreams(list)
        .map_err(ApiError::Internal)?;

    let (persisted, persist_error) = persist_or_report(&st);
    st.shared.record_config_event(
        "update",
        json!({ "id": id, "name": updated.name, "persisted": persisted }),
    );

    let stats = st
        .shared
        .registry
        .get(id)
        .map(|u| serde_json::to_value(u.stats()).unwrap())
        .unwrap_or(Value::Null);
    Ok(Json(json!({
        "upstream": stats,
        "persisted": persisted,
        "persist_error": persist_error,
    })))
}

async fn delete_upstream(
    State(st): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let _guard = st.mutation.lock().await;
    let current: AppConfig = (**st.shared.app.load()).clone();

    let existing = current
        .upstreams
        .iter()
        .find(|u| u.id == id)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("upstream {id} not found")))?;

    let list: Vec<UpstreamConfig> = current
        .upstreams
        .into_iter()
        .filter(|u| u.id != id)
        .collect();
    st.shared
        .apply_upstreams(list)
        .map_err(ApiError::Internal)?;

    let (persisted, persist_error) = persist_or_report(&st);
    st.shared.record_config_event(
        "delete",
        json!({ "id": id, "name": existing.name, "persisted": persisted }),
    );

    Ok(Json(json!({
        "deleted": id,
        "persisted": persisted,
        "persist_error": persist_error,
    })))
}

/// Persist after a successful in-memory mutation. A persistence failure is
/// reported but never rolls back the applied configuration (the data plane
/// must keep running; `/api/diagnostics` surfaces the error). When no config
/// path is set the gateway runs purely in memory and reports `persisted=false`.
fn persist_or_report(st: &ApiState) -> (bool, Option<String>) {
    if st.shared.config_path.get().is_none() {
        return (false, None);
    }
    match st.shared.persist_config() {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e)),
    }
}

async fn test_upstream(
    State(st): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let runtime = st
        .shared
        .registry
        .get(id)
        .ok_or_else(|| ApiError::NotFound(format!("upstream {id} not found")))?;
    let cfg = runtime.config();
    let result = probe_once(&st.shared, &st.forwarder, &runtime).await;
    Ok(Json(json!({
        "upstream": cfg.name,
        "address": cfg.address.to_string(),
        "port": cfg.port,
        "protocol": cfg.protocol.to_string(),
        "result": result,
        "health": runtime.health_status(),
    })))
}

/// Recent recorded events for one upstream (health transitions + probes).
async fn upstream_events(
    State(st): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    if st.shared.registry.get(id).is_none() {
        return Err(ApiError::NotFound(format!("upstream {id} not found")));
    }
    let events = st.shared.events.health.recent_for_upstream(id, 50);
    Ok(Json(json!({ "events": events })))
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_statuses() {
        assert!(matches!(
            ApiError::BadRequest("x".into()),
            ApiError::BadRequest(_)
        ));
        let r = ApiError::NotFound("nope".into()).into_response();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let r = ApiError::Conflict("c".into()).into_response();
        assert_eq!(r.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn health_endpoint_returns_version() {
        let v = health().await;
        assert_eq!(v["status"], "ok");
        assert!(!v["version"].as_str().unwrap().is_empty());
    }

    #[test]
    fn invalid_import_request_is_rejected_by_serde() {
        let res: Result<ImportConfigRequest, _> = serde_json::from_str(r#"{"bogus": 1}"#);
        assert!(res.is_err());
    }

    #[test]
    fn merged_events_keep_every_kind_during_a_flood() {
        // 100 failovers, all newer than everything else: the merge must still
        // reserve room for the older config / health / system events.
        let mk = |action: &str, ts_ms: u64| {
            let mut e = Event::config(action, json!({}));
            e.ts_ms = ts_ms;
            e
        };
        let config = vec![mk("startup", 1_000), mk("apply", 2_000)];
        let health = vec![mk("transition", 3_000), mk("transition", 4_000)];
        let failover: Vec<Event> = (0..100).map(|i| mk("retry", 10_000 + i)).collect();
        let system = vec![mk("rate_limited", 5_000)];

        let out = merge_event_shares([config, health, failover, system], 20);
        assert!(out.len() <= 20);
        assert!(out.iter().any(|e| e.action == "startup"), "config kept");
        assert!(out.iter().any(|e| e.action == "transition"), "health kept");
        assert!(
            out.iter().any(|e| e.action == "rate_limited"),
            "system kept"
        );
        assert!(out.iter().any(|e| e.action == "retry"), "failovers kept");
        // Newest first.
        assert!(out.windows(2).all(|w| w[0].ts_ms >= w[1].ts_ms));
        // A small limit must not panic or go negative on the share math.
        let out = merge_event_shares([vec![mk("startup", 1)], vec![], vec![], vec![]], 1);
        assert_eq!(out.len(), 1);
    }
}
