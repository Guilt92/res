//! Axum control plane: REST API, Prometheus endpoint, dashboard hosting.
//!
//! The API is strictly a management plane: DNS query processing never calls
//! into it, never touches the file system or the network on its own, and
//! keeps working when this HTTP server is down. Configuration persistence is
//! a single atomic file write per mutation — there is no database anywhere.

use std::net::IpAddr;
use std::sync::Arc;

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

    json!({
        "uptime_seconds": st.shared.uptime().as_secs(),
        "qps": round2(st.shared.qps.current()),
        "queries_total": queries_total,
        "queries_udp": queries_udp,
        "queries_tcp": queries_tcp,
        "responses_total": responses,
        "success_count": success,
        "error_count": errors,
        "success_rate": if responses == 0 { 1.0 } else { success as f64 / responses as f64 },
        "error_rate": if responses == 0 { 0.0 } else { errors as f64 / responses as f64 },
        "latency": {
            "samples": lat.count,
            "last_ms": round2(lat.last_ms),
            "avg_ms": round2(lat.avg_ms),
            "p50_ms": round2(lat.p50_ms),
            "p95_ms": round2(lat.p95_ms),
            "p99_ms": round2(lat.p99_ms),
        },
        "cache": {
            "enabled": st.shared.rt.load().cache.enabled,
            "entries": st.shared.cache.len(),
            "hits": hits,
            "misses": misses,
            "hit_ratio": if cache_reads == 0 { 0.0 } else { hits as f64 / cache_reads as f64 },
        },
        "upstreams": {
            "total": total,
            "enabled": enabled,
            "healthy": healthy,
            "degraded": degraded,
            "down": down,
        },
        "failovers": metrics.failovers_total.get(),
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
            "open_fds": open_fd_count(),
        },
        "recent_failovers": st.shared.events.failover.recent(10),
        "recent_config_events": st.shared.events.config.recent(10),
    }))
}

/// Open file descriptors of this process (0 when unavailable).
fn open_fd_count() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/proc/self/fd")
            .map(|d| d.count() as u64)
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
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
    /// `config`, `health` or `failover` (default: all three merged).
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
        Some(other) => {
            return Err(ApiError::BadRequest(format!(
                "unknown kind '{other}' (expected config|health|failover)"
            )))
        }
        None => {
            let mut all = st.shared.events.config.recent(limit);
            all.extend(st.shared.events.health.recent(limit));
            all.extend(st.shared.events.failover.recent(limit));
            all.sort_by_key(|e| std::cmp::Reverse(e.ts_ms));
            all.truncate(limit);
            all
        }
    };
    events.sort_by_key(|e| std::cmp::Reverse(e.ts_ms));
    Ok(Json(json!({ "events": events })))
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
    let upstreams: Vec<Value> = st
        .shared
        .registry
        .snapshot()
        .iter()
        .map(|u| serde_json::to_value(u.stats()).expect("serializable"))
        .collect();
    Json(json!({ "upstreams": upstreams }))
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
}
