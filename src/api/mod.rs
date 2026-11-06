//! Axum control plane: REST API, Prometheus endpoint, dashboard hosting.
//!
//! The API is strictly a management plane: DNS query processing never calls
//! into it, never touches the file system or the network on its own, and
//! keeps working when this HTTP server is down. Configuration persistence is
//! a single atomic file write per mutation — there is no database anywhere.
//!
//! Configuration updates swap an immutable `ArcSwap` snapshot: in-flight DNS
//! queries keep the snapshot they started with and finish safely; queries
//! accepted after the swap observe the new configuration immediately.
//!
//! Authentication: whenever a password (`RES_ADMIN_PASSWORD` / credentials
//! file) or `server.api_token` is configured, every `/api/*` route except
//! `/api/health`, `/api/auth/info`, and `/api/auth/login` requires a session
//! cookie (viewer or admin) or `Authorization: Bearer <api_token>`.
//! Mutations additionally require the admin role and, for cookie-authenticated
//! requests, a matching `X-CSRF-Token` header (double-submit). Starting with
//! no credentials is refused unless `[auth].allow_open_mode = true` is set
//! explicitly for isolated development.

mod acl;
mod assets;
mod auth_routes;
mod cache;
mod client_ip;
mod config_routes;
mod policy;
mod prom;
mod proxy;
mod upstreams;
use acl::*;
use auth_routes::{auth_info, login, logout, revoke_sessions, rotate_password, session_info};
use cache::*;
use config_routes::*;
use policy::*;
use proxy::*;
use upstreams::*;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::serve::IncomingStream;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

/// Socket peer information for both the plain and TLS Axum listeners. Axum's
/// built-in `ConnectInfo<SocketAddr>` only knows its own `TcpListener`; a local
/// newtype lets the TLS listener carry the same peer address without trusting
/// proxy headers.
#[derive(Debug, Clone, Copy)]
pub struct ClientAddr(pub std::net::SocketAddr);

impl Connected<IncomingStream<'_, tokio::net::TcpListener>> for ClientAddr {
    fn connect_info(stream: IncomingStream<'_, tokio::net::TcpListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

impl Connected<IncomingStream<'_, crate::tls::TlsListener>> for ClientAddr {
    fn connect_info(stream: IncomingStream<'_, crate::tls::TlsListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

use crate::acl::{AclAction, AclConfig, AclEntry, AclRules};
use crate::auth::{AuthState, LoginError, Role};
use crate::config::{AppConfig, Protocol, ProxyProtocol, UpstreamConfig};
use crate::dns::forward::Forwarder;
use crate::dns::msg::Rcode;
use crate::events::Event;
use crate::shared::Shared;
use crate::upstream::{health::probe_once, PoolCounts};

/// Name of the session cookie (HttpOnly, SameSite=Strict).
pub const SESSION_COOKIE: &str = "res_session";
/// Name of the CSRF cookie (readable by dashboard JS; double-submit).
pub const CSRF_COOKIE: &str = "res_csrf";

#[derive(Clone)]
pub struct ApiState {
    pub shared: Arc<Shared>,
    /// Serialises configuration mutations (create/update/delete/import).
    pub mutation: Arc<tokio::sync::Mutex<()>>,
    /// Bounded HTTP concurrency: at most `API_CONCURRENCY` handlers run at
    /// once; further requests wait briefly and then fail fast with 503.
    pub api_sem: Arc<tokio::sync::Semaphore>,
    /// Cached Prometheus reachability probe (refreshed at most every 10 s).
    probe: Arc<std::sync::Mutex<Option<ProbeState>>>,
    /// Password authentication state (sessions, lockouts, argon2 hashes).
    pub auth: Arc<AuthState>,
}

/// Cap on simultaneous HTTP handlers (each waiting request holds a
/// connection plus its buffered body — this is the memory ceiling).
const API_CONCURRENCY: usize = 256;
/// How long a request may wait for a concurrency permit before getting 503.
const API_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

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
    Unauthorized(String),
    /// 403: authenticated but not allowed (viewer attempting a mutation, or
    /// a cookie-authenticated mutation without a valid CSRF token).
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    /// 409: the operation is only allowed with an explicit confirmation
    /// (e.g. disabling the last enabled upstream).
    NeedsConfirm(String),
    /// 500: the candidate could not be made durable, so it was not applied.
    Persist(String),
    Internal(String),
}

impl ApiError {
    fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Unauthorized(_) => "unauthorized",
            ApiError::Forbidden(_) => "forbidden",
            ApiError::NotFound(_) => "not_found",
            ApiError::Conflict(_) => "conflict",
            ApiError::NeedsConfirm(_) => "confirm_required",
            ApiError::Persist(_) => "persist_failed",
            ApiError::Internal(_) => "internal",
        }
    }

    fn message(&self) -> &str {
        match self {
            ApiError::BadRequest(m)
            | ApiError::Unauthorized(m)
            | ApiError::Forbidden(m)
            | ApiError::NotFound(m)
            | ApiError::Conflict(m)
            | ApiError::NeedsConfirm(m)
            | ApiError::Persist(m)
            | ApiError::Internal(m) => m,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) | ApiError::NeedsConfirm(_) => StatusCode::CONFLICT,
            ApiError::Persist(_) | ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = json!({ "error": self.message(), "code": self.code() });
        (status, Json(body)).into_response()
    }
}

/// Extract the session token from the `Cookie` header.
fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == SESSION_COOKIE).then_some(v)
        })
        .next()
}

/// The authenticated principal of a request, if any.
#[derive(Debug, Clone)]
struct Principal {
    username: String,
    role: Role,
    /// True when authentication used the session cookie (CSRF applies).
    via_cookie: bool,
}

/// Resolve the request principal: bearer `api_token` (admin) first, then the
/// session cookie. `None` when the request is anonymous.
fn principal(st: &ApiState, headers: &HeaderMap) -> Option<Principal> {
    let token = st.shared.app.load().server.api_token.clone();
    if !token.is_empty() {
        let provided = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if ct_eq(provided.as_bytes(), token.as_bytes()) {
            return Some(Principal {
                username: "(api_token)".into(),
                role: Role::Admin,
                via_cookie: false,
            });
        }
    }
    if let Some(tok) = session_cookie(headers) {
        if let Some(sess) = st.auth.session(tok) {
            return Some(Principal {
                username: sess.username,
                role: sess.role,
                via_cookie: true,
            });
        }
    }
    None
}

/// CSRF double-submit check for cookie-authenticated mutations: the
/// `X-CSRF-Token` header must equal the session's CSRF token. Bearer-token
/// requests are exempt (no ambient credentials to ride).
fn check_csrf(st: &ApiState, headers: &HeaderMap, op: &str) -> Result<(), ApiError> {
    let Some(tok) = session_cookie(headers) else {
        return Err(ApiError::Forbidden("session cookie required".into()));
    };
    let Some(sess) = st.auth.session(tok) else {
        return Err(ApiError::Unauthorized("session expired".into()));
    };
    let provided = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if ct_eq(provided.as_bytes(), sess.csrf.as_bytes()) {
        Ok(())
    } else {
        st.shared.record_config_event(
            "unauthorized",
            json!({ "op": op, "outcome": "denied", "reason": "csrf" }),
        );
        Err(ApiError::Forbidden(
            "missing or invalid X-CSRF-Token header".into(),
        ))
    }
}

/// Authorization for configuration-changing endpoints.
///
/// Order: bearer `api_token` (admin) → admin session (+ CSRF when via
/// cookie) → open (only when password auth is disabled and no token is
/// configured). Viewer sessions are rejected. Failures are audited (op only —
/// never the presented credentials).
fn require_admin(st: &ApiState, headers: &HeaderMap, op: &str) -> Result<(), ApiError> {
    match principal(st, headers) {
        Some(p) if p.role == Role::Admin => {
            if p.via_cookie {
                check_csrf(st, headers, op)?;
            }
            Ok(())
        }
        Some(p) => {
            st.shared.record_config_event(
                "unauthorized",
                json!({ "op": op, "outcome": "denied", "role": p.role.as_str() }),
            );
            Err(ApiError::Forbidden(format!(
                "admin role required (authenticated as {})",
                p.role.as_str()
            )))
        }
        None => {
            if !auth_configured(st) && st.auth.open_mode_allowed() {
                // Explicit development posture: no password and no token.
                return Ok(());
            }
            st.shared
                .record_config_event("unauthorized", json!({ "op": op, "outcome": "denied" }));
            Err(ApiError::Unauthorized(
                "authentication required (session cookie or Authorization: Bearer <token>)".into(),
            ))
        }
    }
}

/// True when any control-plane credential exists (password auth or bearer
/// token). In this mode read routes are no longer anonymous.
fn auth_configured(st: &ApiState) -> bool {
    st.auth.enabled() || !st.shared.app.load().server.api_token.is_empty()
}

/// Length-independent byte-wise equality (avoids early-out on first diff).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Optimistic concurrency: reject mutations prepared against an outdated
/// configuration snapshot. `expected == None` skips the check (API
/// compatibility for clients that do not opt in).
fn check_generation(st: &ApiState, expected: Option<u64>, op: &str) -> Result<(), ApiError> {
    if let Some(g) = expected {
        let cur = st.shared.config_generation();
        if g != cur {
            st.shared.record_config_event(
                "stale_update_rejected",
                json!({ "op": op, "expected": g, "actual": cur, "outcome": "rejected" }),
            );
            return Err(ApiError::Conflict(format!(
                "stale configuration: request has generation {g}, active generation is {cur}; \
                 reload the upstream list and retry"
            )));
        }
    }
    Ok(())
}

/// Refuse operations that would leave zero enabled upstreams unless the
/// caller explicitly confirms. "Enabled" is checked against the *configuration*
/// (health can be temporarily down for all upstreams without blocking admin
/// recovery actions).
fn check_last_usable(
    st: &ApiState,
    next: &[UpstreamConfig],
    confirm: bool,
    op: &str,
    name: &str,
) -> Result<(), ApiError> {
    let currently_enabled = st
        .shared
        .app
        .load()
        .upstreams
        .iter()
        .filter(|u| u.enabled)
        .count();
    let next_enabled = next.iter().filter(|u| u.enabled).count();
    if currently_enabled > 0 && next_enabled == 0 && !confirm {
        st.shared.record_config_event(
            "confirm_required",
            json!({ "op": op, "upstream": name, "outcome": "rejected" }),
        );
        return Err(ApiError::NeedsConfirm(format!(
            "this {op} would leave zero enabled upstreams (the gateway would answer \
             SERVFAIL for all queries); retry with confirm=true to proceed"
        )));
    }
    Ok(())
}

/// Audit a rejected configuration change, then hand the error back to the
/// caller. Detail never contains secrets.
fn reject(st: &ApiState, action: &str, mut detail: Value, err: ApiError) -> ApiError {
    if let Value::Object(ref mut m) = detail {
        m.insert("outcome".into(), "rejected".into());
        m.insert("reason".into(), Value::String(err.message().to_string()));
    }
    st.shared.record_config_event(action, detail);
    err
}

pub fn router(shared: Arc<Shared>, auth: Arc<AuthState>) -> Router {
    let state = ApiState {
        shared,
        mutation: Arc::new(tokio::sync::Mutex::new(())),
        api_sem: Arc::new(tokio::sync::Semaphore::new(API_CONCURRENCY)),
        probe: Arc::new(std::sync::Mutex::new(None)),
        auth,
    };

    let dashboard = state
        .shared
        .app
        .load()
        .server
        .dashboard_dir
        .clone()
        .filter(|d| d.exists());

    // Unauthenticated: liveness probe, login, and the capability probe the
    // dashboard needs to choose between password and token sign-in.
    let open = Router::new()
        .route("/api/health", get(health))
        .route("/api/auth/login", post(login))
        .route("/api/auth/info", get(auth_info));

    // Everything else requires a principal when password auth is enabled.
    let protected = Router::new()
        .route("/api/auth/session", get(session_info).delete(logout))
        .route("/api/auth/sessions", axum::routing::delete(revoke_sessions))
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
        .route("/api/config/rollback", post(rollback_config))
        .route("/api/config/events", get(config_events))
        .route("/api/events", get(all_events))
        .route("/api/history", get(history))
        .route("/api/timeseries", get(timeseries))
        .route("/api/clients", get(top_clients))
        .route("/api/domains", get(top_domains))
        .route("/api/monitoring", get(monitoring_info))
        .route("/api/acl", get(get_acl).put(put_acl))
        .route("/api/acl/entries", post(create_acl_entry))
        .route(
            "/api/acl/entries/{id}",
            patch(patch_acl_entry).delete(delete_acl_entry),
        )
        .route("/api/cache", get(get_cache).put(put_cache))
        .route("/api/cache/clear", post(clear_cache))
        .route("/api/proxy", get(get_proxy).put(put_proxy))
        .route("/api/proxy/test", post(test_proxy))
        .route(
            "/api/health/config",
            get(get_health_config).put(put_health_config),
        )
        .route("/api/selection", get(get_selection).put(put_selection))
        .route("/api/auth/rotate-password", post(rotate_password))
        .route_layer(middleware::from_fn_with_state(state.clone(), read_guard));

    // /metrics: open by default (Prometheus scrapes it without cookies);
    // when [auth].protect_metrics is on, only RES_METRICS_TOKEN is accepted.
    let metrics = Router::new()
        .route("/metrics", get(metrics_endpoint))
        .route_layer(middleware::from_fn_with_state(state.clone(), metrics_guard));

    // Bounded control-plane concurrency (outermost of the API routers, so
    // it caps argon2 logins and mutations too). Registered before the
    // dashboard fallback so static files never consume permits: the panel
    // must stay loadable while the API is shedding load.
    let app = open
        .merge(protected)
        .merge(metrics)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            api_concurrency,
        ))
        .with_state(state.clone());

    let app = match dashboard {
        Some(dir) => {
            // Async, in-memory, ETag/compression-aware (see `assets`).
            let assets = Arc::new(assets::Assets::new(dir));
            app.fallback(move |req: axum::extract::Request| {
                let assets = Arc::clone(&assets);
                async move {
                    assets
                        .serve(req.method(), req.uri().path(), req.headers())
                        .await
                }
            })
        }
        // No dashboard: still answer unknown paths with JSON, never an
        // empty opaque 404 (clients get a machine-readable error).
        None => app.fallback(|req: axum::extract::Request| async move {
            ApiError::NotFound(format!("no route for {}", req.uri().path())).into_response()
        }),
    };
    app.layer(middleware::from_fn_with_state(
        state.clone(),
        security_headers,
    ))
}

/// Bounded HTTP concurrency (audit GAP-3): at most `API_CONCURRENCY`
/// handlers run at once; a request waits up to `API_BUSY_TIMEOUT` for a
/// permit and then fails fast with a typed JSON 503. Bounding *in-flight*
/// handlers is the memory ceiling; bounding the *wait queue* too keeps a
/// slow backend from accumulating an unbounded pile of parked connections.
async fn api_concurrency(
    State(st): State<ApiState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    match tokio::time::timeout(API_BUSY_TIMEOUT, st.api_sem.acquire()).await {
        Ok(Ok(_permit)) => next.run(req).await,
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "control plane at capacity, retry shortly",
                "code": "busy",
            })),
        )
            .into_response(),
    }
}

/// Dashboard assets are external files, so scripts can be locked to `self`.
/// `style-src-attr` permits the chart/canvas markup that still uses inline
/// `style` attributes; inline `<style>`/`<script>` blocks are not allowed.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self';      style-src 'self'; img-src 'self' data:;      font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self';      frame-ancestors 'none'; object-src 'none'";

/// Response headers for every API/dashboard reply: MIME sniffing off,
/// framing off, no referrer leakage, CSP hardened for external dashboard
/// assets, and no shared/browser caching for authenticated API payloads
/// (which can contain configuration and session metadata).
async fn security_headers(
    State(st): State<ApiState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let tls = st.shared.app.load().server.tls_enabled();
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        "content-security-policy",
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    if tls {
        // Only sent when this listener terminates TLS itself. Reverse-proxy
        // deployments should set HSTS at the proxy.
        h.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    h.insert(
        "x-permitted-cross-domain-policies",
        HeaderValue::from_static("none"),
    );
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if path.starts_with("/api/") || path == "/metrics" {
        // Sessions, CSRF tokens, config exports and live stats must never be
        // stored by a shared cache or replayed from the browser back/forward
        // cache after logout.
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    res
}

/// Read-route guard: whenever any credential is configured (password auth or
/// bearer token), every read route requires a live session (viewer or admin)
/// or the bearer api_token. `/api/health`, `/api/auth/info`, and
/// `/api/auth/login` are registered before the route_layer and stay open.
/// Only the explicit development open mode is anonymous.
async fn read_guard(
    State(st): State<ApiState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    if !auth_configured(&st) {
        if st.auth.open_mode_allowed() {
            return next.run(req).await;
        }
        return ApiError::Unauthorized(
            "authentication is required but no credentials are configured; \
             set server.api_token or [auth].allow_open_mode for development"
                .into(),
        )
        .into_response();
    }
    match principal(&st, req.headers()) {
        Some(_) => next.run(req).await,
        None => {
            st.shared.record_config_event(
                "unauthorized",
                serde_json::json!({ "op": "read", "outcome": "denied" }),
            );
            ApiError::Unauthorized(
                "authentication required (session cookie or Authorization: Bearer <token>)".into(),
            )
            .into_response()
        }
    }
}

/// `/metrics` guard: open by default (Prometheus scrapes without cookies).
/// When `[auth].protect_metrics` is on, only a dedicated metrics bearer token
/// is accepted. Administrator API tokens and dashboard sessions are
/// intentionally not valid here, so a leak of the scrape credential cannot
/// grant control-plane access. If no `RES_METRICS_TOKEN` is configured the
/// endpoint fails closed with 401 rather than falling back to another
/// credential.
async fn metrics_guard(
    State(st): State<ApiState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let (protected, configured) = {
        let app = st.shared.app.load();
        (app.auth.protect_metrics, app.auth.metrics_token.clone())
    };
    if !protected {
        return next.run(req).await;
    }
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !configured.is_empty() && ct_eq(provided.as_bytes(), configured.as_bytes()) {
        next.run(req).await
    } else {
        ApiError::Unauthorized(
            "metrics require the dedicated RES_METRICS_TOKEN bearer credential".into(),
        )
        .into_response()
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

    let counts = upstream_counts(&st);
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
            "api_tls": app.server.tls_enabled(),
        },
        "config": {
            "path": st.shared.config_path.get().map(|p| p.display().to_string()),
            "source": cfg_state.source,
            "error": cfg_state.error,
            "warnings": app.warnings(),
            "generation": st.shared.config_generation(),
        },
        "auth": {
            "required": auth_configured(&st),
            "open_mode": !auth_configured(&st) && st.auth.open_mode_allowed(),
            "password_auth": st.auth.enabled(),
            "token_auth": !app.server.api_token.is_empty(),
            "admin_username": st.auth.admin_username(),
            "viewer_enabled": st.auth.viewer_enabled(),
            "session_ttl_secs": st.auth.session_ttl().as_secs(),
            "sessions": st.auth.session_count(),
        },
        "selector": {
            "strategy": st.shared.current_selector().describe(),
            "latency_reference_ms": rt.selection.latency_reference_ms,
            "tier_policy": match rt.selection.tier_policy {
                crate::config::TierPolicy::Strict => "strict",
                crate::config::TierPolicy::Shared => "shared",
            },
            "lower_tier_share": rt.selection.lower_tier_share,
            "degraded_policy": match rt.selection.degraded_policy {
                crate::config::DegradedPolicy::Usable => "usable",
                crate::config::DegradedPolicy::LastResort => "last_resort",
            },
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
            "max_memory_bytes": rt.cache.max_memory_bytes,
            "min_ttl_secs": rt.cache.min_ttl_secs,
            "max_ttl_secs": rt.cache.max_ttl_secs,
            "negative_max_ttl_secs": rt.cache.negative_max_ttl_secs,
            "memory_bytes": st.shared.cache.memory_bytes(),
        },
        "upstreams": {
            "total": counts.total,
            "enabled": counts.enabled,
            "disabled": counts.disabled,
            "healthy": counts.healthy,
            "degraded": counts.degraded,
            "recovering": counts.recovering,
            "usable": counts.usable,
            "down": counts.unhealthy,
            "unhealthy": counts.unhealthy,
        },
        "emergency": {
            "no_active_upstreams": counts.enabled == 0,
            "no_healthy_upstreams": counts.no_healthy(),
            "no_usable_upstreams": counts.emergency(),
            "active_upstreams": counts.enabled,
            "usable_upstreams": counts.usable,
        },
        "proxy": {
            "enabled": app.proxy.enabled,
            "protocol": app.proxy.protocol.as_str(),
            "address": app.proxy.address.to_string(),
            "port": app.proxy.port,
            "username": app.proxy.username,
            "password_set": !app.proxy.password.is_empty(),
            "connect_timeout_ms": app.proxy.connect_timeout_ms,
            "udp_supported": app.proxy.protocol.supports_udp(),
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
    let counts = upstream_counts(st);

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
            "evictions": metrics.cache_evictions_total.get(),
            "expirations": metrics.cache_expirations_total.get(),
            "memory_bytes": st.shared.cache.memory_bytes(),
            "capacity": st.shared.rt.load().cache.max_entries,
            "memory_capacity_bytes": st.shared.rt.load().cache.max_memory_bytes,
        },
        "upstreams": {
            "total": counts.total,
            "enabled": counts.enabled,
            "disabled": counts.disabled,
            "healthy": counts.healthy,
            "degraded": counts.degraded,
            "recovering": counts.recovering,
            "usable": counts.usable,
            "down": counts.unhealthy,
            "unhealthy": counts.unhealthy,
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
        "rrl_truncated": metrics.rrl_truncated_total.get(),
        "rrl_dropped": metrics.rrl_dropped_total.get(),
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

    let sel = st.shared.rt.load().selection.clone();
    let latency_ref = sel.latency_reference_ms;
    let min_probe_samples = sel.min_probe_samples;
    let upstreams: Vec<Value> = st
        .shared
        .registry
        .snapshot()
        .iter()
        .map(|u| {
            serde_json::to_value(u.stats_with_latency_ref(latency_ref, min_probe_samples))
                .expect("serializable")
        })
        .collect();
    let counts = upstream_counts(&st);

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
            "api_tls": app.server.tls_enabled(),
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
            "total": counts.total,
            "enabled": counts.enabled,
            "disabled": counts.disabled,
            "healthy": counts.healthy,
            "degraded": counts.degraded,
            "recovering": counts.recovering,
            "usable": counts.usable,
            "down": counts.unhealthy,
            "unhealthy": counts.unhealthy,
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
            "max_memory_bytes": rt.cache.max_memory_bytes,
            "min_ttl_secs": rt.cache.min_ttl_secs,
            "max_ttl_secs": rt.cache.max_ttl_secs,
            "negative_max_ttl_secs": rt.cache.negative_max_ttl_secs,
            "memory_bytes": st.shared.cache.memory_bytes(),
        },
        "proxy": {
            "enabled": app.proxy.enabled,
            "protocol": app.proxy.protocol.as_str(),
            "address": app.proxy.address.to_string(),
            "port": app.proxy.port,
            "username": app.proxy.username,
            "password_set": !app.proxy.password.is_empty(),
            "connect_timeout_ms": app.proxy.connect_timeout_ms,
            "udp_supported": app.proxy.protocol.supports_udp(),
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
            "no_active_upstreams": counts.enabled == 0,
            "no_healthy_upstreams": counts.no_healthy(),
            "no_usable_upstreams": counts.emergency(),
            "active_upstreams": counts.enabled,
            "usable_upstreams": counts.usable,
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

fn upstream_counts(st: &ApiState) -> PoolCounts {
    PoolCounts::from_snapshot(&st.shared.registry.snapshot())
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
/// Addresses follow the configured `client_ip_privacy` policy (full by
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
    let (reachable, error) = cached_probe(&st, &cfg).await;
    Json(json!({
        "prometheus": {
            "configured": true,
            "url": cfg.prometheus_url,
            "reachable": reachable,
            "error": error,
        },
    }))
}

async fn cached_probe(
    st: &ApiState,
    cfg: &crate::config::MonitoringConfig,
) -> (bool, Option<String>) {
    const TTL: Duration = Duration::from_secs(10);
    let url = cfg.prometheus_url.as_str();
    {
        let g = st.probe.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = g.as_ref() {
            if p.url == url && p.at.elapsed() < TTL {
                return (p.reachable, p.error.clone());
            }
        }
    }
    let (reachable, error) = match prom::PromClient::new(url) {
        Ok(c) => match c
            .with_basic_auth(&cfg.prometheus_username, &cfg.prometheus_password)
            .probe()
            .await
        {
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
    let monitoring = st.shared.app.load().monitoring.clone();
    let url = monitoring.prometheus_url.trim().to_string();
    if url.is_empty() {
        return Err("prometheus not configured".into());
    }
    let client = prom::PromClient::new(&url)?.with_basic_auth(
        &monitoring.prometheus_username,
        &monitoring.prometheus_password,
    );
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

/// Publish a validated candidate only after it is durable.
///
/// `next` must already have passed [`Shared::validate_config`]. When a config
/// path is set the candidate is written atomically first; a failed write
/// returns an error and leaves the active configuration untouched. Without a
/// config path the gateway is intentionally memory-only and `persisted=false`.
async fn commit_config(st: &ApiState, next: AppConfig) -> Result<bool, ApiError> {
    let Some(path) = st.shared.config_path.get().cloned() else {
        st.shared.replace_config(next).map_err(ApiError::Internal)?;
        return Ok(false);
    };
    let previous = AppConfig::clone(st.shared.app.load().as_ref());
    let candidate = next.clone();
    // save_atomic fsyncs the file and directory; never run that on a Tokio
    // worker. The mutation lock is still held by the caller, so serializing
    // through the blocking pool cannot reorder API mutations.
    let shared = Arc::clone(&st.shared);
    let write_path = path.clone();
    let write =
        tokio::task::spawn_blocking(move || shared.persist_candidate(&write_path, &candidate))
            .await;
    match write {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return Err(ApiError::Persist(format!(
                "configuration was not applied: could not persist {}: {e}",
                path.display()
            )))
        }
        Err(e) => {
            return Err(ApiError::Persist(format!(
                "configuration was not applied: persistence task failed for {}: {e}",
                path.display()
            )))
        }
    }

    if let Err(e) = st.shared.replace_config(next) {
        // Validation ran before the write, so this is an internal invariant
        // failure. Best-effort restore the previous on-disk configuration so
        // a restart cannot silently adopt a version the runtime rejected.
        let shared = Arc::clone(&st.shared);
        let restore_path = path.clone();
        let restore =
            tokio::task::spawn_blocking(move || shared.persist_candidate(&restore_path, &previous))
                .await;
        let rollback = match restore {
            Ok(Ok(())) => "previous configuration restored".to_string(),
            Ok(Err(e)) => format!("restoring previous configuration also failed: {e}"),
            Err(e) => format!("restore task failed: {e}"),
        };
        return Err(ApiError::Internal(format!(
            "configuration could not be activated ({e}); {rollback}"
        )));
    }
    Ok(true)
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
}
