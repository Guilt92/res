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

mod prom;

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
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
        Some(dir) => app.fallback(move |req: axum::extract::Request| {
            let dir = dir.clone();
            async move { dashboard_fallback(&dir, &req) }
        }),
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

/// Hardened dashboard/static fallback (replaces `ServeDir` + index
/// fallback):
///
/// * `/api/*` (and `/metrics`) that matched no route answer **JSON 404** —
///   serving `index.html` with status 200 would mask broken clients;
/// * `..` segments and dotfiles are never served (the config, credentials
///   and `.git` material can sit next to the dashboard directory);
/// * a missing *asset* (has a file extension) is a visible 404; only
///   extensionless paths fall back to `index.html` (SPA entry);
/// * non-GET/HEAD methods are refused.
fn dashboard_fallback(dir: &std::path::Path, req: &axum::extract::Request) -> Response {
    let path = req.uri().path().to_string();
    if path.starts_with("/api/") || path == "/metrics" {
        return ApiError::NotFound(format!("no route for {path}")).into_response();
    }
    if req.method() != axum::http::Method::GET && req.method() != axum::http::Method::HEAD {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            Json(json!({
                "error": "method not allowed",
                "code": "method_not_allowed",
            })),
        )
            .into_response();
    }

    let rel = path.trim_start_matches('/');
    let mut clean = std::path::PathBuf::from(&dir);
    let mut last_seg = "";
    if !rel.is_empty() {
        for seg in rel.split('/') {
            if seg.is_empty() || seg == "." || seg == ".." || seg.starts_with('.') {
                return ApiError::NotFound(format!("no route for {path}")).into_response();
            }
            clean.push(seg);
            last_seg = seg;
        }
    }
    if !clean.starts_with(dir) {
        return ApiError::NotFound(format!("no route for {path}")).into_response();
    }

    match std::fs::read(&clean) {
        Ok(bytes) => {
            let mime = match clean.extension().and_then(|e| e.to_str()) {
                Some("html") => "text/html; charset=utf-8",
                Some("css") => "text/css",
                Some("js") => "application/javascript",
                Some("ttf") => "font/ttf",
                Some("woff") => "font/woff",
                Some("woff2") => "font/woff2",
                Some("svg") => "image/svg+xml",
                Some("png") => "image/png",
                Some("ico") => "image/x-icon",
                _ => "application/octet-stream",
            };
            ([(header::CONTENT_TYPE, mime)], bytes).into_response()
        }
        Err(_) => {
            if last_seg.contains('.') {
                // An asset that does not exist must be a visible failure,
                // not a silently-rending HTML page.
                ApiError::NotFound(format!("asset not found: {path}")).into_response()
            } else {
                let index = dir.join("index.html");
                match std::fs::read(&index) {
                    Ok(b) => {
                        ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], b).into_response()
                    }
                    Err(e) => {
                        ApiError::Internal(format!("index.html unreadable: {e}")).into_response()
                    }
                }
            }
        }
    }
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

/// GET /api/auth/info — unauthenticated capability probe. Exposes only
/// booleans so the dashboard can show password and/or token sign-in without
/// leaking account names, token material, or session state.
async fn auth_info(State(st): State<ApiState>) -> Json<Value> {
    let token_auth = !st.shared.app.load().server.api_token.is_empty();
    let password_auth = st.auth.enabled();
    Json(json!({
        "password_auth": password_auth,
        "token_auth": token_auth,
        "open_mode": !password_auth && !token_auth && st.auth.open_mode_allowed(),
    }))
}

// ---------------------------------------------------------------------------
// Authentication: login, logout, session introspection
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    username: String,
    password: String,
}

/// POST /api/auth/login — exchange username/password for a session cookie.
/// Always returns 401 with an identical message for unknown users and wrong
/// passwords; lockouts and per-IP rate limits return 429. Rate/lockout state
/// is per-username and per-client-IP.
async fn login(
    State(st): State<ApiState>,
    ConnectInfo(ClientAddr(addr)): ConnectInfo<ClientAddr>,
    Json(req): Json<LoginRequest>,
) -> Response {
    if !st.auth.enabled() {
        return ApiError::Unauthorized("password authentication is not configured".into())
            .into_response();
    }
    // Bound credential sizes before they touch argon2, the lockout table or
    // the audit ring: without this a 2 MB body (framework default) could be
    // fed straight into the hash and stored verbatim in bounded maps/rings.
    if req.username.is_empty() || req.username.len() > 64 {
        return ApiError::BadRequest("username must be 1..=64 characters".into()).into_response();
    }
    if req.password.is_empty() || req.password.len() > 1024 {
        return ApiError::BadRequest("password must be 1..=1024 characters".into()).into_response();
    }
    // Per-IP rate limit (independent of per-username lockout).
    if let Err(retry_after_secs) = st.auth.check_login_rate(addr.ip()) {
        st.shared.record_config_event(
            "login",
            serde_json::json!({
                "user": req.username,
                "client": st.shared.client_label(addr.ip()),
                "outcome": "rate_limited",
                "retry_after_secs": retry_after_secs,
            }),
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(
                header::RETRY_AFTER,
                HeaderValue::from_str(&retry_after_secs.to_string())
                    .unwrap_or(HeaderValue::from_static("60")),
            )],
            Json(json!({
                "error": "too many login attempts from this address; try again later",
                "code": "rate_limited",
            })),
        )
            .into_response();
    }
    st.auth.record_login_attempt(addr.ip());
    // argon2 (~19 MiB, tens of ms) runs on the blocking pool so Tokio
    // workers and the DNS hot path never stall behind a login.
    let auth = Arc::clone(&st.auth);
    let (u, p) = (req.username.clone(), req.password.clone());
    let verified = tokio::task::spawn_blocking(move || auth.login(&u, &p)).await;
    let login_result = match verified {
        Ok(r) => r,
        Err(join_err) => {
            tracing::error!(event = "login_task_failed", error = %join_err);
            return ApiError::Internal("login evaluation failed".into()).into_response();
        }
    };
    match login_result {
        Ok((token, session)) => {
            st.auth.clear_login_rate(addr.ip());
            st.shared.record_config_event(
                "login",
                serde_json::json!({
                    "user": session.username,
                    "role": session.role.as_str(),
                    "client": st.shared.client_label(addr.ip()),
                    "outcome": "success",
                }),
            );
            let max_age = st.auth.session_ttl().as_secs();
            let secure = if st.auth.secure_cookies() {
                "; Secure"
            } else {
                ""
            };
            let cookie = |name: &str, value: &str, http_only: bool| {
                format!(
                    "{name}={value}; Path=/; Max-Age={max_age}; SameSite=Strict{secure}{}",
                    if http_only { "; HttpOnly" } else { "" }
                )
            };
            // HeaderMap::append (not insert) so both Set-Cookie headers survive.
            let mut headers = HeaderMap::new();
            headers.append(
                header::SET_COOKIE,
                HeaderValue::from_str(&cookie(SESSION_COOKIE, &token, true))
                    .unwrap_or(HeaderValue::from_static("res_session=; Max-Age=0")),
            );
            headers.append(
                header::SET_COOKIE,
                HeaderValue::from_str(&cookie(CSRF_COOKIE, &session.csrf, false))
                    .unwrap_or(HeaderValue::from_static("res_csrf=; Max-Age=0")),
            );
            let body = json!({
                "username": session.username,
                "role": session.role.as_str(),
                "csrf_token": session.csrf,
                "expires_in_secs": max_age,
            });
            (StatusCode::OK, headers, Json(body)).into_response()
        }
        Err(LoginError::InvalidCredentials) => {
            st.shared.record_config_event(
                "login",
                serde_json::json!({
                    "user": req.username,
                    "client": st.shared.client_label(addr.ip()),
                    "outcome": "failed",
                }),
            );
            ApiError::Unauthorized("invalid username or password".into()).into_response()
        }
        Err(LoginError::Locked { retry_after_secs }) => {
            st.shared.record_config_event(
                "login",
                serde_json::json!({
                    "user": req.username,
                    "client": st.shared.client_label(addr.ip()),
                    "outcome": "locked",
                    "retry_after_secs": retry_after_secs,
                }),
            );
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(
                    header::RETRY_AFTER,
                    HeaderValue::from_str(&retry_after_secs.to_string())
                        .unwrap_or(HeaderValue::from_static("60")),
                )],
                Json(json!({
                    "error": format!("too many failed attempts; try again in {retry_after_secs}s"),
                    "code": "locked",
                })),
            )
                .into_response()
        }
    }
}

/// DELETE /api/auth/session — invalidate the current session and clear
/// cookies. Requires a live session and, for cookie-authenticated requests,
/// a matching `X-CSRF-Token` header (prevents forced-logout CSRF). Bearer
/// requests clear nothing extra.
async fn logout(State(st): State<ApiState>, headers: HeaderMap) -> Response {
    if let Some(tok) = session_cookie(&headers) {
        if let Some(sess) = st.auth.session(tok) {
            // CSRF double-submit for cookie-authenticated logout.
            let provided = headers
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !ct_eq(provided.as_bytes(), sess.csrf.as_bytes()) {
                return ApiError::Forbidden("missing or invalid X-CSRF-Token header".into())
                    .into_response();
            }
            st.auth.logout(tok);
            st.shared.record_config_event(
                "logout",
                serde_json::json!({ "user": sess.username, "outcome": "success" }),
            );
        }
    }
    let secure = if st.auth.secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    let clear =
        |name: &str| format!("{name}=; Path=/; Max-Age=0; SameSite=Strict; HttpOnly{secure}");
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear(SESSION_COOKIE))
            .unwrap_or(HeaderValue::from_static("res_session=; Max-Age=0")),
    );
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear(CSRF_COOKIE))
            .unwrap_or(HeaderValue::from_static("res_csrf=; Max-Age=0")),
    );
    (headers, Json(json!({ "status": "ok" }))).into_response()
}

/// GET /api/auth/session — who am I? Returns 401 when unauthenticated.
async fn session_info(State(st): State<ApiState>, headers: HeaderMap) -> Response {
    match principal(&st, &headers) {
        Some(p) => Json(json!({
            "username": p.username,
            "role": p.role.as_str(),
            "via": if p.via_cookie { "session" } else { "token" },
            "session_ttl_secs": st.auth.session_ttl().as_secs(),
            "sessions": st.auth.session_count(),
        }))
        .into_response(),
        None => ApiError::Unauthorized("no active session".into()).into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotatePasswordRequest {
    /// Which account to rotate: `"admin"` or `"viewer"`.
    account: String,
    new_password: String,
}

/// POST /api/auth/rotate-password — change a stored password (admin only).
/// Requires either an admin session (with CSRF) or the bearer api_token.
/// Persists the new hash to the credentials file when a config path is known.
async fn rotate_password(
    State(st): State<ApiState>,
    ConnectInfo(ClientAddr(addr)): ConnectInfo<ClientAddr>,
    headers: HeaderMap,
    Json(req): Json<RotatePasswordRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "rotate_password")?;
    // The server is the source of truth for password policy: a browser-side
    // `minlength` check alone would be bypassed by a direct API call.
    const MIN_PASSWORD_LEN: usize = 8;
    if req.new_password.len() < MIN_PASSWORD_LEN || req.new_password.len() > 1024 {
        return Err(ApiError::BadRequest(format!(
            "new_password must be {MIN_PASSWORD_LEN}..=1024 characters"
        )));
    }
    let account = req.account.to_ascii_lowercase();
    // Hashing (argon2) and the credential-file write run on the blocking
    // pool; nothing here may stall a Tokio worker.
    let auth = Arc::clone(&st.auth);
    let cfg_path = st.shared.config_path.get().cloned();
    let new_password = req.new_password.clone();
    let account_for_task = account.clone();
    let rotated = tokio::task::spawn_blocking(move || {
        let changed = match account_for_task.as_str() {
            "admin" => auth.rotate_admin_password(&new_password),
            "viewer" => auth.rotate_viewer_password(&new_password),
            other => {
                return (
                    Err(format!("unknown account '{other}' (expected admin|viewer)")),
                    false,
                    None,
                )
            }
        };
        if !changed {
            return (
                Err(format!(
                    "no '{account_for_task}' credential is configured to rotate"
                )),
                false,
                None,
            );
        }
        // Persist when a config path is known; report failure honestly.
        match cfg_path {
            Some(path) => match auth.persist_credentials(&path) {
                Ok(()) => (Ok(()), true, None),
                Err(e) => (Ok(()), false, Some(e)),
            },
            None => (
                Ok(()),
                false,
                Some("no config path known; hash is in-memory only".into()),
            ),
        }
    })
    .await;
    let (outcome, persisted, persist_error) = match rotated {
        Ok(r) => r,
        Err(join_err) => {
            tracing::error!(event = "rotate_task_failed", error = %join_err);
            return Err(ApiError::Internal("password rotation failed".into()));
        }
    };
    if let Err(msg) = outcome {
        return Err(ApiError::BadRequest(msg));
    }
    // Revoking every existing session is the point of rotating a possibly
    // compromised credential: sessions minted with the old password must
    // not outlive the rotation. The operator logs in again with the new one.
    let sessions_revoked = st.auth.session_count();
    st.auth.logout_all();
    st.shared.record_config_event(
        "rotate_password",
        json!({
            "account": account,
            "client": st.shared.client_label(addr.ip()),
            "persisted": persisted,
            "persist_error": persist_error,
            "sessions_revoked": sessions_revoked,
            "outcome": if persist_error.is_some() { "applied_persist_failed" } else { "applied" },
        }),
    );
    Ok(Json(json!({
        "status": "ok",
        "account": account,
        "persisted": persisted,
        "persist_error": persist_error,
        "sessions_revoked": sessions_revoked,
        "note": "all existing sessions were invalidated; log in again with the new password",
    })))
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
// Configuration export / import / events
// ---------------------------------------------------------------------------

async fn export_config(
    State(st): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let app = st.shared.app.load();
    // Viewers (and anonymous open-mode readers) must never see the bearer
    // token: re-serialize with it stripped. Admins get the full export.
    let is_admin = principal(&st, &headers).is_some_and(|p| p.role == Role::Admin);
    let mut redacted = AppConfig::clone(app.as_ref());
    // Proxy passwords never leave the process, regardless of role.
    redacted.proxy.password.clear();
    let toml_text = if is_admin {
        redacted.to_toml().map_err(ApiError::Internal)?
    } else {
        redacted.server.api_token = String::new();
        redacted.to_toml().map_err(ApiError::Internal)?
    };
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
    headers: HeaderMap,
    Query(q): Query<ImportConfigQuery>,
    Json(req): Json<ImportConfigRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "import")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, q.generation, "import")?;

    // Parse + validate BEFORE touching runtime state: an invalid import must
    // leave the running configuration completely unchanged.
    let next = AppConfig::parse(&req.toml).map_err(|e| {
        reject(
            &st,
            "import_rejected",
            json!({ "op": "import" }),
            ApiError::BadRequest(e),
        )
    })?;

    check_last_usable(
        &st,
        &next.upstreams,
        q.confirm.unwrap_or(false),
        "import",
        "(all)",
    )?;

    st.shared.replace_config(next).map_err(|e| {
        reject(
            &st,
            "import_rejected",
            json!({ "op": "import" }),
            ApiError::BadRequest(e),
        )
    })?;

    let (persisted, persist_error) = if req.persist {
        persist_or_report(&st).await
    } else {
        (false, None)
    };

    st.shared.record_config_event(
        "import",
        json!({
            "upstreams": st.shared.app.load().upstreams.len(),
            "persisted": persisted,
            "persist_error": persist_error,
            "outcome": if persist_error.is_some() { "applied_persist_failed" } else { "applied" },
        }),
    );

    Ok(Json(json!({
        "status": "ok",
        "persisted": persisted,
        "persist_error": persist_error,
        "upstreams": st.shared.app.load().upstreams.len(),
        "generation": st.shared.config_generation(),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackConfigQuery {
    generation: Option<u64>,
    #[serde(default)]
    confirm: bool,
}

/// POST /api/config/rollback — restore the configuration from the
/// `<file>.backup` written by the previous successful persist. Applies at
/// runtime and re-persists the restored content as the primary file (so the
/// backup becomes the pre-rollback configuration, enabling a double-rollback).
async fn rollback_config(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<RollbackConfigQuery>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "rollback")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, q.generation, "rollback")?;

    let Some(path) = st.shared.config_path.get().cloned() else {
        return Err(ApiError::BadRequest(
            "no configuration file is set; rollback requires a persisted config path".into(),
        ));
    };
    let backup = AppConfig::backup_path(&path);
    if !backup.exists() {
        return Err(ApiError::NotFound(format!(
            "no backup file at {}",
            backup.display()
        )));
    }

    // Parse + validate BEFORE touching runtime state.
    let next = AppConfig::load(&backup).map_err(|e| {
        reject(
            &st,
            "rollback_rejected",
            json!({ "op": "rollback", "backup": backup.display().to_string() }),
            ApiError::BadRequest(format!("backup is invalid: {e}")),
        )
    })?;

    check_last_usable(&st, &next.upstreams, q.confirm, "rollback", "(backup)")?;

    st.shared.replace_config(next).map_err(|e| {
        reject(
            &st,
            "rollback_rejected",
            json!({ "op": "rollback" }),
            ApiError::BadRequest(e),
        )
    })?;

    // Persist the restored configuration as the primary file. A failure here
    // is reported but the runtime already runs the backup content.
    let (persisted, persist_error) = persist_or_report(&st).await;

    st.shared.record_config_event(
        "rollback",
        json!({
            "backup": backup.display().to_string(),
            "upstreams": st.shared.app.load().upstreams.len(),
            "persisted": persisted,
            "persist_error": persist_error,
            "outcome": if persist_error.is_some() { "applied_persist_failed" } else { "applied" },
        }),
    );

    Ok(Json(json!({
        "status": "ok",
        "backup": backup.display().to_string(),
        "persisted": persisted,
        "persist_error": persist_error,
        "upstreams": st.shared.app.load().upstreams.len(),
        "generation": st.shared.config_generation(),
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

// ---------------------------------------------------------------------------
// ACL management (runtime apply + atomic persist) and cache control
// ---------------------------------------------------------------------------

/// `source` distinguishes entries loaded from the structured `[[acl.entries]]`
/// config ("config") from those synthesised from the legacy flat
/// `allowed_cidrs`/`denied_cidrs` lists ("legacy") — the dashboard's Source
/// column needs it and cannot be derived client-side.
fn acl_entry_json(e: &AclEntry, source: &str) -> Value {
    json!({
        "id": e.id,
        "cidr": e.cidr,
        "action": e.action.as_str(),
        "enabled": e.enabled,
        "source": source,
    })
}

/// Shared guardrails for any ACL mutation that would produce an empty allow
/// list (fail-closed = refuse every query) or a /0 open-resolver allow network.
fn acl_guardrails(entries: &[AclEntry], confirm: bool) -> Result<(), ApiError> {
    if confirm {
        return Ok(());
    }
    let any_allow = entries
        .iter()
        .any(|e| e.action == AclAction::Allow && e.enabled);
    if !any_allow {
        return Err(ApiError::NeedsConfirm(
            "every allow entry is disabled or the allow list is empty (fail-closed refuses \
             every DNS query); retry with confirm=true to proceed"
                .into(),
        ));
    }
    let open = entries.iter().any(|e| {
        e.action == AclAction::Allow
            && e.enabled
            && crate::acl::normalize_cidr(&e.cidr)
                .map(|n| n.prefix_len() == 0)
                .unwrap_or(false)
    });
    if open {
        return Err(ApiError::NeedsConfirm(
            "the allow list contains a /0 network, which makes this an open resolver; \
             retry with confirm=true to proceed"
                .into(),
        ));
    }
    Ok(())
}

/// Apply a full entry list to the running config, persist atomically, and
/// record a config event. Callers must already hold the mutation lock, have
/// validated the entries parse, and checked the optimistic generation.
async fn apply_acl_entries(
    st: &ApiState,
    entries: Vec<AclEntry>,
    op: &str,
    confirm: bool,
) -> Result<Json<Value>, ApiError> {
    acl_guardrails(&entries, confirm)?;

    let mut next = AppConfig::clone(st.shared.app.load().as_ref());
    next.acl.set_entries(entries.clone());
    st.shared.replace_config(next).map_err(|e| {
        reject(
            st,
            &format!("{op}_rejected"),
            json!({ "op": op }),
            ApiError::BadRequest(e),
        )
    })?;
    let (persisted, persist_error) = persist_or_report(st).await;
    let outcome = if persist_error.is_some() {
        "applied_persist_failed"
    } else {
        "applied"
    };
    st.shared.record_config_event(
        op,
        json!({
            "entries": entries.len(),
            "persisted": persisted,
            "persist_error": persist_error,
            "outcome": outcome,
        }),
    );
    let rt = st.shared.rt.load();
    Ok(Json(json!({
        "status": "ok",
        "entries": entries.iter().map(|e| acl_entry_json(e, "config")).collect::<Vec<_>>(),
        "allowed_count": rt.acl.allowed_count(),
        "denied_count": rt.acl.denied_count(),
        "persisted": persisted,
        "persist_error": persist_error,
        "generation": st.shared.config_generation(),
    })))
}

/// GET /api/acl — effective entries (with ids) + evaluation counts.
async fn get_acl(State(st): State<ApiState>) -> Json<Value> {
    let app = st.shared.app.load();
    let rt = st.shared.rt.load();
    let entries = app.acl.effective_entries();
    let acl_source = if app.acl.entries.is_empty() {
        "legacy"
    } else {
        "config"
    };
    Json(json!({
        "entries": entries
            .iter()
            .map(|e| acl_entry_json(e, acl_source))
            .collect::<Vec<_>>(),
        // Legacy view for older dashboards: synthesised from enabled entries.
        "allowed_cidrs": entries
            .iter()
            .filter(|e| e.action == AclAction::Allow && e.enabled)
            .map(|e| e.cidr.clone())
            .collect::<Vec<_>>(),
        "denied_cidrs": entries
            .iter()
            .filter(|e| e.action == AclAction::Deny && e.enabled)
            .map(|e| e.cidr.clone())
            .collect::<Vec<_>>(),
        "allowed_count": rt.acl.allowed_count(),
        "denied_count": rt.acl.denied_count(),
        "generation": st.shared.config_generation(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AclUpdateRequest {
    /// Preferred shape: full structured entry list (replaces everything).
    #[serde(default)]
    entries: Option<Vec<AclEntry>>,
    /// Legacy shape: flat allow list (used when `entries` is absent).
    #[serde(default)]
    allowed_cidrs: Option<Vec<String>>,
    /// Legacy shape: flat deny list (used when `entries` is absent).
    #[serde(default)]
    denied_cidrs: Option<Vec<String>>,
    /// Optimistic concurrency guard (generation of the read the client edited).
    generation: Option<u64>,
    /// Required when the resulting allow list is empty (fail-closed would
    /// refuse every query) or contains a /0 network (open resolver).
    #[serde(default)]
    confirm: bool,
}

/// PUT /api/acl — validate, apply at runtime, persist atomically. Accepts
/// either the structured `entries` list or the legacy flat CIDR lists.
/// Denies are evaluated before allows (deny wins). Invalid CIDRs, bare-IP
/// normalisation failures, duplicates and allow/deny conflicts are rejected
/// without touching the running rules.
async fn put_acl(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<AclPutQuery>,
    Json(req): Json<AclUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "acl_update")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation.or(q.generation), "acl_update")?;

    // Build the entry list from whichever shape the client sent.
    let entries: Vec<AclEntry> = if let Some(entries) = req.entries {
        entries
    } else {
        let allowed = req.allowed_cidrs.unwrap_or_default();
        let denied = req.denied_cidrs.unwrap_or_default();
        let mut out = Vec::with_capacity(allowed.len() + denied.len());
        for s in allowed {
            out.push(AclEntry {
                id: String::new(),
                cidr: s,
                action: AclAction::Allow,
                enabled: true,
            });
        }
        for s in denied {
            out.push(AclEntry {
                id: String::new(),
                cidr: s,
                action: AclAction::Deny,
                enabled: true,
            });
        }
        out
    };

    // Reject invalid CIDRs / duplicates / conflicts before touching anything.
    let mut probe = AclConfig::default();
    probe.set_entries(entries.clone());
    AclRules::parse(&probe).map_err(|e| {
        reject(
            &st,
            "acl_update_rejected",
            json!({ "op": "acl_update" }),
            ApiError::BadRequest(e),
        )
    })?;

    apply_acl_entries(&st, entries, "acl_update", req.confirm).await
}

#[derive(Deserialize)]
struct AclPutQuery {
    generation: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AclEntryCreate {
    /// CIDR network or bare IPv4/IPv6 address.
    cidr: String,
    /// `"allow"` or `"deny"`.
    action: AclAction,
    /// Defaults to true.
    #[serde(default = "default_true_bool")]
    enabled: bool,
    generation: Option<u64>,
    #[serde(default)]
    confirm: bool,
}

fn default_true_bool() -> bool {
    true
}

/// POST /api/acl/entries — append one entry (admin only).
async fn create_acl_entry(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<AclEntryCreate>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "acl_entry_create")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation, "acl_entry_create")?;

    let mut entries = st.shared.app.load().acl.effective_entries();
    let new = AclEntry {
        id: String::new(),
        cidr: req.cidr.trim().to_string(),
        action: req.action,
        enabled: req.enabled,
    }
    .with_derived_id();
    // Reject exact duplicates early for a clearer error than the parse path.
    if entries.iter().any(|e| {
        e.action == new.action
            && crate::acl::normalize_cidr(&e.cidr)
                .ok()
                .zip(crate::acl::normalize_cidr(&new.cidr).ok())
                .map(|(a, b)| a == b)
                .unwrap_or(false)
    }) {
        return Err(ApiError::Conflict(format!(
            "duplicate ACL entry: {} {}",
            new.action.as_str(),
            new.cidr
        )));
    }
    entries.push(new);
    apply_acl_entries(&st, entries, "acl_entry_create", req.confirm).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AclEntryPatch {
    /// New CIDR (bare IP or network).
    #[serde(default)]
    cidr: Option<String>,
    #[serde(default)]
    action: Option<AclAction>,
    #[serde(default)]
    enabled: Option<bool>,
    generation: Option<u64>,
    #[serde(default)]
    confirm: bool,
}

/// PATCH /api/acl/entries/{id} — update one entry in place (admin only).
async fn patch_acl_entry(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<AclEntryPatch>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "acl_entry_patch")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation, "acl_entry_patch")?;

    let mut entries = st.shared.app.load().acl.effective_entries();
    let pos = entries
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("ACL entry '{id}' not found")))?;

    if let Some(cidr) = &req.cidr {
        entries[pos].cidr = cidr.trim().to_string();
    }
    if let Some(action) = req.action {
        entries[pos].action = action;
    }
    if let Some(enabled) = req.enabled {
        entries[pos].enabled = enabled;
    }
    // Changing cidr/action invalidates a content-derived id; re-derive so the
    // id stays a stable function of the entry's meaning.
    if req.cidr.is_some() || req.action.is_some() {
        entries[pos].id = AclEntry::derive_id(entries[pos].action, &entries[pos].cidr);
    }
    apply_acl_entries(&st, entries, "acl_entry_patch", req.confirm).await
}

#[derive(Deserialize)]
struct AclEntryDeleteQuery {
    generation: Option<u64>,
    #[serde(default)]
    confirm: bool,
}

/// DELETE /api/acl/entries/{id} — remove one entry (admin only).
async fn delete_acl_entry(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<AclEntryDeleteQuery>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "acl_entry_delete")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, q.generation, "acl_entry_delete")?;

    let mut entries = st.shared.app.load().acl.effective_entries();
    let pos = entries
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("ACL entry '{id}' not found")))?;
    entries.remove(pos);
    apply_acl_entries(&st, entries, "acl_entry_delete", q.confirm).await
}

/// POST /api/cache/clear — drop every cache entry immediately (admin only).
async fn clear_cache(
    State(st): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "cache_clear")?;
    let before = st.shared.cache.len();
    let mem = st.shared.cache.memory_bytes();
    st.shared.cache.clear();
    st.shared.metrics.cache_entries.set(0);
    st.shared.metrics.cache_memory_bytes.set(0);
    st.shared.metrics.cache_clears_total.inc();
    st.shared.record_config_event(
        "cache_clear",
        json!({
            "entries_dropped": before,
            "memory_bytes_freed": mem,
            "outcome": "applied"
        }),
    );
    Ok(Json(json!({
        "status": "ok",
        "entries_dropped": before,
        "memory_bytes_freed": mem,
    })))
}

// ---------------------------------------------------------------------------
// Outbound upstream proxy (SOCKS5 / HTTP CONNECT)
// ---------------------------------------------------------------------------

fn proxy_json(app: &AppConfig) -> Value {
    json!({
        "enabled": app.proxy.enabled,
        "protocol": app.proxy.protocol.as_str(),
        "address": app.proxy.address.to_string(),
        "port": app.proxy.port,
        "username": app.proxy.username,
        "password_set": !app.proxy.password.is_empty(),
        "connect_timeout_ms": app.proxy.connect_timeout_ms,
        "udp_supported": app.proxy.protocol.supports_udp(),
        // Secrets are write-only: the dashboard must send a replacement to
        // change them and can request an explicit clear.
        "password": Value::Null,
        "generation": 0,
    })
}

async fn get_proxy(State(st): State<ApiState>) -> Json<Value> {
    let app = st.shared.app.load();
    let mut v = proxy_json(&app);
    if let Value::Object(ref mut m) = v {
        m.insert(
            "generation".into(),
            Value::from(st.shared.config_generation()),
        );
    }
    Json(v)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyUpdateRequest {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    protocol: Option<ProxyProtocol>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    username: Option<String>,
    /// Absent = keep the stored password. Empty string is rejected as a
    /// change; use `clear_password` to remove it explicitly.
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    clear_password: bool,
    #[serde(default)]
    connect_timeout_ms: Option<u64>,
    generation: Option<u64>,
}

async fn put_proxy(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<AclPutQuery>,
    Json(req): Json<ProxyUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "proxy_update")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation.or(q.generation), "proxy_update")?;

    let mut next = AppConfig::clone(st.shared.app.load().as_ref());
    if let Some(enabled) = req.enabled {
        next.proxy.enabled = enabled;
    }
    if let Some(protocol) = req.protocol {
        next.proxy.protocol = protocol;
    }
    if let Some(address) = req.address.as_deref() {
        next.proxy.address = address
            .trim()
            .parse()
            .map_err(|e| ApiError::BadRequest(format!("invalid proxy address: {e}")))?;
    }
    if let Some(port) = req.port {
        next.proxy.port = port;
    }
    if let Some(username) = req.username.as_ref() {
        next.proxy.username = username.clone();
    }
    if req.clear_password {
        next.proxy.password.clear();
    } else if let Some(password) = req.password.as_ref() {
        if password.is_empty() {
            return Err(ApiError::BadRequest(
                "proxy.password cannot be set to an empty string; use clear_password".into(),
            ));
        }
        next.proxy.password = password.clone();
    }
    if let Some(timeout) = req.connect_timeout_ms {
        next.proxy.connect_timeout_ms = timeout;
    }
    let password_changed = req.clear_password || req.password.is_some();

    st.shared.replace_config(next).map_err(|e| {
        reject(
            &st,
            "proxy_update_rejected",
            json!({ "op": "proxy_update" }),
            ApiError::BadRequest(e),
        )
    })?;
    let (persisted, persist_error) = persist_or_report(&st).await;
    let outcome = if persist_error.is_some() {
        "applied_persist_failed"
    } else {
        "applied"
    };
    st.shared.record_config_event(
        "proxy_update",
        json!({
            "enabled": req.enabled,
            "protocol": req.protocol.map(|p| p.as_str()),
            "address": req.address.as_deref(),
            "port": req.port,
            "username": req.username.as_deref(),
            "password_changed": password_changed,
            "persisted": persisted,
            "persist_error": persist_error,
            "outcome": outcome,
        }),
    );
    let app = st.shared.app.load();
    let mut v = proxy_json(&app);
    if let Value::Object(ref mut m) = v {
        m.insert("status".into(), Value::from("ok"));
        m.insert("persisted".into(), Value::from(persisted));
        m.insert("persist_error".into(), json!(persist_error));
        m.insert(
            "generation".into(),
            Value::from(st.shared.config_generation()),
        );
    }
    Ok(Json(v))
}

/// POST /api/proxy/test — establish a real tunnel through the configured
/// proxy to the first enabled upstream. It validates routing/authentication
/// but deliberately does not send a DNS query (no health state changes).
async fn test_proxy(
    State(st): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "proxy_test")?;
    let app = AppConfig::clone(st.shared.app.load().as_ref());
    if !app.proxy.enabled {
        return Err(ApiError::BadRequest("proxy is disabled".into()));
    }
    let up = app
        .upstreams
        .iter()
        .find(|u| u.enabled)
        .ok_or_else(|| ApiError::BadRequest("no enabled upstream to test".into()))?;
    let target = std::net::SocketAddr::new(up.address, up.port);
    let started = Instant::now();
    let budget = Duration::from_millis(app.proxy.connect_timeout_ms);
    let outcome = if up.protocol == Protocol::Udp {
        crate::proxy::open_udp(&app.proxy, budget)
            .await
            .map(|_assoc| "udp_associate")
    } else {
        crate::proxy::connect_tcp(&app.proxy, target, budget)
            .await
            .map(|_stream| "tcp_tunnel")
    };
    let (reachable, error) = match outcome {
        Ok(kind) => (true, Some(kind)),
        Err(e) => (false, Some(e.kind.as_str())),
    };
    Ok(Json(json!({
        "reachable": reachable,
        "protocol": app.proxy.protocol.as_str(),
        "upstream": up.name,
        "target": target.to_string(),
        "transport": up.protocol.to_string(),
        "tunnel": if reachable { error } else { None },
        "error": if reachable { None } else { error },
        "latency_ms": (started.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
    })))
}

// ---------------------------------------------------------------------------
// Cache settings (hot-reloadable TTL bounds / capacity / enable flag)
// ---------------------------------------------------------------------------

/// GET /api/cache — live cache state + the settings that control it.
async fn get_cache(State(st): State<ApiState>) -> Json<Value> {
    let rt = st.shared.rt.load();
    Json(json!({
        "enabled": rt.cache.enabled,
        "entries": st.shared.cache.len(),
        "max_entries": rt.cache.max_entries,
        "max_memory_bytes": rt.cache.max_memory_bytes,
        "min_ttl_secs": rt.cache.min_ttl_secs,
        "max_ttl_secs": rt.cache.max_ttl_secs,
        "negative_max_ttl_secs": rt.cache.negative_max_ttl_secs,
        "memory_bytes": st.shared.cache.memory_bytes(),
        "generation": st.shared.config_generation(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheUpdateRequest {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    max_entries: Option<usize>,
    #[serde(default)]
    max_memory_bytes: Option<usize>,
    #[serde(default)]
    min_ttl_secs: Option<u64>,
    #[serde(default)]
    max_ttl_secs: Option<u64>,
    #[serde(default)]
    negative_max_ttl_secs: Option<u64>,
    generation: Option<u64>,
}

/// PUT /api/cache — update cache settings, apply at runtime, persist
/// atomically. Lowering `max_entries` trims the live cache immediately;
/// disabling the cache clears it.
async fn put_cache(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<AclPutQuery>,
    Json(req): Json<CacheUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "cache_update")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation.or(q.generation), "cache_update")?;

    let mut next = AppConfig::clone(st.shared.app.load().as_ref());
    if let Some(enabled) = req.enabled {
        next.cache.enabled = enabled;
    }
    if let Some(max_entries) = req.max_entries {
        next.cache.max_entries = max_entries;
    }
    if let Some(max_memory_bytes) = req.max_memory_bytes {
        next.cache.max_memory_bytes = max_memory_bytes;
    }
    if let Some(min_ttl_secs) = req.min_ttl_secs {
        next.cache.min_ttl_secs = min_ttl_secs;
    }
    if let Some(max_ttl_secs) = req.max_ttl_secs {
        next.cache.max_ttl_secs = max_ttl_secs;
    }
    if let Some(negative_max_ttl_secs) = req.negative_max_ttl_secs {
        next.cache.negative_max_ttl_secs = negative_max_ttl_secs;
    }
    st.shared.replace_config(next).map_err(|e| {
        reject(
            &st,
            "cache_update_rejected",
            json!({ "op": "cache_update" }),
            ApiError::BadRequest(e),
        )
    })?;
    let (persisted, persist_error) = persist_or_report(&st).await;
    let outcome = if persist_error.is_some() {
        "applied_persist_failed"
    } else {
        "applied"
    };
    st.shared.record_config_event(
        "cache_update",
        json!({
            "enabled": req.enabled,
            "max_entries": req.max_entries,
            "max_memory_bytes": req.max_memory_bytes,
            "min_ttl_secs": req.min_ttl_secs,
            "max_ttl_secs": req.max_ttl_secs,
            "negative_max_ttl_secs": req.negative_max_ttl_secs,
            "persisted": persisted,
            "persist_error": persist_error,
            "outcome": outcome,
        }),
    );
    let rt = st.shared.rt.load();
    Ok(Json(json!({
        "status": "ok",
        "enabled": rt.cache.enabled,
        "entries": st.shared.cache.len(),
        "max_entries": rt.cache.max_entries,
        "max_memory_bytes": rt.cache.max_memory_bytes,
        "min_ttl_secs": rt.cache.min_ttl_secs,
        "max_ttl_secs": rt.cache.max_ttl_secs,
        "negative_max_ttl_secs": rt.cache.negative_max_ttl_secs,
        "memory_bytes": st.shared.cache.memory_bytes(),
        "persisted": persisted,
        "persist_error": persist_error,
        "generation": st.shared.config_generation(),
    })))
}

// ---------------------------------------------------------------------------
// Health-check and selection policy configuration (read + write)
// ---------------------------------------------------------------------------

/// GET `/api/health/config`: the full `[health]` section as the dashboard
/// edits it (the liveness probe stays at the open `/api/health` route).
async fn get_health_config(State(st): State<ApiState>) -> Json<Value> {
    let app = st.shared.app.load();
    Json(json!({
        "health": app.health,
        "generation": st.shared.config_generation(),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthConfigUpdateRequest {
    enabled: Option<bool>,
    interval_ms: Option<u64>,
    timeout_ms: Option<u64>,
    failure_threshold: Option<u32>,
    recovery_threshold: Option<u32>,
    min_successes: Option<usize>,
    tcp_probes: Option<bool>,
    probes: Option<Vec<crate::config::HealthProbe>>,
    dwell_ms: Option<u64>,
    generation: Option<u64>,
}

async fn put_health_config(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<AclPutQuery>,
    Json(req): Json<HealthConfigUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "health_update")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation.or(q.generation), "health_update")?;

    let mut next = AppConfig::clone(st.shared.app.load().as_ref());
    let probes_updated = req.probes.is_some();
    if let Some(v) = req.enabled {
        next.health.enabled = v;
    }
    if let Some(v) = req.interval_ms {
        next.health.interval_ms = v;
    }
    if let Some(v) = req.timeout_ms {
        next.health.timeout_ms = v;
    }
    if let Some(v) = req.failure_threshold {
        next.health.failure_threshold = v;
    }
    if let Some(v) = req.recovery_threshold {
        next.health.recovery_threshold = v;
    }
    if let Some(v) = req.min_successes {
        next.health.min_successes = v;
    }
    if let Some(v) = req.tcp_probes {
        next.health.tcp_probes = v;
    }
    if let Some(v) = req.probes {
        next.health.probes = v;
    }
    if let Some(v) = req.dwell_ms {
        next.health.dwell_ms = v;
    }
    st.shared.replace_config(next).map_err(|e| {
        reject(
            &st,
            "health_update_rejected",
            json!({ "op": "health_update" }),
            ApiError::BadRequest(e),
        )
    })?;
    let (persisted, persist_error) = persist_or_report(&st).await;
    let outcome = if persist_error.is_some() {
        "applied_persist_failed"
    } else {
        "applied"
    };
    st.shared.record_config_event(
        "health_update",
        json!({
            "enabled": req.enabled,
            "interval_ms": req.interval_ms,
            "timeout_ms": req.timeout_ms,
            "probes": probes_updated,
            "persisted": persisted,
            "persist_error": persist_error,
            "outcome": outcome,
        }),
    );
    Ok(Json(json!({
        "status": "ok",
        "health": st.shared.app.load().health,
        "persisted": persisted,
        "persist_error": persist_error,
        "generation": st.shared.config_generation(),
    })))
}

async fn get_selection(State(st): State<ApiState>) -> Json<Value> {
    let app = st.shared.app.load();
    Json(json!({
        "selection": app.selection,
        "generation": st.shared.config_generation(),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionConfigUpdateRequest {
    strategy: Option<crate::config::SelectionStrategy>,
    latency_reference_ms: Option<f64>,
    tier_policy: Option<crate::config::TierPolicy>,
    lower_tier_share: Option<f64>,
    degraded_policy: Option<crate::config::DegradedPolicy>,
    min_probe_samples: Option<u32>,
    generation: Option<u64>,
}

async fn put_selection(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<AclPutQuery>,
    Json(req): Json<SelectionConfigUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "selection_update")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation.or(q.generation), "selection_update")?;

    let mut next = AppConfig::clone(st.shared.app.load().as_ref());
    if let Some(v) = req.strategy {
        next.selection.strategy = v;
    }
    if let Some(v) = req.latency_reference_ms {
        next.selection.latency_reference_ms = v;
    }
    if let Some(v) = req.tier_policy {
        next.selection.tier_policy = v;
    }
    if let Some(v) = req.lower_tier_share {
        next.selection.lower_tier_share = v;
    }
    if let Some(v) = req.degraded_policy {
        next.selection.degraded_policy = v;
    }
    if let Some(v) = req.min_probe_samples {
        next.selection.min_probe_samples = v;
    }
    st.shared.replace_config(next).map_err(|e| {
        reject(
            &st,
            "selection_update_rejected",
            json!({ "op": "selection_update" }),
            ApiError::BadRequest(e),
        )
    })?;
    let (persisted, persist_error) = persist_or_report(&st).await;
    let outcome = if persist_error.is_some() {
        "applied_persist_failed"
    } else {
        "applied"
    };
    st.shared.record_config_event(
        "selection_update",
        json!({
            "strategy": req.strategy,
            "latency_reference_ms": req.latency_reference_ms,
            "tier_policy": req.tier_policy,
            "lower_tier_share": req.lower_tier_share,
            "degraded_policy": req.degraded_policy,
            "min_probe_samples": req.min_probe_samples,
            "persisted": persisted,
            "persist_error": persist_error,
            "outcome": outcome,
        }),
    );
    let rt = st.shared.rt.load();
    Ok(Json(json!({
        "status": "ok",
        "selection": rt.selection,
        "persisted": persisted,
        "persist_error": persist_error,
        "generation": st.shared.config_generation(),
    })))
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
    /// Per-upstream health probe interval override (ms).
    pub probe_interval_ms: Option<u64>,
    /// Per-upstream health probe timeout override (ms).
    pub probe_timeout_ms: Option<u64>,
    /// Per-upstream probe list override (replaces `[health].probes`).
    pub probes: Option<Vec<crate::config::HealthProbe>>,
    /// Per-upstream expected rcode for health probes (`UpstreamConfig::expect_rcode`).
    pub expect_rcode: Option<String>,
    /// SNI/certificate name for `protocol = "tls"`.
    pub tls_server_name: Option<String>,
    /// Optional PEM CA bundle for `protocol = "tls"`.
    pub tls_ca_file: Option<std::path::PathBuf>,
    /// Accepted and ignored on create (the dashboard sends `confirm` on every
    /// write; only updates/deletes need it). Typed here because
    /// `deny_unknown_fields` would otherwise reject the panel's payload with
    /// a 422 — the "Add upstream" button was broken by exactly that.
    pub confirm: Option<bool>,
    /// Optional optimistic-concurrency guard: reject if the active
    /// configuration generation no longer matches.
    pub generation: Option<u64>,
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
    /// Per-upstream health probe interval override (ms).
    pub probe_interval_ms: Option<u64>,
    /// Per-upstream health probe timeout override (ms).
    pub probe_timeout_ms: Option<u64>,
    /// Explicitly clear the probe interval override (back to inheriting
    /// `[health].interval`). Independent of `clear_probes`: wiping the probe
    /// *list* must not silently delete the cadence overrides.
    pub clear_probe_interval_ms: Option<bool>,
    /// Explicitly clear the probe timeout override (back to inheriting
    /// `[health].timeout`).
    pub clear_probe_timeout_ms: Option<bool>,
    /// Per-upstream probe list override (replaces `[health].probes`).
    pub probes: Option<Vec<crate::config::HealthProbe>>,
    /// Per-upstream expected rcode for health probes; validated against the
    /// known rcode set by `UpstreamConfig::validate`.
    pub expect_rcode: Option<String>,
    /// Explicitly clear the `expect_rcode` override.
    pub clear_expect_rcode: Option<bool>,
    /// SNI/certificate name for `protocol = "tls"`.
    pub tls_server_name: Option<String>,
    /// Optional PEM CA bundle for `protocol = "tls"`.
    pub tls_ca_file: Option<std::path::PathBuf>,
    /// Explicitly clear the TLS server name / CA bundle.
    pub clear_tls: Option<bool>,
    /// Explicitly clear the per-upstream probe overrides.
    pub clear_probes: Option<bool>,
    /// Required when the update would disable the last enabled upstream.
    pub confirm: Option<bool>,
    /// Optional optimistic-concurrency guard (see `CreateUpstreamRequest`).
    pub generation: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteUpstreamQuery {
    pub confirm: Option<bool>,
    pub generation: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportConfigQuery {
    pub confirm: Option<bool>,
    pub generation: Option<u64>,
}

fn parse_address(s: &str) -> Result<IpAddr, ApiError> {
    s.trim()
        .parse()
        .map_err(|e| ApiError::BadRequest(format!("invalid address '{s}': {e}")))
}

async fn list_upstreams(State(st): State<ApiState>) -> Json<Value> {
    use crate::upstream::HealthStatus;

    let sel = st.shared.rt.load().selection.clone();
    let latency_ref = sel.latency_reference_ms;
    let min_probe_samples = sel.min_probe_samples;
    let rows: Vec<crate::upstream::UpstreamStats> = st
        .shared
        .registry
        .snapshot()
        .iter()
        .map(|u| u.stats_with_latency_ref(latency_ref, min_probe_samples))
        .collect();

    // Selection semantics (mirrors `selection.rs`): an UNHEALTHY upstream is
    // scored 0 while any upstream is HEALTHY, so it is *kept* as a fallback
    // but not used. RECOVERING is usable (scored between healthy and
    // degraded). With `degraded_policy = "last_resort"`, DEGRADED behaves like
    // UNHEALTHY while any HEALTHY/RECOVERING upstream exists.
    let any_up = rows
        .iter()
        .any(|r| r.enabled && matches!(r.health, HealthStatus::Healthy | HealthStatus::Recovering));
    let degraded_last_resort =
        st.shared.rt.load().selection.degraded_policy == crate::config::DegradedPolicy::LastResort;
    let mut eligible = Vec::new();
    let mut in_use = Vec::new();
    let mut idle = Vec::new();
    let mut avoided = Vec::new();
    let mut disabled = Vec::new();
    let (mut up, mut degraded, mut recovering, mut down) = (0usize, 0usize, 0usize, 0usize);
    let mut sum_qps = 0.0f64;

    // First pass: classify, then rank eligible upstreams by composite score
    // (descending) so operators can see why a given upstream wins or loses.
    let classified: Vec<(Value, bool, f64, String)> = rows
        .iter()
        .map(|r| {
            let mut v = serde_json::to_value(r).expect("serializable");
            if !r.enabled {
                disabled.push(r.name.clone());
                v["eligible"] = Value::Bool(false);
                return (v, false, 0.0, "disabled".into());
            }
            match r.health {
                HealthStatus::Healthy => up += 1,
                HealthStatus::Degraded => degraded += 1,
                HealthStatus::Recovering => recovering += 1,
                HealthStatus::Unhealthy => down += 1,
            }
            let is_eligible =
                crate::selection::candidate_eligible(r.health, any_up, degraded_last_resort);
            v["eligible"] = Value::Bool(is_eligible);
            sum_qps += r.qps;
            let reason = match (r.health, is_eligible) {
                (HealthStatus::Healthy, true) => "healthy",
                (HealthStatus::Recovering, true) => "recovering",
                (HealthStatus::Degraded, true) => "degraded_usable",
                (HealthStatus::Degraded, false) => "degraded_last_resort",
                (HealthStatus::Unhealthy, _) => "unhealthy",
                _ => "not_eligible",
            };
            (v, is_eligible, r.score.score, reason.into())
        })
        .collect();

    // Rank eligible by score descending (stable: higher score first, ties
    // broken by lower upstream id for determinism).
    let mut order: Vec<usize> = classified
        .iter()
        .enumerate()
        .filter(|(_, (_, ok, _, _))| *ok)
        .map(|(i, _)| i)
        .collect();
    order.sort_by(|&a, &b| {
        classified[b]
            .2
            .partial_cmp(&classified[a].2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                let id_a = classified[a].0["id"].as_i64().unwrap_or(i64::MAX);
                let id_b = classified[b].0["id"].as_i64().unwrap_or(i64::MAX);
                id_a.cmp(&id_b)
            })
    });
    let mut ranks: HashMap<i64, u32> = HashMap::new();
    for (rank, &idx) in order.iter().enumerate() {
        let id = classified[idx].0["id"].as_i64().unwrap_or(0);
        ranks.insert(id, rank as u32 + 1);
    }

    let upstreams: Vec<Value> = classified
        .into_iter()
        .map(|(mut v, is_eligible, score, reason)| {
            let id = v["id"].as_i64().unwrap_or(0);
            // Keep the serialized `score` breakdown (factors + composite):
            // the dashboard renders the factors in a tooltip. `score_value`
            // is the same composite as a plain number for scripted clients.
            v["score_value"] = json!(score);
            v["rank"] = ranks.get(&id).map_or(Value::Null, |r| json!(r));
            v["reason"] = Value::String(reason);
            if is_eligible {
                eligible.push(v["name"].as_str().unwrap_or("").to_string());
                let in_use_now = v["in_use"].as_bool().unwrap_or(false);
                if in_use_now {
                    in_use.push(v["name"].as_str().unwrap_or("").to_string());
                } else {
                    idle.push(v["name"].as_str().unwrap_or("").to_string());
                }
            } else if v["enabled"].as_bool().unwrap_or(true) {
                avoided.push(v["name"].as_str().unwrap_or("").to_string());
            }
            v
        })
        .collect();
    let usable = up + degraded + recovering;
    let emergency = !rows.is_empty() && eligible.is_empty();

    Json(json!({
        "upstreams": upstreams,
        "generation": st.shared.config_generation(),
        "state": {
            "total": rows.len(),
            // "up"/"down" are legacy aliases for healthy/unhealthy counts;
            // the canonical per-state names are healthy/degraded/recovering/
            // unhealthy (also present on each upstream's `health` field).
            "up": up,
            "healthy": up,
            "degraded": degraded,
            "recovering": recovering,
            "usable": usable,
            "unhealthy": down,
            "down": down,
            "disabled": disabled.len(),
            "eligible": eligible,
            "in_use": in_use,
            "idle": idle,
            "avoided": avoided,
            "disabled_names": disabled,
            "total_qps": round2(sum_qps),
            // Canonical emergency: no configured upstream can serve. A
            // disabled-but-healthy upstream must not mask this.
            "emergency": emergency,
        },
    }))
}

async fn get_upstream(
    State(st): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let sel = st.shared.rt.load().selection.clone();
    st.shared
        .registry
        .get(id)
        .map(|u| {
            Json(json!({
                "upstream": serde_json::to_value(
                    u.stats_with_latency_ref(sel.latency_reference_ms, sel.min_probe_samples)
                ).unwrap()
            }))
        })
        .ok_or_else(|| ApiError::NotFound(format!("upstream {id} not found")))
}

async fn create_upstream(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<CreateUpstreamRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    require_admin(&st, &headers, "create")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation, "create")?;
    let current: AppConfig = (**st.shared.app.load()).clone();

    let name_hint: String = req.name.trim().chars().take(64).collect();
    let mut candidate = UpstreamConfig {
        id: 0,
        name: req.name.trim().to_string(),
        address: parse_address(&req.address)
            .map_err(|e| reject(&st, "create_rejected", json!({ "name": name_hint }), e))?,
        port: req.port.unwrap_or(53),
        protocol: req.protocol.unwrap_or(Protocol::Udp),
        enabled: req.enabled.unwrap_or(true),
        priority: req.priority.unwrap_or(1),
        weight: req.weight.unwrap_or(1),
        timeout_ms: req.timeout_ms,
        probe_interval_ms: req.probe_interval_ms,
        probe_timeout_ms: req.probe_timeout_ms,
        probes: req.probes.clone(),
        expect_rcode: req.expect_rcode.clone(),
        tls_server_name: req.tls_server_name.clone(),
        tls_ca_file: req.tls_ca_file.clone(),
    };
    candidate.validate().map_err(|e| {
        reject(
            &st,
            "create_rejected",
            json!({ "name": candidate.name }),
            ApiError::BadRequest(e),
        )
    })?;
    if current.upstreams.iter().any(|u| u.name == candidate.name) {
        return Err(reject(
            &st,
            "create_rejected",
            json!({ "name": candidate.name }),
            ApiError::Conflict(format!("upstream name '{}' already exists", candidate.name)),
        ));
    }

    let mut list = current.upstreams.clone();
    let next_id = list.iter().map(|u| u.id).max().unwrap_or(0).max(0) + 1;
    candidate.id = next_id;
    list.push(candidate.clone());

    st.shared.apply_upstreams(list).map_err(|e| {
        reject(
            &st,
            "create_rejected",
            json!({ "name": candidate.name }),
            ApiError::Internal(e),
        )
    })?;

    let (persisted, persist_error) = persist_or_report(&st).await;
    st.shared.record_config_event(
        "create",
        json!({
            "id": next_id,
            "name": candidate.name,
            "persisted": persisted,
            "outcome": if persist_error.is_some() { "applied_persist_failed" } else { "applied" },
        }),
    );

    let sel = st.shared.rt.load().selection.clone();
    let stats = st
        .shared
        .registry
        .get(next_id)
        .map(|u| {
            serde_json::to_value(
                u.stats_with_latency_ref(sel.latency_reference_ms, sel.min_probe_samples),
            )
            .unwrap()
        })
        .unwrap_or(Value::Null);
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "upstream": stats,
            "persisted": persisted,
            "persist_error": persist_error,
            "generation": st.shared.config_generation(),
        })),
    ))
}

async fn patch_upstream(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<UpdateUpstreamRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "update")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, req.generation, "update")?;
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
    if let Some(weight) = req.weight {
        updated.weight = weight;
    }
    if Some(true) == req.clear_timeout {
        updated.timeout_ms = None;
    } else if let Some(t) = req.timeout_ms {
        updated.timeout_ms = Some(t);
    }
    if Some(true) == req.clear_expect_rcode {
        updated.expect_rcode = None;
    } else if let Some(rc) = &req.expect_rcode {
        updated.expect_rcode = Some(rc.clone());
    }
    if Some(true) == req.clear_tls {
        updated.tls_server_name = None;
        updated.tls_ca_file = None;
    } else {
        if let Some(name) = &req.tls_server_name {
            updated.tls_server_name = if name.trim().is_empty() {
                None
            } else {
                Some(name.clone())
            };
        }
        if let Some(path) = &req.tls_ca_file {
            updated.tls_ca_file = Some(path.clone());
        }
    }
    if Some(true) == req.clear_probes {
        updated.probes = None;
    } else if let Some(probes) = &req.probes {
        updated.probes = Some(probes.clone());
    }
    if Some(true) == req.clear_probe_interval_ms {
        updated.probe_interval_ms = None;
    } else if let Some(t) = req.probe_interval_ms {
        updated.probe_interval_ms = Some(t);
    }
    if Some(true) == req.clear_probe_timeout_ms {
        updated.probe_timeout_ms = None;
    } else if let Some(t) = req.probe_timeout_ms {
        updated.probe_timeout_ms = Some(t);
    }
    updated.validate().map_err(|e| {
        reject(
            &st,
            "update_rejected",
            json!({ "id": id, "name": updated.name }),
            ApiError::BadRequest(e),
        )
    })?;
    if current
        .upstreams
        .iter()
        .any(|u| u.id != id && u.name == updated.name)
    {
        return Err(reject(
            &st,
            "update_rejected",
            json!({ "id": id, "name": updated.name }),
            ApiError::Conflict(format!("upstream name '{}' already exists", updated.name)),
        ));
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
    check_last_usable(
        &st,
        &list,
        req.confirm.unwrap_or(false),
        "update",
        &updated.name,
    )?;
    st.shared.apply_upstreams(list).map_err(|e| {
        reject(
            &st,
            "update_rejected",
            json!({ "id": id, "name": updated.name }),
            ApiError::Internal(e),
        )
    })?;

    let (persisted, persist_error) = persist_or_report(&st).await;
    st.shared.record_config_event(
        "update",
        json!({
            "id": id,
            "name": updated.name,
            "persisted": persisted,
            "outcome": if persist_error.is_some() { "applied_persist_failed" } else { "applied" },
        }),
    );

    let sel = st.shared.rt.load().selection.clone();
    let stats = st
        .shared
        .registry
        .get(id)
        .map(|u| {
            serde_json::to_value(
                u.stats_with_latency_ref(sel.latency_reference_ms, sel.min_probe_samples),
            )
            .unwrap()
        })
        .unwrap_or(Value::Null);
    Ok(Json(json!({
        "upstream": stats,
        "persisted": persisted,
        "persist_error": persist_error,
        "generation": st.shared.config_generation(),
    })))
}

async fn delete_upstream(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<DeleteUpstreamQuery>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "delete")?;
    let _guard = st.mutation.lock().await;
    check_generation(&st, q.generation, "delete")?;
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
    check_last_usable(
        &st,
        &list,
        q.confirm.unwrap_or(false),
        "delete",
        &existing.name,
    )?;
    st.shared.apply_upstreams(list).map_err(|e| {
        reject(
            &st,
            "delete_rejected",
            json!({ "id": id, "name": existing.name }),
            ApiError::Internal(e),
        )
    })?;

    let (persisted, persist_error) = persist_or_report(&st).await;
    st.shared.record_config_event(
        "delete",
        json!({
            "id": id,
            "name": existing.name,
            "persisted": persisted,
            "outcome": if persist_error.is_some() { "applied_persist_failed" } else { "applied" },
        }),
    );

    Ok(Json(json!({
        "deleted": id,
        "persisted": persisted,
        "persist_error": persist_error,
        "generation": st.shared.config_generation(),
    })))
}

/// Persist after a successful in-memory mutation. A persistence failure is
/// reported but never rolls back the applied configuration (the data plane
/// must keep running; `/api/diagnostics` surfaces the error). When no config
/// path is set the gateway runs purely in memory and reports `persisted=false`.
async fn persist_or_report(st: &ApiState) -> (bool, Option<String>) {
    if st.shared.config_path.get().is_none() {
        return (false, None);
    }
    // save_atomic fsyncs the file and directory; never run that on a Tokio
    // worker. The mutation lock is still held by the caller, so serializing
    // through the blocking pool cannot reorder API mutations.
    let shared = Arc::clone(&st.shared);
    match tokio::task::spawn_blocking(move || shared.persist_config()).await {
        Ok(Ok(())) => (true, None),
        Ok(Err(e)) => (false, Some(e)),
        Err(e) => (false, Some(format!("persist task failed: {e}"))),
    }
}

async fn test_upstream(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "test")?;
    let runtime = st
        .shared
        .registry
        .get(id)
        .ok_or_else(|| ApiError::NotFound(format!("upstream {id} not found")))?;
    let cfg = runtime.config();
    // Build from the live configuration so a proxy change applies to the
    // operator-triggered probe immediately.
    let forwarder = Forwarder::from_shared(&st.shared);
    let result = probe_once(&st.shared, &forwarder, &runtime).await;
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
