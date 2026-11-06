//! Outbound upstream proxy (SOCKS5 / HTTP CONNECT) settings.

use super::*;

// ---------------------------------------------------------------------------
// Outbound upstream proxy (SOCKS5 / HTTP CONNECT)
// ---------------------------------------------------------------------------

pub(super) fn proxy_json(app: &AppConfig) -> Value {
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

pub(super) async fn get_proxy(State(st): State<ApiState>) -> Json<Value> {
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
pub(super) struct ProxyUpdateRequest {
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

pub(super) async fn put_proxy(
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

    if let Err(e) = crate::shared::Shared::validate_config(&mut next) {
        return Err(reject(
            &st,
            "proxy_update_rejected",
            json!({ "op": "proxy_update" }),
            ApiError::BadRequest(e),
        ));
    }
    let persisted = commit_config(&st, next).await?;
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
            "outcome": "applied",
        }),
    );
    let app = st.shared.app.load();
    let mut v = proxy_json(&app);
    if let Value::Object(ref mut m) = v {
        m.insert("status".into(), Value::from("ok"));
        m.insert("persisted".into(), Value::from(persisted));
        m.insert("persist_error".into(), Value::Null);
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
pub(super) async fn test_proxy(
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
