//! Authentication endpoints: capability probe, login, logout, session
//! introspection/revocation and password rotation.

use super::*;

/// GET /api/auth/info — unauthenticated capability probe. Exposes only
/// booleans so the dashboard can show password and/or token sign-in without
/// leaking account names, token material, or session state.
pub(super) async fn auth_info(State(st): State<ApiState>) -> Json<Value> {
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
pub(super) struct LoginRequest {
    username: String,
    password: String,
}

/// POST /api/auth/login — exchange username/password for a session cookie.
/// Always returns 401 with an identical message for unknown users and wrong
/// passwords; lockouts and per-IP rate limits return 429. Rate/lockout state
/// is per-username and per-client-IP.
pub(super) async fn login(
    State(st): State<ApiState>,
    ConnectInfo(ClientAddr(peer)): ConnectInfo<ClientAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Response {
    // Effective client: the socket peer unless it is a configured trusted
    // proxy (see `client_ip`). Rate limiting and lockout use this address;
    // audit events record both it and the real socket peer.
    let client = client_ip::resolve(
        peer.ip(),
        &headers,
        &st.shared.app.load().server.trusted_proxies,
    );
    let addr = std::net::SocketAddr::new(client, peer.port());
    let peer_label = st.shared.client_label(peer.ip());
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
    // Per-IP limit: check and count in one atomic step.
    if let Err(retry_after_secs) = st.auth.begin_login_attempt(addr.ip()) {
        st.shared.record_config_event(
            "login",
            serde_json::json!({
                "user": req.username,
                "client": st.shared.client_label(addr.ip()),
                "peer": peer_label,
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
    // argon2 (~19 MiB, tens of ms) runs on the blocking pool so Tokio
    // workers and the DNS hot path never stall behind a login.
    let auth = Arc::clone(&st.auth);
    let (u, p) = (req.username.clone(), req.password.clone());
    let verified = tokio::task::spawn_blocking(move || auth.login(&u, &p, client)).await;
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
                "peer": peer_label,
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
                "peer": peer_label,
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
                "peer": peer_label,
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
pub(super) async fn logout(State(st): State<ApiState>, headers: HeaderMap) -> Response {
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
pub(super) async fn session_info(State(st): State<ApiState>, headers: HeaderMap) -> Response {
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
pub(super) struct RotatePasswordRequest {
    /// Which account to rotate: `"admin"` or `"viewer"`.
    account: String,
    new_password: String,
}

/// POST /api/auth/rotate-password — change a stored password (admin only).
/// Requires either an admin session (with CSRF) or the bearer api_token.
/// Persists the new hash to the credentials file when a config path is known.
pub(super) async fn rotate_password(
    State(st): State<ApiState>,
    ConnectInfo(ClientAddr(peer)): ConnectInfo<ClientAddr>,
    headers: HeaderMap,
    Json(req): Json<RotatePasswordRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "rotate_password")?;
    let client = client_ip::resolve(
        peer.ip(),
        &headers,
        &st.shared.app.load().server.trusted_proxies,
    );
    let peer_label = st.shared.client_label(peer.ip());
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
    let rotated = tokio::task::spawn_blocking(move || match account_for_task.as_str() {
        "admin" => {
            let path = match cfg_path {
                Some(p) => p,
                None => {
                    return (
                        Err("no config path known; cannot persist admin credential".into()),
                        false,
                        Some("no config path known; cannot persist".into()),
                    );
                }
            };
            match auth.set_admin_password(&path, &new_password) {
                Ok(()) => (Ok(()), true, None),
                Err(e) => (Err(e.clone()), false, Some(e)),
            }
        }
        "viewer" => {
            if !auth.rotate_viewer_password(&new_password) {
                return (
                    Err(format!(
                        "no '{account_for_task}' credential is configured to rotate"
                    )),
                    false,
                    None,
                );
            }
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
        }
        other => (
            Err(format!("unknown account '{other}' (expected admin|viewer)")),
            false,
            None,
        ),
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
            "client": st.shared.client_label(client),
                "peer": peer_label,
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

/// DELETE /api/auth/sessions — administrative session revocation: invalidate
/// every session except the caller's own (an admin who suspects a stolen
/// cookie can cut off every other browser without being signed out). Bearer
/// token callers have no session of their own, so *all* sessions are
/// revoked. Admin only; cookie requests need the CSRF header.
pub(super) async fn revoke_sessions(
    State(st): State<ApiState>,
    ConnectInfo(ClientAddr(peer)): ConnectInfo<ClientAddr>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_admin(&st, &headers, "revoke_sessions")?;
    let client = client_ip::resolve(
        peer.ip(),
        &headers,
        &st.shared.app.load().server.trusted_proxies,
    );
    let revoked = match session_cookie(&headers) {
        Some(tok) if st.auth.session(tok).is_some() => st.auth.revoke_all_except(tok),
        _ => {
            let n = st.auth.session_count();
            st.auth.logout_all();
            n
        }
    };
    st.shared.record_config_event(
        "revoke_sessions",
        json!({
            "client": st.shared.client_label(client),
            "peer": st.shared.client_label(peer.ip()),
            "sessions_revoked": revoked,
            "outcome": "applied",
        }),
    );
    Ok(Json(json!({ "status": "ok", "sessions_revoked": revoked })))
}
