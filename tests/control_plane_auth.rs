//! Control-plane authentication over HTTP: per-client lockout, trusted-proxy
//! client resolution, spoofed forwarded headers, session revocation and idle
//! expiry.

#![allow(dead_code)]

mod common;

use common::*;
use std::net::SocketAddr;

const LOGIN_BAD: &str = r#"{"username":"admin","password":"bad"}"#;
const LOGIN_OK: &str = r#"{"username":"admin","password":"admin-pw"}"#;

fn xff(v: &str) -> Vec<(String, String)> {
    vec![("X-Forwarded-For".into(), v.into())]
}

async fn login_status(api: SocketAddr, body: &str, headers: &[(String, String)]) -> (u16, String) {
    let raw = http_raw("POST", api, "/api/auth/login", Some(body), headers).await;
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, raw)
}

fn trusting_loopback() -> res::config::AppConfig {
    let mut cfg = base_config();
    cfg.server.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attacker_lockout_does_not_lock_the_admin_on_another_address() {
    let mut cfg = trusting_loopback();
    cfg.auth.max_failed_attempts = 3;
    cfg.auth.login_rate_limit_per_minute = 0;
    let gw = start_gateway_with_passwords(cfg, "admin-pw", None).await;
    let api = gw.api_addr().unwrap();
    let attacker = xff("203.0.113.9");
    for _ in 0..3 {
        assert_eq!(login_status(api, LOGIN_BAD, &attacker).await.0, 401);
    }
    // The attacker is now locked out - even with the right password...
    assert_eq!(login_status(api, LOGIN_OK, &attacker).await.0, 429);
    // ...but the administrator on another address signs in normally.
    let (status, raw) = login_status(api, LOGIN_OK, &xff("198.51.100.4")).await;
    assert_eq!(status, 200, "{raw}");
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_trusted_proxies_forwarded_headers_are_ignored() {
    let mut cfg = base_config(); // trusted_proxies empty
    cfg.auth.login_rate_limit_per_minute = 3;
    cfg.auth.max_failed_attempts = u32::MAX;
    let gw = start_gateway_with_passwords(cfg, "admin-pw", None).await;
    let api = gw.api_addr().unwrap();
    // Each request claims a different client; all come from the same socket
    // peer, so the per-IP limit still applies on the 4th attempt.
    for i in 0..3 {
        let h = xff(&format!("203.0.113.{}", 10 + i));
        assert_eq!(login_status(api, LOGIN_BAD, &h).await.0, 401);
    }
    assert_eq!(
        login_status(api, LOGIN_BAD, &xff("198.51.100.99")).await.0,
        429
    );
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trusted_proxy_rate_limit_is_per_forwarded_client() {
    let mut cfg = trusting_loopback();
    cfg.auth.login_rate_limit_per_minute = 2;
    cfg.auth.max_failed_attempts = u32::MAX;
    let gw = start_gateway_with_passwords(cfg, "admin-pw", None).await;
    let api = gw.api_addr().unwrap();
    let a = xff("203.0.113.1");
    for _ in 0..2 {
        assert_eq!(login_status(api, LOGIN_BAD, &a).await.0, 401);
    }
    assert_eq!(login_status(api, LOGIN_BAD, &a).await.0, 429);
    // A different forwarded client has its own budget.
    assert_eq!(
        login_status(api, LOGIN_BAD, &xff("203.0.113.2")).await.0,
        401
    );
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spoofed_left_hops_cannot_reset_the_limit_behind_a_trusted_proxy() {
    let mut cfg = trusting_loopback();
    cfg.auth.login_rate_limit_per_minute = 2;
    cfg.auth.max_failed_attempts = u32::MAX;
    let gw = start_gateway_with_passwords(cfg, "admin-pw", None).await;
    let api = gw.api_addr().unwrap();
    // The proxy appends the true client (203.0.113.7); the attacker prepends
    // forged addresses. Only the proxy-appended hop is believed.
    for i in 0..2 {
        let h = xff(&format!("10.9.9.{i}, 203.0.113.7"));
        assert_eq!(login_status(api, LOGIN_BAD, &h).await.0, 401);
    }
    assert_eq!(
        login_status(api, LOGIN_BAD, &xff("1.2.3.4, 203.0.113.7"))
            .await
            .0,
        429
    );
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_events_record_both_client_and_socket_peer() {
    let mut cfg = trusting_loopback();
    cfg.server.api_token = "tok".into();
    let gw = start_gateway_with_passwords(cfg, "admin-pw", None).await;
    let api = gw.api_addr().unwrap();
    assert_eq!(
        login_status(api, LOGIN_BAD, &xff("203.0.113.5")).await.0,
        401
    );
    let (status, body) = http_auth("GET", api, "/api/config/events", None, Some("tok")).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("203.0.113.5"),
        "forwarded client recorded: {body}"
    );
    assert!(
        body.contains("127.0.0.1"),
        "real socket peer recorded: {body}"
    );
    gw.shutdown().await;
}

async fn session_of(api: SocketAddr, user: &str, pw: &str) -> (String, String) {
    let body = format!(r#"{{"username":"{user}","password":"{pw}"}}"#);
    let (status, raw) = login_status(api, &body, &[]).await;
    assert_eq!(status, 200, "{raw}");
    (
        set_cookie(&raw, "res_session").expect("session"),
        set_cookie(&raw, "res_csrf").expect("csrf"),
    )
}

fn cookie(sess: &str) -> Vec<(String, String)> {
    vec![("Cookie".into(), format!("res_session={sess}"))]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_can_revoke_all_other_sessions() {
    let mut cfg = base_config();
    cfg.auth.login_rate_limit_per_minute = 0;
    let gw = start_gateway_with_passwords(cfg, "admin-pw", Some("view-pw")).await;
    let api = gw.api_addr().unwrap();
    let (a, a_csrf) = session_of(api, "admin", "admin-pw").await;
    let (b, _) = session_of(api, "admin", "admin-pw").await;
    let (v, v_csrf) = session_of(api, "viewer", "view-pw").await;

    // A viewer may not revoke sessions.
    let mut h = cookie(&v);
    h.push(("X-CSRF-Token".into(), v_csrf));
    let (status, _) = http_headers("DELETE", api, "/api/auth/sessions", None, &h).await;
    assert_eq!(status, 403);
    // Admin without the CSRF header is refused.
    let (status, _) = http_headers("DELETE", api, "/api/auth/sessions", None, &cookie(&a)).await;
    assert_eq!(status, 403);

    let mut h = cookie(&a);
    h.push(("X-CSRF-Token".into(), a_csrf));
    let (status, body) = http_headers("DELETE", api, "/api/auth/sessions", None, &h).await;
    assert_eq!(status, 200, "{body}");
    let v_json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v_json["sessions_revoked"], 2, "{body}");

    assert_eq!(
        http_headers("GET", api, "/api/status", None, &cookie(&a))
            .await
            .0,
        200
    );
    assert_eq!(
        http_headers("GET", api, "/api/status", None, &cookie(&b))
            .await
            .0,
        401
    );
    assert_eq!(
        http_headers("GET", api, "/api/status", None, &cookie(&v))
            .await
            .0,
        401
    );
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_sessions_are_rejected_over_http() {
    let mut cfg = base_config();
    cfg.auth.session_idle_timeout_ms = 400;
    cfg.auth.login_rate_limit_per_minute = 0;
    let gw = start_gateway_with_passwords(cfg, "admin-pw", None).await;
    let api = gw.api_addr().unwrap();
    let (s, _) = session_of(api, "admin", "admin-pw").await;
    assert_eq!(
        http_headers("GET", api, "/api/status", None, &cookie(&s))
            .await
            .0,
        200
    );
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    assert_eq!(
        http_headers("GET", api, "/api/status", None, &cookie(&s))
            .await
            .0,
        401
    );
    gw.shutdown().await;
}
