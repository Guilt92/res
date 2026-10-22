//! End-to-end integration tests: a real gateway (UDP + TCP + API) talking to
//! in-process fake upstreams. No external DNS server or network is required.

mod common;

use std::time::Duration;

use common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RData;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Minimal HTTPS client for the management listener, trusting only the test
/// CA. Deliberately checks certificate validation instead of disabling it.
async fn tls_http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let pem = std::fs::read(TLS_CA_PATH).expect("read test CA");
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(pem)).expect("parse test CA") {
        roots.add(cert.into()).expect("add test CA");
    }
    let config = std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let mut tls = tokio_rustls::TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .expect("TLS handshake");
    tls.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .expect("write request");
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).into_owned()
}

fn answers_ip(resp: &hickory_proto::op::Message) -> Option<std::net::Ipv4Addr> {
    match resp.answers.first()?.data {
        RData::A(a) => Some(a.0),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_forwarding_returns_upstream_answer() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    let resp = udp_query(addr, "example.test").await.expect("response");
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(answers_ip(&resp), Some(ANSWER));
    assert_eq!(fake.hits(), 1);

    gw.shutdown().await;
    fake.stop().await;
}

/// Management API served directly over HTTPS, with certificate validation and
/// HSTS instead of a plaintext listener.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_tls_serves_validated_https_with_hsts() {
    let mut cfg = base_config();
    cfg.server.tls_cert = Some(TLS_CERT_PATH.into());
    cfg.server.tls_key = Some(TLS_KEY_PATH.into());
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let raw = tls_http_get(api, "/api/health").await;
    assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
    assert!(
        raw.to_ascii_lowercase()
            .contains("strict-transport-security: max-age=31536000"),
        "TLS responses must carry HSTS: {raw}"
    );
    assert!(raw.contains("\"status\":\"ok\""), "{raw}");

    // A plain HTTP request to the TLS port must not be served.
    let mut tcp = tokio::net::TcpStream::connect(api).await.expect("tcp");
    tcp.write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write plain");
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut buf))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(0);
    assert!(
        !String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/"),
        "plaintext must not be served on the TLS listener"
    );

    gw.shutdown().await;
}

/// Management TLS is all-or-nothing: a half-configured identity is rejected
/// at startup, never silently served as plain HTTP.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_tls_requires_both_certificate_and_key() {
    let mut cfg = base_config();
    cfg.server.tls_cert = Some(TLS_CERT_PATH.into());
    let err = res::runtime::start(cfg, None)
        .await
        .err()
        .expect("certificate without key must fail");
    assert!(
        err.to_string().contains("tls_cert and server.tls_key"),
        "unexpected error: {err}"
    );
}

/// DNS-over-TLS upstream with SNI verified against a private CA. The answer
/// must travel inside TLS with no UDP/plain-TCP fallback.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dot_forwarding_uses_validated_tls() {
    let fake = FakeTlsUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("dot-1", "localhost"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    let resp = udp_query(addr, "dot.test").await.expect("response");
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(answers_ip(&resp), Some(ANSWER));
    assert_eq!(fake.hits(), 1, "query must reach the TLS upstream");

    gw.shutdown().await;
    fake.stop().await;
}

/// A certificate/SNI mismatch is a hard failure: no plaintext retry and no
/// silent downgrade to the same address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dot_rejects_server_name_mismatch_without_downgrade() {
    let fake = FakeTlsUpstream::start().await;
    let mut cfg = base_config();
    cfg.query.max_attempts = 1;
    cfg.query.upstream_timeout_ms = 1000;
    cfg.query.timeout_ms = 2000;
    cfg.upstreams
        .push(fake.config("dot-bad-name", "wrong.example"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    let resp = udp_query(addr, "dot.test").await.expect("response");
    assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(
        fake.hits(),
        0,
        "mismatched certificate must not carry a query"
    );

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_forwarding_returns_upstream_answer() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let addr = gw.tcp_addr().expect("tcp addr");

    let resp = tcp_query(addr, "example.test").await.expect("response");
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(answers_ip(&resp), Some(ANSWER));
    assert!(fake.hits() >= 1);

    gw.shutdown().await;
    fake.stop().await;
}

/// IPv6 listeners use the same data/control planes. The test skips on hosts
/// with IPv6 disabled (common in minimal CI images) instead of failing for
/// an environment property the gateway cannot change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipv6_loopback_serves_dns_and_api_when_available() {
    if tokio::net::UdpSocket::bind("[::1]:0").await.is_err() {
        eprintln!("skipping IPv6 test: IPv6 loopback is unavailable");
        return;
    }
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.server.udp_addr = "[::1]:0".parse().expect("udp addr");
    cfg.server.tcp_addr = "[::1]:0".parse().expect("tcp addr");
    cfg.server.api_addr = "[::1]:0".parse().expect("api addr");
    cfg.upstreams.push(fake.config("fake-v6"));
    let gw = start_gateway(cfg).await;
    let udp = gw.udp_addr().expect("udp addr");
    let tcp = gw.tcp_addr().expect("tcp addr");
    let api = gw.api_addr().expect("api addr");
    assert!(udp.is_ipv6() && tcp.is_ipv6() && api.is_ipv6());

    let sock = tokio::net::UdpSocket::bind("[::1]:0")
        .await
        .expect("v6 udp");
    sock.connect(udp).await.expect("connect v6 udp");
    let query = res::dns::msg::build_query("ipv6.test", "A").expect("query");
    sock.send(&query).await.expect("send v6 udp");
    let mut buf = vec![0u8; 65_535];
    let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
        .await
        .expect("v6 udp timeout")
        .expect("v6 udp recv");
    let resp = hickory_proto::op::Message::from_vec(&buf[..n]).expect("v6 udp parse");
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(answers_ip(&resp), Some(ANSWER));

    let resp = tcp_query(tcp, "ipv6.test").await.expect("v6 tcp answer");
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(answers_ip(&resp), Some(ANSWER));

    let (status, body) = http("GET", api, "/api/health", None).await;
    assert_eq!(status, 200, "v6 API: {body}");

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncated_udp_response_falls_back_to_tcp() {
    let fake = FakeUpstream::start().await;
    fake.set_truncate_udp(true); // UDP answers are TC=1, TCP answers fully
    let mut cfg = base_config();
    cfg.server.upstream_tcp_fallback = true;
    cfg.query.upstream_timeout_ms = 1000;
    cfg.query.timeout_ms = 3000;
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    let resp = udp_query(addr, "large.test").await.expect("response");
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    // The final answer must be complete: it can only come from the TCP retry.
    assert_eq!(answers_ip(&resp), Some(ANSWER));
    assert!(
        fake.hits() >= 2,
        "expected UDP probe + TCP retry, got {}",
        fake.hits()
    );

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failover_skips_silent_upstream_and_succeeds() {
    let dead = FakeUpstream::start().await;
    dead.set_answering(false);
    let live = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.query.max_attempts = 3;
    cfg.query.upstream_timeout_ms = 300;
    cfg.query.timeout_ms = 2000;
    // Strict priority tiers make the retry deterministic: the dead upstream
    // is always attempted first, the live one only as the failover target.
    let mut dead_cfg = dead.config("dead");
    dead_cfg.priority = 1;
    let mut live_cfg = live.config("live");
    live_cfg.priority = 2;
    cfg.upstreams.push(dead_cfg);
    cfg.upstreams.push(live_cfg);
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    let resp = udp_query(addr, "failover.test").await.expect("response");
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(answers_ip(&resp), Some(ANSWER));
    assert_eq!(live.hits(), 1, "the live upstream must have answered");

    // The retry must be visible in the metrics (counted once per query).
    let text = gw.shared.metrics.render();
    let failovers: u64 = text
        .lines()
        .find(|l| l.starts_with("res_failovers_total "))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert!(
        failovers >= 1,
        "expected failovers_total >= 1, got {failovers}"
    );
    // The failover latency histogram must observe the extra time the client
    // waited for the dead upstream (one observation per successful failover).
    let fo_latency: u64 = text
        .lines()
        .find(|l| l.starts_with("res_failover_latency_seconds_count "))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert!(
        fo_latency >= 1,
        "expected failover_latency observations >= 1, got {fo_latency}"
    );

    // The retry must also appear in the bounded failover event ring with the
    // failing upstream, the reason and the fallback target.
    let api = gw.api_addr().expect("api addr");
    let (status, body) = http("GET", api, "/api/events?kind=failover&limit=10", None).await;
    assert_eq!(status, 200, "events body: {body}");
    let events: serde_json::Value = serde_json::from_str(&body).expect("events json");
    let list = events["events"].as_array().expect("events array");
    assert!(!list.is_empty(), "expected a recorded failover event");
    assert_eq!(list[0]["kind"], "failover");
    assert_eq!(list[0]["reason"], "timeout");
    assert_eq!(list[0]["upstream"], "dead");
    assert_eq!(list[0]["fallback"], "live");
    assert!(list[0]["attempts"].as_u64().unwrap_or(0) >= 2);
    assert!(
        list[0]["extra_latency_ms"].is_number(),
        "the panel needs the real added latency: {body}"
    );

    // Per-upstream failover accounting: the failing upstream owns the count.
    let (status, body) = http("GET", api, "/api/upstreams", None).await;
    assert_eq!(status, 200, "upstreams body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("upstreams json");
    let state = &v["state"];
    assert_eq!(state["total"].as_u64(), Some(2), "{body}");
    assert_eq!(state["emergency"].as_bool(), Some(false), "{body}");
    let eligible = state["eligible"].as_array().expect("eligible list");
    assert!(
        eligible.iter().any(|n| n == "live"),
        "the answering upstream must be eligible: {body}"
    );
    let ups = v["upstreams"].as_array().expect("upstreams array");
    let dead_stats = ups
        .iter()
        .find(|u| u["name"] == "dead")
        .expect("dead stats");
    let live_stats = ups
        .iter()
        .find(|u| u["name"] == "live")
        .expect("live stats");
    assert!(
        dead_stats["failovers"].as_u64().unwrap_or(0) >= 1,
        "dead upstream must own the failover count: {dead_stats}"
    );
    assert_eq!(
        live_stats["failovers"].as_u64().unwrap_or(0),
        0,
        "the answering upstream must not own failovers"
    );
    assert!(
        dead_stats["last_failure_ago_secs"].is_number(),
        "last failure timestamp expected"
    );
    assert!(
        dead_stats["failure_rate"].as_f64().is_some_and(|r| r > 0.9),
        "every attempt on the dead upstream failed: {dead_stats}"
    );
    assert!(
        dead_stats["qps"].is_number() && dead_stats["in_use"].is_boolean(),
        "sampled rate fields are required: {dead_stats}"
    );
    assert!(
        dead_stats["eligible"].is_boolean(),
        "eligibility flag is required: {dead_stats}"
    );

    gw.shutdown().await;
    dead.stop().await;
    live.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_refuses_disallowed_client() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    // Loopback is deliberately not in the allow list.
    cfg.acl.allowed_cidrs = vec!["198.51.100.0/24".to_string()];
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    let resp = udp_query(addr, "denied.test").await.expect("REFUSED reply");
    assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
    assert!(resp.answers.is_empty());
    assert_eq!(fake.hits(), 0, "denied queries must never be forwarded");

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limit_drops_excess_queries() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.ratelimit.enabled = true;
    cfg.ratelimit.per_ip_qps = 1.0;
    cfg.ratelimit.per_ip_burst = 1;
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    // First query consumes the whole bucket.
    assert!(udp_query(addr, "burst-1.test").await.is_some());
    // The immediate second query must be silently dropped.
    let second = udp_query_timeout(addr, "burst-2.test", Duration::from_millis(500)).await;
    assert!(second.is_none(), "second query should be rate limited");

    let text = gw.shared.metrics.render();
    assert!(
        text.contains("res_rate_limit_dropped_total"),
        "rate limit metric missing"
    );

    gw.shutdown().await;
    fake.stop().await;
}

/// Response-rate limiting is a UDP amplification guard: repeated identical
/// answers become TC=1 so the client can retry over TCP, while the connected
/// TCP path still receives the complete answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rrl_truncates_repeated_udp_responses_but_not_tcp() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.cache.enabled = true;
    cfg.rrl.enabled = true;
    cfg.rrl.per_client_qps = 0.001;
    cfg.rrl.burst = 2;
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let udp = gw.udp_addr().expect("udp addr");
    let tcp = gw.tcp_addr().expect("tcp addr");

    let first = udp_query(udp, "rrl.test").await.expect("first answer");
    assert!(!first.metadata.truncation);
    let second = udp_query(udp, "rrl.test").await.expect("second answer");
    assert!(!second.metadata.truncation);
    let third = udp_query(udp, "rrl.test").await.expect("limited answer");
    assert!(
        third.metadata.truncation,
        "third identical UDP answer must be TC=1"
    );

    let over_tcp = tcp_query(tcp, "rrl.test").await.expect("tcp answer");
    assert!(!over_tcp.metadata.truncation);
    assert_eq!(over_tcp.metadata.response_code, ResponseCode::NoError);

    let text = gw.shared.metrics.render();
    assert!(text.contains("res_rrl_truncated_total 1"), "{text}");
    assert!(text.contains("res_rrl_dropped_total 0"), "{text}");

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rrl_drop_action_sheds_repeated_udp_responses() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.cache.enabled = true;
    cfg.rrl.enabled = true;
    cfg.rrl.per_client_qps = 0.001;
    cfg.rrl.burst = 1;
    cfg.rrl.action = res::ratelimit::RrlAction::Drop;
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let udp = gw.udp_addr().expect("udp addr");

    assert!(udp_query(udp, "rrl-drop.test").await.is_some());
    assert!(
        udp_query_timeout(udp, "rrl-drop.test", Duration::from_millis(300))
            .await
            .is_none(),
        "drop action must send nothing for the limited response"
    );
    assert!(gw
        .shared
        .metrics
        .render()
        .contains("res_rrl_dropped_total 1"));

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_packets_dropped_notimp_answered() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    // Garbage: silently dropped (no response at all).
    let drop = udp_send_raw(addr, b"garbage!", Duration::from_millis(500)).await;
    assert!(drop.is_none(), "malformed packet must be dropped");

    // Well-formed query with a non-QUERY opcode: explicit NOTIMP.
    let mut q = res::dns::msg::build_query("opcode.test", "A").expect("query");
    q[2] = (q[2] & 0x87) | (2 << 3); // opcode = UPDATE
    let resp = udp_send_raw(addr, &q, Duration::from_secs(2))
        .await
        .expect("NOTIMP");
    assert_eq!(resp.metadata.response_code, ResponseCode::NotImp);
    assert_eq!(fake.hits(), 0, "neither packet may reach the upstream");

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_exposes_status_metrics_and_upstreams() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");

    // Generate some traffic first.
    assert!(udp_query(udp, "metrics.test").await.is_some());

    let (status, body) = http("GET", api, "/api/status", None).await;
    assert_eq!(status, 200, "status body: {body}");
    assert!(body.contains("\"udp\""), "status body: {body}");

    let (status, body) = http("GET", api, "/metrics", None).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("res_queries_total{transport=\"udp\"}"),
        "metrics missing udp counter"
    );
    assert!(body.contains("res_upstream_health"), "health gauge missing");

    let (status, body) = http("GET", api, "/api/upstreams", None).await;
    assert_eq!(status, 200);
    assert!(body.contains("\"fake-1\""), "upstream list body: {body}");

    gw.shutdown().await;
    fake.stop().await;
}

/// An idle gateway must report *unmeasured* quantities as `null`, never as a
/// plausible-looking default (the dashboard renders `null` as "N/A").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_gateway_reports_no_fake_metrics() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");

    // Health probes may run, but no *client* query has been sent.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (status, body) = http("GET", api, "/api/stats", None).await;
    assert_eq!(status, 200, "stats body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("stats json");
    assert_eq!(v["queries_total"].as_u64(), Some(0), "{body}");
    assert_eq!(v["qps"].as_f64(), Some(0.0), "idle qps is a real 0: {body}");
    assert_eq!(v["failovers"].as_u64(), Some(0));
    assert_eq!(v["rate_limited"].as_u64(), Some(0));
    assert!(v["success_rate"].is_null(), "no responses => {body}");
    assert!(v["error_rate"].is_null(), "no responses => {body}");
    assert_eq!(v["latency"]["samples"].as_u64(), Some(0), "{body}");
    assert!(v["latency"]["p50_ms"].is_null(), "no samples => {body}");
    assert!(v["latency"]["p95_ms"].is_null(), "no samples => {body}");
    assert!(v["latency"]["p99_ms"].is_null(), "no samples => {body}");
    assert!(
        v["cache"]["hit_ratio"].is_null(),
        "no cache reads => {body}"
    );

    let (status, body) = http("GET", api, "/api/upstreams", None).await;
    assert_eq!(status, 200, "upstreams body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("upstreams json");
    let up = &v["upstreams"][0];
    assert_eq!(up["queries"].as_u64(), Some(0), "{body}");
    assert!(up["success_rate"].is_null(), "no client queries => {body}");
    assert!(up["timeout_rate"].is_null(), "{body}");
    assert!(up["servfail_rate"].is_null(), "{body}");
    assert_eq!(up["latency"]["samples"].as_u64(), Some(0), "{body}");
    assert!(up["latency"]["p50_ms"].is_null(), "{body}");
    assert!(up["latency"]["p95_ms"].is_null(), "{body}");
    // The panel renders the score factors; the API must keep the structured
    // breakdown intact instead of replacing it with a bare number.
    assert!(up["score"].is_object(), "score breakdown expected: {body}");
    assert!(
        up["score"]["score"].is_number(),
        "composite score expected: {body}"
    );
    assert!(
        up["score"]["health_factor"].is_number(),
        "score factors expected: {body}"
    );
    assert!(up["score_value"].is_number(), "{body}");

    // Let the 1 Hz sampler produce real (idle) buckets: latency series must
    // stay empty while the measured counters stay 0.
    tokio::time::sleep(Duration::from_millis(2600)).await;
    let (status, body) = http("GET", api, "/api/timeseries?range=5m&source=native", None).await;
    assert_eq!(status, 200, "timeseries body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("timeseries json");
    let pts = |key: &str| -> Vec<Option<f64>> {
        v["series"][key]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|p| p[1].as_f64())
            .collect()
    };
    assert!(
        pts("p50_ms").iter().all(Option::is_none),
        "no latency sample may be invented: {body}"
    );
    assert!(
        pts("success_pct").iter().all(Option::is_none),
        "no responses => no success rate: {body}"
    );
    assert!(
        pts("cache_hit_pct").iter().all(Option::is_none),
        "no cache reads => no hit ratio: {body}"
    );
    assert!(
        pts("qps").iter().all(|p| p.is_none_or(|q| q == 0.0)),
        "idle qps must be 0, not a guess: {body}"
    );

    // The same fields become measurements once traffic actually flows.
    assert!(udp_query(udp, "idle.test").await.is_some());
    let (status, body) = http("GET", api, "/api/stats", None).await;
    assert_eq!(status, 200, "stats body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("stats json");
    assert_eq!(v["queries_total"].as_u64(), Some(1), "{body}");
    assert!(
        v["success_rate"]
            .as_f64()
            .is_some_and(|r| (r - 1.0).abs() < 1e-9),
        "measured after traffic: {body}"
    );
    assert!(
        v["latency"]["p50_ms"].as_f64().is_some(),
        "measured: {body}"
    );

    let (status, body) = http("GET", api, "/api/upstreams", None).await;
    assert_eq!(status, 200, "upstreams body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("upstreams json");
    let up = &v["upstreams"][0];
    assert_eq!(up["queries"].as_u64(), Some(1), "{body}");
    assert!(
        up["success_rate"].as_f64().is_some(),
        "now measured: {body}"
    );
    assert!(up["latency"]["p50_ms"].as_f64().is_some(), "{body}");

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_service_metrics_report_real_traffic() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");
    let tcp = gw.tcp_addr().expect("tcp addr");

    // ---- idle: every service counter is a real zero, ratios unmeasured ----
    let (status, body) = http("GET", api, "/api/stats", None).await;
    assert_eq!(status, 200, "stats body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("stats json");
    let t = &v["traffic"];
    assert_eq!(t["udp_packets_received"].as_u64(), Some(0), "{body}");
    assert_eq!(t["udp_packets_sent"].as_u64(), Some(0), "{body}");
    assert_eq!(t["request_bytes"].as_u64(), Some(0), "{body}");
    assert_eq!(t["response_bytes"].as_u64(), Some(0), "{body}");
    assert!(
        t["avg_request_bytes"].is_null(),
        "no queries => no average: {body}"
    );
    assert!(
        t["avg_response_bytes"].is_null(),
        "no responses => no average: {body}"
    );
    assert_eq!(t["client_ip_privacy"].as_str(), Some("masked"), "{body}");
    assert_eq!(t["clients"]["tracked_keys"].as_u64(), Some(0), "{body}");
    assert_eq!(t["domains"]["tracked_keys"].as_u64(), Some(0), "{body}");
    assert!(
        t["top_clients"].as_array().is_some_and(|r| r.is_empty()),
        "nothing tracked yet: {body}"
    );
    assert_eq!(t["query_type"]["A"].as_u64(), Some(0), "{body}");

    // ---- status exposes the privacy policy ----
    let (status, body) = http("GET", api, "/api/status", None).await;
    assert_eq!(status, 200, "status body: {body}");
    let s: serde_json::Value = serde_json::from_str(&body).expect("status json");
    assert_eq!(s["privacy"]["client_ip"].as_str(), Some("masked"), "{body}");
    assert_eq!(s["privacy"]["top_clients_max"].as_u64(), Some(4096));
    assert_eq!(s["privacy"]["top_domains_max"].as_u64(), Some(8192));

    // ---- real traffic: 3 UDP + 1 TCP query ----
    for name in ["a.example.test", "b.example.test", "a.example.test"] {
        assert!(
            udp_query(udp, name).await.is_some(),
            "udp answer for {name}"
        );
    }
    assert!(
        tcp_query(tcp, "a.example.test").await.is_some(),
        "tcp answer"
    );

    let (status, body) = http("GET", api, "/api/stats", None).await;
    assert_eq!(status, 200, "stats body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("stats json");
    let t = &v["traffic"];
    assert_eq!(v["queries_total"].as_u64(), Some(4), "{body}");
    assert_eq!(t["udp_packets_received"].as_u64(), Some(3), "{body}");
    assert_eq!(t["udp_packets_sent"].as_u64(), Some(3), "{body}");
    assert!(t["request_bytes"].as_u64().is_some_and(|b| b > 0), "{body}");
    assert!(
        t["response_bytes"].as_u64().is_some_and(|b| b > 0),
        "{body}"
    );
    assert!(
        t["avg_request_bytes"].as_f64().is_some_and(|a| a > 0.0),
        "measured after traffic: {body}"
    );
    assert!(
        t["avg_response_bytes"].as_f64().is_some_and(|a| a > 0.0),
        "measured after traffic: {body}"
    );
    assert_eq!(t["query_type"]["A"].as_u64(), Some(4), "{body}");
    assert_eq!(t["query_type"]["AAAA"].as_u64(), Some(0), "{body}");
    assert_eq!(t["clients"]["tracked_keys"].as_u64(), Some(1), "{body}");
    assert_eq!(t["clients"]["recorded_requests"].as_u64(), Some(4));
    assert_eq!(t["domains"]["tracked_keys"].as_u64(), Some(2), "{body}");

    // ---- packet-level observations (real maximums, not configured limits)
    assert!(
        t["max_request_bytes"].as_i64().is_some_and(|b| b > 0),
        "largest observed request: {body}"
    );
    assert!(
        t["max_response_bytes"].as_i64().is_some_and(|b| b > 0),
        "largest observed response: {body}"
    );
    assert_eq!(t["oversized_packets"].as_u64(), Some(0), "{body}");

    // ---- service-level rates: measured zeros are 0, missing denominators null
    assert_eq!(v["timeout_count"].as_u64(), Some(0), "{body}");
    assert_eq!(
        v["timeout_rate"].as_f64(),
        Some(0.0),
        "0 deadlines over 4 queries is a measured zero: {body}"
    );
    assert_eq!(v["failover_rate"].as_f64(), Some(0.0), "{body}");

    let top_clients = t["top_clients"].as_array().expect("top clients");
    assert_eq!(top_clients.len(), 1, "{body}");
    assert_eq!(
        top_clients[0]["client"].as_str(),
        Some("127.x.x.x"),
        "client address must be masked by default: {body}"
    );
    assert_eq!(top_clients[0]["count"].as_u64(), Some(4), "{body}");
    assert_eq!(top_clients[0]["requests"].as_u64(), Some(4), "{body}");
    assert_eq!(top_clients[0]["ok"].as_u64(), Some(4), "{body}");
    assert_eq!(top_clients[0]["udp"].as_u64(), Some(3), "{body}");
    assert_eq!(top_clients[0]["tcp"].as_u64(), Some(1), "{body}");
    assert_eq!(top_clients[0]["share"].as_f64(), Some(1.0), "{body}");

    let top_domains = t["top_domains"].as_array().expect("top domains");
    assert_eq!(
        top_domains[0]["domain"].as_str(),
        Some("a.example.test"),
        "{body}"
    );
    assert_eq!(top_domains[0]["count"].as_u64(), Some(3), "{body}");

    // ---- dedicated introspection endpoints ----
    let (status, body) = http("GET", api, "/api/clients?limit=5", None).await;
    assert_eq!(status, 200, "clients body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("clients json");
    assert_eq!(v["privacy"].as_str(), Some("masked"), "{body}");
    assert_eq!(
        v["tracked"]["recorded_requests"].as_u64(),
        Some(4),
        "{body}"
    );
    assert_eq!(v["rows"][0]["client"].as_str(), Some("127.x.x.x"), "{body}");
    assert_eq!(v["rows"][0]["count"].as_u64(), Some(4), "{body}");
    assert_eq!(v["rows"][0]["failed"].as_u64(), Some(0), "{body}");
    assert_eq!(v["rows"][0]["timeouts"].as_u64(), Some(0), "{body}");
    assert_eq!(v["rows"][0]["acl_denied"].as_u64(), Some(0), "{body}");
    assert_eq!(v["rows"][0]["rate_limited"].as_u64(), Some(0), "{body}");
    assert!(
        v["rows"][0]["avg_ms"].as_f64().is_some_and(|m| m >= 0.0),
        "measured average per client: {body}"
    );
    assert!(
        v["rows"][0]["p95_ms"].as_f64().is_some_and(|m| m >= 0.0),
        "measured p95 per client: {body}"
    );
    assert!(
        v["rows"][0]["bytes"].as_u64().is_some_and(|b| b > 0),
        "{body}"
    );

    // Sorting is accepted and echoed back (orders are applied to real counts).
    let (status, body) = http("GET", api, "/api/clients?sort=bytes", None).await;
    assert_eq!(status, 200, "sort query: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("clients json");
    assert_eq!(v["sort"].as_str(), Some("bytes"), "{body}");

    // ---- current upstream state summary ----
    let (status, body) = http("GET", api, "/api/upstreams", None).await;
    assert_eq!(status, 200, "upstreams body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("upstreams json");
    let state = &v["state"];
    assert_eq!(state["total"].as_u64(), Some(1), "{body}");
    assert_eq!(state["healthy"].as_u64(), Some(1), "{body}");
    assert_eq!(state["emergency"].as_bool(), Some(false), "{body}");
    assert_eq!(
        state["eligible"].as_array().and_then(|a| a[0].as_str()),
        Some("fake-1"),
        "{body}"
    );
    assert_eq!(
        v["upstreams"][0]["failure_rate"].as_f64(),
        Some(0.0),
        "0 failures over real attempts: {body}"
    );

    let (status, body) = http("GET", api, "/api/domains?limit=5", None).await;
    assert_eq!(status, 200, "domains body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("domains json");
    assert_eq!(v["rows"][0]["domain"].as_str(), Some("a.example.test"));
    assert_eq!(v["rows"][0]["count"].as_u64(), Some(3), "{body}");
    assert_eq!(v["rows"][1]["domain"].as_str(), Some("b.example.test"));

    // ---- limits are validated ----
    let (status, _) = http("GET", api, "/api/clients?limit=0", None).await;
    assert_eq!(status, 200, "limit 0 falls back to the default");
    let (status, _) = http("GET", api, "/api/clients?limit=1000", None).await;
    assert_eq!(status, 200, "oversized limit is clamped");

    // ---- Prometheus exposition carries the same real numbers ----
    let (status, text) = http("GET", api, "/metrics", None).await;
    assert_eq!(status, 200);
    assert!(
        text.contains("res_udp_packets_received_total 3"),
        "wire counters must be exported:\n{text}"
    );
    assert!(text.contains("res_udp_packets_sent_total 3"), "{text}");
    assert!(text.contains("res_request_bytes_total "), "{text}");
    assert!(
        text.contains("res_query_type_total{qtype=\"A\"} 4"),
        "query-type histogram must be exported:\n{text}"
    );

    // ---- per-client Prometheus series (top-N export, masked labels) ----
    assert!(
        text.contains("res_client_queries_total{client=\"127.x.x.x\"} 4"),
        "per-client request counter must be exported:\n{text}"
    );
    assert!(
        text.contains("res_client_query_result_total{client=\"127.x.x.x\",result=\"ok\"} 4"),
        "per-client outcome counters:\n{text}"
    );
    assert!(
        !text.contains("res_client_query_result_total") || !text.contains("result=\"timeout\""),
        "outcomes that never happened must not be padded:\n{text}"
    );
    let bytes_line = text
        .lines()
        .find(|l| l.starts_with("res_client_request_bytes_total{client=\"127.x.x.x\"}"))
        .expect("per-client byte counter exported");
    assert!(
        bytes_line
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|b| b > 0),
        "real request bytes per client:\n{text}"
    );

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn privacy_off_stops_tracking_clients_and_hides_addresses() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("fake-1"));
    cfg.monitoring.client_ip_privacy = res::config::ClientIpPrivacy::Off;
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");

    assert!(udp_query(udp, "private.test").await.is_some());

    let (status, body) = http("GET", api, "/api/clients", None).await;
    assert_eq!(status, 200, "clients body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("clients json");
    assert_eq!(v["privacy"].as_str(), Some("off"), "{body}");
    assert_eq!(v["tracked"]["cap"].as_u64(), Some(0), "{body}");
    assert_eq!(v["tracked"]["tracked_keys"].as_u64(), Some(0), "{body}");
    assert!(
        v["rows"].as_array().is_some_and(|r| r.is_empty()),
        "no addresses may be exposed: {body}"
    );

    // Domains are still tracked (they are not personal data).
    let (_, body) = http("GET", api, "/api/domains", None).await;
    let v: serde_json::Value = serde_json::from_str(&body).expect("domains json");
    assert_eq!(v["tracked"]["tracked_keys"].as_u64(), Some(1), "{body}");

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_crud_works_with_file_config_only() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("seed"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    // CREATE
    let (status, body) = http(
        "POST",
        api,
        "/api/upstreams",
        Some(r#"{"name":"api-created","address":"127.0.0.1","port":5354}"#),
    )
    .await;
    assert_eq!(status, 201, "create body: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("json");
    let id = created["upstream"]["id"]
        .as_i64()
        .unwrap_or_else(|| panic!("missing id in {body}"));

    // LIST contains it
    let (status, body) = http("GET", api, "/api/upstreams", None).await;
    assert_eq!(status, 200);
    assert!(body.contains("api-created"));

    // UPDATE
    let (status, body) = http(
        "PATCH",
        api,
        &format!("/api/upstreams/{id}"),
        Some(r#"{"priority":7}"#),
    )
    .await;
    assert_eq!(status, 200, "patch body: {body}");
    assert!(body.contains("\"priority\":7") || body.contains("\"priority\": 7"));

    // DELETE
    let (status, body) = http("DELETE", api, &format!("/api/upstreams/{id}"), None).await;
    assert!(status == 200 || status == 204, "delete body: {body}");

    // Gone from the list, but the seed upstream still works.
    let (status, body) = http("GET", api, "/api/upstreams", None).await;
    assert_eq!(status, 200);
    assert!(!body.contains("api-created"));
    assert!(body.contains("\"seed\""));

    // DNS data plane still forwards after mutations.
    let udp = gw.udp_addr().expect("udp addr");
    assert!(udp_query(udp, "still-works.test").await.is_some());

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_checker_marks_upstream_down_and_recovers() {
    let flaky = FakeUpstream::start().await;
    let stable = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.health.enabled = true;
    cfg.health.interval_ms = 100;
    cfg.health.timeout_ms = 300;
    cfg.health.failure_threshold = 2;
    cfg.health.recovery_threshold = 1;
    cfg.query.upstream_timeout_ms = 300;
    cfg.query.timeout_ms = 2000;
    cfg.upstreams.push(flaky.config("flaky"));
    cfg.upstreams.push(stable.config("stable"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");

    // Both start healthy.
    assert!(
        wait_for_health(api, "flaky", "healthy", Duration::from_secs(5)).await,
        "flaky should start healthy"
    );
    assert!(
        wait_for_health(api, "stable", "healthy", Duration::from_secs(5)).await,
        "stable should start healthy"
    );

    // Outage: flaky stops answering -> must be marked down.
    flaky.set_answering(false);
    assert!(
        wait_for_health(api, "flaky", "unhealthy", Duration::from_secs(6)).await,
        "flaky upstream should be marked down"
    );

    // The data plane keeps answering through the healthy upstream.
    let resp = udp_query(udp, "during-outage.test")
        .await
        .expect("gateway must still answer during an outage");
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(answers_ip(&resp), Some(ANSWER));

    // Recovery: flaky answers again -> marked up.
    flaky.set_answering(true);
    assert!(
        wait_for_health(api, "flaky", "healthy", Duration::from_secs(6)).await,
        "flaky upstream should recover"
    );

    // ---- Prometheus health metrics reflect exactly what happened ----
    let (status, text) = http("GET", api, "/metrics", None).await;
    assert_eq!(status, 200);
    let success = metric_f64(
        &text,
        "res_healthcheck_total",
        r#"result="success",upstream="flaky""#,
    )
    .unwrap_or(0.0);
    assert!(success >= 1.0, "successful rounds exported:\n{text}");
    let failure = metric_f64(
        &text,
        "res_healthcheck_total",
        r#"result="failure",upstream="flaky""#,
    )
    .unwrap_or(0.0);
    assert!(failure >= 1.0, "failed rounds exported:\n{text}");
    let last_ok = metric_f64(
        &text,
        "res_healthcheck_last_success_timestamp_seconds",
        r#"upstream="flaky""#,
    )
    .unwrap_or(0.0);
    assert!(
        last_ok > 1_700_000_000.0,
        "real last-success unix timestamp (never epoch 0):\n{text}"
    );
    let changes = metric_f64(
        &text,
        "res_upstream_state_changes_total",
        r#"upstream="flaky""#,
    )
    .unwrap_or(0.0);
    // up -> degraded -> down -> up: at least three real transitions.
    assert!(
        changes >= 3.0,
        "state transitions counted (got {changes}):\n{text}"
    );
    let stable_changes = metric_f64(
        &text,
        "res_upstream_state_changes_total",
        r#"upstream="stable""#,
    )
    .unwrap_or(0.0);
    assert_eq!(
        stable_changes, 0.0,
        "a healthy upstream must not accumulate transitions:\n{text}"
    );

    gw.shutdown().await;
    flaky.stop().await;
    stable.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_shutdown_stops_listeners() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.server.shutdown_grace_ms = 200;
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let udp = gw.udp_addr().expect("udp addr");
    let api = gw.api_addr().expect("api addr");

    assert!(udp_query(udp, "before.test").await.is_some());
    let (status, _) = http("GET", api, "/api/health", None).await;
    assert_eq!(status, 200);

    gw.shutdown().await;

    // Listeners are gone: no UDP answer, API refuses connections.
    assert!(
        udp_query_timeout(udp, "after.test", Duration::from_millis(500))
            .await
            .is_none()
    );
    assert!(
        tokio::net::TcpStream::connect(api).await.is_err(),
        "API listener should be closed after shutdown"
    );

    fake.stop().await;
}

fn body_health(body: &str, name: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v["upstreams"]
        .as_array()?
        .iter()
        .find(|u| u["name"] == name)?
        .get("health")?
        .as_str()
        .map(|s| s.to_string())
}

/// Value of one exact `name{labels}` line from a Prometheus exposition
/// (`None` when the series was never exported).
fn metric_f64(text: &str, name: &str, labels: &str) -> Option<f64> {
    let head = format!("{name}{{{labels}}}");
    text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next()? == head)
            .then(|| it.next()?.parse::<f64>().ok())
            .flatten()
    })
}

async fn wait_for_health(
    api: std::net::SocketAddr,
    name: &str,
    want: &str,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let (_, body) = http("GET", api, "/api/upstreams", None).await;
        if body_health(&body, name).as_deref() == Some(want) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            eprintln!("wait_for_health({name} -> {want}) timed out; body={body}");
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_export_import_roundtrip_and_rejects_invalid() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("seed"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    // EXPORT: the running configuration comes back as loadable TOML.
    let (status, body) = http("GET", api, "/api/config", None).await;
    assert_eq!(status, 200, "export body: {body}");
    let exported: serde_json::Value = serde_json::from_str(&body).expect("json");
    let toml_text = exported["toml"].as_str().expect("toml string").to_string();
    assert!(
        toml_text.contains("[query]"),
        "export missing sections: {toml_text}"
    );
    let reparsed = res::config::AppConfig::parse(&toml_text).expect("exported toml loads");
    assert_eq!(reparsed.upstreams.len(), 1);

    // IMPORT: add a second upstream through the config endpoint.
    let mut imported = reparsed;
    imported.upstreams.push(res::config::UpstreamConfig {
        id: 0,
        name: "imported".into(),
        address: "9.9.9.9".parse().unwrap(),
        ..Default::default()
    });
    let import_body =
        serde_json::json!({ "toml": imported.to_toml().expect("serialize") }).to_string();
    let (status, body) = http("PUT", api, "/api/config", Some(&import_body)).await;
    assert_eq!(status, 200, "import body: {body}");

    let (status, body) = http("GET", api, "/api/upstreams", None).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("imported"),
        "imported upstream missing: {body}"
    );

    // INVALID IMPORT: rejected, runtime state completely unchanged.
    let bad = serde_json::json!({ "toml": "this is not toml {" }).to_string();
    let (status, body) = http("PUT", api, "/api/config", Some(&bad)).await;
    assert_eq!(status, 400, "invalid import must be rejected: {body}");
    let (status, body) = http("GET", api, "/api/upstreams", None).await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        v["upstreams"].as_array().expect("array").len(),
        2,
        "invalid import must not change the running config: {body}"
    );

    // Config events recorded in the bounded ring.
    let (status, body) = http("GET", api, "/api/config/events", None).await;
    assert_eq!(status, 200);
    assert!(body.contains("\"import\""), "config events: {body}");

    // Unknown event kind is a client error, not a panic.
    let (status, _) = http("GET", api, "/api/events?kind=bogus", None).await;
    assert_eq!(status, 400);

    // The data plane keeps answering after all of this (either upstream may
    // win the selection, including the imported public one).
    let resp = udp_query(gw.udp_addr().expect("udp addr"), "after-import.test")
        .await
        .expect("dns after import");
    assert!(
        resp.metadata.response_code == ResponseCode::NoError
            || resp.metadata.response_code == ResponseCode::NXDomain
    );

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_mutations_persist_atomically_with_backup() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("seed"));

    let dir = std::env::temp_dir().join(format!("res-api-cfg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let path = dir.join("res.toml");

    let gw = start_gateway_with_path(cfg, path.clone()).await;
    let api = gw.api_addr().expect("api addr");

    // First mutation creates the primary file.
    let (status, body) = http(
        "POST",
        api,
        "/api/upstreams",
        Some(r#"{"name":"persisted-a","address":"127.0.0.1","port":53}"#),
    )
    .await;
    assert_eq!(status, 201, "create: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(created["persisted"], true, "body: {body}");
    let loaded = res::config::AppConfig::load(&path).expect("persisted file loads");
    assert!(loaded.upstreams.iter().any(|u| u.name == "persisted-a"));
    assert!(
        !res::config::AppConfig::backup_path(&path).exists(),
        "no backup expected before the second write"
    );

    // Second mutation: previous valid file is preserved as last-known-good.
    let (status, body) = http(
        "POST",
        api,
        "/api/upstreams",
        Some(r#"{"name":"persisted-b","address":"127.0.0.2","port":53}"#),
    )
    .await;
    assert_eq!(status, 201, "create: {body}");
    let backup = res::config::AppConfig::load(&res::config::AppConfig::backup_path(&path))
        .expect("backup loads");
    assert!(
        backup.upstreams.iter().any(|u| u.name == "persisted-a"),
        "backup must hold the previous configuration"
    );
    let current = res::config::AppConfig::load(&path).expect("primary loads");
    assert!(current.upstreams.iter().any(|u| u.name == "persisted-b"));

    // No stray temp files left behind.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );

    // The persisted config survived: restart-equivalence check by reloading.
    let _ = std::fs::remove_dir_all(&dir);
    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn diagnostics_and_emergency_visibility_when_all_upstreams_down() {
    let dead = FakeUpstream::start().await;
    dead.set_answering(false);
    let mut cfg = base_config();
    cfg.health.enabled = true;
    cfg.health.interval_ms = 100;
    cfg.health.timeout_ms = 200;
    cfg.health.failure_threshold = 1;
    cfg.health.recovery_threshold = 1;
    cfg.query.upstream_timeout_ms = 200;
    cfg.query.timeout_ms = 600;
    cfg.upstreams.push(dead.config("only-dead"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");

    assert!(
        wait_for_health(api, "only-dead", "unhealthy", Duration::from_secs(5)).await,
        "single dead upstream should be marked down"
    );

    // Status exposes the emergency condition instead of hiding it.
    let (status, body) = http("GET", api, "/api/status", None).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["emergency"]["no_healthy_upstreams"], true, "{body}");
    assert_eq!(v["upstreams"]["healthy"], 0, "{body}");

    // Diagnostics: one-shot troubleshooting view.
    let (status, body) = http("GET", api, "/api/diagnostics", None).await;
    assert_eq!(status, 200, "{body}");
    let d: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(d["emergency"]["no_healthy_upstreams"], true, "{body}");
    assert!(d["listeners"]["udp"].is_string(), "{body}");
    assert!(d["config"]["source"].is_string(), "{body}");
    assert_eq!(d["upstreams"]["unhealthy"], 1, "{body}");
    assert!(
        d["upstreams"]["list"][0]["last_state_change_ago_secs"].is_number(),
        "{body}"
    );
    assert!(
        d["resources"]["resident_memory_bytes"].is_number(),
        "{body}"
    );
    assert!(d["events"]["health"].as_u64().unwrap_or(0) >= 1, "{body}");

    // Clients get a fast SERVFAIL rather than a hang.
    let resp = udp_query(udp, "nobody.test").await.expect("servfail reply");
    assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);

    // On-demand probe + health event history for the upstream.
    let (status, body) = http("GET", api, "/api/upstreams", None).await;
    assert_eq!(status, 200);
    let list: serde_json::Value = serde_json::from_str(&body).expect("json");
    let id = list["upstreams"][0]["id"].as_i64().expect("id");
    let (status, body) = http("POST", api, &format!("/api/upstreams/{id}/test"), None).await;
    assert_eq!(status, 200, "probe: {body}");
    let (status, body) = http("GET", api, &format!("/api/upstreams/{id}/health"), None).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"probe\""), "health events: {body}");

    gw.shutdown().await;
    dead.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn history_timeseries_and_monitoring_endpoints() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");

    // Real traffic, then wait for the 1 Hz sampler to record + close buckets
    // (baseline at t0, first deltas at ~1s, bucket pushed on the next tick).
    for i in 0..25 {
        assert!(udp_query(udp, &format!("q{i}.test")).await.is_some());
    }
    tokio::time::sleep(Duration::from_millis(2600)).await;
    let _ = udp_query(udp, "late.test").await;
    tokio::time::sleep(Duration::from_millis(1400)).await;

    // /api/history: native series derived from real metrics.
    let (status, body) = http("GET", api, "/api/history?range=5m", None).await;
    assert_eq!(status, 200, "history body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("history json");
    assert_eq!(v["source"], "native");
    assert_eq!(v["range"], "5m");
    let qps = v["series"]["qps"].as_array().expect("qps series");
    assert!(!qps.is_empty(), "expected recorded qps buckets");
    // qps buckets are rates over bucket widths that can exceed 1s, so the raw
    // sum of rates slightly undershoots the query count — scale back by step.
    let step = v["step_seconds"].as_f64().unwrap_or(1.0).max(1.0);
    let total_q: f64 = qps.iter().filter_map(|p| p[1].as_f64()).sum::<f64>() * step;
    assert!(
        total_q >= 24.0,
        "queries must show up in the series: {total_q}"
    );
    assert!(v["series"]["p95_ms"].as_array().is_some());
    assert!(v["series"]["healthy"].as_array().is_some());
    let up_qps = v["upstreams"]["fake-1"]["qps"]
        .as_array()
        .expect("per-upstream qps");
    let up_total: f64 = up_qps.iter().filter_map(|p| p[1].as_f64()).sum::<f64>() * step;
    assert!(
        up_total >= 24.0,
        "per-upstream qps must reflect real traffic: {up_total}"
    );
    let up_p50 = v["upstreams"]["fake-1"]["p50_ms"]
        .as_array()
        .expect("per-upstream p50");
    assert!(
        up_p50.iter().any(|p| p[1].as_f64().is_some()),
        "per-upstream p50 from real histogram"
    );
    let up_to = v["upstreams"]["fake-1"]["timeout_pct"]
        .as_array()
        .expect("per-upstream timeout");
    assert!(
        up_to.iter().any(|p| p[1].as_f64().is_some()),
        "per-upstream timeout pct defined when traffic exists"
    );
    let healthy = v["series"]["healthy"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p[1].as_f64())
        .fold(0.0f64, f64::max);
    assert_eq!(healthy, 1.0, "single upstream => healthy must be 1");

    // Invalid ranges are rejected.
    let (status, _) = http("GET", api, "/api/history?range=nope", None).await;
    assert_eq!(status, 400);
    let (status, _) = http("GET", api, "/api/history?range=30d", None).await;
    assert_eq!(status, 400);

    // /api/timeseries: native source.
    let (status, body) = http("GET", api, "/api/timeseries?range=5m&source=native", None).await;
    assert_eq!(status, 200, "timeseries body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("timeseries json");
    assert_eq!(v["source"], "native");

    // source=auto falls back to native when Prometheus is not configured.
    let (status, body) = http("GET", api, "/api/timeseries?range=5m&source=auto", None).await;
    assert_eq!(status, 200, "auto body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("auto json");
    assert_eq!(v["source"], "native");
    assert_eq!(v["fallback_reason"], "prometheus_not_configured");

    // Explicit prometheus source without configuration is a client error.
    let (status, _) = http(
        "GET",
        api,
        "/api/timeseries?range=5m&source=prometheus",
        None,
    )
    .await;
    assert_eq!(status, 400);

    // Unknown source rejected.
    let (status, _) = http("GET", api, "/api/timeseries?range=5m&source=bogus", None).await;
    assert_eq!(status, 400);

    // /api/monitoring reports the unconfigured Prometheus integration.
    let (status, body) = http("GET", api, "/api/monitoring", None).await;
    assert_eq!(status, 200, "monitoring body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("monitoring json");
    assert_eq!(v["prometheus"]["configured"], false);
    assert_eq!(v["prometheus"]["reachable"], false);

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn system_events_capture_acl_and_rate_limit_activity() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("fake-1"));
    // Loopback is NOT allowed: every client query is refused by the ACL.
    cfg.acl.allowed_cidrs = vec!["10.0.0.0/8".to_string()];
    cfg.ratelimit.enabled = true;
    cfg.ratelimit.per_ip_qps = 1.0;
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");

    // ACL denial (REFUSED response) must land in the system event ring.
    let resp = udp_query(udp, "acl.test").await.expect("response");
    assert_eq!(resp.metadata.response_code, ResponseCode::Refused);

    // With the ACL denying everything the rate limiter never sees a query,
    // so use a second gateway for the rate-limit path.
    let (status, body) = http("GET", api, "/api/events?kind=system&limit=10", None).await;
    assert_eq!(status, 200, "events body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("events json");
    let events = v["events"].as_array().expect("events array");
    assert!(!events.is_empty(), "expected a system event");
    assert_eq!(events[0]["kind"], "system");
    assert_eq!(events[0]["action"], "acl_denied");
    // Default privacy: the event carries the masked address, never the host.
    assert_eq!(
        events[0]["detail"]["client_ip"].as_str(),
        Some("127.x.x.x"),
        "{body}"
    );

    gw.shutdown().await;
    fake.stop().await;

    // Rate limit path: allow loopback, drop every query after the first.
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("fake-1"));
    cfg.ratelimit.enabled = true;
    cfg.ratelimit.per_ip_qps = 1.0;
    cfg.ratelimit.per_ip_burst = 1;
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");
    let _ = udp_query(udp, "burst-a.test").await;
    for _ in 0..10 {
        let _ = udp_query_timeout(udp, "burst-b.test", Duration::from_millis(300)).await;
    }
    let (status, body) = http("GET", api, "/api/events?kind=system&limit=10", None).await;
    assert_eq!(status, 200, "events body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("events json");
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "rate_limited"),
        "expected a rate_limited system event, got {events:?}"
    );

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn system_events_capture_client_deadlines() {
    let dead_a = FakeUpstream::start().await;
    dead_a.set_answering(false);
    let dead_b = FakeUpstream::start().await;
    dead_b.set_answering(false);
    let mut cfg = base_config();
    // Two dead upstreams so retries keep happening until the clock runs out
    // (with a single upstream the pool empties first: `upstream_failure`).
    let mut a = dead_a.config("dead-a");
    a.priority = 1;
    let mut b = dead_b.config("dead-b");
    b.priority = 2;
    cfg.upstreams.push(a);
    cfg.upstreams.push(b);
    // Attempt budget (150 + 50 ms) reaches the total deadline (200 ms) on
    // the third loop iteration: `deadline`.
    cfg.query.upstream_timeout_ms = 150;
    cfg.query.timeout_ms = 200;
    cfg.query.max_attempts = 3;
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");

    // Two queries: each hits the total deadline (client-visible timeout).
    let r1 = udp_query_timeout(udp, "deadline-1.test", Duration::from_millis(900)).await;
    let r2 = udp_query_timeout(udp, "deadline-2.test", Duration::from_millis(900)).await;
    assert_eq!(
        r1.map(|m| m.metadata.response_code),
        Some(ResponseCode::ServFail)
    );
    assert_eq!(
        r2.map(|m| m.metadata.response_code),
        Some(ResponseCode::ServFail)
    );

    let (status, body) = http("GET", api, "/api/events?kind=system&limit=10", None).await;
    assert_eq!(status, 200, "events body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("events json");
    let events = v["events"].as_array().expect("events array");
    let deadline = events
        .iter()
        .find(|e| e["action"] == "query_deadline")
        .expect("query_deadline system event");
    assert_eq!(deadline["detail"]["transport"], "udp");

    // Deadline responses are also visible in the metrics used by history.
    let text = gw.shared.metrics.render();
    assert!(
        text.contains("res_query_errors_total{reason=\"deadline\"} 2"),
        "expected two deadline errors:\n{text}"
    );

    gw.shutdown().await;
    dead_a.stop().await;
    dead_b.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_and_upstream_rates_are_measured_from_real_traffic() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("fake-rate"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");

    for _ in 0..6 {
        assert!(udp_query(udp, "rate.test").await.is_some(), "answer");
    }

    // The sampler ticks once per second. Poll until we observe the window in
    // which these queries were actually measured (rates are window-based, so
    // a single fixed sleep could race past it).
    let mut client_rps = 0.0;
    let mut up_qps = 0.0;
    let mut in_use = false;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(4000);
    while tokio::time::Instant::now() < deadline && !(client_rps > 0.0 && up_qps > 0.0 && in_use) {
        let (_, body) = http("GET", api, "/api/clients?limit=5", None).await;
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
            client_rps = v["rows"][0]["rps"].as_f64().unwrap_or(0.0);
        }
        let (_, body) = http("GET", api, "/api/upstreams", None).await;
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
            up_qps = v["upstreams"][0]["qps"].as_f64().unwrap_or(0.0);
            in_use = v["upstreams"][0]["in_use"].as_bool().unwrap_or(false)
                && v["state"]["in_use"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|n| n == "fake-rate"));
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    let (status, body) = http("GET", api, "/api/clients?limit=5", None).await;
    assert_eq!(status, 200, "clients body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("clients json");
    let row = &v["rows"][0];
    assert_eq!(row["requests"].as_u64(), Some(6), "{body}");
    assert_eq!(row["ok"].as_u64(), Some(6), "{body}");
    assert_eq!(row["share"].as_f64(), Some(1.0), "{body}");
    assert!(
        row["avg_ms"].as_f64().is_some_and(|m| m >= 0.0),
        "measured average: {body}"
    );
    assert!(
        client_rps > 0.0,
        "client rps must be measured in some window: {body}"
    );
    assert!(
        up_qps > 0.0 && in_use,
        "upstream qps/in_use must be measured in some window: {body}"
    );

    gw.shutdown().await;
    fake.stop().await;
}

// ---------------------------------------------------------------------------
// Regression tests for the audit fixes (cache, selection policies, timeouts)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_serves_hits_with_decremented_ttl_and_correct_rcode() {
    let fake = FakeUpstream::start().await;
    fake.set_nxdomain(true);
    let mut cfg = base_config();
    cfg.cache.enabled = true;
    cfg.cache.max_entries = 128;
    cfg.cache.negative_max_ttl_secs = 30;
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    // First query: miss, forwarded, then cached (NXDOMAIN + SOA -> negative).
    let r1 = udp_query(addr, "nx.test").await.expect("nxdomain reply");
    assert_eq!(r1.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(fake.hits(), 1);

    // Second query: served from cache, upstream not contacted again.
    let r2 = udp_query(addr, "nx.test").await.expect("cached nxdomain");
    assert_eq!(r2.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(fake.hits(), 1, "second query must be a cache hit");

    // The cached rcode must be recorded as NXDOMAIN, not NOERROR.
    let text = gw.shared.metrics.render();
    let nxdomain_hits = text
        .lines()
        .find(|l| l.starts_with("res_response_rcode_total{rcode=\"NXDOMAIN\"}"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    assert!(
        nxdomain_hits >= 2,
        "both the miss and the hit must be counted as NXDOMAIN, got {nxdomain_hits}"
    );

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_positive_answer_serves_decremented_ttl() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.cache.enabled = true;
    cfg.cache.max_entries = 128;
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    let r1 = udp_query(addr, "ttl.test").await.expect("answer");
    assert_eq!(answers_ip(&r1), Some(ANSWER));
    assert_eq!(fake.hits(), 1);

    // Second query: cache hit. TTL must be <= the upstream TTL and not grow.
    let r2 = udp_query(addr, "ttl.test").await.expect("cached answer");
    assert_eq!(answers_ip(&r2), Some(ANSWER));
    assert_eq!(fake.hits(), 1, "second query must be a cache hit");
    let ttl1 = r1.answers.first().map(|r| r.ttl).unwrap_or(u32::MAX);
    let ttl2 = r2.answers.first().map(|r| r.ttl).unwrap_or(u32::MAX);
    assert!(
        ttl2 <= ttl1,
        "cached TTL must not exceed the original: {ttl1} -> {ttl2}"
    );

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_is_disabled_by_base_config_and_misses_when_off() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config(); // cache.enabled = false by default in base_config
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    let _ = udp_query(addr, "off.test").await.expect("first");
    let _ = udp_query(addr, "off.test").await.expect("second");
    assert_eq!(fake.hits(), 2, "disabled cache must forward every query");

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn min_ttl_threshold_skips_short_answers() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.cache.enabled = true;
    cfg.cache.min_ttl_secs = 300; // upstream answers TTL=60 -> never cacheable
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    let _ = udp_query(addr, "skip.test").await.expect("first");
    let _ = udp_query(addr, "skip.test").await.expect("second");
    assert_eq!(
        fake.hits(),
        2,
        "answers below the TTL threshold must always be forwarded"
    );

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_tier_policy_sends_traffic_to_lower_tiers() {
    let primary = FakeUpstream::start().await;
    let secondary = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.selection.tier_policy = res::config::TierPolicy::Shared;
    cfg.selection.lower_tier_share = 0.5;
    let mut p = primary.config("primary");
    p.priority = 1;
    let mut s = secondary.config("secondary");
    s.priority = 2;
    cfg.upstreams.push(p);
    cfg.upstreams.push(s);
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    // 100 independent queries keep the "at least one lower-tier pick"
    // assertion reliable; a 20-query sample occasionally flaked at 50%.
    for i in 0..100 {
        let r = udp_query(addr, &format!("q{i}.test"))
            .await
            .expect("answer");
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    }
    // Strict policy would give the secondary zero traffic; shared must give
    // it roughly half of 100 queries (>= 1 is enough to prove the policy).
    let sec_hits = secondary.hits();
    assert!(
        sec_hits >= 1,
        "shared tier policy must send some traffic to the lower tier, got {sec_hits}"
    );
    assert!(
        primary.hits() >= 1,
        "the best tier must keep most of the traffic"
    );

    gw.shutdown().await;
    primary.stop().await;
    secondary.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_timeout_is_enforced_and_recorded() {
    let slow = FakeUpstream::start().await;
    slow.set_delay_ms(400);
    let mut cfg = base_config();
    cfg.query.upstream_timeout_ms = 100;
    cfg.query.timeout_ms = 250;
    cfg.query.max_attempts = 1;
    cfg.upstreams.push(slow.config("slow"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    let started = std::time::Instant::now();
    let resp = udp_query_timeout(addr, "slow.test", Duration::from_secs(3))
        .await
        .expect("SERVFAIL reply");
    let elapsed = started.elapsed();
    assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
    assert!(
        elapsed < Duration::from_millis(350),
        "per-attempt timeout must cut the query short: {elapsed:?}"
    );

    let text = gw.shared.metrics.render();
    let timeouts = text
        .lines()
        .find(|l| l.starts_with("res_upstream_timeouts_total{upstream=\"slow\"}"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    assert!(
        timeouts >= 1,
        "upstream timeout must be counted: {timeouts}"
    );

    gw.shutdown().await;
    slow.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn total_deadline_bounds_the_whole_query_across_attempts() {
    let a = FakeUpstream::start().await;
    a.set_delay_ms(300);
    let b = FakeUpstream::start().await;
    b.set_delay_ms(300);
    let mut cfg = base_config();
    cfg.query.upstream_timeout_ms = 150;
    cfg.query.timeout_ms = 400;
    cfg.query.max_attempts = 3;
    let mut ca = a.config("a");
    ca.priority = 1;
    let mut cb = b.config("b");
    cb.priority = 2;
    cfg.upstreams.push(ca);
    cfg.upstreams.push(cb);
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    let started = std::time::Instant::now();
    let resp = udp_query_timeout(addr, "deadline.test", Duration::from_secs(3))
        .await
        .expect("SERVFAIL reply");
    let elapsed = started.elapsed();
    assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
    // Two attempts at 150ms each would be 300ms; the total deadline (400ms)
    // must bound everything even if all upstreams hang.
    assert!(
        elapsed < Duration::from_millis(700),
        "total deadline must bound the query: {elapsed:?}"
    );

    gw.shutdown().await;
    a.stop().await;
    b.stop().await;
}

// ---------------------------------------------------------------------------
// Upstream DNS management (live API): auth, generations, guards, in-flight
// safety, persistence failures, concurrency.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_management_requires_admin_token_when_configured() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.server.api_token = "sekrit-token".into();
    cfg.upstreams.push(fake.config("seed"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    // A bearer token is a credential: reads require it too.
    let (status, body) = http("GET", api, "/api/upstreams", None).await;
    assert_eq!(status, 401, "{body}");
    let (status, body) = http_auth("GET", api, "/api/upstreams", None, Some("sekrit-token")).await;
    assert_eq!(status, 200, "{body}");

    // Mutations without / with a wrong token are rejected and audited.
    let create = r#"{"name":"nope","address":"127.0.0.1","port":53}"#;
    let (status, body) = http("POST", api, "/api/upstreams", Some(create)).await;
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("unauthorized"), "{body}");
    let (status, body) =
        http_auth("POST", api, "/api/upstreams", Some(create), Some("wrong")).await;
    assert_eq!(status, 401, "{body}");

    // With the correct token the create succeeds.
    let (status, body) = http_auth(
        "POST",
        api,
        "/api/upstreams",
        Some(create),
        Some("sekrit-token"),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("json");
    let id = created["upstream"]["id"].as_i64().expect("id");

    // PATCH, test and DELETE are gated too.
    let (status, _) = http(
        "PATCH",
        api,
        &format!("/api/upstreams/{id}"),
        Some(r#"{"weight":2}"#),
    )
    .await;
    assert_eq!(status, 401);
    let (status, _) = http_auth(
        "PATCH",
        api,
        &format!("/api/upstreams/{id}"),
        Some(r#"{"weight":2}"#),
        Some("sekrit-token"),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = http("POST", api, &format!("/api/upstreams/{id}/test"), None).await;
    assert_eq!(status, 401);
    let (status, _) = http_auth(
        "POST",
        api,
        &format!("/api/upstreams/{id}/test"),
        None,
        Some("sekrit-token"),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = http("DELETE", api, &format!("/api/upstreams/{id}"), None).await;
    assert_eq!(status, 401);
    let (status, body) = http_auth(
        "DELETE",
        api,
        &format!("/api/upstreams/{id}?confirm=true"),
        None,
        Some("sekrit-token"),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // Status advertises that auth is required; audit ring holds the denials.
    let (status, body) = http_auth("GET", api, "/api/status", None, Some("sekrit-token")).await;
    assert_eq!(status, 200);
    assert!(body.contains("\"required\":true"), "{body}");
    assert!(body.contains("\"open_mode\":false"), "{body}");
    let (_, body) = http_auth("GET", api, "/api/config/events", None, Some("sekrit-token")).await;
    assert!(body.contains("unauthorized"), "{body}");

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_management_generation_guards_stale_updates() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("seed"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let (status, body) = http(
        "POST",
        api,
        "/api/upstreams",
        Some(r#"{"name":"gen-a","address":"127.0.0.1","port":53}"#),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let a: serde_json::Value = serde_json::from_str(&body).expect("json");
    let id_a = a["upstream"]["id"].as_i64().expect("id");
    let gen_after_a = a["generation"].as_u64().expect("generation");

    // A second mutation moves the generation forward.
    let (status, body) = http(
        "POST",
        api,
        "/api/upstreams",
        Some(r#"{"name":"gen-b","address":"127.0.0.2","port":53}"#),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let b: serde_json::Value = serde_json::from_str(&body).expect("json");
    let gen_after_b = b["generation"].as_u64().expect("generation");
    assert!(gen_after_b > gen_after_a);

    // A PATCH prepared against the old generation is rejected …
    let (status, body) = http(
        "PATCH",
        api,
        &format!("/api/upstreams/{id_a}"),
        Some(&format!(r#"{{"weight":9,"generation":{gen_after_a}}}"#)),
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("stale configuration"), "{body}");

    // … while the current generation is accepted.
    let (status, body) = http(
        "PATCH",
        api,
        &format!("/api/upstreams/{id_a}"),
        Some(&format!(r#"{{"weight":9,"generation":{gen_after_b}}}"#)),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn last_enabled_upstream_requires_confirmation() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("only"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");
    let id = {
        let (_, body) = http("GET", api, "/api/upstreams", None).await;
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        v["upstreams"][0]["id"].as_i64().expect("id")
    };

    // Data plane works while the upstream is enabled.
    assert!(udp_query(udp, "before.test").await.is_some());

    // Disabling the last enabled upstream needs an explicit confirmation.
    let (status, body) = http(
        "PATCH",
        api,
        &format!("/api/upstreams/{id}"),
        Some(r#"{"enabled":false}"#),
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("confirm_required"), "{body}");
    let (_, body) = http("GET", api, "/api/upstreams", None).await;
    assert!(
        body.contains("\"enabled\":true") || body.contains("\"enabled\": true"),
        "{body}"
    );

    // Removing it has the same guard.
    let (status, body) = http("DELETE", api, &format!("/api/upstreams/{id}"), None).await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("confirm_required"), "{body}");

    // Confirmed removal goes through; the gateway answers SERVFAIL with an
    // empty pool, then recovers as soon as a replacement is added.
    let (status, body) = http(
        "DELETE",
        api,
        &format!("/api/upstreams/{id}?confirm=true"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let resp = udp_query(udp, "empty-pool.test")
        .await
        .expect("SERVFAIL reply");
    assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);

    let (status, body) = http(
        "POST",
        api,
        "/api/upstreams",
        Some(&format!(
            r#"{{"name":"replacement","address":"{}","port":{}}}"#,
            fake.addr.ip(),
            fake.addr.port()
        )),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert!(udp_query(udp, "recovered.test").await.is_some());

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_changes_apply_at_runtime_and_survive_inflight_queries() {
    let a = FakeUpstream::start().await;
    let b = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(a.config("live-a"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");

    // Add a second upstream at runtime (no restart) and point it at fake b.
    let (status, body) = http(
        "POST",
        api,
        "/api/upstreams",
        Some(r#"{"name":"live-b","address":"127.0.0.1","port":1}"#),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let id_b = {
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        v["upstream"]["id"].as_i64().expect("id")
    };
    let (status, body) = http(
        "PATCH",
        api,
        &format!("/api/upstreams/{id_b}"),
        Some(&format!(
            r#"{{"address":"{}","port":{}}}"#,
            b.addr.ip(),
            b.addr.port()
        )),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // A continuous query stream runs while upstreams are disabled/enabled.
    // In-flight queries hold the ArcSwap snapshot and must all succeed.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_w = stop.clone();
    let worker = tokio::spawn(async move {
        let (mut ok, mut fail) = (0u64, 0u64);
        while !stop_w.load(std::sync::atomic::Ordering::Relaxed) {
            if udp_query(udp, "inflight.test").await.is_some() {
                ok += 1;
            } else {
                fail += 1;
            }
        }
        (ok, fail)
    });

    // Disable a, queries keep working via b; re-enable a; disable again.
    let id_a = {
        let (_, body) = http("GET", api, "/api/upstreams", None).await;
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        v["upstreams"]
            .as_array()
            .expect("array")
            .iter()
            .find(|u| u["name"] == "live-a")
            .expect("live-a present")["id"]
            .as_i64()
            .expect("id")
    };
    for enabled in [false, true, false] {
        let (status, body) = http(
            "PATCH",
            api,
            &format!("/api/upstreams/{id_a}"),
            Some(&format!(r#"{{"enabled":{enabled}}}"#)),
        )
        .await;
        assert_eq!(status, 200, "live-a enable={enabled}: {body}");
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let (ok, fail) = worker.await.expect("worker");
    assert!(ok > 0, "query stream made no progress");
    assert_eq!(fail, 0, "in-flight queries failed during upstream changes");

    // New queries immediately used the updated pool (fake b saw traffic).
    assert!(
        b.hits() > 0,
        "runtime-added upstream never received traffic"
    );

    gw.shutdown().await;
    a.stop().await;
    b.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_upstream_update_leaves_active_config_intact() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("seed"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp addr");
    let id = {
        let (_, body) = http("GET", api, "/api/upstreams", None).await;
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        v["upstreams"][0]["id"].as_i64().expect("id")
    };

    // Invalid address, invalid port, zero priority/weight/timeout are all
    // rejected with 400; unknown fields fail body deserialization (422).
    for body in [
        r#"{"address":"not-an-ip"}"#,
        r#"{"port":0}"#,
        r#"{"priority":0}"#,
        r#"{"weight":0}"#,
        r#"{"timeout_ms":0}"#,
    ] {
        let (status, resp) = http("PATCH", api, &format!("/api/upstreams/{id}"), Some(body)).await;
        assert_eq!(status, 400, "expected rejection for {body}: {resp}");
    }
    let (status, resp) = http(
        "PATCH",
        api,
        &format!("/api/upstreams/{id}"),
        Some(r#"{"bogus":1}"#),
    )
    .await;
    assert!(
        status == 400 || status == 422,
        "unknown field must be rejected: {status} {resp}"
    );

    // Renaming to an existing peer's name is a conflict, not a silent merge.
    let (status, body) = http(
        "POST",
        api,
        "/api/upstreams",
        Some(r#"{"name":"taken-name","address":"127.0.0.1","port":54}"#),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let (status, resp) = http(
        "PATCH",
        api,
        &format!("/api/upstreams/{id}"),
        Some(r#"{"name":"taken-name"}"#),
    )
    .await;
    assert_eq!(status, 409, "{resp}");

    // Active configuration unchanged, rejections audited, data plane alive.
    let (_, body) = http("GET", api, "/api/upstreams", None).await;
    assert!(body.contains("\"seed\""));
    assert!(
        body.contains(r#""address":"127.0.0.1""#) || body.contains(r#""address": "127.0.0.1""#),
        "{body}"
    );
    let (_, events) = http("GET", api, "/api/config/events", None).await;
    assert!(events.contains("update_rejected"), "{events}");
    assert!(udp_query(udp, "still-works.test").await.is_some());

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persist_failure_is_reported_and_audited() {
    use std::os::unix::fs::PermissionsExt;

    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("seed"));
    let dir = std::env::temp_dir().join(format!("res-persist-fail-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let path = dir.join("res.toml");
    let gw = start_gateway_with_path(cfg, path.clone()).await;
    let api = gw.api_addr().expect("api addr");

    // One successful mutation establishes a valid on-disk configuration.
    let (status, body) = http(
        "POST",
        api,
        "/api/upstreams",
        Some(r#"{"name":"baseline","address":"127.0.0.2","port":53}"#),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).expect("json")["persisted"],
        true,
        "{body}"
    );

    // Make the config directory read-only so the atomic write cannot create
    // its temp file.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).expect("chmod");

    let (status, body) = http(
        "POST",
        api,
        "/api/upstreams",
        Some(r#"{"name":"orphan","address":"127.0.0.1","port":53}"#),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(created["persisted"], false, "{body}");
    assert!(
        created["persist_error"].is_string(),
        "persist_error must be reported: {body}"
    );

    // The divergence is loudly audited (in-memory ring + /api/config/events).
    let (_, events) = http("GET", api, "/api/config/events", None).await;
    assert!(
        events.contains("persist_failed") || events.contains("applied_persist_failed"),
        "{events}"
    );

    // The runtime keeps the new config (documented policy: never roll back
    // the data plane), and the last valid file on disk is still loadable.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod back");
    let on_disk = res::config::AppConfig::load(&path).expect("file still loads");
    assert!(
        on_disk.upstreams.iter().any(|u| u.name == "baseline"),
        "previous valid configuration must survive"
    );
    assert!(
        !on_disk.upstreams.iter().any(|u| u.name == "orphan"),
        "failed persist must not have touched the file"
    );

    let _ = std::fs::remove_dir_all(&dir);
    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_upstream_creates_are_serialized() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("seed"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let mut tasks = Vec::new();
    for i in 0..8 {
        tasks.push(tokio::spawn(async move {
            http(
                "POST",
                api,
                "/api/upstreams",
                Some(&format!(
                    r#"{{"name":"cc-{i}","address":"127.0.0.1","port":53}}"#
                )),
            )
            .await
        }));
    }
    let mut generations = Vec::new();
    for t in tasks {
        let (status, body) = t.await.expect("join");
        assert_eq!(status, 201, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        generations.push(v["generation"].as_u64().expect("generation"));
    }
    // Every mutation bumped the generation exactly once (serialized, no lost
    // updates).
    let mut sorted = generations.clone();
    sorted.sort_unstable();
    let unique: std::collections::BTreeSet<u64> = generations.iter().copied().collect();
    assert_eq!(unique.len(), 8, "generation collisions: {sorted:?}");

    let (_, body) = http("GET", api, "/api/upstreams", None).await;
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let names: Vec<&str> = v["upstreams"]
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|u| u["name"].as_str())
        .collect();
    assert_eq!(names.len(), 9, "{names:?}");
    for i in 0..8 {
        assert!(names.contains(&format!("cc-{i}").as_str()), "{names:?}");
    }

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manual_upstream_test_reports_probe_result() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    // Enable health checks so the probe path has a configured probe name.
    cfg.health.enabled = true;
    cfg.upstreams.push(fake.config("probed"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let id = {
        let (_, body) = http("GET", api, "/api/upstreams", None).await;
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        v["upstreams"][0]["id"].as_i64().expect("id")
    };

    let (status, body) = http("POST", api, &format!("/api/upstreams/{id}/test"), None).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["result"]["success"], true, "{body}");
    assert!(v["result"]["latency_ms"].is_number(), "{body}");

    // The probe is recorded as a health event.
    let (_, body) = http("GET", api, &format!("/api/upstreams/{id}/health"), None).await;
    assert!(body.contains("probe"), "{body}");

    gw.shutdown().await;
    fake.stop().await;
}

// ---------------------------------------------------------------------------
// Auth integration tests
// ---------------------------------------------------------------------------

/// Production default is fail-closed: missing credentials must abort startup
/// unless the operator explicitly enables development open mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_startup_refuses_missing_credentials_without_explicit_open_mode() {
    let mut cfg = base_config();
    cfg.auth.allow_open_mode = false;
    let auth = std::sync::Arc::new(res::auth::AuthState::from_passwords(
        cfg.auth.clone(),
        None,
        None,
    ));
    let err = res::runtime::start_with_auth(cfg.clone(), None, auth)
        .await
        .err()
        .expect("startup must fail without credentials");
    assert!(
        err.to_string().contains("no control-plane credentials"),
        "unexpected error: {err}"
    );

    // The same configuration starts only after the explicit escape hatch.
    cfg.auth.allow_open_mode = true;
    let auth = std::sync::Arc::new(res::auth::AuthState::from_passwords(
        cfg.auth.clone(),
        None,
        None,
    ));
    let gw = res::runtime::start_with_auth(cfg, None, auth)
        .await
        .expect("explicit open mode must start");
    let api = gw.api_addr().expect("api addr");
    let (status, body) = http("GET", api, "/api/auth/info", None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).expect("json")["open_mode"],
        true,
        "{body}"
    );
    gw.shutdown().await;
}

/// A bearer token must protect reads as well as mutations, and the metrics
/// credential must be a distinct metrics-only principal rather than the
/// administrator API token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_only_auth_guards_reads_and_metrics() {
    let mut cfg = base_config();
    cfg.auth.allow_open_mode = false;
    cfg.auth.protect_metrics = true;
    cfg.auth.metrics_token = "metrics-only-token".into();
    cfg.server.api_token = "sekrit-token".into();
    let auth = std::sync::Arc::new(res::auth::AuthState::from_passwords(
        cfg.auth.clone(),
        None,
        None,
    ));
    let gw = res::runtime::start_with_auth(cfg, None, auth)
        .await
        .expect("token-only gateway should start");
    let api = gw.api_addr().expect("api addr");

    let (status, body) = http("GET", api, "/api/auth/info", None).await;
    assert_eq!(status, 200, "{body}");
    let info: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(info["password_auth"], false, "{body}");
    assert_eq!(info["token_auth"], true, "{body}");
    assert_eq!(info["open_mode"], false, "{body}");

    let (status, body) = http("GET", api, "/api/status", None).await;
    assert_eq!(status, 401, "{body}");
    let (status, body) = http_auth("GET", api, "/api/status", None, Some("sekrit-token")).await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = http("GET", api, "/metrics", None).await;
    assert_eq!(status, 401, "{body}");
    let (status, body) = http_auth("GET", api, "/metrics", None, Some("sekrit-token")).await;
    assert_eq!(status, 401, "admin token must not scrape metrics: {body}");
    let (status, body) = http_auth("GET", api, "/metrics", None, Some("metrics-only-token")).await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = http_auth("GET", api, "/api/status", None, Some("metrics-only-token")).await;
    assert_eq!(
        status, 401,
        "metrics token must not grant control-plane access"
    );

    gw.shutdown().await;
}

/// `protect_metrics` with no dedicated token fails closed: it must not fall
/// back to the administrator bearer token or an unauthenticated scrape.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protected_metrics_without_dedicated_token_fails_closed() {
    let mut cfg = base_config();
    cfg.auth.allow_open_mode = false;
    cfg.auth.protect_metrics = true;
    cfg.server.api_token = "sekrit-token".into();
    let auth = std::sync::Arc::new(res::auth::AuthState::from_passwords(
        cfg.auth.clone(),
        None,
        None,
    ));
    let gw = res::runtime::start_with_auth(cfg, None, auth)
        .await
        .expect("token-only gateway should start");
    let api = gw.api_addr().expect("api addr");

    let (status, _) = http("GET", api, "/metrics", None).await;
    assert_eq!(status, 401);
    let (status, _) = http_auth("GET", api, "/metrics", None, Some("sekrit-token")).await;
    assert_eq!(
        status, 401,
        "missing metrics token must not fall back to the admin token"
    );

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_login_session_and_logout_flow() {
    let cfg = base_config();
    let gw = start_gateway_with_passwords(cfg, "s3cret-admin", Some("view-pw")).await;
    let api = gw.api_addr().expect("api addr");

    // Reads require authentication when password auth is enabled.
    let (status, _) = http("GET", api, "/api/status", None).await;
    assert_eq!(status, 401, "unauthenticated read must be 401");

    // Login fails with wrong password (401, identical message).
    let (status, body) = http(
        "POST",
        api,
        "/api/auth/login",
        Some(r#"{"username":"admin","password":"wrong"}"#),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("invalid username or password"), "{body}");

    // Login succeeds and sets cookies.
    let raw = http_raw(
        "POST",
        api,
        "/api/auth/login",
        Some(r#"{"username":"admin","password":"s3cret-admin"}"#),
        &[],
    )
    .await;
    assert!(raw.starts_with("HTTP/1.1 200"), "login must succeed: {raw}");
    let session = set_cookie(&raw, "res_session").expect("session cookie");
    let csrf = set_cookie(&raw, "res_csrf").expect("csrf cookie");
    assert!(!session.is_empty());
    assert!(!csrf.is_empty());

    // Authenticated read works with the session cookie.
    let (status, body) = http_headers(
        "GET",
        api,
        "/api/status",
        None,
        &[("Cookie".into(), format!("res_session={session}"))],
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // Mutation with cookie but without CSRF is forbidden.
    let (status, body) = http_headers(
        "POST",
        api,
        "/api/cache/clear",
        None,
        &[("Cookie".into(), format!("res_session={session}"))],
    )
    .await;
    assert_eq!(status, 403, "CSRF required for cookie mutation: {body}");

    // Mutation with cookie + CSRF succeeds.
    let (status, body) = http_headers(
        "POST",
        api,
        "/api/cache/clear",
        None,
        &[
            ("Cookie".into(), format!("res_session={session}")),
            ("X-CSRF-Token".into(), csrf.clone()),
        ],
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // Logout without CSRF is forbidden.
    let (status, _) = http_headers(
        "DELETE",
        api,
        "/api/auth/session",
        None,
        &[("Cookie".into(), format!("res_session={session}"))],
    )
    .await;
    assert_eq!(status, 403, "logout must require CSRF");

    // Logout with CSRF succeeds and invalidates the session.
    let (status, _) = http_headers(
        "DELETE",
        api,
        "/api/auth/session",
        None,
        &[
            ("Cookie".into(), format!("res_session={session}")),
            ("X-CSRF-Token".into(), csrf),
        ],
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = http_headers(
        "GET",
        api,
        "/api/status",
        None,
        &[("Cookie".into(), format!("res_session={session}"))],
    )
    .await;
    assert_eq!(status, 401, "session must be dead after logout");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_lockout_returns_429_with_retry_after() {
    let mut cfg = base_config();
    cfg.auth.max_failed_attempts = 3;
    let gw = start_gateway_with_passwords(cfg, "pw", None).await;
    let api = gw.api_addr().expect("api addr");

    for _ in 0..3 {
        let (status, _) = http(
            "POST",
            api,
            "/api/auth/login",
            Some(r#"{"username":"admin","password":"bad"}"#),
        )
        .await;
        assert_eq!(status, 401);
    }

    // Locked: even the correct password gets 429 + Retry-After.
    let raw = http_raw(
        "POST",
        api,
        "/api/auth/login",
        Some(r#"{"username":"admin","password":"pw"}"#),
        &[],
    )
    .await;
    assert!(raw.starts_with("HTTP/1.1 429"), "expected 429, got: {raw}");
    assert!(
        raw.to_ascii_lowercase().contains("retry-after:"),
        "Retry-After header required: {raw}"
    );

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_login_rate_limit_returns_429() {
    let mut cfg = base_config();
    cfg.auth.login_rate_limit_per_minute = 3;
    cfg.auth.max_failed_attempts = u32::MAX; // avoid per-username lockout
    let gw = start_gateway_with_passwords(cfg, "pw", None).await;
    let api = gw.api_addr().expect("api addr");

    // 3 attempts allowed (all fail with wrong password, but not locked).
    for _ in 0..3 {
        let (status, _) = http(
            "POST",
            api,
            "/api/auth/login",
            Some(r#"{"username":"admin","password":"bad"}"#),
        )
        .await;
        assert_eq!(status, 401);
    }
    // 4th attempt from same IP is rate-limited.
    let raw = http_raw(
        "POST",
        api,
        "/api/auth/login",
        Some(r#"{"username":"admin","password":"bad"}"#),
        &[],
    )
    .await;
    assert!(raw.starts_with("HTTP/1.1 429"), "expected 429, got: {raw}");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_config_export_redacts_token_for_viewers() {
    let mut cfg = base_config();
    cfg.server.api_token = "sekrit-token".into();
    let gw = start_gateway_with_passwords(cfg, "admin-pw", Some("view-pw")).await;
    let api = gw.api_addr().expect("api addr");

    // Viewer login.
    let raw = http_raw(
        "POST",
        api,
        "/api/auth/login",
        Some(r#"{"username":"viewer","password":"view-pw"}"#),
        &[],
    )
    .await;
    let session = set_cookie(&raw, "res_session").expect("session");

    // Viewer export must not contain the api_token.
    let (status, body) = http_headers(
        "GET",
        api,
        "/api/config",
        None,
        &[("Cookie".into(), format!("res_session={session}"))],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        !body.contains("sekrit-token"),
        "viewer must not see api_token: {body}"
    );
    assert!(!body.contains("api_token"), "token field must be stripped");

    // Admin (via bearer token) sees the full export.
    let (status, body) = http_auth("GET", api, "/api/config", None, Some("sekrit-token")).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("sekrit-token"), "admin keeps full export");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_viewer_cannot_mutate_configuration() {
    let cfg = base_config();
    let gw = start_gateway_with_passwords(cfg, "admin-pw", Some("view-pw")).await;
    let api = gw.api_addr().expect("api addr");

    let raw = http_raw(
        "POST",
        api,
        "/api/auth/login",
        Some(r#"{"username":"viewer","password":"view-pw"}"#),
        &[],
    )
    .await;
    let session = set_cookie(&raw, "res_session").expect("session");
    let csrf = set_cookie(&raw, "res_csrf").expect("csrf");
    let headers = [
        ("Cookie".into(), format!("res_session={session}")),
        ("X-CSRF-Token".into(), csrf.clone()),
    ];

    // Viewer reads are allowed.
    let (status, body) = http_headers("GET", api, "/api/status", None, &headers).await;
    assert_eq!(status, 200, "{body}");

    // Every configuration mutation is rejected by the backend, not just by
    // the dashboard's disabled controls.
    let mutations = [
        ("POST", "/api/cache/clear", None),
        (
            "PUT",
            "/api/acl",
            Some(r#"{"entries":[{"cidr":"127.0.0.0/8","action":"allow","enabled":true}]}"#),
        ),
        (
            "POST",
            "/api/upstreams",
            Some(r#"{"name":"viewer-nope","address":"127.0.0.1","port":53}"#),
        ),
        (
            "POST",
            "/api/auth/rotate-password",
            Some(r#"{"account":"admin","new_password":"viewer-should-not"}"#),
        ),
    ];
    for (method, path, body) in mutations {
        let (status, response) = http_headers(method, api, path, body, &headers).await;
        assert_eq!(
            status, 403,
            "viewer {method} {path} must be 403, got {status}: {response}"
        );
    }

    // The admin can still perform the same mutation after login.
    let raw = http_raw(
        "POST",
        api,
        "/api/auth/login",
        Some(r#"{"username":"admin","password":"admin-pw"}"#),
        &[],
    )
    .await;
    let admin_session = set_cookie(&raw, "res_session").expect("admin session");
    let admin_csrf = set_cookie(&raw, "res_csrf").expect("admin csrf");
    let (status, body) = http_headers(
        "POST",
        api,
        "/api/cache/clear",
        None,
        &[
            ("Cookie".into(), format!("res_session={admin_session}")),
            ("X-CSRF-Token".into(), admin_csrf),
        ],
    )
    .await;
    assert_eq!(status, 200, "{body}");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_rotate_password_invalidates_old_and_works_with_new() {
    let cfg = base_config();
    let gw = start_gateway_with_passwords(cfg, "old-pw", None).await;
    let api = gw.api_addr().expect("api addr");

    // Login with old password works.
    let (status, _) = http(
        "POST",
        api,
        "/api/auth/login",
        Some(r#"{"username":"admin","password":"old-pw"}"#),
    )
    .await;
    assert_eq!(status, 200);

    // Rotate via bearer-token auth (no cookie needed for rotation bootstrap).
    // First we need a token; use the admin session for rotation instead.
    let raw = http_raw(
        "POST",
        api,
        "/api/auth/login",
        Some(r#"{"username":"admin","password":"old-pw"}"#),
        &[],
    )
    .await;
    let session = set_cookie(&raw, "res_session").expect("session");
    let csrf = set_cookie(&raw, "res_csrf").expect("csrf");

    let (status, body) = http_headers(
        "POST",
        api,
        "/api/auth/rotate-password",
        Some(r#"{"account":"admin","new_password":"brand-new"}"#),
        &[
            ("Cookie".into(), format!("res_session={session}")),
            ("X-CSRF-Token".into(), csrf),
        ],
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // Rotation is not just a hash swap: every pre-rotation session — the
    // one that performed the rotation included — is revoked server-side.
    let (status, _) = http_headers(
        "GET",
        api,
        "/api/status",
        None,
        &[("Cookie".into(), format!("res_session={session}"))],
    )
    .await;
    assert_eq!(status, 401, "pre-rotation session must be revoked");

    // Old password no longer works.
    let (status, _) = http(
        "POST",
        api,
        "/api/auth/login",
        Some(r#"{"username":"admin","password":"old-pw"}"#),
    )
    .await;
    assert_eq!(status, 401, "old password must be dead");

    // New password works.
    let (status, _) = http(
        "POST",
        api,
        "/api/auth/login",
        Some(r#"{"username":"admin","password":"brand-new"}"#),
    )
    .await;
    assert_eq!(status, 200, "new password must work");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_secure_cookies_flag_set_when_configured() {
    let mut cfg = base_config();
    cfg.auth.secure_cookies = true;
    let gw = start_gateway_with_passwords(cfg, "pw", None).await;
    let api = gw.api_addr().expect("api addr");

    let raw = http_raw(
        "POST",
        api,
        "/api/auth/login",
        Some(r#"{"username":"admin","password":"pw"}"#),
        &[],
    )
    .await;
    assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
    assert!(
        raw.contains("Secure"),
        "Secure flag expected on cookies: {raw}"
    );

    gw.shutdown().await;
}

/// Password rotation enforces the server-side minimum length even when the
/// caller bypasses the dashboard's form validation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_rotate_password_rejects_short_password() {
    let mut cfg = base_config();
    cfg.server.api_token = "rotation-token".into();
    let gw = start_gateway_with_passwords(cfg, "admin-pw", None).await;
    let api = gw.api_addr().expect("api addr");

    let (status, body) = http_auth(
        "POST",
        api,
        "/api/auth/rotate-password",
        Some(r#"{"account":"admin","new_password":"short"}"#),
        Some("rotation-token"),
    )
    .await;
    assert_eq!(status, 400, "short password must be rejected: {body}");
    assert!(
        body.contains("8..=1024"),
        "error must state the policy: {body}"
    );

    let (status, body) = http_auth(
        "POST",
        api,
        "/api/auth/rotate-password",
        Some(r#"{"account":"admin","new_password":"long-enough"}"#),
        Some("rotation-token"),
    )
    .await;
    assert_eq!(status, 200, "valid password must rotate: {body}");

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// ACL per-entry management: structured entries, bare IPs, enable/disable,
// conflict rejection, per-entry CRUD.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_get_returns_entries_with_ids_and_legacy_view() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let (status, body) = http("GET", api, "/api/acl", None).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let entries = v["entries"].as_array().expect("entries array");
    assert!(
        !entries.is_empty(),
        "default allow list synthesised: {body}"
    );
    assert!(
        entries
            .iter()
            .all(|e| !e["id"].as_str().unwrap_or("").is_empty()),
        "every entry has an id: {body}"
    );
    // Legacy view is populated from enabled allow entries.
    assert!(
        v["allowed_cidrs"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "{body}"
    );

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_put_accepts_structured_entries_and_bare_ips() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.server.api_token = "sekrit".into();
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let put = r#"{
        "entries": [
            {"cidr": "192.0.2.10", "action": "allow", "enabled": true},
            {"cidr": "192.0.2.0/24", "action": "deny", "enabled": true}
        ]
    }"#;
    let (status, body) = http_auth("PUT", api, "/api/acl", Some(put), Some("sekrit")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["status"], "ok");
    assert_eq!(v["entries"].as_array().expect("entries").len(), 2);
    assert_eq!(v["denied_count"], 1, "{body}");

    // GET reflects the new entry list.
    let (status, body) = http_auth("GET", api, "/api/acl", None, Some("sekrit")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["entries"].as_array().expect("entries").len(), 2);

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_put_rejects_duplicates_and_conflicts() {
    let mut cfg = base_config();
    cfg.server.api_token = "sekrit".into();
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    // Duplicate allow entries.
    let dup = r#"{"entries":[
        {"cidr":"10.0.0.0/8","action":"allow"},
        {"cidr":"10.0.0.0/8","action":"allow"}
    ]}"#;
    let (status, body) = http_auth("PUT", api, "/api/acl", Some(dup), Some("sekrit")).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("duplicate"), "{body}");

    // Same network in both allow and deny.
    let conflict = r#"{"entries":[
        {"cidr":"10.0.0.0/8","action":"allow"},
        {"cidr":"10.0.0.0/8","action":"deny"}
    ]}"#;
    let (status, body) = http_auth("PUT", api, "/api/acl", Some(conflict), Some("sekrit")).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("conflict"), "{body}");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_put_legacy_lists_still_work() {
    let mut cfg = base_config();
    cfg.server.api_token = "sekrit".into();
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let put = r#"{"allowed_cidrs":["127.0.0.0/8"],"denied_cidrs":[]}"#;
    let (status, body) = http_auth("PUT", api, "/api/acl", Some(put), Some("sekrit")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["allowed_count"], 1, "{body}");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_entry_crud_lifecycle() {
    let mut cfg = base_config();
    cfg.server.api_token = "sekrit".into();
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    // Create a new entry (bare IP).
    let create = r#"{"cidr":"203.0.113.99","action":"allow","enabled":true}"#;
    let (status, body) = http_auth(
        "POST",
        api,
        "/api/acl/entries",
        Some(create),
        Some("sekrit"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let entries = v["entries"].as_array().expect("entries");
    let new_id = entries
        .iter()
        .find(|e| e["cidr"] == "203.0.113.99")
        .and_then(|e| e["id"].as_str())
        .expect("new entry id")
        .to_string();

    // Disable it via PATCH.
    let (status, body) = http_auth(
        "PATCH",
        api,
        &format!("/api/acl/entries/{new_id}"),
        Some(r#"{"enabled":false}"#),
        Some("sekrit"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let disabled = v["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|e| e["id"] == new_id)
        .expect("entry present");
    assert_eq!(disabled["enabled"], false, "{body}");

    // Delete it.
    let (status, body) = http_auth(
        "DELETE",
        api,
        &format!("/api/acl/entries/{new_id}"),
        None,
        Some("sekrit"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(
        !v["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .any(|e| e["id"] == new_id),
        "entry deleted: {body}"
    );

    // Deleting a missing entry is 404.
    let (status, body) = http_auth(
        "DELETE",
        api,
        &format!("/api/acl/entries/{new_id}"),
        None,
        Some("sekrit"),
    )
    .await;
    assert_eq!(status, 404, "{body}");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_entry_create_rejects_duplicate() {
    let mut cfg = base_config();
    cfg.server.api_token = "sekrit".into();
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let create = r#"{"cidr":"192.0.2.0/24","action":"allow"}"#;
    let (status, body) = http_auth(
        "POST",
        api,
        "/api/acl/entries",
        Some(create),
        Some("sekrit"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    // Same network again → 409 conflict.
    let (status, body) = http_auth(
        "POST",
        api,
        "/api/acl/entries",
        Some(create),
        Some("sekrit"),
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("duplicate"), "{body}");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_put_empty_allow_needs_confirm() {
    let mut cfg = base_config();
    cfg.server.api_token = "sekrit".into();
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let put = r#"{"entries":[]}"#;
    let (status, body) = http_auth("PUT", api, "/api/acl", Some(put), Some("sekrit")).await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("confirm"), "{body}");

    // With confirm=true it goes through.
    let put = r#"{"entries":[],"confirm":true}"#;
    let (status, body) = http_auth("PUT", api, "/api/acl", Some(put), Some("sekrit")).await;
    assert_eq!(status, 200, "{body}");

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// Cache settings: hot-reloadable capacity / TTL bounds / enable flag,
// memory accounting, clears counter.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_get_returns_settings_and_memory() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.cache.enabled = true;
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let (status, body) = http("GET", api, "/api/cache", None).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["enabled"], true, "{body}");
    assert!(v["max_entries"].as_u64().unwrap_or(0) > 0, "{body}");
    assert!(v.get("memory_bytes").is_some(), "{body}");
    assert!(v.get("min_ttl_secs").is_some(), "{body}");
    assert!(v.get("max_ttl_secs").is_some(), "{body}");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_put_updates_settings_and_persists() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.cache.enabled = true;
    cfg.server.api_token = "sekrit".into();
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let put =
        r#"{"max_entries":64,"min_ttl_secs":5,"max_ttl_secs":300,"negative_max_ttl_secs":10}"#;
    let (status, body) = http_auth("PUT", api, "/api/cache", Some(put), Some("sekrit")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["max_entries"], 64, "{body}");
    assert_eq!(v["min_ttl_secs"], 5, "{body}");
    assert_eq!(v["max_ttl_secs"], 300, "{body}");
    assert_eq!(v["negative_max_ttl_secs"], 10, "{body}");

    // Settings are live: GET reflects the new values.
    let (status, body) = http_auth("GET", api, "/api/cache", None, Some("sekrit")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["max_entries"], 64, "{body}");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_put_invalid_settings_rejected() {
    let mut cfg = base_config();
    cfg.server.api_token = "sekrit".into();
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    // max_ttl < min_ttl is invalid.
    let put = r#"{"min_ttl_secs":100,"max_ttl_secs":50}"#;
    let (status, body) = http_auth("PUT", api, "/api/cache", Some(put), Some("sekrit")).await;
    assert_eq!(status, 400, "{body}");

    // max_entries = 0 is invalid.
    let put = r#"{"max_entries":0}"#;
    let (status, body) = http_auth("PUT", api, "/api/cache", Some(put), Some("sekrit")).await;
    assert_eq!(status, 400, "{body}");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_disabling_via_put_clears_entries() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.cache.enabled = true;
    cfg.server.api_token = "sekrit".into();
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp");

    // Populate the cache with a real query.
    let resp = udp_query(udp, "warm.test").await.expect("response");
    assert_eq!(answers_ip(&resp), Some(ANSWER));
    // Second query should hit the cache (upstream hits stay at 1).
    let _ = udp_query(udp, "warm.test").await.expect("response");
    assert_eq!(fake.hits(), 1, "second query must be a cache hit");

    let (status, body) = http_auth("GET", api, "/api/cache", None, Some("sekrit")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v["entries"].as_u64().unwrap_or(0) >= 1, "{body}");

    // Disable the cache: replace_config clears resident entries.
    let (status, body) = http_auth(
        "PUT",
        api,
        "/api/cache",
        Some(r#"{"enabled":false}"#),
        Some("sekrit"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["enabled"], false, "{body}");
    assert_eq!(v["entries"], 0, "cache cleared on disable: {body}");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_clear_reports_memory_freed() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.cache.enabled = true;
    cfg.server.api_token = "sekrit".into();
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");
    let udp = gw.udp_addr().expect("udp");

    let _ = udp_query(udp, "fill.test").await.expect("response");
    let (status, body) = http_auth("POST", api, "/api/cache/clear", None, Some("sekrit")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v["entries_dropped"].as_u64().unwrap_or(0) >= 1, "{body}");
    assert!(v["memory_bytes_freed"].as_u64().unwrap_or(0) > 0, "{body}");

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// Upstream probe overrides + config rollback from backup.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_create_accepts_probe_overrides() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.server.api_token = "sekrit".into();
    cfg.upstreams.push(fake.config("seed"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let create = r#"{
        "name":"probe-up",
        "address":"127.0.0.1",
        "port": 53,
        "probe_interval_ms": 2000,
        "probe_timeout_ms": 800,
        "probes": [{"name":"example.com.","type":"A"}]
    }"#;
    let (status, body) =
        http_auth("POST", api, "/api/upstreams", Some(create), Some("sekrit")).await;
    assert_eq!(status, 201, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let id = v["upstream"]["id"].as_i64().expect("id");

    // Config export shows the probe overrides.
    let (status, body) = http_auth("GET", api, "/api/config", None, Some("sekrit")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let toml = v["toml"].as_str().expect("toml");
    assert!(toml.contains("probe_interval_ms = 2000"), "{toml}");
    assert!(toml.contains("probe_timeout_ms = 800"), "{toml}");
    assert!(toml.contains("example.com"), "{toml}");

    // PATCH clears them. `clear_probes` only removes the probe *list* —
    // the cadence overrides need their dedicated flags, so wiping the list
    // can no longer silently delete a tuned interval/timeout (behaviour
    // change: the old coupling was an audit finding).
    let (status, body) = http_auth(
        "PATCH",
        api,
        &format!("/api/upstreams/{id}"),
        Some(r#"{"clear_probes":true}"#),
        Some("sekrit"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = http_auth("GET", api, "/api/config", None, Some("sekrit")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let toml = v["toml"].as_str().expect("toml");
    assert!(
        toml.contains("probe_interval_ms = 2000"),
        "clear_probes must not touch the cadence: {toml}"
    );

    let (status, body) = http_auth(
        "PATCH",
        api,
        &format!("/api/upstreams/{id}"),
        Some(r#"{"clear_probe_interval_ms":true,"clear_probe_timeout_ms":true}"#),
        Some("sekrit"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = http_auth("GET", api, "/api/config", None, Some("sekrit")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let toml = v["toml"].as_str().expect("toml");
    assert!(!toml.contains("probe_interval_ms = 2000"), "{toml}");
    assert!(!toml.contains("probe_timeout_ms = 800"), "{toml}");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_rollback_restores_backup() {
    use std::path::PathBuf;

    let fake = FakeUpstream::start().await;
    let dir = std::env::temp_dir().join(format!("res-rollback-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path: PathBuf = dir.join("res.toml");
    // Seed a config file that will become the backup after the first mutation.
    let mut seed = base_config();
    seed.server.api_token = "sekrit".into();
    seed.upstreams.push(fake.config("primary"));
    // Persist the seed as the initial primary so AppConfig::load works.
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(seed.to_toml().unwrap().as_bytes())
            .expect("write");
    }
    let gw = start_gateway_with_path(seed, path.clone()).await;
    let api = gw.api_addr().expect("api addr");

    // Mutate: create a new upstream (writes primary + backup of previous).
    let create = r#"{"name":"added","address":"127.0.0.1","port":53}"#;
    let (status, body) =
        http_auth("POST", api, "/api/upstreams", Some(create), Some("sekrit")).await;
    assert_eq!(status, 201, "{body}");
    assert!(path.exists());
    let backup = res::config::backup_path(&path);
    assert!(
        backup.exists(),
        "backup written by persist: {}",
        backup.display()
    );

    // Rollback restores the backup (without "added").
    let (status, body) = http_auth("POST", api, "/api/config/rollback", None, Some("sekrit")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["status"], "ok", "{body}");

    let (status, body) = http_auth("GET", api, "/api/upstreams", None, Some("sekrit")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let names: Vec<String> = v["upstreams"]
        .as_array()
        .expect("upstreams")
        .iter()
        .filter_map(|u| u["name"].as_str().map(str::to_string))
        .collect();
    assert!(names.contains(&"primary".to_string()), "{body}");
    assert!(!names.contains(&"added".to_string()), "rolled back: {body}");

    gw.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_rollback_missing_backup_is_404() {
    let mut cfg = base_config();
    cfg.server.api_token = "sekrit".into();
    // No config_path set → rollback must refuse cleanly.
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let (status, body) = http_auth("POST", api, "/api/config/rollback", None, Some("sekrit")).await;
    assert_eq!(status, 400, "{body}");

    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn any_policy_refuse_is_the_default() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    let resp = udp_query_type(addr, "example.test", "ANY")
        .await
        .expect("NOTIMP reply");
    assert_eq!(resp.metadata.response_code, ResponseCode::NotImp);
    assert_eq!(fake.hits(), 0, "ANY must not reach upstream");

    // Normal A queries still work.
    let ok = udp_query(addr, "example.test").await.expect("answer");
    assert_eq!(ok.metadata.response_code, ResponseCode::NoError);
    assert_eq!(fake.hits(), 1);

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rd_zero_queries_bypass_cache_and_zone_transfers_are_refused() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.cache.enabled = true;
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    // Prime the cache with a recursive query.
    let first = udp_query(addr, "snoop.test").await.expect("first answer");
    assert_eq!(first.metadata.response_code, ResponseCode::NoError);
    assert_eq!(fake.hits(), 1);

    // The same question with RD=0 must reach the upstream instead of being
    // answered from the recursive cache (cache snooping).
    let mut raw = res::dns::msg::build_query("snoop.test", "A").expect("query");
    raw[2] &= 0xFE; // clear RD
    let iterative = udp_send_raw(addr, &raw, std::time::Duration::from_secs(2))
        .await
        .expect("iterative answer");
    assert_eq!(iterative.metadata.response_code, ResponseCode::NoError);
    assert_eq!(fake.hits(), 2, "RD=0 query must not be served from cache");

    for qtype in ["AXFR", "IXFR"] {
        let resp = udp_query_type(addr, "example.test", qtype)
            .await
            .expect("transfer refusal");
        assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
    }
    assert_eq!(fake.hits(), 2, "zone transfers must not reach upstream");

    gw.shutdown().await;
    fake.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn any_policy_forward_can_be_opted_in() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.query.any_policy = res::config::AnyPolicy::Forward;
    cfg.upstreams.push(fake.config("fake-1"));
    let gw = start_gateway(cfg).await;
    let addr = gw.udp_addr().expect("udp addr");

    // Explicit opt-in: the ANY query is passed upstream (fake answers with
    // an A record regardless of type, which is fine for this check).
    let resp = udp_query_type(addr, "example.test", "ANY")
        .await
        .expect("response");
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert!(
        fake.hits() >= 1,
        "ANY must reach upstream under forward policy"
    );

    gw.shutdown().await;
    fake.stop().await;
}

// ---------------------------------------------------------------------------
// Audit Batch 1: dashboard-shaped payloads, ACL source, health/selection
// endpoints, hardened dashboard fallback, login caps, cache byte cap.
// ---------------------------------------------------------------------------

/// The panel sends `confirm` on every write (umgSubmit). `deny_unknown_fields`
/// used to turn that into a 422 and break "Add upstream" outright.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_create_upstream_accepts_dashboard_shaped_payload() {
    let fake = FakeUpstream::start().await;
    let mut cfg = base_config();
    cfg.upstreams.push(fake.config("seed"));
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let (status, body) = http(
        "POST",
        api,
        "/api/upstreams",
        Some(
            r#"{"name":"panel-created","address":"127.0.0.1","port":5355,
                "confirm":true,"expect_rcode":"NOERROR","priority":2,
                "probe_interval_ms":9000,"probe_timeout_ms":4000,
                "probes":[{"type":"A","name":"example.com"}]}"#,
        ),
    )
    .await;
    assert_eq!(
        status, 201,
        "dashboard-shaped create must be accepted: {body}"
    );
    let created: serde_json::Value = serde_json::from_str(&body).expect("json");
    let id = created["upstream"]["id"].as_i64().expect("id");

    // expect_rcode round-trips through create, and clear_expect_rcode works.
    assert_eq!(created["upstream"]["expect_rcode"], "NOERROR");
    assert_eq!(created["upstream"]["probe_interval_ms"], 9000);
    assert_eq!(created["upstream"]["probes"][0]["type"], "A");
    let (status, body) = http(
        "PATCH",
        api,
        &format!("/api/upstreams/{id}"),
        Some(r#"{"clear_expect_rcode":true}"#),
    )
    .await;
    assert_eq!(status, 200, "clear_expect_rcode patch: {body}");
    let after: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(
        after["upstream"]["expect_rcode"].is_null(),
        "expect_rcode must be cleared: {body}"
    );

    // clear_probes wipes ONLY the probe list; the cadence overrides keep
    // their values unless the dedicated clear flags are sent.
    let (status, body) = http(
        "PATCH",
        api,
        &format!("/api/upstreams/{id}"),
        Some(r#"{"clear_probes":true}"#),
    )
    .await;
    assert_eq!(status, 200, "clear_probes patch: {body}");
    let after: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(after["upstream"]["probes"].is_null(), "{body}");
    assert_eq!(
        after["upstream"]["probe_interval_ms"], 9000,
        "clear_probes must not wipe the probe interval: {body}"
    );
    assert_eq!(after["upstream"]["probe_timeout_ms"], 4000, "{body}");

    let (status, body) = http(
        "PATCH",
        api,
        &format!("/api/upstreams/{id}"),
        Some(r#"{"clear_probe_interval_ms":true,"clear_timeout":true}"#),
    )
    .await;
    assert_eq!(status, 200, "clear interval patch: {body}");
    let after: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(after["upstream"]["probe_interval_ms"].is_null(), "{body}");
    assert!(after["upstream"]["timeout_ms"].is_null(), "{body}");
    assert_eq!(
        after["upstream"]["probe_timeout_ms"], 4000,
        "interval clear must not touch the probe timeout: {body}"
    );

    let (status, _) = http("DELETE", api, &format!("/api/upstreams/{id}"), None).await;
    assert!(status == 200 || status == 204);
    gw.shutdown().await;
    fake.stop().await;
}

/// ACL entries report where they came from: `config` for file-structured
/// entries, `legacy` for ones synthesised from the flat allow/deny lists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_acl_reports_entry_source() {
    let cfg = base_config();
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    // Empty structured section → legacy synthesised view.
    let (status, body) = http("GET", api, "/api/acl", None).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let entries = v["entries"].as_array().expect("entries array");
    assert!(!entries.is_empty(), "{body}");
    assert!(
        entries.iter().all(|e| e["source"] == "legacy"),
        "every synthesised entry must be marked legacy: {body}"
    );

    // Structured PUT → source becomes `config`.
    let (status, body) = http(
        "PUT",
        api,
        "/api/acl",
        Some(
            r#"{"entries":[{"cidr":"10.9.0.0/16","action":"deny","enabled":true}],"confirm":true}"#,
        ),
    )
    .await;
    assert_eq!(status, 200, "acl put: {body}");
    let (status, body) = http("GET", api, "/api/acl", None).await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["entries"][0]["source"], "config", "{body}");

    gw.shutdown().await;
}

/// GET/PUT round trip for the health-check section, including generation
/// guarding and validation of nonsense values.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_health_config_roundtrip_and_guards() {
    let cfg = base_config();
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let (status, body) = http("GET", api, "/api/health/config", None).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let gen = v["generation"].as_u64().expect("generation");
    assert!(v["health"]["enabled"].is_boolean(), "{body}");
    assert!(v["health"]["probes"].is_array(), "{body}");

    // Valid update with the current generation succeeds and bumps it.
    let (status, body) = http(
        "PUT",
        api,
        "/api/health/config",
        Some(&format!(r#"{{"enabled":false,"generation":{gen}}}"#)),
    )
    .await;
    assert_eq!(status, 200, "health put: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["health"]["enabled"], false);
    assert!(v["generation"].as_u64() > Some(gen), "{body}");

    // The stale generation is refused with 409.
    let (status, body) = http(
        "PUT",
        api,
        "/api/health/config",
        Some(&format!(r#"{{"enabled":true,"generation":{gen}}}"#)),
    )
    .await;
    assert_eq!(status, 409, "stale generation must conflict: {body}");

    // Nonsense values never persist (validation runs before the swap).
    let (status, body) = http(
        "PUT",
        api,
        "/api/health/config",
        Some(r#"{"interval_ms":50}"#),
    )
    .await;
    assert_eq!(status, 400, "interval below 100ms must be rejected: {body}");

    // Unknown fields are refused, not silently ignored.
    let (status, _) = http(
        "PUT",
        api,
        "/api/health/config",
        Some(r#"{"bogus_field":1}"#),
    )
    .await;
    assert_eq!(status, 422);

    gw.shutdown().await;
}

/// GET/PUT round trip for the selection policy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_selection_roundtrip_and_guards() {
    let cfg = base_config();
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let (status, body) = http("GET", api, "/api/selection", None).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v["selection"]["strategy"].is_string(), "{body}");
    let gen = v["generation"].as_u64().expect("generation");

    let (status, body) = http(
        "PUT",
        api,
        "/api/selection",
        Some(&format!(
            r#"{{"strategy":"best_score","min_probe_samples":5,"generation":{gen}}}"#
        )),
    )
    .await;
    assert_eq!(status, 200, "selection put: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["selection"]["strategy"], "best_score");
    assert_eq!(v["selection"]["min_probe_samples"], 5);

    let (status, body) = http(
        "PUT",
        api,
        "/api/selection",
        Some(r#"{"lower_tier_share":2.0}"#),
    )
    .await;
    assert_eq!(status, 400, "share outside 0..=1 must be rejected: {body}");

    gw.shutdown().await;
}

/// Login input length caps: oversized credentials are refused before any
/// argon2 work or rate-limit state is touched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_login_rejects_oversized_credentials() {
    let gw = start_gateway_with_passwords(base_config(), "pw", None).await;
    let api = gw.api_addr().expect("api addr");

    let long_user = "u".repeat(65);
    let (status, _) = http(
        "POST",
        api,
        "/api/auth/login",
        Some(&format!(r#"{{"username":"{long_user}","password":"pw"}}"#)),
    )
    .await;
    assert_eq!(status, 400, "65-char username must be refused");

    let long_pw = "p".repeat(1025);
    let (status, _) = http(
        "POST",
        api,
        "/api/auth/login",
        Some(&format!(r#"{{"username":"admin","password":"{long_pw}"}}"#)),
    )
    .await;
    assert_eq!(status, 400, "1025-char password must be refused");

    gw.shutdown().await;
}

/// The cache byte-cap knob is exposed and validated end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_cache_reports_and_updates_byte_cap() {
    let cfg = base_config();
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let (status, body) = http("GET", api, "/api/cache", None).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v["max_memory_bytes"].as_u64().unwrap_or(0) > 0, "{body}");

    let (status, body) = http(
        "PUT",
        api,
        "/api/cache",
        Some(r#"{"max_memory_bytes":1048576}"#),
    )
    .await;
    assert_eq!(status, 200, "cache put: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["max_memory_bytes"], 1048576, "{body}");

    let (status, body) = http("PUT", api, "/api/cache", Some(r#"{"max_memory_bytes":0}"#)).await;
    assert_eq!(status, 400, "zero byte cap must be rejected: {body}");

    gw.shutdown().await;
}

/// Hardened dashboard fallback: JSON 404 for unknown API paths, SPA index
/// for clean routes, real 404 for missing assets, dotfiles and `..` never
/// served, security headers on every response.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dashboard_fallback_is_hardened() {
    // Use the same relative directory as `config/res.toml`; this catches
    // regressions where the dashboard is silently treated as disabled.
    let dash = std::path::PathBuf::from("dashboard");
    assert!(
        dash.join("index.html").exists(),
        "repo dashboard must exist"
    );
    let mut cfg = base_config();
    cfg.server.dashboard_dir = Some(dash);
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    // The SPA entry is served with the right type.
    let raw = http_raw("GET", api, "/", None, &[]).await;
    let head = raw.split("\r\n\r\n").next().unwrap_or("").to_lowercase();
    assert!(
        raw.contains(" 200"),
        "GET / must be 200: {}",
        &raw[..raw.len().min(200)]
    );
    assert!(head.contains("content-type: text/html"), "{head}");
    // Security headers on static responses (L10).
    assert!(head.contains("x-content-type-options: nosniff"), "{head}");
    assert!(head.contains("x-frame-options: deny"), "{head}");
    assert!(head.contains("referrer-policy: no-referrer"), "{head}");
    assert!(
        head.contains("content-security-policy: default-src 'none'; script-src 'self'"),
        "CSP missing or weakened: {head}"
    );
    assert!(
        !head.contains("script-src 'self' 'unsafe-inline'")
            && !head.contains("script-src 'unsafe-inline'")
            && !head.contains("script-src 'self' 'unsafe-eval'"),
        "scripts must not allow inline/eval: {head}"
    );
    assert!(
        raw.contains("res · Observability"),
        "index body must be served"
    );
    assert!(
        !raw.contains("<style") && !raw.contains("<script>"),
        "index must not carry inline style/script blocks"
    );

    // Split dashboard assets are same-origin files with correct MIME types.
    for (path, mime) in [
        ("/app.css", "content-type: text/css"),
        ("/app.js", "content-type: application/javascript"),
        ("/boot.js", "content-type: application/javascript"),
    ] {
        let raw = http_raw("GET", api, path, None, &[]).await;
        let head = raw.split("\r\n\r\n").next().unwrap_or("").to_lowercase();
        assert!(raw.contains(" 200"), "{path} must be served");
        assert!(head.contains(mime), "{path} mime: {head}");
    }

    // Fonts still resolve with their MIME type.
    let (status, body) = http("GET", api, "/fonts/Shabnam.ttf", None).await;
    assert_eq!(status, 200, "font must be served");
    assert!(
        body.starts_with("\u{0}\x01\x00\x00"),
        "must be raw ttf bytes"
    );

    // Unknown /api paths answer JSON 404, never the HTML page with 200.
    let raw = http_raw("GET", api, "/api/definitely-not-a-route", None, &[]).await;
    assert!(raw.contains(" 404"), "unknown api path must 404");
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    let v: serde_json::Value = serde_json::from_str(body).expect("json 404, not HTML");
    assert!(v["error"].is_string(), "{body}");

    // Extensionless unknown paths get the SPA entry (deep links).
    let (status, body) = http("GET", api, "/some/spa/route", None).await;
    assert_eq!(status, 200, "SPA route must fall back to index");
    assert!(body.contains("res · Observability"));

    // A missing *asset* stays a visible 404 instead of a lying 200.
    let (status, _) = http("GET", api, "/missing-asset.js", None).await;
    assert_eq!(status, 404, "missing assets must not serve index.html");

    // Dotfiles are never served.
    let (status, _) = http("GET", api, "/.res.toml", None).await;
    assert_eq!(status, 404, "dotfiles must not be served");

    // `..` traversal segments are refused before touching the filesystem.
    let (status, _) = http("GET", api, "/../src/main.rs", None).await;
    assert_eq!(status, 404, "traversal must not be served");

    // POST to static content is refused.
    let (status, _) = http("POST", api, "/", Some("{}")).await;
    assert_eq!(status, 405, "static serving must be read-only");

    gw.shutdown().await;
}

/// Security headers are present on API responses too, not just static ones.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_responses_carry_security_headers() {
    let cfg = base_config();
    let gw = start_gateway(cfg).await;
    let api = gw.api_addr().expect("api addr");

    let raw = http_raw("GET", api, "/api/health", None, &[]).await;
    let head = raw.split("\r\n\r\n").next().unwrap_or("").to_lowercase();
    assert!(head.contains("x-content-type-options: nosniff"), "{head}");
    assert!(head.contains("x-frame-options: deny"), "{head}");
    assert!(head.contains("referrer-policy: no-referrer"), "{head}");
    assert!(
        head.contains("content-security-policy: default-src 'none'"),
        "CSP missing on API responses: {head}"
    );
    assert!(
        head.contains("cache-control: no-store"),
        "API payloads must not be cached: {head}"
    );
    assert!(
        head.contains("cross-origin-opener-policy: same-origin"),
        "{head}"
    );
    assert!(head.contains("permissions-policy:"), "{head}");

    // Even the JSON 404 fallback carries them (layer wraps the fallback).
    let raw = http_raw("GET", api, "/api/nope", None, &[]).await;
    let head = raw.split("\r\n\r\n").next().unwrap_or("").to_lowercase();
    assert!(head.contains("x-content-type-options: nosniff"), "{head}");

    gw.shutdown().await;
}
