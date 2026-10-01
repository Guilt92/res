//! End-to-end integration tests: a real gateway (UDP + TCP + API) talking to
//! in-process fake upstreams. No external DNS server or network is required.

mod common;

use std::time::Duration;

use common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RData;

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
    assert_eq!(state["up"].as_u64(), Some(1), "{body}");
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
        wait_for_health(api, "flaky", "up", Duration::from_secs(5)).await,
        "flaky should start healthy"
    );
    assert!(
        wait_for_health(api, "stable", "up", Duration::from_secs(5)).await,
        "stable should start healthy"
    );

    // Outage: flaky stops answering -> must be marked down.
    flaky.set_answering(false);
    assert!(
        wait_for_health(api, "flaky", "down", Duration::from_secs(6)).await,
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
        wait_for_health(api, "flaky", "up", Duration::from_secs(6)).await,
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
        wait_for_health(api, "only-dead", "down", Duration::from_secs(5)).await,
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
    assert_eq!(d["upstreams"]["down"], 1, "{body}");
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
