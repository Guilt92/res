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
        .find(|l| l.starts_with("outisdns_failovers_total "))
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
        text.contains("outisdns_rate_limit_dropped_total"),
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
    let mut q = outisdns::dns::msg::build_query("opcode.test", "A").expect("query");
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
        body.contains("outisdns_queries_total{transport=\"udp\"}"),
        "metrics missing udp counter"
    );
    assert!(
        body.contains("outisdns_upstream_health"),
        "health gauge missing"
    );

    let (status, body) = http("GET", api, "/api/upstreams", None).await;
    assert_eq!(status, 200);
    assert!(body.contains("\"fake-1\""), "upstream list body: {body}");

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
    let reparsed = outisdns::config::AppConfig::parse(&toml_text).expect("exported toml loads");
    assert_eq!(reparsed.upstreams.len(), 1);

    // IMPORT: add a second upstream through the config endpoint.
    let mut imported = reparsed;
    imported.upstreams.push(outisdns::config::UpstreamConfig {
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

    let dir = std::env::temp_dir().join(format!("outisdns-api-cfg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let path = dir.join("outisdns.toml");

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
    let loaded = outisdns::config::AppConfig::load(&path).expect("persisted file loads");
    assert!(loaded.upstreams.iter().any(|u| u.name == "persisted-a"));
    assert!(
        !outisdns::config::AppConfig::backup_path(&path).exists(),
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
    let backup =
        outisdns::config::AppConfig::load(&outisdns::config::AppConfig::backup_path(&path))
            .expect("backup loads");
    assert!(
        backup.upstreams.iter().any(|u| u.name == "persisted-a"),
        "backup must hold the previous configuration"
    );
    let current = outisdns::config::AppConfig::load(&path).expect("primary loads");
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
