//! Hot-path micro-benchmark: the synchronous admission phase, in-process,
//! plus the cache and one UDP upstream exchange (I/O stages are labelled).
//!
//! Stages measured (in the order a real packet hits them):
//!
//! 1. `parse`       – DNS query parsing/validation
//! 2. `acl`         – CIDR allow/deny evaluation (fail-closed)
//! 3. `ratelimit`   – token-bucket check (global + per-IP shard)
//! 4. `selector`    – upstream selection over an 8-candidate pool
//! 5. `admission`   – parse + acl + ratelimit combined (pre-cache precheck)
//! 6. `resp_parse`  – lightweight upstream-response view (correlation path)
//! 7. `cache_hit`   – response-cache lookup + TTL rewrite (256-name set)
//! 8. `udp_exchange`– full upstream UDP exchange incl. socket bind/connect
//!
//! Usage: `cargo run --release --bin res-hotpath-bench -- --iters 200000`
//! The system block in the output records the machine the numbers came from.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use clap::Parser;
use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::{Name, RData, Record};
use res::acl::{AclConfig, AclRules};
use res::cache::{CacheKey, DnsCache};
use res::config::{CacheConfig, Protocol, SelectionConfig, SelectionStrategy, UpstreamConfig};
use res::dns::forward::Forwarder;
use res::dns::msg;
use res::ratelimit::{RateLimitConfig, RateLimiter};
use res::selection::{build_selector, StateView, UpstreamSelector};
use res::sysinfo::SystemInfo;
use res::upstream::HealthStatus;

#[derive(Parser, Debug)]
#[command(
    name = "res-hotpath-bench",
    about = "In-process micro-benchmark of the DNS hot path (no I/O except udp_exchange)"
)]
struct Args {
    /// Iterations for the heavier stages (parse/admission); lighter stages
    /// run 25x this many.
    #[arg(long, default_value_t = 200_000)]
    iters: u64,
    /// Number of upstream candidates for the selector stage.
    #[arg(long, default_value_t = 8)]
    upstreams: usize,
    /// Candidate pool size used when reporting per-query headroom.
    #[arg(long, default_value_t = 1024)]
    candidates: usize,
}

struct Stage {
    name: &'static str,
    iters: u64,
    ns_per_op: f64,
    ops_per_sec: f64,
}

fn main() {
    let args = Args::parse();
    let sys = SystemInfo::collect();

    // ---- fixtures -------------------------------------------------------
    let raw = msg::build_query("bench-1.example.com", "A").expect("build query");
    let acl = AclRules::parse(&AclConfig::default()).expect("acl");
    let client: IpAddr = "10.1.2.3".parse().expect("ip");
    let rl_cfg = RateLimitConfig {
        enabled: true,
        ..RateLimitConfig::default()
    };
    let limiter = RateLimiter::new();
    let selector: Box<dyn UpstreamSelector> = build_selector(&SelectionConfig {
        strategy: SelectionStrategy::WeightedReliability,
        latency_reference_ms: 50.0,
        ..SelectionConfig::default()
    });
    let views: Vec<StateView> = (0..args.upstreams.max(2))
        .map(|i| StateView {
            id: i as i64 + 1,
            health: if i == 0 {
                HealthStatus::Up
            } else {
                HealthStatus::Degraded
            },
            priority: 1,
            weight: 1 + (i as u32 % 3),
            reliability: 0.9,
            p95_ms: 8.0 + i as f64,
            avg_ms: 6.0 + i as f64,
            has_latency: true,
        })
        .collect();

    // A realistic response: question + 4 A answers (~90 bytes wire).
    let resp_bytes = sample_response();
    let resp_view = msg::parse_response(&resp_bytes).expect("resp");

    let cache_cfg = CacheConfig {
        enabled: true,
        ..CacheConfig::default()
    };
    let cache = DnsCache::new();
    let cache_keys: Vec<CacheKey> = (0..256u32)
        .map(|i| CacheKey {
            name: format!("ws{i}.example.com."),
            qtype: 1,
            qclass: 1,
            cd: false,
        })
        .collect();
    for k in &cache_keys {
        cache.put(
            k.clone(),
            resp_bytes.clone(),
            Duration::from_secs(60),
            msg::Rcode::NoError,
            &cache_cfg,
        );
    }

    let light = args.iters.saturating_mul(25).max(100_000);
    let heavy = args.iters.max(1_000);

    let mut stages = Vec::new();

    stages.push(run("parse", heavy, || {
        black_box(msg::parse_query(black_box(&raw)).expect("parse"))
    }));
    stages.push(run("acl", light, || {
        black_box(acl.decide(black_box(client)))
    }));
    stages.push(run("ratelimit", light, || {
        black_box(limiter.check(black_box(client), black_box(&rl_cfg)))
    }));
    stages.push(run("selector", light, || {
        black_box(selector.select(black_box(&views)))
    }));
    stages.push(run("admission", heavy, || {
        // Mirror of the synchronous precheck order (minus the cache lookup).
        let q = msg::parse_query(black_box(&raw)).expect("parse");
        black_box(acl.decide(black_box(client)));
        black_box(limiter.check(black_box(client), &rl_cfg));
        black_box(q)
    }));
    stages.push(run("resp_parse", light, || {
        black_box(msg::parse_response(black_box(&resp_bytes)).expect("view"))
    }));
    let mut i = 0usize;
    stages.push(run("cache_hit", heavy, || {
        let k = &cache_keys[i % cache_keys.len()];
        i += 1;
        black_box(cache.get(k, 0xBEEF, &cache_cfg))
    }));

    // ---- I/O stage: one full upstream UDP exchange ----------------------
    let io_iters = heavy.clamp(1_000, 20_000);
    let exchange_ns = bench_udp_exchange(&raw, io_iters);
    stages.push(Stage {
        name: "udp_exchange",
        iters: io_iters,
        ns_per_op: exchange_ns,
        ops_per_sec: 1_000_000_000.0 / exchange_ns.max(f64::MIN_POSITIVE),
    });

    // ---- report ---------------------------------------------------------
    println!("--- system ---");
    print!("{}", sys.render());
    println!("--- config ---");
    println!("stage iterations:  parse/admission={heavy} acl/ratelimit/selector={light}");
    println!(
        "selector pool:     {} candidates (weighted_reliability)",
        args.upstreams
    );
    println!(
        "acl rules:         {} networks (fail-closed default)",
        AclRules::parse(&AclConfig::default())
            .expect("acl")
            .allowed_count()
    );
    println!(
        "ratelimit:         enabled (per-IP {}/s, global {}/s)",
        rl_cfg.per_ip_qps, rl_cfg.global_qps
    );
    println!("cache:             256-name working set, 60s TTL");
    let _ = resp_view;
    println!("--- results ---");
    println!(
        "{:<12} {:>12} {:>14} {:>16}",
        "stage", "iters", "ns/op", "ops/sec"
    );
    for s in &stages {
        println!(
            "{:<12} {:>12} {:>14.1} {:>16.0}",
            s.name, s.iters, s.ns_per_op, s.ops_per_sec
        );
    }
    if let Some(adm) = stages.iter().find(|s| s.name == "admission") {
        println!("--- headroom ---");
        println!(
            "theoretical admission capacity: {:.0} queries/sec/core (sync precheck only)",
            adm.ops_per_sec
        );
        println!(
            "per-query admission budget: {:.1} ns of a 1 MHz wall-clock slice",
            adm.ns_per_op
        );
    }
}

fn sample_response() -> Vec<u8> {
    let query = msg::parse_query(&msg::build_query("ws0.example.com", "A").unwrap()).unwrap();
    let mut m = Message::response(query.id, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.metadata.recursion_available = true;
    m.queries = query.queries.clone();
    for i in 0..4u8 {
        m.answers.push(Record::from_rdata(
            Name::from_ascii("ws0.example.com").unwrap(),
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, i).into()),
        ));
    }
    m.to_vec().unwrap()
}

/// One full upstream UDP exchange per iteration: bind + connect + send +
/// recv + correlate against a local responder. Quantifies the socket cost
/// that a per-query socket (vs a pool) pays.
fn bench_udp_exchange(raw: &[u8], iters: u64) -> f64 {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async move {
        let responder = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind responder");
        let raddr = responder.local_addr().expect("responder addr");
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = responder.recv_from(&mut buf).await else {
                    break;
                };
                if n < 12 {
                    continue;
                }
                let mut resp = buf[..n].to_vec();
                resp[2] |= 0x80; // QR = response
                let _ = responder.send_to(&resp, peer).await;
            }
        });
        let up = UpstreamConfig {
            id: 1,
            name: "bench".into(),
            address: raddr.ip(),
            port: raddr.port(),
            protocol: Protocol::Udp,
            enabled: true,
            priority: 1,
            weight: 1,
            timeout_ms: None,
        };
        let fwd = Forwarder::new(false);
        let q = msg::parse_query(raw).expect("parse");
        // Warmup.
        for _ in 0..iters.min(2_000) {
            black_box(
                fwd.exchange(&up, &q, raw, Duration::from_millis(500))
                    .await
                    .ok(),
            );
        }
        let started = Instant::now();
        for _ in 0..iters {
            black_box(
                fwd.exchange(&up, &q, raw, Duration::from_millis(500))
                    .await
                    .expect("exchange"),
            );
        }
        started.elapsed().as_nanos() as f64 / iters as f64
    })
}

fn run<T>(name: &'static str, iters: u64, mut f: impl FnMut() -> T) -> Stage {
    // Warmup (also brings the code paths into the branch predictors/ICache).
    for _ in 0..iters.min(50_000) {
        black_box(f());
    }
    let started = Instant::now();
    for _ in 0..iters {
        black_box(f());
    }
    let elapsed = started.elapsed();
    let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;
    Stage {
        name,
        iters,
        ns_per_op,
        ops_per_sec: 1_000_000_000.0 / ns_per_op.max(f64::MIN_POSITIVE),
    }
}
