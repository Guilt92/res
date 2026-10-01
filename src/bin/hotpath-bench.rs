//! Hot-path micro-benchmark: the synchronous admission phase, in-process,
//! without any sockets.
//!
//! Stages measured (in the order a real packet hits them):
//!
//! 1. `parse`      – DNS query parsing/validation
//! 2. `acl`        – CIDR allow/deny evaluation (fail-closed)
//! 3. `ratelimit`  – token-bucket check (global + per-IP shard)
//! 4. `selector`   – upstream selection over an 8-candidate pool
//! 5. `admission`  – parse + acl + ratelimit combined (pre-cache precheck)
//!
//! Usage: `cargo run --release --bin res-hotpath-bench -- --iters 200000`
//! The system block in the output records the machine the numbers came from.

use std::hint::black_box;
use std::net::IpAddr;
use std::time::Instant;

use clap::Parser;
use res::acl::{AclConfig, AclRules};
use res::config::{SelectionConfig, SelectionStrategy};
use res::dns::msg;
use res::ratelimit::{RateLimitConfig, RateLimiter};
use res::selection::{build_selector, StateView, UpstreamSelector};
use res::sysinfo::SystemInfo;
use res::upstream::HealthStatus;

#[derive(Parser, Debug)]
#[command(
    name = "res-hotpath-bench",
    about = "In-process micro-benchmark of the DNS hot path (no I/O)"
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
