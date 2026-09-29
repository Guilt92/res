//! Token-bucket rate limiting (per client IP + global).
//!
//! Memory is bounded: the per-IP table is sharded and pruned, stale entries
//! are evicted, and the oldest idle entry is dropped when a shard is full.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RateLimitConfig {
    /// Master switch.
    pub enabled: bool,
    /// Sustained queries per second per client IP.
    pub per_ip_qps: f64,
    /// Burst tokens per client IP.
    pub per_ip_burst: u32,
    /// Maximum tracked client IPs across all shards (bounded memory).
    pub max_tracked_clients: usize,
    /// Global sustained QPS.
    pub global_qps: f64,
    /// Global burst tokens.
    pub global_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_ip_qps: 50.0,
            per_ip_burst: 100,
            max_tracked_clients: 65_536,
            global_qps: 50_000.0,
            global_burst: 100_000,
        }
    }
}

const SHARDS: usize = 64;
/// Entries idle longer than this are pruned regardless of table size.
const IDLE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn refill(&mut self, qps: f64, burst: f64) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * qps).min(burst);
    }
}

pub struct RateLimiter {
    shards: Vec<Mutex<HashMap<IpAddr, Bucket>>>,
    global: Mutex<Bucket>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            // `INFINITY` clamps to the configured burst on the first refill,
            // so a freshly started process does not reject the first queries.
            global: Mutex::new(Bucket {
                tokens: f64::INFINITY,
                last: Instant::now(),
            }),
        }
    }

    /// Returns `true` when the query is allowed to proceed.
    pub fn check(&self, client: IpAddr, cfg: &RateLimitConfig) -> bool {
        if !cfg.enabled {
            return true;
        }
        if !self.take(&self.global, cfg.global_qps, cfg.global_burst) {
            return false;
        }
        let shard_idx = shard_of(client);
        let shard = &self.shards[shard_idx];
        let cap = (cfg.max_tracked_clients / SHARDS).max(1);

        let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= cap {
            prune(&mut map, cap);
        }
        let burst = cfg.per_ip_burst as f64;
        let bucket = map.entry(client).or_insert(Bucket {
            tokens: burst,
            last: Instant::now(),
        });
        bucket.refill(cfg.per_ip_qps, burst);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn take(&self, lock: &Mutex<Bucket>, qps: f64, burst: u32) -> bool {
        let mut b = lock.lock().unwrap_or_else(|e| e.into_inner());
        b.refill(qps, burst as f64);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Number of tracked clients (approximate, for diagnostics).
    pub fn tracked_clients(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len())
            .sum()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

fn shard_of(ip: IpAddr) -> usize {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ip.hash(&mut h);
    (h.finish() as usize) % SHARDS
}

fn prune(map: &mut HashMap<IpAddr, Bucket>, cap: usize) {
    // Drop long-idle, fully refilled buckets first.
    map.retain(|_, b| b.last.elapsed() < IDLE_TTL);
    if map.len() < cap {
        return;
    }
    // Still full: evict the least recently used entries.
    let mut entries: Vec<(IpAddr, Instant)> = map.iter().map(|(ip, b)| (*ip, b.last)).collect();
    entries.sort_by_key(|(_, last)| *last);
    let overflow = map.len() + 1 - cap;
    for (ip, _) in entries.into_iter().take(overflow) {
        map.remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            per_ip_qps: 50.0,
            per_ip_burst: 5,
            max_tracked_clients: 1_000,
            global_qps: 100_000.0,
            global_burst: 1_000_000,
        }
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn allows_up_to_burst_then_denies() {
        let rl = RateLimiter::new();
        let c = cfg();
        for i in 0..5 {
            assert!(rl.check(ip(1), &c), "request {i} within burst should pass");
        }
        assert!(!rl.check(ip(1), &c), "6th immediate request must be denied");
    }

    #[test]
    fn different_ips_have_independent_buckets() {
        let rl = RateLimiter::new();
        let c = cfg();
        for _ in 0..5 {
            assert!(rl.check(ip(1), &c));
        }
        assert!(!rl.check(ip(1), &c));
        assert!(rl.check(ip(2), &c), "other IP unaffected");
    }

    #[test]
    fn disabled_never_limits() {
        let rl = RateLimiter::new();
        let mut c = cfg();
        c.enabled = false;
        for _ in 0..10_000 {
            assert!(rl.check(ip(1), &c));
        }
    }

    #[test]
    fn global_limit_applies_across_ips() {
        let rl = RateLimiter::new();
        let mut c = cfg();
        c.per_ip_burst = 1000;
        c.global_burst = 10;
        c.global_qps = 0.01; // effectively no refill during the test
        let mut allowed = 0;
        for n in 0..50 {
            if rl.check(IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 0, n)), &c) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 10, "global burst must cap total");
    }

    #[test]
    fn tokens_refill_over_time() {
        let rl = RateLimiter::new();
        let mut c = cfg();
        c.per_ip_burst = 1;
        c.per_ip_qps = 1000.0; // 1 token per ms
        assert!(rl.check(ip(9), &c));
        assert!(!rl.check(ip(9), &c));
        std::thread::sleep(Duration::from_millis(25));
        assert!(rl.check(ip(9), &c), "token should have refilled");
    }

    #[test]
    fn table_stays_bounded() {
        let rl = RateLimiter::new();
        let mut c = cfg();
        c.max_tracked_clients = 256;
        c.per_ip_burst = 10;
        for n in 0..5000u32 {
            let addr = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000u32 + n));
            rl.check(addr, &c);
        }
        assert!(
            rl.tracked_clients() <= 256,
            "tracked clients {} exceeds bound",
            rl.tracked_clients()
        );
    }
}
