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

use crate::dns::msg::Rcode;

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

/// What to do with a response that exceeds its response-rate bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RrlAction {
    /// Send nothing. Suitable only when a client is known to retry over TCP.
    Drop,
    /// Send a minimal TC=1 answer so the client retries over TCP (default).
    Truncate,
}

/// Response-rate limiting (RRL) for client-facing UDP answers.
///
/// The bucket key is `(client IP, lowercased question name, qtype, rcode)`,
/// so an attacker cannot turn one cached answer or one upstream query into an
/// unbounded stream of identical UDP responses. TCP is not limited here:
/// there is no spoofed-source amplification on a connected, handshaken
/// transport, and the normal query/connection limits still apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RrlConfig {
    /// Master switch. Enabled by default with thresholds that match the
    /// default per-client request rate, so ordinary traffic is unaffected.
    pub enabled: bool,
    /// Sustained identical UDP responses per client per second.
    pub per_client_qps: f64,
    /// Immediate identical-response burst per client.
    pub burst: u32,
    /// Maximum tracked response keys across all shards (bounded memory).
    pub max_tracked_keys: usize,
    /// Drop the answer or return TC=1 when the bucket is exhausted.
    pub action: RrlAction,
}

impl Default for RrlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_client_qps: 50.0,
            burst: 100,
            max_tracked_keys: 65_536,
            action: RrlAction::Truncate,
        }
    }
}

const SHARDS: usize = 64;
/// Entries idle longer than this are pruned regardless of table size.
const IDLE_TTL: Duration = Duration::from_secs(60);
/// Response keys are idle-pruned sooner than request buckets: they are a
/// per-question amplification guard, not accounting state.
const RRL_IDLE_TTL: Duration = Duration::from_secs(30);

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
    ///
    /// Order matters for fairness: the *per-IP* bucket is consulted first,
    /// so a single noisy client that is over its own limit cannot drain the
    /// shared global bucket and starve every other client (a global token is
    /// only spent once the client's own budget has admitted the query).
    pub fn check(&self, client: IpAddr, cfg: &RateLimitConfig) -> bool {
        if !cfg.enabled {
            return true;
        }
        // Dual-stack listeners present IPv4 peers as ::ffff:a.b.c.d; bucket
        // both spellings to the same key or each client gets two buckets.
        let client = canonical(client);
        if !self.take_per_ip(client, cfg) {
            return false;
        }
        self.take(&self.global, cfg.global_qps, cfg.global_burst)
    }

    fn take_per_ip(&self, client: IpAddr, cfg: &RateLimitConfig) -> bool {
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

/// Fold IPv4-mapped IPv6 (`::ffff:a.b.c.d`) onto plain IPv4 so one client
/// cannot hold two buckets under dual-stack sockets.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RrlKey {
    client: IpAddr,
    name: String,
    qtype: u16,
    rcode: Rcode,
}

pub struct ResponseRateLimiter {
    shards: Vec<Mutex<HashMap<RrlKey, Bucket>>>,
}

impl ResponseRateLimiter {
    pub fn new() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    /// Returns `true` when this response is within its bucket.
    ///
    /// The key deliberately includes the response rcode and qtype: NXDOMAIN
    /// or SERVFAIL answers (which can carry SOA data) cannot hide inside a
    /// stream of positive answers, and vice versa.
    pub fn allow(
        &self,
        client: IpAddr,
        name: &str,
        qtype: u16,
        rcode: Rcode,
        cfg: &RrlConfig,
    ) -> bool {
        if !cfg.enabled {
            return true;
        }
        let key = RrlKey {
            client: canonical(client),
            name: name.to_ascii_lowercase(),
            qtype,
            rcode,
        };
        let shard_idx = rrl_shard_of(&key);
        let shard = &self.shards[shard_idx];
        let cap = (cfg.max_tracked_keys / SHARDS).max(1);
        let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= cap {
            prune_rrl(&mut map, cap);
        }
        let burst = cfg.burst as f64;
        let bucket = map.entry(key).or_insert(Bucket {
            tokens: burst,
            last: Instant::now(),
        });
        bucket.refill(cfg.per_client_qps, burst);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Number of tracked response keys (approximate diagnostics).
    pub fn tracked_keys(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len())
            .sum()
    }

    /// Drop all state (used when RRL is disabled by a hot reload).
    pub fn clear(&self) {
        for shard in &self.shards {
            shard.lock().unwrap_or_else(|e| e.into_inner()).clear();
        }
    }

    /// Enforce a new configured key bound after a hot reload.
    pub fn trim_to(&self, max_tracked_keys: usize) {
        let cap = (max_tracked_keys / SHARDS).max(1);
        for shard in &self.shards {
            let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
            if map.len() > cap {
                prune_rrl(&mut map, cap);
            }
        }
    }
}

impl Default for ResponseRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

fn rrl_shard_of(key: &RrlKey) -> usize {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    (h.finish() as usize) % SHARDS
}

fn prune_rrl(map: &mut HashMap<RrlKey, Bucket>, cap: usize) {
    map.retain(|_, b| b.last.elapsed() < RRL_IDLE_TTL);
    if map.len() < cap {
        return;
    }
    let mut entries: Vec<(RrlKey, Instant)> =
        map.iter().map(|(k, b)| (k.clone(), b.last)).collect();
    entries.sort_by_key(|(_, last)| *last);
    let overflow = map.len() + 1 - cap;
    for (key, _) in entries.into_iter().take(overflow) {
        map.remove(&key);
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

    /// One client over its own limit must not consume global tokens:
    /// per-IP denial happens *before* the global bucket is touched (the
    /// §13 "one noisy client" isolation rule).
    #[test]
    fn per_ip_denial_does_not_drain_global_bucket() {
        let rl = RateLimiter::new();
        let mut c = cfg();
        c.per_ip_burst = 1;
        c.per_ip_qps = 0.0001;
        c.global_burst = 5;
        c.global_qps = 0.0001; // no meaningful refill during the test

        // Noisy client: 1 allowed, then 9 per-IP denials.
        for _ in 0..10 {
            rl.check(ip(7), &c);
        }
        // 4 of the 5 global tokens must remain for everyone else.
        let mut allowed = 0;
        for n in 100..110u8 {
            if rl.check(ip(n), &c) {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed, 4,
            "per-IP denials must not drain the shared global bucket"
        );
    }

    /// `::ffff:10.0.0.1` and `10.0.0.1` are the same client.
    #[test]
    fn v4_mapped_ipv6_shares_the_v4_bucket() {
        let rl = RateLimiter::new();
        let c = cfg(); // per_ip_burst = 5
        let plain = ip(3);
        let mapped: IpAddr = "::ffff:10.0.0.3".parse().unwrap();
        for _ in 0..5 {
            assert!(rl.check(mapped, &c), "mapped spelling within burst");
        }
        assert!(
            !rl.check(plain, &c),
            "plain v4 must see the same exhausted bucket"
        );
        assert!(!rl.check(mapped, &c), "mapped spelling exhausted too");
    }

    fn rrl_cfg() -> RrlConfig {
        RrlConfig {
            enabled: true,
            per_client_qps: 0.001,
            burst: 3,
            max_tracked_keys: 1_000,
            action: RrlAction::Truncate,
        }
    }

    #[test]
    fn rrl_allows_burst_then_limits_identical_responses() {
        let rrl = ResponseRateLimiter::new();
        let c = rrl_cfg();
        for i in 0..3 {
            assert!(
                rrl.allow(ip(1), "example.com", 1, Rcode::NoError, &c),
                "response {i} within burst"
            );
        }
        assert!(
            !rrl.allow(ip(1), "example.com", 1, Rcode::NoError, &c),
            "identical response beyond burst must be limited"
        );
        assert!(
            rrl.allow(ip(1), "other.example", 1, Rcode::NoError, &c),
            "a different question has an independent bucket"
        );
        assert!(
            rrl.allow(ip(1), "example.com", 28, Rcode::NoError, &c),
            "a different qtype has an independent bucket"
        );
        assert!(
            rrl.allow(ip(1), "example.com", 1, Rcode::NXDomain, &c),
            "a different rcode has an independent bucket"
        );
        assert!(
            rrl.allow(ip(2), "example.com", 1, Rcode::NoError, &c),
            "a different client has an independent bucket"
        );
    }

    #[test]
    fn rrl_is_case_insensitive_and_canonicalizes_mapped_ipv4() {
        let rrl = ResponseRateLimiter::new();
        let c = rrl_cfg();
        for _ in 0..3 {
            assert!(rrl.allow(ip(4), "Mixed.Example", 1, Rcode::NoError, &c));
        }
        let mapped: IpAddr = "::ffff:10.0.0.4".parse().unwrap();
        assert!(
            !rrl.allow(mapped, "mixed.example", 1, Rcode::NoError, &c),
            "case and v4-mapped spelling must share one bucket"
        );
    }

    #[test]
    fn rrl_disabled_never_limits_and_table_is_bounded() {
        let rrl = ResponseRateLimiter::new();
        let mut c = rrl_cfg();
        c.enabled = false;
        for _ in 0..10_000 {
            assert!(rrl.allow(ip(1), "example.com", 1, Rcode::NoError, &c));
        }

        c.enabled = true;
        c.max_tracked_keys = 256;
        for n in 0..5_000u32 {
            let client = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000u32 + n));
            rrl.allow(client, "example.com", 1, Rcode::NoError, &c);
        }
        assert!(
            rrl.tracked_keys() <= 256,
            "tracked response keys {} exceed bound",
            rrl.tracked_keys()
        );
        rrl.clear();
        assert_eq!(rrl.tracked_keys(), 0);
    }
}
