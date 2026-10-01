//! Bounded traffic introspection for the DNS service: which clients send how
//! many requests, how they fared, and which names they ask for.
//!
//! Design constraints:
//!
//! * **Bounded memory** — every table has a hard key capacity; when full the
//!   tail (lowest request counts) is pruned, never the map itself.
//! * **O(1) hot path** — one `Mutex` lock and a hash lookup per request; the
//!   prune runs at most once per 64 rejected *new* keys.
//! * **No invented numbers** — requests whose key did not fit are counted
//!   separately (`skipped_requests`) instead of silently disappearing, and
//!   totals always come from the Prometheus counters, not from these tables.
//!   Unmeasured values (`avg_ms`, `p95_ms`, `share`) stay `None` until real
//!   samples exist; `rps` is the measured rate since the previous sample.
//! * **Privacy** — client addresses are masked by default; see
//!   [`ClientIpPrivacy`]. Sorting always uses the real (unmasked) counters.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::config::ClientIpPrivacy;

/// Number of rejected new keys that triggers a tail prune.
const PRUNE_AFTER_MISSES: u64 = 64;
/// Fraction of the table kept by a prune (the heaviest half).
const PRUNE_KEEP_FRACTION: usize = 2;
/// Recent per-client latencies kept for the P95 estimate.
const LAT_RING: usize = 16;

/// Per-table bookkeeping exposed by the API (all values are real counts).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct TableStats {
    /// Distinct keys currently held.
    pub tracked_keys: usize,
    /// Hard capacity of the table.
    pub cap: usize,
    /// Requests attributed to a tracked key.
    pub recorded_requests: u64,
    /// Requests whose key was new while the table was full (unattributable).
    pub skipped_requests: u64,
    /// How many tail prunes have run since start.
    pub prunes: u64,
}

/// How one client request ended (per-client accounting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Answered with a normal response (NOERROR/NXDOMAIN/…).
    Ok,
    /// Answered with an error or dropped (SERVFAIL, REFUSED, malformed, …).
    Failed,
    /// Gave up at the client deadline.
    Timeout,
    /// Rejected by the ACL (REFUSED).
    AclDenied,
    /// Rejected by the rate limiter (dropped).
    RateLimited,
}

/// Sort order for the per-client table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientSort {
    #[default]
    Requests,
    Bytes,
    Failed,
    Timeouts,
    Rps,
    Latency,
}

impl ClientSort {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "requests" => Some(Self::Requests),
            "bytes" => Some(Self::Bytes),
            "failed" => Some(Self::Failed),
            "timeouts" => Some(Self::Timeouts),
            "rps" => Some(Self::Rps),
            "latency" => Some(Self::Latency),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requests => "requests",
            Self::Bytes => "bytes",
            Self::Failed => "failed",
            Self::Timeouts => "timeouts",
            Self::Rps => "rps",
            Self::Latency => "latency",
        }
    }
}

/// One row of the per-client table (all counters are real measurements).
#[derive(Debug, Clone, Serialize)]
pub struct ClientRow {
    /// Address as it may be shown for the configured privacy level.
    pub client: String,
    /// Alias of `requests` kept for the stats/top lists.
    pub count: u64,
    pub requests: u64,
    /// Share of all recorded requests (`None` while nothing is recorded).
    pub share: Option<f64>,
    /// Measured requests/second since the previous 1 s sample.
    pub rps: f64,
    pub ok: u64,
    pub failed: u64,
    pub timeouts: u64,
    pub rate_limited: u64,
    pub acl_denied: u64,
    /// Average time to answer (`None` until the first measured answer).
    pub avg_ms: Option<f64>,
    /// P95 of the most recent answers (`None` until measured).
    pub p95_ms: Option<f64>,
    /// Request payload bytes seen from this client.
    pub bytes: u64,
    pub udp: u64,
    pub tcp: u64,
}

/// Per-client runtime record.
#[derive(Debug, Clone)]
struct ClientEntry {
    requests: u64,
    udp: u64,
    tcp: u64,
    bytes: u64,
    ok: u64,
    failed: u64,
    timeouts: u64,
    acl_denied: u64,
    rate_limited: u64,
    lat_sum_us: u64,
    lat_count: u64,
    /// Ring of the most recent latencies (microseconds).
    lat_ring: [u32; LAT_RING],
    lat_idx: usize,
    lat_filled: usize,
    rps: f64,
    prev_requests: u64,
    prev_sample: Instant,
}

impl ClientEntry {
    fn new() -> Self {
        Self {
            requests: 0,
            udp: 0,
            tcp: 0,
            bytes: 0,
            ok: 0,
            failed: 0,
            timeouts: 0,
            acl_denied: 0,
            rate_limited: 0,
            lat_sum_us: 0,
            lat_count: 0,
            lat_ring: [0; LAT_RING],
            lat_idx: 0,
            lat_filled: 0,
            rps: 0.0,
            prev_requests: 0,
            prev_sample: Instant::now(),
        }
    }

    fn push_latency(&mut self, us: u32) {
        self.lat_ring[self.lat_idx] = us;
        self.lat_idx = (self.lat_idx + 1) % LAT_RING;
        if self.lat_filled < LAT_RING {
            self.lat_filled += 1;
        }
        self.lat_sum_us += u64::from(us);
        self.lat_count += 1;
    }

    fn samples(&self) -> Vec<u32> {
        self.lat_ring[..self.lat_filled].to_vec()
    }
}

/// `key → record` table with a hard capacity and tail pruning.
#[derive(Debug)]
struct ClientTable {
    map: HashMap<IpAddr, ClientEntry>,
    cap: usize,
    recorded: u64,
    skipped: u64,
    misses_since_prune: u64,
    prunes: u64,
}

impl ClientTable {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            cap,
            recorded: 0,
            skipped: 0,
            misses_since_prune: 0,
            prunes: 0,
        }
    }

    fn record(&mut self, ip: IpAddr, tcp: bool, bytes: usize) {
        if self.cap == 0 {
            return;
        }
        self.recorded += 1;
        if let Some(e) = self.map.get_mut(&ip) {
            e.requests += 1;
            if tcp {
                e.tcp += 1;
            } else {
                e.udp += 1;
            }
            e.bytes += bytes as u64;
            return;
        }
        if self.map.len() < self.cap {
            let mut e = ClientEntry::new();
            e.requests = 1;
            e.bytes = bytes as u64;
            if tcp {
                e.tcp = 1;
            } else {
                e.udp = 1;
            }
            self.map.insert(ip, e);
            return;
        }
        // Full: attribute the request to nothing rather than to a wrong key.
        self.skipped += 1;
        self.misses_since_prune += 1;
        if self.misses_since_prune >= PRUNE_AFTER_MISSES {
            self.prune();
            self.misses_since_prune = 0;
        }
    }

    fn prune(&mut self) {
        let keep = (self.cap / PRUNE_KEEP_FRACTION).max(1);
        if self.map.len() <= keep {
            return;
        }
        let mut rows: Vec<(&IpAddr, u64)> = self.map.iter().map(|(k, e)| (k, e.requests)).collect();
        rows.sort_unstable_by_key(|(_, v)| std::cmp::Reverse(*v));
        let drop_keys: Vec<IpAddr> = rows.into_iter().skip(keep).map(|(k, _)| *k).collect();
        for k in drop_keys {
            self.map.remove(&k);
        }
        self.prunes += 1;
    }

    fn set_cap(&mut self, cap: usize) {
        self.cap = cap;
        if self.map.len() > cap && cap > 0 {
            self.prune();
        }
    }

    fn stats(&self) -> TableStats {
        TableStats {
            tracked_keys: self.map.len(),
            cap: self.cap,
            recorded_requests: self.recorded,
            skipped_requests: self.skipped,
            prunes: self.prunes,
        }
    }
}

/// `key → count` table with a hard capacity and tail pruning.
#[derive(Debug)]
struct CountTable<K> {
    map: HashMap<K, u64>,
    cap: usize,
    recorded: u64,
    skipped: u64,
    misses_since_prune: u64,
    prunes: u64,
}

impl<K: Eq + Hash + Clone + Ord> CountTable<K> {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            cap,
            recorded: 0,
            skipped: 0,
            misses_since_prune: 0,
            prunes: 0,
        }
    }

    /// Count one occurrence of `key`.
    fn record(&mut self, key: K) {
        if self.cap == 0 {
            return;
        }
        self.recorded += 1;
        if let Some(c) = self.map.get_mut(&key) {
            *c += 1;
            return;
        }
        if self.map.len() < self.cap {
            self.map.insert(key, 1);
            return;
        }
        // Full: attribute the request to nothing rather than to a wrong key.
        self.skipped += 1;
        self.misses_since_prune += 1;
        if self.misses_since_prune >= PRUNE_AFTER_MISSES {
            self.prune();
            self.misses_since_prune = 0;
        }
    }

    /// Drop the least-frequent half of the table (heavy hitters survive).
    fn prune(&mut self) {
        let keep = (self.cap / PRUNE_KEEP_FRACTION).max(1);
        if self.map.len() <= keep {
            return;
        }
        let mut rows: Vec<(&K, u64)> = self.map.iter().map(|(k, v)| (k, *v)).collect();
        rows.sort_unstable_by_key(|(_, v)| std::cmp::Reverse(*v));
        let drop_keys: Vec<K> = rows
            .into_iter()
            .skip(keep)
            .map(|(k, _)| k.clone())
            .collect();
        for k in drop_keys {
            self.map.remove(&k);
        }
        self.prunes += 1;
    }

    fn set_cap(&mut self, cap: usize) {
        self.cap = cap;
        if self.map.len() > cap && cap > 0 {
            self.prune();
        }
    }

    fn stats(&self) -> TableStats {
        TableStats {
            tracked_keys: self.map.len(),
            cap: self.cap,
            recorded_requests: self.recorded,
            skipped_requests: self.skipped,
            prunes: self.prunes,
        }
    }

    /// `(key, count)` pairs, highest count first.
    fn top(&self, limit: usize) -> Vec<(K, u64)> {
        let mut rows: Vec<(K, u64)> = self.map.iter().map(|(k, v)| (k.clone(), *v)).collect();
        rows.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        rows.truncate(limit.max(1));
        rows
    }
}

/// How many clients (and with which privacy) are exported as Prometheus
/// series by the client-metrics collector.
#[derive(Debug, Clone, Copy)]
struct PromExport {
    cap: usize,
    privacy: ClientIpPrivacy,
}

/// Runtime traffic tables (top clients + top queried names).
pub struct TrafficStats {
    clients: Mutex<ClientTable>,
    domains: Mutex<CountTable<String>>,
    prom_export: Mutex<PromExport>,
}

impl TrafficStats {
    pub fn new(clients_cap: usize, domains_cap: usize) -> Self {
        Self {
            clients: Mutex::new(ClientTable::new(clients_cap)),
            domains: Mutex::new(CountTable::new(domains_cap)),
            prom_export: Mutex::new(PromExport {
                cap: 100,
                privacy: ClientIpPrivacy::default(),
            }),
        }
    }

    /// Update the Prometheus client-series export settings (top-N cap and
    /// address privacy) after startup or a configuration reload.
    pub fn set_prom_export(&self, cap: usize, privacy: ClientIpPrivacy) {
        let mut e = self.prom_export.lock().unwrap_or_else(|x| x.into_inner());
        e.cap = cap;
        e.privacy = privacy;
    }

    /// Current Prometheus client-series export settings.
    pub fn prom_export(&self) -> (usize, ClientIpPrivacy) {
        let e = self.prom_export.lock().unwrap_or_else(|x| x.into_inner());
        (e.cap, e.privacy)
    }

    /// Attribute one received request to `client` (payload bytes as seen).
    pub fn record_request(&self, client: IpAddr, tcp: bool, bytes: usize) {
        let mut t = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        t.record(client, tcp, bytes);
    }

    /// Compatibility shorthand used by tests: one UDP request, no payload size.
    pub fn record_client(&self, client: IpAddr) {
        self.record_request(client, false, 0);
    }

    /// Record how a client request ended. Ignored when the client key was
    /// never recorded (table full/disabled) — unattributable outcomes are
    /// reported through the global metrics instead, never invented here.
    pub fn record_outcome(&self, client: IpAddr, outcome: Outcome, latency: Option<Duration>) {
        let mut t = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        if t.cap == 0 {
            return;
        }
        let Some(e) = t.map.get_mut(&client) else {
            return;
        };
        match outcome {
            Outcome::Ok => e.ok += 1,
            Outcome::Failed => e.failed += 1,
            Outcome::Timeout => e.timeouts += 1,
            Outcome::AclDenied => e.acl_denied += 1,
            Outcome::RateLimited => e.rate_limited += 1,
        }
        if let Some(d) = latency {
            let us = d.as_micros().min(u128::from(u32::MAX)) as u32;
            e.push_latency(us);
        }
    }

    /// Refresh the per-client requests/second estimate (called from the 1 Hz
    /// sampler; `rps` is the measured rate over the elapsed window).
    pub fn sample_rates(&self) {
        let now = Instant::now();
        let mut t = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        if t.cap == 0 {
            return;
        }
        for e in t.map.values_mut() {
            let dt = now
                .saturating_duration_since(e.prev_sample)
                .as_secs_f64()
                .max(f64::MIN_POSITIVE);
            let delta = e.requests.saturating_sub(e.prev_requests);
            e.rps = delta as f64 / dt;
            e.prev_requests = e.requests;
            e.prev_sample = now;
        }
    }

    /// Count one query for `name` (lowercased, trailing dot stripped).
    pub fn record_domain(&self, name: &str) {
        let normalized = normalize_name(name);
        let mut t = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        t.record(normalized);
    }

    /// Apply new table capacities after a configuration reload.
    pub fn set_caps(&self, clients_cap: usize, domains_cap: usize) {
        self.clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_cap(clients_cap);
        self.domains
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_cap(domains_cap);
    }

    pub fn client_stats(&self) -> TableStats {
        self.clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stats()
    }

    pub fn domain_stats(&self) -> TableStats {
        self.domains
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stats()
    }

    /// Per-client rows. `Full` keeps real addresses, `Masked` aggregates by
    /// masked value (counters summed, recent latencies merged), `Off` returns
    /// nothing. Sorting always uses the real counters.
    pub fn client_rows(
        &self,
        limit: usize,
        sort: ClientSort,
        privacy: ClientIpPrivacy,
    ) -> Vec<ClientRow> {
        if privacy == ClientIpPrivacy::Off {
            return Vec::new();
        }
        let t = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        if t.cap == 0 || t.map.is_empty() {
            return Vec::new();
        }
        let recorded = t.recorded;
        let mut rows: Vec<ClientRow> = match privacy {
            ClientIpPrivacy::Full => t
                .map
                .iter()
                .map(|(ip, e)| row_from(ip.to_string(), e, recorded))
                .collect(),
            ClientIpPrivacy::Masked => {
                // Merge entries that mask to the same label: real counters are
                // summed, recent latency samples are pooled for the P95.
                struct Agg {
                    requests: u64,
                    udp: u64,
                    tcp: u64,
                    bytes: u64,
                    ok: u64,
                    failed: u64,
                    timeouts: u64,
                    acl_denied: u64,
                    rate_limited: u64,
                    lat_sum_us: u64,
                    lat_count: u64,
                    rps: f64,
                    samples: Vec<u32>,
                }
                let mut by_mask: HashMap<String, Agg> = HashMap::new();
                for (ip, e) in t.map.iter() {
                    let label = mask_ip(*ip);
                    let a = by_mask.entry(label).or_insert_with(|| Agg {
                        requests: 0,
                        udp: 0,
                        tcp: 0,
                        bytes: 0,
                        ok: 0,
                        failed: 0,
                        timeouts: 0,
                        acl_denied: 0,
                        rate_limited: 0,
                        lat_sum_us: 0,
                        lat_count: 0,
                        rps: 0.0,
                        samples: Vec::with_capacity(LAT_RING),
                    });
                    a.requests += e.requests;
                    a.udp += e.udp;
                    a.tcp += e.tcp;
                    a.bytes += e.bytes;
                    a.ok += e.ok;
                    a.failed += e.failed;
                    a.timeouts += e.timeouts;
                    a.acl_denied += e.acl_denied;
                    a.rate_limited += e.rate_limited;
                    a.lat_sum_us += e.lat_sum_us;
                    a.lat_count += e.lat_count;
                    a.rps += e.rps;
                    a.samples.extend(e.samples());
                }
                by_mask
                    .into_iter()
                    .map(|(label, a)| ClientRow {
                        client: label,
                        count: a.requests,
                        requests: a.requests,
                        share: share_of(a.requests, recorded),
                        rps: round2(a.rps),
                        ok: a.ok,
                        failed: a.failed,
                        timeouts: a.timeouts,
                        rate_limited: a.rate_limited,
                        acl_denied: a.acl_denied,
                        avg_ms: avg_ms(a.lat_sum_us, a.lat_count),
                        p95_ms: percentile_ms(&a.samples),
                        bytes: a.bytes,
                        udp: a.udp,
                        tcp: a.tcp,
                    })
                    .collect()
            }
            ClientIpPrivacy::Off => Vec::new(),
        };
        sort_rows(&mut rows, sort);
        rows.truncate(limit.max(1));
        rows
    }

    pub fn top_domains(&self, limit: usize) -> Vec<(String, u64)> {
        self.domains
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .top(limit)
    }
}

fn row_from(client: String, e: &ClientEntry, recorded: u64) -> ClientRow {
    let samples = e.samples();
    ClientRow {
        count: e.requests,
        requests: e.requests,
        share: share_of(e.requests, recorded),
        rps: round2(e.rps),
        ok: e.ok,
        failed: e.failed,
        timeouts: e.timeouts,
        rate_limited: e.rate_limited,
        acl_denied: e.acl_denied,
        avg_ms: avg_ms(e.lat_sum_us, e.lat_count),
        p95_ms: percentile_ms(&samples),
        bytes: e.bytes,
        udp: e.udp,
        tcp: e.tcp,
        client,
    }
}

fn share_of(part: u64, total: u64) -> Option<f64> {
    if total == 0 {
        None
    } else {
        Some(part as f64 / total as f64)
    }
}

fn avg_ms(sum_us: u64, count: u64) -> Option<f64> {
    if count == 0 {
        None
    } else {
        Some(round2(sum_us as f64 / count as f64 / 1000.0))
    }
}

/// P95 of latency samples in microseconds → milliseconds (`None` if empty).
fn percentile_ms(samples: &[u32]) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let mut v = samples.to_vec();
    v.sort_unstable();
    let idx = ((95.0 * v.len() as f64).ceil() as usize).clamp(1, v.len()) - 1;
    Some(round2(v[idx] as f64 / 1000.0))
}

fn sort_rows(rows: &mut [ClientRow], sort: ClientSort) {
    rows.sort_by(|a, b| {
        let ord = match sort {
            ClientSort::Requests => b.requests.cmp(&a.requests),
            ClientSort::Bytes => b.bytes.cmp(&a.bytes),
            ClientSort::Failed => (b.failed + b.timeouts).cmp(&(a.failed + a.timeouts)),
            ClientSort::Timeouts => b.timeouts.cmp(&a.timeouts),
            ClientSort::Rps => b
                .rps
                .partial_cmp(&a.rps)
                .unwrap_or(std::cmp::Ordering::Equal),
            ClientSort::Latency => b
                .p95_ms
                .partial_cmp(&a.p95_ms)
                .unwrap_or(std::cmp::Ordering::Equal),
        };
        ord.then_with(|| a.client.cmp(&b.client))
    });
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self::new(4_096, 8_192)
    }
}

/// Lowercase name without the root dot, bounded to the protocol maximum.
fn normalize_name(name: &str) -> String {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() {
        // Root query: keep it as its own key instead of an empty string.
        return ".".to_string();
    }
    if n.len() > 253 {
        n[..253].to_string()
    } else {
        n
    }
}

/// Hide the host part of an address: IPv4 keeps the first octet
/// (`10.x.x.x`), IPv6 keeps the first 48 bits (`2001:db8:1::x`).
pub fn mask_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => format!("{}.x.x.x", a.octets()[0]),
        IpAddr::V6(a) => {
            let s = a.segments();
            if s[0] == 0 && s[1] == 0 && s[2] == 0 {
                "::x".to_string()
            } else {
                format!("{:x}:{:x}:{:x}::x", s[0], s[1], s[2])
            }
        }
    }
}

/// Address as it may be shown/logged for the configured privacy level;
/// `None` when client addresses must not be exposed at all.
pub fn client_display(ip: IpAddr, privacy: ClientIpPrivacy) -> Option<String> {
    match privacy {
        ClientIpPrivacy::Off => None,
        ClientIpPrivacy::Full => Some(ip.to_string()),
        ClientIpPrivacy::Masked => Some(mask_ip(ip)),
    }
}

/// `{"domain": "…", "count": n}` rows for the API.
pub fn domain_rows(rows: Vec<(String, u64)>) -> Vec<serde_json::Value> {
    rows.into_iter()
        .map(|(domain, count)| serde_json::json!({ "domain": domain, "count": count }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn ipv6(segments: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        ))
    }

    #[test]
    fn masks_ipv4_and_ipv6() {
        assert_eq!(mask_ip(ipv4(10, 1, 2, 3)), "10.x.x.x");
        assert_eq!(mask_ip(ipv4(192, 168, 0, 7)), "192.x.x.x");
        assert_eq!(
            mask_ip(ipv6([0x2001, 0xdb8, 1, 0, 0, 0, 0, 1])),
            "2001:db8:1::x"
        );
        assert_eq!(mask_ip(ipv6([0, 0, 0, 0, 0, 0, 0, 1])), "::x");
    }

    #[test]
    fn privacy_levels_control_exposure() {
        let ip = ipv4(10, 1, 2, 3);
        assert_eq!(
            client_display(ip, ClientIpPrivacy::Full).as_deref(),
            Some("10.1.2.3")
        );
        assert_eq!(
            client_display(ip, ClientIpPrivacy::Masked).as_deref(),
            Some("10.x.x.x")
        );
        assert_eq!(client_display(ip, ClientIpPrivacy::Off), None);
    }

    #[test]
    fn counts_and_ranks_keys() {
        let t = TrafficStats::new(16, 16);
        for _ in 0..5 {
            t.record_client(ipv4(10, 0, 0, 1));
        }
        t.record_client(ipv4(10, 0, 0, 2));
        t.record_domain("Example.COM.");
        t.record_domain("example.com");
        t.record_domain("other.test");

        let top = t.client_rows(10, ClientSort::Requests, ClientIpPrivacy::Masked);
        assert_eq!(
            top[0].client, "10.x.x.x",
            "masked aggregates both addresses"
        );
        assert_eq!(top[0].count, 6);
        assert_eq!(top[0].requests, 6);

        let doms = t.top_domains(10);
        assert_eq!(doms[0], ("example.com".to_string(), 2));
        assert_eq!(doms[1], ("other.test".to_string(), 1));
    }

    #[test]
    fn table_stays_bounded_and_reports_skips() {
        let t = TrafficStats::new(32, 8);
        for n in 0..10_000u32 {
            t.record_client(ipv4(10, 0, (n >> 8) as u8, n as u8));
        }
        let s = t.client_stats();
        assert!(s.tracked_keys <= 32, "tracked {}", s.tracked_keys);
        assert!(s.prunes > 0, "prunes must have run");
        assert!(s.skipped_requests > 0, "skips must be reported");
        // Every request is accounted for: nothing silently disappears.
        assert_eq!(s.recorded_requests, 10_000);
        assert!(s.recorded_requests >= s.tracked_keys as u64);
    }

    #[test]
    fn zero_cap_disables_tracking() {
        let t = TrafficStats::new(0, 0);
        for _ in 0..100 {
            t.record_client(ipv4(10, 0, 0, 1));
            t.record_domain("example.com");
        }
        let s = t.client_stats();
        assert_eq!(s.tracked_keys, 0);
        assert_eq!(s.recorded_requests, 0);
        assert!(t
            .client_rows(5, ClientSort::Requests, ClientIpPrivacy::Masked)
            .is_empty());
        assert!(t.top_domains(5).is_empty());
    }

    #[test]
    fn caps_can_grow_and_shrink() {
        let t = TrafficStats::new(4, 4);
        for n in 0..100u32 {
            t.record_client(ipv4(10, 0, 0, n as u8));
        }
        t.set_caps(1_000, 1_000);
        assert!(t.client_stats().cap == 1_000);
        t.set_caps(2, 2);
        assert!(t.client_stats().tracked_keys <= 2);
    }

    #[test]
    fn records_outcomes_latency_and_transport() {
        let t = TrafficStats::new(8, 8);
        let ip = ipv4(10, 0, 0, 1);
        t.record_request(ip, false, 40);
        t.record_request(ip, true, 30);
        t.record_outcome(ip, Outcome::Ok, Some(Duration::from_millis(5)));
        t.record_outcome(ip, Outcome::Timeout, Some(Duration::from_millis(1000)));
        t.record_outcome(ip, Outcome::RateLimited, None);

        let rows = t.client_rows(10, ClientSort::Requests, ClientIpPrivacy::Full);
        let r = &rows[0];
        assert_eq!(r.requests, 2);
        assert_eq!(r.udp, 1);
        assert_eq!(r.tcp, 1);
        assert_eq!(r.bytes, 70);
        assert_eq!(r.ok, 1);
        assert_eq!(r.timeouts, 1);
        assert_eq!(r.rate_limited, 1);
        assert_eq!(r.avg_ms, Some(502.5), "measured average");
        assert_eq!(r.p95_ms, Some(1000.0), "p95 of recent answers");
        // Both requests have an outcome → success ratio exists but the API
        // never invents one here: `share` is measured against recorded total.
        assert_eq!(r.share, Some(1.0));
    }

    #[test]
    fn unmeasured_values_stay_none() {
        let t = TrafficStats::new(8, 8);
        let ip = ipv4(10, 0, 0, 1);
        t.record_request(ip, false, 40);
        let r = &t.client_rows(1, ClientSort::Requests, ClientIpPrivacy::Full)[0];
        assert_eq!(r.avg_ms, None, "no answer measured yet");
        assert_eq!(r.p95_ms, None, "no answer measured yet");
        assert_eq!(r.rps, 0.0, "no rate sample yet");
        assert_eq!(r.ok, 0);
        assert_eq!(r.failed, 0);
    }

    #[test]
    fn sorts_by_requested_key() {
        let t = TrafficStats::new(16, 16);
        let a = ipv4(10, 0, 0, 1);
        let b = ipv4(10, 0, 0, 2);
        for _ in 0..3 {
            t.record_request(a, false, 10);
        }
        for _ in 0..5 {
            t.record_request(b, false, 1);
        }
        let rows = t.client_rows(10, ClientSort::Bytes, ClientIpPrivacy::Full);
        assert_eq!(rows[0].client, "10.0.0.1", "more bytes first");
        let rows = t.client_rows(10, ClientSort::Requests, ClientIpPrivacy::Full);
        assert_eq!(rows[0].client, "10.0.0.2", "more requests first");
    }

    #[test]
    fn rate_sampling_measures_requests_per_second() {
        let t = TrafficStats::new(8, 8);
        let ip = ipv4(10, 0, 0, 1);
        t.record_request(ip, false, 0);
        std::thread::sleep(Duration::from_millis(1100));
        t.record_request(ip, false, 0);
        t.record_request(ip, false, 0);
        t.sample_rates();
        let r = &t.client_rows(1, ClientSort::Requests, ClientIpPrivacy::Full)[0];
        // 3 requests over ~1.1s (+measurement time): a real measured rate.
        assert!(r.rps > 1.0 && r.rps < 4.0, "rps {}", r.rps);
        t.sample_rates();
        let r = &t.client_rows(1, ClientSort::Requests, ClientIpPrivacy::Full)[0];
        assert_eq!(r.rps, 0.0, "no new requests in the second window");
    }

    #[test]
    fn privacy_off_returns_no_rows_even_when_tracked() {
        let t = TrafficStats::new(8, 8);
        t.record_request(ipv4(10, 0, 0, 1), false, 10);
        assert!(t
            .client_rows(10, ClientSort::Requests, ClientIpPrivacy::Off)
            .is_empty());
    }
}
