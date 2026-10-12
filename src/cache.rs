//! Optional, bounded DNS response cache.
//!
//! Deliberately simple: FIFO eviction, strict TTL handling, hard entry cap.
//! Cached responses serve *decremented* TTLs on every hit (RFC 1035), and
//! expired entries are removed lazily on lookup. Enabled by default —
//! disable with `[cache] enabled = false`.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::config::CacheConfig;
use crate::dns::msg::{self, Rcode};

/// Cache identity of a question: name, type, class and the client's CD bit
/// (responses may differ when Checking Disabled is set).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    pub cd: bool,
}

#[derive(Debug)]
struct Entry {
    bytes: Vec<u8>,
    /// (byte offset, original TTL) for every record; rewritten on each hit.
    ttl_slots: Vec<(usize, u32)>,
    stored_at: Instant,
    expires_at: Instant,
    rcode: Rcode,
}

/// Result of a cache lookup (the caller owns the metric accounting).
pub enum CacheLookup {
    Hit {
        bytes: Vec<u8>,
        rcode: Rcode,
    },
    Miss,
    /// The entry existed but its TTL ran out; it has been removed.
    Expired,
}

#[derive(Debug, Default)]
struct Inner {
    map: HashMap<CacheKey, Entry>,
    order: VecDeque<CacheKey>,
}

/// Bounded TTL cache. All operations are short critical sections: no lock is
/// ever held across I/O.
pub struct DnsCache {
    inner: std::sync::Mutex<Inner>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(Inner::default()),
        }
    }

    /// Look up a response. Returns a copy with the transaction id rewritten
    /// to the requesting client's id and every record TTL decremented by the
    /// time the entry spent in the cache.
    pub fn get(&self, key: &CacheKey, client_id: u16, cfg: &CacheConfig) -> CacheLookup {
        if !cfg.enabled {
            return CacheLookup::Miss;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let expired = {
            let Some(e) = inner.map.get(key) else {
                return CacheLookup::Miss;
            };
            e.expires_at <= Instant::now()
        };
        if expired {
            if inner.map.remove(key).is_some() {
                inner.order.retain(|x| x != key);
            }
            return CacheLookup::Expired;
        }
        let Some(entry) = inner.map.get(key) else {
            return CacheLookup::Miss;
        };
        let elapsed = entry.stored_at.elapsed().as_secs();
        let mut bytes = entry.bytes.clone();
        for (off, ttl) in &entry.ttl_slots {
            let v = ttl.saturating_sub(elapsed as u32);
            bytes[*off..*off + 4].copy_from_slice(&v.to_be_bytes());
        }
        msg::set_transaction_id(&mut bytes, client_id);
        // Invariant: entry expiry equals the original minimum TTL, so
        // `elapsed` never exceeds it and no served TTL goes below zero.
        CacheLookup::Hit {
            bytes,
            rcode: entry.rcode,
        }
    }

    /// Store a response. `ttl` is the cache lifetime derived by the caller
    /// (`msg::cacheable_ttl` / `msg::negative_ttl`); `rcode` is the response
    /// code served to clients for this entry. Returns the number of capacity
    /// evictions performed.
    pub fn put(
        &self,
        key: CacheKey,
        response: Vec<u8>,
        ttl: Duration,
        rcode: Rcode,
        cfg: &CacheConfig,
    ) -> u32 {
        if !cfg.enabled || ttl.is_zero() || response.is_empty() {
            return 0;
        }
        let Some(ttl_slots) = msg::collect_ttl_slots(&response) else {
            return 0;
        };
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Refreshing an existing key updates it in place: no capacity
        // eviction, and the order entry is moved to the back (the key was
        // just re-validated, so it must not be the next eviction victim).
        let now = Instant::now();
        if let Some(e) = inner.map.get_mut(&key) {
            e.bytes = response;
            e.ttl_slots = ttl_slots;
            e.stored_at = now;
            e.expires_at = now + ttl;
            e.rcode = rcode;
            inner.order.retain(|x| x != &key);
            inner.order.push_back(key);
            return 0;
        }
        let mut evicted = 0u32;
        while inner.map.len() >= cfg.max_entries {
            match inner.order.pop_front() {
                Some(k) => {
                    inner.map.remove(&k);
                    evicted += 1;
                }
                None => break,
            }
        }
        inner.map.insert(
            key.clone(),
            Entry {
                bytes: response,
                ttl_slots,
                stored_at: now,
                expires_at: now + ttl,
                rcode,
            },
        );
        inner.order.push_back(key);
        evicted
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.map.clear();
        inner.order.clear();
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool, max: usize) -> CacheConfig {
        CacheConfig {
            enabled,
            max_entries: max,
            min_ttl_secs: 0,
            max_ttl_secs: 3600,
            negative_max_ttl_secs: 30,
        }
    }

    fn resp(id: u16) -> Vec<u8> {
        let mut v = vec![0u8; 20];
        v[0] = (id >> 8) as u8;
        v[1] = id as u8;
        v
    }

    fn key(name: &str) -> CacheKey {
        CacheKey {
            name: name.to_string(),
            qtype: 1,
            qclass: 1,
            cd: false,
        }
    }

    fn hit(l: CacheLookup) -> Vec<u8> {
        match l {
            CacheLookup::Hit { bytes, .. } => bytes,
            _ => panic!("expected hit"),
        }
    }

    #[test]
    fn hit_returns_response_with_client_id() {
        let c = DnsCache::new();
        let cfg = cfg(true, 10);
        c.put(
            key("a.example"),
            resp(1111),
            Duration::from_secs(60),
            Rcode::NoError,
            &cfg,
        );
        let got = hit(c.get(&key("a.example"), 2222, &cfg));
        assert_eq!(u16::from_be_bytes([got[0], got[1]]), 2222);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn miss_when_absent_or_disabled() {
        let c = DnsCache::new();
        let on = cfg(true, 10);
        let off = cfg(false, 10);
        assert!(matches!(c.get(&key("x"), 1, &on), CacheLookup::Miss));
        c.put(
            key("x"),
            resp(1),
            Duration::from_secs(60),
            Rcode::NoError,
            &on,
        );
        assert!(
            matches!(c.get(&key("x"), 1, &off), CacheLookup::Miss),
            "disabled cache never hits"
        );
        // Disabled cache never stores either.
        c.put(
            key("y"),
            resp(2),
            Duration::from_secs(60),
            Rcode::NoError,
            &off,
        );
        assert!(matches!(c.get(&key("y"), 1, &on), CacheLookup::Miss));
    }

    #[test]
    fn respects_ttl_expiry() {
        let c = DnsCache::new();
        let cfg = cfg(true, 10);
        c.put(
            key("a"),
            resp(1),
            Duration::from_millis(30),
            Rcode::NoError,
            &cfg,
        );
        assert!(matches!(c.get(&key("a"), 1, &cfg), CacheLookup::Hit { .. }));
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            matches!(c.get(&key("a"), 1, &cfg), CacheLookup::Expired),
            "expired entry must report Expired"
        );
        assert_eq!(c.len(), 0, "expired entry is removed");
    }

    #[test]
    fn zero_ttl_is_not_stored() {
        let c = DnsCache::new();
        let cfg = cfg(true, 10);
        c.put(key("a"), resp(1), Duration::ZERO, Rcode::NoError, &cfg);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn bounded_capacity_evicts_oldest() {
        let c = DnsCache::new();
        let cfg = cfg(true, 3);
        for i in 0..10 {
            let n = c.put(
                key(&format!("k{i}")),
                resp(i),
                Duration::from_secs(60),
                Rcode::NoError,
                &cfg,
            );
            if i >= 3 {
                assert_eq!(n, 1, "each insert beyond capacity evicts one");
            }
        }
        assert_eq!(c.len(), 3);
        // The oldest keys are gone, the newest survive.
        assert!(matches!(c.get(&key("k0"), 1, &cfg), CacheLookup::Miss));
        assert!(matches!(
            c.get(&key("k9"), 1, &cfg),
            CacheLookup::Hit { .. }
        ));
        assert!(matches!(
            c.get(&key("k7"), 1, &cfg),
            CacheLookup::Hit { .. }
        ));
    }

    #[test]
    fn reinserting_key_does_not_duplicate_order() {
        // Regression: put() used to push a second order entry for the same
        // key, so the next capacity eviction dropped a key that had just been
        // refreshed (and its neighbour) while the map kept a stale entry.
        let c = DnsCache::new();
        let cfg = cfg(true, 2);
        c.put(
            key("hot"),
            resp(1),
            Duration::from_secs(60),
            Rcode::NoError,
            &cfg,
        );
        c.put(
            key("other"),
            resp(2),
            Duration::from_secs(60),
            Rcode::NoError,
            &cfg,
        );
        // Refresh "hot" several times: capacity is full, but the refreshed
        // key must never be the one evicted.
        for i in 0..5 {
            c.put(
                key("hot"),
                resp(10 + i),
                Duration::from_secs(60),
                Rcode::NoError,
                &cfg,
            );
        }
        assert_eq!(c.len(), 2);
        assert!(matches!(
            c.get(&key("hot"), 9, &cfg),
            CacheLookup::Hit { .. }
        ));
        assert!(matches!(
            c.get(&key("other"), 9, &cfg),
            CacheLookup::Hit { .. }
        ));
    }

    #[test]
    fn distinct_keys_are_isolated() {
        let c = DnsCache::new();
        let cfg = cfg(true, 10);
        c.put(
            key("a"),
            resp(1),
            Duration::from_secs(60),
            Rcode::NoError,
            &cfg,
        );
        assert!(matches!(c.get(&key("b"), 1, &cfg), CacheLookup::Miss));
        // Different qtype is a different key.
        let mut k = key("a");
        k.qtype = 28;
        assert!(matches!(c.get(&k, 1, &cfg), CacheLookup::Miss));
        // CD bit is part of the key.
        let mut k = key("a");
        k.cd = true;
        assert!(matches!(c.get(&k, 1, &cfg), CacheLookup::Miss));
    }

    #[test]
    fn hit_reports_stored_rcode() {
        let c = DnsCache::new();
        let cfg = cfg(true, 10);
        c.put(
            key("nx"),
            resp(1),
            Duration::from_secs(30),
            Rcode::NXDomain,
            &cfg,
        );
        match c.get(&key("nx"), 5, &cfg) {
            CacheLookup::Hit { rcode, .. } => assert_eq!(rcode, Rcode::NXDomain),
            _ => panic!("expected hit"),
        }
    }
}
