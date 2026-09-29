//! Optional, bounded DNS response cache.
//!
//! Deliberately simple: FIFO eviction, strict TTL handling, hard entry cap.
//! Disabled by default — enable with `[cache] enabled = true`.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::config::CacheConfig;
use crate::dns::msg;

pub type CacheKey = (String, u16, u16);

#[derive(Debug)]
struct Entry {
    bytes: Vec<u8>,
    expires_at: Instant,
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
    /// to the requesting client's id.
    pub fn get(&self, key: &CacheKey, client_id: u16, cfg: &CacheConfig) -> Option<Vec<u8>> {
        if !cfg.enabled {
            return None;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let expired = {
            let e = inner.map.get(key)?;
            e.expires_at <= Instant::now()
        };
        if expired {
            inner.map.remove(key);
            return None;
        }
        let mut bytes = inner.map.get(key)?.bytes.clone();
        msg::set_transaction_id(&mut bytes, client_id);
        Some(bytes)
    }

    /// Store a response with the TTL derived from its records (already
    /// clamped by the caller through [`msg::cacheable_ttl`]).
    pub fn put(&self, key: CacheKey, response: Vec<u8>, ttl: Duration, cfg: &CacheConfig) {
        if !cfg.enabled || ttl.is_zero() || response.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        while inner.map.len() >= cfg.max_entries {
            match inner.order.pop_front() {
                Some(k) => {
                    inner.map.remove(&k);
                }
                None => break,
            }
        }
        inner.map.insert(
            key.clone(),
            Entry {
                bytes: response,
                expires_at: Instant::now() + ttl,
            },
        );
        inner.order.push_back(key);
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
        }
    }

    fn resp(id: u16) -> Vec<u8> {
        let mut v = vec![0u8; 20];
        v[0] = (id >> 8) as u8;
        v[1] = id as u8;
        v
    }

    fn key(name: &str) -> CacheKey {
        (name.to_string(), 1, 1)
    }

    #[test]
    fn hit_returns_response_with_client_id() {
        let c = DnsCache::new();
        let cfg = cfg(true, 10);
        c.put(key("a.example"), resp(1111), Duration::from_secs(60), &cfg);
        let got = c.get(&key("a.example"), 2222, &cfg).expect("hit");
        assert_eq!(u16::from_be_bytes([got[0], got[1]]), 2222);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn miss_when_absent_or_disabled() {
        let c = DnsCache::new();
        let on = cfg(true, 10);
        let off = cfg(false, 10);
        assert!(c.get(&key("x"), 1, &on).is_none());
        c.put(key("x"), resp(1), Duration::from_secs(60), &on);
        assert!(
            c.get(&key("x"), 1, &off).is_none(),
            "disabled cache never hits"
        );
        // Disabled cache never stores either.
        c.put(key("y"), resp(2), Duration::from_secs(60), &off);
        assert!(c.get(&key("y"), 1, &on).is_none());
    }

    #[test]
    fn respects_ttl_expiry() {
        let c = DnsCache::new();
        let cfg = cfg(true, 10);
        c.put(key("a"), resp(1), Duration::from_millis(30), &cfg);
        assert!(c.get(&key("a"), 1, &cfg).is_some());
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            c.get(&key("a"), 1, &cfg).is_none(),
            "expired entry must miss"
        );
        assert_eq!(c.len(), 0, "expired entry is removed");
    }

    #[test]
    fn zero_ttl_is_not_stored() {
        let c = DnsCache::new();
        let cfg = cfg(true, 10);
        c.put(key("a"), resp(1), Duration::ZERO, &cfg);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn bounded_capacity_evicts_oldest() {
        let c = DnsCache::new();
        let cfg = cfg(true, 3);
        for i in 0..10 {
            c.put(
                key(&format!("k{i}")),
                resp(i),
                Duration::from_secs(60),
                &cfg,
            );
        }
        assert_eq!(c.len(), 3);
        // The oldest keys are gone, the newest survive.
        assert!(c.get(&key("k0"), 1, &cfg).is_none());
        assert!(c.get(&key("k9"), 1, &cfg).is_some());
        assert!(c.get(&key("k7"), 1, &cfg).is_some());
    }

    #[test]
    fn distinct_keys_are_isolated() {
        let c = DnsCache::new();
        let cfg = cfg(true, 10);
        c.put(key("a"), resp(1), Duration::from_secs(60), &cfg);
        assert!(c.get(&key("b"), 1, &cfg).is_none());
        // Different qtype is a different key.
        let mut k = key("a");
        k.1 = 28;
        assert!(c.get(&k, 1, &cfg).is_none());
    }
}
