//! Optional, bounded DNS response cache.
//!
//! Deliberately simple: FIFO eviction, strict TTL handling, hard entry cap.
//! Cached responses serve *decremented* TTLs on every hit (RFC 1035), and
//! expired entries are removed lazily on lookup. Enabled by default —
//! disable with `[cache] enabled = false`.
//!
//! Also home to the cache-miss *single-flight* registry: concurrent queries
//! for the same question while a forward is already in flight coalesce onto
//! that one upstream query instead of each sending their own (thundering-herd
//! protection for hot names right after a cache miss / expiry).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::config::CacheConfig;
use crate::dns::msg::{self, Rcode};

/// Cache identity of a question: name, type, class, RD and the client's CD
/// bit. Responses may differ when recursion is not requested or Checking
/// Disabled is set, so neither may share an entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    pub cd: bool,
    pub rd: bool,
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

/// Approximate per-entry overhead beyond the raw DNS message bytes
/// (map entry, key string, TTL slot vec, Instant fields). Used only for the
/// `res_cache_memory_bytes` observability gauge — not a precise allocator
/// accounting.
const ENTRY_OVERHEAD_BYTES: usize = 128;

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
    /// Approximate total bytes of all stored responses + per-entry overhead.
    memory_bytes: usize,
}

impl Inner {
    fn account_insert(&mut self, bytes_len: usize) {
        self.memory_bytes = self
            .memory_bytes
            .saturating_add(bytes_len)
            .saturating_add(ENTRY_OVERHEAD_BYTES);
    }

    fn account_remove(&mut self, bytes_len: usize) {
        self.memory_bytes = self
            .memory_bytes
            .saturating_sub(bytes_len.saturating_add(ENTRY_OVERHEAD_BYTES));
    }
}

/// FIFO-evict until the cache fits `cap` bytes. Callers guarantee the entry
/// worth keeping is at the *back* of `order` (and that a single entry can
/// never exceed `cap` on insert), so the loop always terminates with the
/// newest data resident. Returns the number of entries evicted.
fn evict_to_byte_cap(inner: &mut Inner, cap: usize) -> u32 {
    let mut evicted = 0u32;
    while inner.memory_bytes > cap {
        match inner.order.pop_front() {
            Some(k) => {
                if let Some(e) = inner.map.remove(&k) {
                    inner.account_remove(e.bytes.len());
                    evicted += 1;
                }
            }
            None => break, // accounting only: no entries left to drop
        }
    }
    evicted
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
            if let Some(e) = inner.map.remove(key) {
                inner.account_remove(e.bytes.len());
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
        // A single response larger than the whole memory budget is never
        // stored (it could not be admitted without evicting everything,
        // including itself).
        if response.len() + ENTRY_OVERHEAD_BYTES > cfg.max_memory_bytes {
            return 0;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Refreshing an existing key updates it in place: no capacity
        // eviction, and the order entry is moved to the back (the key was
        // just re-validated, so it must not be the next eviction victim).
        let now = Instant::now();
        if let Some(e) = inner.map.get_mut(&key) {
            let old_len = e.bytes.len();
            e.bytes = response;
            e.ttl_slots = ttl_slots;
            e.stored_at = now;
            e.expires_at = now + ttl;
            e.rcode = rcode;
            let new_len = e.bytes.len();
            // NLL: `e` is no longer used after this point.
            inner.memory_bytes = inner
                .memory_bytes
                .saturating_sub(old_len.saturating_add(ENTRY_OVERHEAD_BYTES))
                .saturating_add(new_len)
                .saturating_add(ENTRY_OVERHEAD_BYTES);
            inner.order.retain(|x| x != &key);
            inner.order.push_back(key);
            let over = evict_to_byte_cap(&mut inner, cfg.max_memory_bytes);
            return over;
        }
        let mut evicted = 0u32;
        while inner.map.len() >= cfg.max_entries {
            match inner.order.pop_front() {
                Some(k) => {
                    if let Some(e) = inner.map.remove(&k) {
                        inner.account_remove(e.bytes.len());
                        evicted += 1;
                    }
                }
                None => break,
            }
        }
        inner.account_insert(response.len());
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
        // Byte budget: FIFO-evict until `max_memory_bytes` holds — the
        // just-inserted entry is safe (checked above) and sits at the back.
        evicted += evict_to_byte_cap(&mut inner, cfg.max_memory_bytes);
        evicted
    }

    /// Drop oldest entries until the cache fits `max_entries` **and**
    /// `max_memory_bytes`. Returns the number of entries removed. Called
    /// when a configuration swap shrinks either cap (disabling the cache is
    /// handled by `clear`).
    pub fn trim_to(&self, max_entries: usize, max_memory_bytes: usize) -> usize {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut removed = 0usize;
        while inner.map.len() > max_entries {
            match inner.order.pop_front() {
                Some(k) => {
                    if let Some(e) = inner.map.remove(&k) {
                        inner.account_remove(e.bytes.len());
                        removed += 1;
                    }
                }
                None => break,
            }
        }
        removed += evict_to_byte_cap(&mut inner, max_memory_bytes) as usize;
        removed
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .len()
    }

    /// Approximate total memory held by cached responses (observability only).
    pub fn memory_bytes(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .memory_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.map.clear();
        inner.order.clear();
        inner.memory_bytes = 0;
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Single-flight (cache-miss coalescing)
// ---------------------------------------------------------------------------

/// Shared result of one coalesced forward. Followers rewrite the leader's
/// embedded transaction ID and apply their own per-client UDP size limit
/// before serving.
#[derive(Clone)]
pub enum FlightOutcome {
    /// The leader's forward succeeded. `response` still carries the *leader's*
    /// transaction ID and is pre-UDP-limit; followers must call
    /// `msg::set_transaction_id` with their own client ID and run
    /// `enforce_client_udp_limit` for their own transport before replying.
    Success {
        response: Arc<Vec<u8>>,
        rcode: Rcode,
    },
    /// The leader exhausted its failover budget (all upstreams failed or the
    /// deadline hit). Followers receive the same terminal failure without
    /// re-attempting the forward — sharing the failure avoids a second
    /// thundering herd against dead upstreams. `reason` matches
    /// [`crate::failover::ForwardError::reason`] so followers can attribute
    /// metrics identically to the leader.
    Failed { reason: &'static str },
}

/// Registry of in-flight forwards keyed by cache identity. The first query
/// for a key becomes the *leader* and performs the forward; concurrent
/// queries for the same key become *followers* and wait for the leader's
/// outcome instead of duplicating the upstream query.
pub struct SingleFlight {
    inner: std::sync::Mutex<HashMap<CacheKey, watch::Sender<Option<FlightOutcome>>>>,
}

/// Role assigned to a query that just checked the single-flight registry.
pub enum FlightRole {
    /// This query is the leader: perform the forward, then call
    /// [`FlightLeader::complete`] (or drop to signal cancellation to
    /// followers, who will retry themselves).
    Leader(FlightLeader),
    /// Another query for the same key is already in flight; wait for its
    /// outcome before deciding whether to serve or retry.
    Follower(watch::Receiver<Option<FlightOutcome>>),
}

/// Leader handle: removes the map entry and notifies followers when dropped
/// (whether completed explicitly or cancelled), so followers never hang on a
/// dead leader.
pub struct FlightLeader {
    sf: Arc<SingleFlight>,
    key: CacheKey,
    tx: watch::Sender<Option<FlightOutcome>>,
    completed: bool,
}

impl FlightLeader {
    /// Publish the outcome to every follower and retire the flight. The
    /// leader should put any cacheable response into the cache *before*
    /// calling this so later (non-coalesced) queries can hit the cache.
    pub fn complete(mut self, outcome: FlightOutcome) {
        self.completed = true;
        self.retire(Some(outcome));
    }

    fn retire(&mut self, outcome: Option<FlightOutcome>) {
        let mut inner = self.sf.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.remove(&self.key);
        drop(inner);
        // Ignore send errors: all followers may have timed out and dropped.
        let _ = self.tx.send(outcome);
    }
}

impl Drop for FlightLeader {
    fn drop(&mut self) {
        if !self.completed {
            // Leader cancelled or panicked: publish `None` so followers know
            // to retry themselves instead of waiting forever.
            self.retire(None);
        }
    }
}

impl SingleFlight {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Join (or start) the flight for `key`. On `Leader`, the caller must
    /// forward the query and then call `complete` (or drop the handle).
    pub fn join(self: &Arc<Self>, key: &CacheKey) -> FlightRole {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = inner.get(key) {
            return FlightRole::Follower(tx.subscribe());
        }
        let (tx, _rx) = watch::channel(None);
        inner.insert(key.clone(), tx.clone());
        drop(inner);
        FlightRole::Leader(FlightLeader {
            sf: Arc::clone(self),
            key: key.clone(),
            tx,
            completed: false,
        })
    }

    /// Number of keys currently in flight (observability / tests).
    pub fn in_flight(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for SingleFlight {
    fn default() -> Self {
        // Note: `join` requires `Arc<Self>`, so this Default is only useful
        // for standalone tests; the pipeline holds an `Arc<SingleFlight>`.
        Self {
            inner: std::sync::Mutex::new(HashMap::new()),
        }
    }
}

/// Result of waiting on a single-flight leader.
pub enum FlightWait {
    /// The leader published an outcome (success or shared failure).
    Outcome(FlightOutcome),
    /// The wait budget elapsed before the leader published anything.
    Timeout,
    /// The leader was cancelled or panicked without publishing; no upstream
    /// query is in flight for this key anymore.
    Cancelled,
}

/// Wait for a leader's outcome, bounded by `budget`.
pub async fn wait_for_flight(
    mut rx: watch::Receiver<Option<FlightOutcome>>,
    budget: Duration,
) -> FlightWait {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        // `borrow_and_update` so a value published between `changed()` calls
        // is not missed on the next iteration.
        if let Some(outcome) = rx.borrow_and_update().clone() {
            return FlightWait::Outcome(outcome);
        }
        match tokio::time::timeout_at(deadline, rx.changed()).await {
            Ok(Ok(())) => continue,
            // Leader dropped without publishing: treat as cancelled.
            Ok(Err(_)) => return FlightWait::Cancelled,
            Err(_) => return FlightWait::Timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool, max: usize) -> CacheConfig {
        CacheConfig {
            enabled,
            max_entries: max,
            max_memory_bytes: 33_554_432,
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
            rd: true,
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

    #[test]
    fn memory_bytes_tracks_put_clear_and_trim() {
        let c = DnsCache::new();
        assert_eq!(c.memory_bytes(), 0);
        let cfg = cfg(true, 10);
        let r = resp(1);
        let len = r.len();
        c.put(key("a"), r, Duration::from_secs(60), Rcode::NoError, &cfg);
        let one = len + ENTRY_OVERHEAD_BYTES;
        assert_eq!(c.memory_bytes(), one);
        c.put(
            key("b"),
            resp(2),
            Duration::from_secs(60),
            Rcode::NoError,
            &cfg,
        );
        assert!(c.memory_bytes() > one);
        // Refresh updates accounting without double-counting.
        let before = c.memory_bytes();
        c.put(
            key("a"),
            resp(11),
            Duration::from_secs(60),
            Rcode::NoError,
            &cfg,
        );
        assert_eq!(c.memory_bytes(), before, "same-size refresh is neutral");
        // Clear resets to zero.
        c.clear();
        assert_eq!(c.memory_bytes(), 0);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn expired_entry_releases_memory() {
        let c = DnsCache::new();
        let cfg = cfg(true, 10);
        c.put(
            key("a"),
            resp(1),
            Duration::from_millis(20),
            Rcode::NoError,
            &cfg,
        );
        assert!(c.memory_bytes() > 0);
        std::thread::sleep(Duration::from_millis(40));
        assert!(matches!(c.get(&key("a"), 1, &cfg), CacheLookup::Expired));
        assert_eq!(c.memory_bytes(), 0, "expired entry must free its bytes");
    }

    #[test]
    fn trim_to_shrinks_to_max_entries() {
        let c = DnsCache::new();
        let cfg = cfg(true, 10);
        for i in 0..5 {
            c.put(
                key(&format!("k{i}")),
                resp(i),
                Duration::from_secs(60),
                Rcode::NoError,
                &cfg,
            );
        }
        assert_eq!(c.len(), 5);
        let removed = c.trim_to(2, 33_554_432);
        assert_eq!(removed, 3);
        assert_eq!(c.len(), 2);
        // Newest entries survive.
        assert!(matches!(
            c.get(&key("k4"), 1, &cfg),
            CacheLookup::Hit { .. }
        ));
        assert!(matches!(c.get(&key("k0"), 1, &cfg), CacheLookup::Miss));
        // Trim to a size already satisfied is a no-op.
        assert_eq!(c.trim_to(2, 33_554_432), 0);
    }

    /// `max_memory_bytes` bounds payload memory even when the entry count
    /// is far from `max_entries` (4096 × 64KiB would otherwise be ~256MiB).
    #[test]
    fn byte_cap_evicts_oldest_until_memory_fits() {
        let c = DnsCache::new();
        let mut cfg = cfg(true, 100);
        // Room for exactly two of these entries (1000 payload + 128 overhead).
        cfg.max_memory_bytes = 2 * (1000 + 128);
        for i in 0..5u16 {
            let mut v = vec![0u8; 1000];
            v[0] = (i >> 8) as u8;
            v[1] = i as u8;
            c.put(
                key(&format!("k{i}")),
                v,
                Duration::from_secs(60),
                Rcode::NoError,
                &cfg,
            );
        }
        assert!(
            c.memory_bytes() <= cfg.max_memory_bytes,
            "byte cap must hold: {} > {}",
            c.memory_bytes(),
            cfg.max_memory_bytes
        );
        assert!(c.len() <= 2, "oldest entries evicted, got {}", c.len());
        assert!(
            matches!(c.get(&key("k4"), 1, &cfg), CacheLookup::Hit { .. }),
            "newest survives"
        );
        assert!(matches!(c.get(&key("k0"), 1, &cfg), CacheLookup::Miss));

        // A single response that cannot fit the entire budget is refused.
        let mut tiny = cfg;
        tiny.max_memory_bytes = 500;
        c.put(
            key("big"),
            vec![0u8; 1000],
            Duration::from_secs(60),
            Rcode::NoError,
            &tiny,
        );
        assert!(matches!(c.get(&key("big"), 1, &tiny), CacheLookup::Miss));
    }

    // ---- single-flight ----

    #[tokio::test]
    async fn singleflight_leader_and_follower_share_outcome() {
        let sf = SingleFlight::new();
        let k = key("hot.example");

        let FlightRole::Leader(leader) = sf.join(&k) else {
            panic!("first join must be leader");
        };
        assert_eq!(sf.in_flight(), 1);

        let FlightRole::Follower(mut rx) = sf.join(&k) else {
            panic!("second join must be follower");
        };
        assert_eq!(sf.in_flight(), 1, "follower must not create a second entry");

        let outcome = FlightOutcome::Success {
            response: Arc::new(resp(42)),
            rcode: Rcode::NoError,
        };
        leader.complete(outcome.clone());

        // The follower observes the published outcome promptly.
        let got = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(o) = rx.borrow_and_update().clone() {
                    break o;
                }
                rx.changed().await.expect("leader still alive");
            }
        })
        .await
        .expect("follower must not hang");
        assert!(matches!(
            got,
            FlightOutcome::Success {
                rcode: Rcode::NoError,
                ..
            }
        ));
        assert_eq!(sf.in_flight(), 0, "flight retires after complete");
    }

    #[tokio::test]
    async fn singleflight_drop_wakes_follower_with_cancellation() {
        let sf = SingleFlight::new();
        let k = key("cancelled.example");

        let FlightRole::Leader(leader) = sf.join(&k) else {
            panic!("first join must be leader");
        };
        let FlightRole::Follower(rx) = sf.join(&k) else {
            panic!("second join must be follower");
        };

        // Dropping the leader without complete() must not leave the follower
        // hanging: wait_for_flight returns Cancelled.
        drop(leader);
        let wait = wait_for_flight(rx, Duration::from_secs(1)).await;
        assert!(matches!(wait, FlightWait::Cancelled));
        assert_eq!(sf.in_flight(), 0);
    }

    #[tokio::test]
    async fn singleflight_wait_times_out_when_leader_is_slow() {
        let sf = SingleFlight::new();
        let k = key("slow.example");

        let FlightRole::Leader(_leader) = sf.join(&k) else {
            panic!("first join must be leader");
        };
        let FlightRole::Follower(rx) = sf.join(&k) else {
            panic!("second join must be follower");
        };

        let wait = wait_for_flight(rx, Duration::from_millis(20)).await;
        assert!(matches!(wait, FlightWait::Timeout));
    }

    #[tokio::test]
    async fn singleflight_later_join_after_complete_becomes_new_leader() {
        let sf = SingleFlight::new();
        let k = key("sequel.example");

        let FlightRole::Leader(leader) = sf.join(&k) else {
            panic!("first join must be leader");
        };
        leader.complete(FlightOutcome::Failed { reason: "test" });

        // After the flight retires, the next join starts a fresh flight.
        let FlightRole::Leader(_again) = sf.join(&k) else {
            panic!("join after complete must be a new leader");
        };
        assert_eq!(sf.in_flight(), 1);
    }

    #[tokio::test]
    async fn singleflight_different_keys_are_independent() {
        let sf = SingleFlight::new();
        let FlightRole::Leader(_a) = sf.join(&key("a.example")) else {
            panic!("expected leader");
        };
        let FlightRole::Leader(_b) = sf.join(&key("b.example")) else {
            panic!("expected leader for distinct key");
        };
        assert_eq!(sf.in_flight(), 2);
    }
}
