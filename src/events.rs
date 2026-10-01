//! Bounded in-memory event logs.
//!
//! Everything an operator needs to answer "what happened?" — configuration
//! changes, health transitions and failover decisions — is recorded here in
//! fixed-capacity rings. No database, no unbounded growth: when a ring is
//! full the oldest event is dropped. Rings are only ever touched on rare
//! events (a config change, a health state change, a retried query), never in
//! the DNS hot path.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};

const CONFIG_RING_CAP: usize = 256;
const HEALTH_RING_CAP: usize = 512;
const FAILOVER_RING_CAP: usize = 512;
const SYSTEM_RING_CAP: usize = 512;

/// One recorded event.
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    /// Unix epoch milliseconds.
    pub ts_ms: u64,
    /// `"config"`, `"health"`, `"failover"` or `"system"` (set by the ring).
    pub kind: String,
    /// What happened: `create` / `update` / `delete` / `import` / `startup` …
    pub action: String,
    /// Upstream name, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_id: Option<i64>,
    /// Health: previous state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Health: new state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Why it happened: `timeout`, `network`, `servfail`, error text, …
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Failover: attempt count at the time of the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
    /// Failover: upstream the query moved to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback: Option<String>,
    /// Extra latency this failure added to the client query (ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_latency_ms: Option<u64>,
    /// System events: how many occurrences this event summarises (coalesced
    /// rate-limit / ACL / deadline events are never emitted one per query).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    /// System events: observation window the `count` spans, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_secs: Option<u64>,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub detail: Value,
}

impl Event {
    pub fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn base(action: &str) -> Self {
        Self {
            ts_ms: Self::now_ms(),
            kind: String::new(),
            action: action.to_string(),
            upstream: None,
            upstream_id: None,
            from: None,
            to: None,
            reason: None,
            attempts: None,
            fallback: None,
            extra_latency_ms: None,
            count: None,
            window_secs: None,
            detail: Value::Null,
        }
    }

    pub fn config(action: &str, detail: Value) -> Self {
        let mut e = Self::base(action);
        e.detail = detail;
        e
    }

    pub fn health(
        action: &str,
        upstream_id: i64,
        upstream: &str,
        from: Option<&str>,
        to: Option<&str>,
        reason: Option<String>,
        detail: Value,
    ) -> Self {
        let mut e = Self::base(action);
        e.upstream_id = Some(upstream_id);
        e.upstream = Some(upstream.to_string());
        e.from = from.map(str::to_string);
        e.to = to.map(str::to_string);
        e.reason = reason;
        e.detail = detail;
        e
    }

    pub fn failover(
        upstream: &str,
        reason: &str,
        attempts: u32,
        fallback: &str,
        extra_latency_ms: u64,
    ) -> Self {
        let mut e = Self::base("retry");
        e.upstream = Some(upstream.to_string());
        e.reason = Some(reason.to_string());
        e.attempts = Some(attempts);
        e.fallback = Some(fallback.to_string());
        e.extra_latency_ms = Some(extra_latency_ms);
        e
    }

    /// A system-level event (emergency, sampled admission-control activity).
    pub fn system(action: &str, detail: Value) -> Self {
        let mut e = Self::base(action);
        e.detail = detail;
        e
    }
}

/// Fixed-capacity FIFO event ring (oldest events are dropped).
pub struct EventLog {
    kind: &'static str,
    cap: usize,
    inner: Mutex<VecDeque<Event>>,
}

impl EventLog {
    pub fn new(kind: &'static str, capacity: usize) -> Self {
        Self {
            kind,
            cap: capacity.max(1),
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(64))),
        }
    }

    pub fn push(&self, mut event: Event) {
        event.kind = self.kind.to_string();
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back(event);
    }

    /// Most recent events first, at most `limit`.
    pub fn recent(&self, limit: usize) -> Vec<Event> {
        let q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().rev().take(limit).cloned().collect()
    }

    /// Most recent events for one upstream (by id), newest first.
    pub fn recent_for_upstream(&self, id: i64, limit: usize) -> Vec<Event> {
        let q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.iter()
            .rev()
            .filter(|e| e.upstream_id == Some(id))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

/// The four event rings owned by [`crate::shared::Shared`].
pub struct EventLogs {
    pub config: EventLog,
    pub health: EventLog,
    pub failover: EventLog,
    /// Emergencies (all upstreams down / recovered) and coalesced
    /// rate-limit / ACL / deadline activity.
    pub system: EventLog,
}

impl EventLogs {
    pub fn new() -> Self {
        Self {
            config: EventLog::new("config", CONFIG_RING_CAP),
            health: EventLog::new("health", HEALTH_RING_CAP),
            failover: EventLog::new("failover", FAILOVER_RING_CAP),
            system: EventLog::new("system", SYSTEM_RING_CAP),
        }
    }

    /// Bounded overview for the diagnostics endpoint.
    pub fn counts(&self) -> Value {
        json!({
            "config": self.config.len(),
            "health": self.health.len(),
            "failover": self.failover.len(),
            "system": self.system.len(),
        })
    }
}

impl Default for EventLogs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_is_bounded_and_drops_oldest() {
        let log = EventLog::new("config", 3);
        for i in 0..5 {
            let mut e = Event::config("update", json!({ "i": i }));
            e.detail = json!({ "i": i });
            log.push(e);
        }
        assert_eq!(log.len(), 3);
        let recent = log.recent(10);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].detail["i"], 4, "newest first");
        assert_eq!(recent[2].detail["i"], 2);
    }

    #[test]
    fn kind_is_set_by_the_ring() {
        let log = EventLog::new("health", 4);
        log.push(Event::health(
            "transition",
            7,
            "cf",
            Some("up"),
            Some("down"),
            None,
            json!({}),
        ));
        let e = log.recent(1).pop().unwrap();
        assert_eq!(e.kind, "health");
        assert_eq!(e.upstream_id, Some(7));
        assert_eq!(e.from.as_deref(), Some("up"));
        assert_eq!(e.to.as_deref(), Some("down"));
    }

    #[test]
    fn system_ring_records_emergencies_with_counts() {
        let logs = EventLogs::new();
        let mut e = Event::system(
            "rate_limited",
            json!({ "client_ip": "10.0.0.9", "transport": "udp" }),
        );
        e.count = Some(17);
        e.window_secs = Some(30);
        logs.system.push(e);
        let e = logs.system.recent(1).pop().unwrap();
        assert_eq!(e.kind, "system");
        assert_eq!(e.count, Some(17));
        assert_eq!(e.window_secs, Some(30));
        assert_eq!(logs.counts()["system"], 1);
    }

    #[test]
    fn filters_by_upstream() {
        let logs = EventLogs::new();
        logs.health.push(Event::health(
            "transition",
            1,
            "a",
            None,
            Some("down"),
            None,
            json!({}),
        ));
        logs.health.push(Event::health(
            "transition",
            2,
            "b",
            None,
            Some("down"),
            None,
            json!({}),
        ));
        let for_one = logs.health.recent_for_upstream(1, 10);
        assert_eq!(for_one.len(), 1);
        assert_eq!(for_one[0].upstream.as_deref(), Some("a"));
    }
}
