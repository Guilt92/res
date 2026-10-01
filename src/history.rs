//! Multi-resolution in-memory time series for the dashboard.
//!
//! Once per second the runtime sampler takes a cheap snapshot of the
//! Prometheus registry (counters, gauges, histogram buckets), converts it to
//! deltas, and folds it into three fixed-capacity rings:
//!
//! | ring | resolution | capacity | covers  |
//! |------|------------|----------|---------|
//! | r1   | 1 s        | 900      | 15 min  |
//! | r2   | 10 s       | 2 160    | 6 h     |
//! | r3   | 60 s       | 10 080   | 7 d     |
//!
//! Coarser rings are rolled up from finer ones (counters summed, latency
//! histograms merged — percentiles stay exact for the merged window, gauges
//! averaged). Reads downsample to at most [`MAX_POINTS`] points per series so
//! every range answers with a bounded payload.
//!
//! Everything here is derived from **real metrics** — there is no synthetic
//! or demo data anywhere in the series.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::metrics::{Metrics, DURATION_BUCKETS, LATENCY_BUCKETS, RCODES};

/// Maximum points returned per series after downsampling.
const MAX_POINTS: usize = 300;
/// Ring capacities (seconds of coverage at each resolution).
const R1_CAP: usize = 900; // 1 s   × 900   = 15 min
const R2_CAP: usize = 2160; // 10 s  × 2160  = 6 h
const R3_CAP: usize = 10080; // 60 s  × 10080 = 7 d
/// Latency histogram length: one cumulative count per bucket + `+Inf`.
const HIST_LEN: usize = DURATION_BUCKETS.len() + 1;
/// Per-upstream latency histograms use [`LATENCY_BUCKETS`] + `+Inf`.
const UP_HIST_LEN: usize = LATENCY_BUCKETS.len() + 1;

// ---------------------------------------------------------------------------
// Snapshot (one gather() of the registry)
// ---------------------------------------------------------------------------

/// Absolute counter / gauge / histogram values at one point in time.
#[derive(Debug, Default)]
struct Snap {
    ts_ms: u64,
    queries: u64,
    /// Per-rcode responses, aligned with [`RCODES`].
    rcode: [u64; 7],
    deadline: u64,
    no_upstreams: u64,
    upstream_failure: u64,
    notimp_errors: u64,
    timeouts: u64,
    failovers: u64,
    rate_limited: u64,
    acl_denied: u64,
    overload: u64,
    malformed: u64,
    hits: u64,
    misses: u64,
    tcp_accepted: u64,
    tcp_rejected: u64,
    packets_in: u64,
    packets_out: u64,
    request_bytes: u64,
    response_bytes: u64,
    // Gauges (absolute).
    inflight: f64,
    tcp_open: f64,
    rss: f64,
    cpu: f64,
    fds: f64,
    healthy: f64,
    degraded: f64,
    down: f64,
    cache_entries: f64,
    // Histograms (cumulative bucket counts incl. +Inf).
    global_hist: Vec<u64>,
    upstreams: HashMap<String, UpSnap>,
}

#[derive(Debug, Default)]
struct UpSnap {
    queries: u64,
    timeouts: u64,
    failovers: u64,
    state: f64,
    hist: Vec<u64>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn label_of<'a>(m: &'a prometheus::proto::Metric, key: &str) -> Option<&'a str> {
    m.get_label()
        .iter()
        .find(|l| l.name() == key)
        .map(|l| l.value())
}

fn counter_value(m: &prometheus::proto::Metric) -> u64 {
    m.get_counter().value() as u64
}

fn gauge_value(m: &prometheus::proto::Metric) -> f64 {
    m.get_gauge().value()
}

/// Cumulative histogram bucket counts including an implied `+Inf` final
/// element (`sample_count`). Returns an empty vector when the metric has no
/// samples yet.
fn hist_counts(h: &prometheus::proto::Histogram) -> Vec<u64> {
    let mut v: Vec<u64> = h
        .get_bucket()
        .iter()
        .map(|b| b.cumulative_count())
        .collect();
    // The crate emits buckets only up to the last finite upper bound; the
    // total (the +Inf bucket) is `sample_count`.
    let total = h.get_sample_count();
    if !v.is_empty() && total <= *v.last().unwrap() {
        // Defensive: never emit a non-monotonic cumulative series.
        v.push(*v.last().unwrap());
    } else {
        v.push(total);
    }
    v
}

fn find<'a>(
    fams: &'a [prometheus::proto::MetricFamily],
    name: &str,
) -> Option<&'a prometheus::proto::MetricFamily> {
    fams.iter().find(|f| f.name() == name)
}

fn sum_counters(fams: &[prometheus::proto::MetricFamily], name: &str) -> u64 {
    find(fams, name)
        .map(|f| f.get_metric().iter().map(counter_value).sum())
        .unwrap_or(0)
}

fn counter_by_label(
    fams: &[prometheus::proto::MetricFamily],
    name: &str,
    key: &str,
    val: &str,
) -> u64 {
    find(fams, name)
        .map(|f| {
            f.get_metric()
                .iter()
                .filter(|m| label_of(m, key) == Some(val))
                .map(counter_value)
                .sum()
        })
        .unwrap_or(0)
}

fn gauge(fams: &[prometheus::proto::MetricFamily], name: &str) -> f64 {
    find(fams, name)
        .and_then(|f| f.get_metric().first())
        .map(gauge_value)
        .unwrap_or(0.0)
}

fn histogram(fams: &[prometheus::proto::MetricFamily], name: &str) -> Vec<u64> {
    find(fams, name)
        .and_then(|f| f.get_metric().first())
        .and_then(|m| m.get_histogram().as_ref())
        .map(hist_counts)
        .unwrap_or_else(|| vec![0; HIST_LEN])
}

fn take_snapshot(metrics: &Metrics) -> Snap {
    let fams = metrics.registry.gather();
    let mut snap = Snap {
        ts_ms: now_ms(),
        queries: sum_counters(&fams, "res_queries_total"),
        deadline: counter_by_label(&fams, "res_query_errors_total", "reason", "deadline"),
        no_upstreams: counter_by_label(&fams, "res_query_errors_total", "reason", "no_upstreams"),
        upstream_failure: counter_by_label(
            &fams,
            "res_query_errors_total",
            "reason",
            "upstream_failure",
        ),
        notimp_errors: counter_by_label(&fams, "res_query_errors_total", "reason", "notimp"),
        timeouts: sum_counters(&fams, "res_upstream_timeouts_total"),
        failovers: sum_counters(&fams, "res_failovers_total"),
        rate_limited: sum_counters(&fams, "res_rate_limit_dropped_total"),
        acl_denied: sum_counters(&fams, "res_acl_denied_total"),
        overload: sum_counters(&fams, "res_overload_dropped_total"),
        malformed: sum_counters(&fams, "res_malformed_packets_total"),
        hits: sum_counters(&fams, "res_cache_hits_total"),
        misses: sum_counters(&fams, "res_cache_misses_total"),
        tcp_accepted: sum_counters(&fams, "res_tcp_connections_total"),
        tcp_rejected: sum_counters(&fams, "res_tcp_connections_rejected_total"),
        packets_in: sum_counters(&fams, "res_udp_packets_received_total"),
        packets_out: sum_counters(&fams, "res_udp_packets_sent_total"),
        request_bytes: sum_counters(&fams, "res_request_bytes_total"),
        response_bytes: sum_counters(&fams, "res_response_bytes_total"),
        inflight: gauge(&fams, "res_udp_inflight"),
        tcp_open: gauge(&fams, "res_tcp_connections"),
        rss: gauge(&fams, "res_resident_memory_bytes"),
        cpu: gauge(&fams, "res_cpu_percent"),
        fds: gauge(&fams, "res_open_fds"),
        // Seeded to 0 and then derived from `res_upstream_state` below so
        // it is never double-counted against the `res_healthy_upstreams`
        // gauge (which reports the same healthy count).
        healthy: 0.0,
        cache_entries: gauge(&fams, "res_cache_entries"),
        global_hist: histogram(&fams, "res_query_duration_seconds"),
        ..Default::default()
    };
    if snap.global_hist.len() != HIST_LEN {
        snap.global_hist.resize(HIST_LEN, 0);
    }

    for (i, rcode) in RCODES.iter().enumerate() {
        snap.rcode[i] = counter_by_label(&fams, "res_response_rcode_total", "rcode", rcode);
    }

    // Per-upstream state gauges (0=DOWN, 1=DEGRADED, 2=UP).
    if let Some(f) = find(&fams, "res_upstream_state") {
        for m in f.get_metric() {
            if let Some(name) = label_of(m, "upstream") {
                let entry = snap.upstreams.entry(name.to_string()).or_default();
                entry.state = gauge_value(m);
                match entry.state as i64 {
                    2 => snap.healthy += 1.0,
                    1 => snap.degraded += 1.0,
                    _ => snap.down += 1.0,
                }
            }
        }
    } else {
        // No state series at all: fall back to the summary gauge (no double
        // count risk — the increment loop above never ran).
        snap.healthy = gauge(&fams, "res_healthy_upstreams");
    }
    // Per-upstream counters + latency histograms.
    if let Some(f) = find(&fams, "res_upstream_queries_total") {
        for m in f.get_metric() {
            if let Some(name) = label_of(m, "upstream") {
                snap.upstreams.entry(name.to_string()).or_default().queries = counter_value(m);
            }
        }
    }
    if let Some(f) = find(&fams, "res_upstream_timeouts_total") {
        for m in f.get_metric() {
            if let Some(name) = label_of(m, "upstream") {
                snap.upstreams.entry(name.to_string()).or_default().timeouts = counter_value(m);
            }
        }
    }
    if let Some(f) = find(&fams, "res_upstream_failovers_total") {
        for m in f.get_metric() {
            if let Some(name) = label_of(m, "upstream") {
                snap.upstreams
                    .entry(name.to_string())
                    .or_default()
                    .failovers = counter_value(m);
            }
        }
    }
    if let Some(f) = find(&fams, "res_upstream_latency_seconds") {
        for m in f.get_metric() {
            if let Some(name) = label_of(m, "upstream") {
                if let Some(h) = m.get_histogram().as_ref() {
                    let mut counts = hist_counts(h);
                    // Never pad *after* the total: that would push the
                    // `+Inf` count off the end and zero the denominator.
                    counts.resize(UP_HIST_LEN, 0);
                    snap.upstreams.entry(name.to_string()).or_default().hist = counts;
                }
            }
        }
    }
    for up in snap.upstreams.values_mut() {
        if up.hist.len() != UP_HIST_LEN {
            up.hist.resize(UP_HIST_LEN, 0);
        }
    }
    snap
}

// ---------------------------------------------------------------------------
// Buckets
// ---------------------------------------------------------------------------

/// One global bucket: counter deltas over `secs` + last-seen gauge values.
#[derive(Debug, Clone)]
struct GBucket {
    ts_ms: u64,
    secs: f64,
    queries: u64,
    /// Upstream *attempts* (sum of per-upstream query counters). A client
    /// query can trigger several attempts, so attempt-level counts (timeouts)
    /// must be divided by this — not by `queries` — to stay within 0..=100%.
    attempts: u64,
    rcode: [u64; 7],
    deadline: u64,
    no_upstreams: u64,
    upstream_failure: u64,
    notimp_errors: u64,
    timeouts: u64,
    failovers: u64,
    rate_limited: u64,
    acl_denied: u64,
    overload: u64,
    malformed: u64,
    hits: u64,
    misses: u64,
    tcp_accepted: u64,
    tcp_rejected: u64,
    packets_in: u64,
    packets_out: u64,
    request_bytes: u64,
    response_bytes: u64,
    hist: Vec<u64>,
    inflight: f64,
    tcp_open: f64,
    rss: f64,
    cpu: f64,
    fds: f64,
    healthy: f64,
    degraded: f64,
    down: f64,
    cache_entries: f64,
}

impl GBucket {
    fn new(ts_ms: u64) -> Self {
        Self {
            ts_ms,
            secs: 0.0,
            queries: 0,
            attempts: 0,
            rcode: [0; 7],
            deadline: 0,
            no_upstreams: 0,
            upstream_failure: 0,
            notimp_errors: 0,
            timeouts: 0,
            failovers: 0,
            rate_limited: 0,
            acl_denied: 0,
            overload: 0,
            malformed: 0,
            hits: 0,
            misses: 0,
            tcp_accepted: 0,
            tcp_rejected: 0,
            packets_in: 0,
            packets_out: 0,
            request_bytes: 0,
            response_bytes: 0,
            hist: vec![0; HIST_LEN],
            inflight: 0.0,
            tcp_open: 0.0,
            rss: 0.0,
            cpu: 0.0,
            fds: 0.0,
            healthy: 0.0,
            degraded: 0.0,
            down: 0.0,
            cache_entries: 0.0,
        }
    }

    /// Absorb `b` (used both for rollup and downsampling).
    fn merge(&mut self, b: &GBucket) {
        self.secs += b.secs;
        self.queries += b.queries;
        self.attempts += b.attempts;
        for i in 0..7 {
            self.rcode[i] += b.rcode[i];
        }
        for (field, other) in [
            (&mut self.deadline, b.deadline),
            (&mut self.no_upstreams, b.no_upstreams),
            (&mut self.upstream_failure, b.upstream_failure),
            (&mut self.notimp_errors, b.notimp_errors),
            (&mut self.timeouts, b.timeouts),
            (&mut self.failovers, b.failovers),
            (&mut self.rate_limited, b.rate_limited),
            (&mut self.acl_denied, b.acl_denied),
            (&mut self.overload, b.overload),
            (&mut self.malformed, b.malformed),
            (&mut self.hits, b.hits),
            (&mut self.misses, b.misses),
            (&mut self.tcp_accepted, b.tcp_accepted),
            (&mut self.tcp_rejected, b.tcp_rejected),
            (&mut self.packets_in, b.packets_in),
            (&mut self.packets_out, b.packets_out),
            (&mut self.request_bytes, b.request_bytes),
            (&mut self.response_bytes, b.response_bytes),
        ] {
            *field += other;
        }
        for i in 0..HIST_LEN {
            self.hist[i] += b.hist[i];
        }
        // Gauges: the later bucket wins (b is always the newer one in rollup;
        // for downsampling this keeps the window-end value, which reads best
        // for "current"-flavoured gauges).
        self.inflight = b.inflight;
        self.tcp_open = b.tcp_open;
        self.rss = b.rss;
        self.cpu = b.cpu;
        self.fds = b.fds;
        self.healthy = b.healthy;
        self.degraded = b.degraded;
        self.down = b.down;
        self.cache_entries = b.cache_entries;
    }

    fn reset(&mut self, ts_ms: u64) {
        let gauges = (
            self.inflight,
            self.tcp_open,
            self.rss,
            self.cpu,
            self.fds,
            self.healthy,
            self.degraded,
            self.down,
            self.cache_entries,
        );
        *self = GBucket::new(ts_ms);
        (
            self.inflight,
            self.tcp_open,
            self.rss,
            self.cpu,
            self.fds,
            self.healthy,
            self.degraded,
            self.down,
            self.cache_entries,
        ) = gauges;
    }
}

/// One per-upstream bucket.
#[derive(Debug, Clone)]
struct UBucket {
    ts_ms: u64,
    secs: f64,
    queries: u64,
    timeouts: u64,
    failovers: u64,
    hist: Vec<u64>,
    state: f64,
}

impl UBucket {
    fn new(ts_ms: u64) -> Self {
        Self {
            ts_ms,
            secs: 0.0,
            queries: 0,
            timeouts: 0,
            failovers: 0,
            hist: vec![0; UP_HIST_LEN],
            state: 2.0,
        }
    }

    fn merge(&mut self, b: &UBucket) {
        self.secs += b.secs;
        self.queries += b.queries;
        self.timeouts += b.timeouts;
        self.failovers += b.failovers;
        for i in 0..UP_HIST_LEN {
            self.hist[i] += b.hist[i];
        }
        self.state = b.state;
    }

    fn reset(&mut self, ts_ms: u64) {
        let state = self.state;
        *self = UBucket::new(ts_ms);
        self.state = state;
    }
}

fn sub_hist(out: &mut [u64], now: &[u64], prev: &[u64]) {
    for (i, o) in out.iter_mut().enumerate() {
        *o = now
            .get(i)
            .copied()
            .unwrap_or(0)
            .saturating_sub(prev.get(i).copied().unwrap_or(0));
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

struct Inner {
    prev: Option<Snap>,
    cur_key: u64,
    cur: GBucket,
    up_cur: HashMap<String, UBucket>,
    acc10: GBucket,
    acc60: GBucket,
    up_acc10: HashMap<String, UBucket>,
    up_acc60: HashMap<String, UBucket>,
    r1: VecDeque<GBucket>,
    r2: VecDeque<GBucket>,
    r3: VecDeque<GBucket>,
    up_r1: HashMap<String, VecDeque<UBucket>>,
    up_r2: HashMap<String, VecDeque<UBucket>>,
    up_r3: HashMap<String, VecDeque<UBucket>>,
}

impl Inner {
    fn new() -> Self {
        let key = now_ms() / 1000 * 1000;
        Self {
            prev: None,
            cur_key: key,
            cur: GBucket::new(key),
            up_cur: HashMap::new(),
            acc10: GBucket::new(key),
            acc60: GBucket::new(key),
            up_acc10: HashMap::new(),
            up_acc60: HashMap::new(),
            r1: VecDeque::with_capacity(R1_CAP),
            r2: VecDeque::with_capacity(R2_CAP),
            r3: VecDeque::with_capacity(R3_CAP),
            up_r1: HashMap::new(),
            up_r2: HashMap::new(),
            up_r3: HashMap::new(),
        }
    }
}

/// Multi-resolution time-series store (see module docs).
pub struct HistoryStore {
    inner: Mutex<Inner>,
}

impl HistoryStore {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            inner: Mutex::new(Inner::new()),
        })
    }

    /// Record one per-second sample. Called from the runtime sampler only.
    pub fn record(&self, metrics: &Metrics) {
        let snap = take_snapshot(metrics);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let key = snap.ts_ms / 1000 * 1000;

        let Some(prev) = inner.prev.take() else {
            // First sample: establish the counter baseline, publish gauges.
            inner.cur_key = key;
            inner.cur = GBucket::new(key);
            apply_gauges(&mut inner.cur, &snap);
            for (name, up) in &snap.upstreams {
                let mut b = UBucket::new(key);
                b.state = up.state;
                inner.up_cur.insert(name.clone(), b);
            }
            inner.prev = Some(snap);
            return;
        };

        let dt = snap.ts_ms.saturating_sub(prev.ts_ms).max(1) as f64 / 1000.0;

        // New wall-clock second: close the open bucket and roll it up.
        if key != inner.cur_key {
            let closed = std::mem::replace(&mut inner.cur, GBucket::new(key));
            if closed.secs > 0.0 {
                Self::roll_g(&mut inner, &closed);
            }
            inner.cur_key = key;

            // Close every per-upstream bucket (including upstreams that just
            // disappeared) and roll them up.
            let closed_ups = std::mem::take(&mut inner.up_cur);
            for (name, b) in &closed_ups {
                if b.secs > 0.0 {
                    Self::roll_u(&mut inner, name, b);
                }
            }
            for name in snap.upstreams.keys() {
                inner.up_cur.insert(name.clone(), UBucket::new(key));
            }
        }

        // Counter / histogram deltas since the previous sample.
        let c = &mut inner.cur;
        c.secs += dt;
        c.queries += snap.queries.saturating_sub(prev.queries);
        for i in 0..7 {
            c.rcode[i] += snap.rcode[i].saturating_sub(prev.rcode[i]);
        }
        c.deadline += snap.deadline.saturating_sub(prev.deadline);
        c.no_upstreams += snap.no_upstreams.saturating_sub(prev.no_upstreams);
        c.upstream_failure += snap.upstream_failure.saturating_sub(prev.upstream_failure);
        c.notimp_errors += snap.notimp_errors.saturating_sub(prev.notimp_errors);
        c.timeouts += snap.timeouts.saturating_sub(prev.timeouts);
        c.failovers += snap.failovers.saturating_sub(prev.failovers);
        c.rate_limited += snap.rate_limited.saturating_sub(prev.rate_limited);
        c.acl_denied += snap.acl_denied.saturating_sub(prev.acl_denied);
        c.overload += snap.overload.saturating_sub(prev.overload);
        c.malformed += snap.malformed.saturating_sub(prev.malformed);
        c.hits += snap.hits.saturating_sub(prev.hits);
        c.misses += snap.misses.saturating_sub(prev.misses);
        c.tcp_accepted += snap.tcp_accepted.saturating_sub(prev.tcp_accepted);
        c.tcp_rejected += snap.tcp_rejected.saturating_sub(prev.tcp_rejected);
        c.packets_in += snap.packets_in.saturating_sub(prev.packets_in);
        c.packets_out += snap.packets_out.saturating_sub(prev.packets_out);
        c.request_bytes += snap.request_bytes.saturating_sub(prev.request_bytes);
        c.response_bytes += snap.response_bytes.saturating_sub(prev.response_bytes);
        sub_hist(&mut c.hist, &snap.global_hist, &prev.global_hist);
        apply_gauges(c, &snap);

        let mut attempts = 0u64;
        for (name, up) in &snap.upstreams {
            let b = inner
                .up_cur
                .entry(name.clone())
                .or_insert_with(|| UBucket::new(key));
            b.secs += dt;
            let p = prev.upstreams.get(name);
            let pq = p.map(|u| u.queries).unwrap_or(0);
            let pt = p.map(|u| u.timeouts).unwrap_or(0);
            let pf = p.map(|u| u.failovers).unwrap_or(0);
            let dq = up.queries.saturating_sub(pq);
            attempts += dq;
            b.queries += dq;
            b.timeouts += up.timeouts.saturating_sub(pt);
            b.failovers += up.failovers.saturating_sub(pf);
            if let Some(p) = p {
                sub_hist(&mut b.hist, &up.hist, &p.hist);
            }
            b.state = up.state;
        }
        inner.cur.attempts += attempts;

        inner.prev = Some(snap);
    }

    /// Close a completed 1 s bucket and roll it into the 10 s / 60 s
    /// accumulators (which are flushed when their windows complete).
    fn roll_g(inner: &mut Inner, closed: &GBucket) {
        let push = |q: &mut VecDeque<GBucket>, cap: usize, b: &GBucket| {
            while q.len() >= cap {
                q.pop_front();
            }
            q.push_back(b.clone());
        };
        push(&mut inner.r1, R1_CAP, closed);

        if inner.acc10.secs == 0.0 {
            inner.acc10.ts_ms = closed.ts_ms;
        }
        inner.acc10.merge(closed);
        if inner.acc10.secs >= 10.0 {
            let done = inner.acc10.clone();
            push(&mut inner.r2, R2_CAP, &done);
            inner.acc10.reset(done.ts_ms);
        }

        if inner.acc60.secs == 0.0 {
            inner.acc60.ts_ms = closed.ts_ms;
        }
        inner.acc60.merge(closed);
        if inner.acc60.secs >= 60.0 {
            let done = inner.acc60.clone();
            push(&mut inner.r3, R3_CAP, &done);
            inner.acc60.reset(done.ts_ms);
        }
    }

    fn roll_u(inner: &mut Inner, name: &str, closed: &UBucket) {
        macro_rules! push {
            ($map:expr, $cap:expr, $b:expr) => {{
                let q = $map
                    .entry(name.to_string())
                    .or_insert_with(|| VecDeque::new());
                while q.len() >= $cap {
                    q.pop_front();
                }
                q.push_back($b.clone());
            }};
        }
        push!(inner.up_r1, R1_CAP, closed);

        let acc = inner
            .up_acc10
            .entry(name.to_string())
            .or_insert_with(|| UBucket::new(closed.ts_ms));
        let start10 = if acc.secs == 0.0 {
            closed.ts_ms
        } else {
            acc.ts_ms
        };
        acc.merge(closed);
        acc.ts_ms = start10;
        if acc.secs >= 10.0 {
            let done = acc.clone();
            push!(inner.up_r2, R2_CAP, &done);
            acc.reset(done.ts_ms);
        }

        let acc = inner
            .up_acc60
            .entry(name.to_string())
            .or_insert_with(|| UBucket::new(closed.ts_ms));
        let start60 = if acc.secs == 0.0 {
            closed.ts_ms
        } else {
            acc.ts_ms
        };
        acc.merge(closed);
        acc.ts_ms = start60;
        if acc.secs >= 60.0 {
            let done = acc.clone();
            push!(inner.up_r3, R3_CAP, &done);
            acc.reset(done.ts_ms);
        }
    }

    /// Query a time range. Returns the normalized dashboard payload with
    /// `source = "native"`. `range` is one of `5m 15m 1h 6h 24h 7d`.
    pub fn query(&self, range: &str) -> Result<Value, String> {
        let secs = range_secs(range)?;
        let now = now_ms();
        let start = now.saturating_sub(secs * 1000);

        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Pick the finest ring that still covers the whole range.
        let (source, all): (&str, Vec<GBucket>) = if secs <= 900 {
            (
                "1s",
                inner
                    .r1
                    .iter()
                    .filter(|b| b.ts_ms + (b.secs * 1000.0) as u64 > start)
                    .cloned()
                    .collect(),
            )
        } else if secs <= 21600 {
            (
                "10s",
                inner
                    .r2
                    .iter()
                    .filter(|b| b.ts_ms + (b.secs * 1000.0) as u64 > start)
                    .cloned()
                    .collect(),
            )
        } else {
            (
                "60s",
                inner
                    .r3
                    .iter()
                    .filter(|b| b.ts_ms + (b.secs * 1000.0) as u64 > start)
                    .cloned()
                    .collect(),
            )
        };

        let up_names: Vec<String> = {
            let mut n: Vec<String> = inner.up_r1.keys().cloned().collect();
            n.extend(inner.up_r2.keys().cloned());
            n.extend(inner.up_r3.keys().cloned());
            n.sort();
            n.dedup();
            n
        };

        let in_window = |b: &UBucket| b.ts_ms + (b.secs * 1000.0) as u64 > start;
        let pick = |r1: Option<&VecDeque<UBucket>>,
                    r2: Option<&VecDeque<UBucket>>,
                    r3: Option<&VecDeque<UBucket>>|
         -> Vec<UBucket> {
            let candidates: [Option<&VecDeque<UBucket>>; 3] = [r1, r2, r3];
            // Order: finest ring that covers the requested range first, then
            // coarser fallbacks (older coverage may live in a higher tier).
            let order: [usize; 3] = if secs <= 900 {
                [0, 1, 2]
            } else if secs <= 21600 {
                [1, 0, 2]
            } else {
                [2, 1, 0]
            };
            for i in order {
                if let Some(r) = candidates[i] {
                    let v: Vec<UBucket> = r.iter().filter(|b| in_window(b)).cloned().collect();
                    if !v.is_empty() {
                        return v;
                    }
                }
            }
            Vec::new()
        };
        let ups: HashMap<String, Vec<UBucket>> = up_names
            .iter()
            .map(|n| {
                let v = pick(inner.up_r1.get(n), inner.up_r2.get(n), inner.up_r3.get(n));
                (n.clone(), v)
            })
            .collect();

        // Open (in-progress) buckets are intentionally excluded: a partially
        // filled 1 s bucket would show a misleading dip.
        drop(inner);

        let merged = downsample_g(all, MAX_POINTS);
        let ts: Vec<u64> = merged.iter().map(|b| b.ts_ms).collect();
        let series = global_series(&merged, &ts);

        let mut upstreams = json!({});
        for (name, buckets) in ups {
            if buckets.is_empty() {
                continue;
            }
            let m = downsample_u(buckets, MAX_POINTS);
            let uts: Vec<u64> = m.iter().map(|b| b.ts_ms).collect();
            upstreams[name] = up_series(&m, &uts);
        }

        let step = if merged.is_empty() {
            1
        } else {
            (merged.iter().map(|b| b.secs).sum::<f64>() / merged.len().max(1) as f64)
                .round()
                .max(1.0) as u64
        };

        Ok(json!({
            "source": "native",
            "range": range,
            "start_ms": start,
            "end_ms": now,
            "step_seconds": step,
            "bucket_source": source,
            "points": merged.len(),
            "generated_ms": now,
            "series": series,
            "upstreams": upstreams,
        }))
    }
}

impl Default for HistoryStore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner::new()),
        }
    }
}

fn apply_gauges(b: &mut GBucket, snap: &Snap) {
    b.inflight = snap.inflight;
    b.tcp_open = snap.tcp_open;
    b.rss = snap.rss;
    b.cpu = snap.cpu;
    b.fds = snap.fds;
    b.healthy = snap.healthy;
    b.degraded = snap.degraded;
    b.down = snap.down;
    b.cache_entries = snap.cache_entries;
}

pub fn range_secs(range: &str) -> Result<u64, String> {
    let (n, unit): (&str, char) = range
        .strip_suffix('s')
        .map(|n| (n, 's'))
        .or_else(|| range.strip_suffix('m').map(|n| (n, 'm')))
        .or_else(|| range.strip_suffix('h').map(|n| (n, 'h')))
        .or_else(|| range.strip_suffix('d').map(|n| (n, 'd')))
        .ok_or_else(|| format!("invalid range '{range}' (expected 5m|15m|1h|6h|24h|7d)"))?;
    let n: u64 = n
        .parse()
        .map_err(|_| format!("invalid range '{range}' (expected 5m|15m|1h|6h|24h|7d)"))?;
    let mult = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        _ => 86400,
    };
    let secs = n * mult;
    if !(60..=7 * 86400).contains(&secs) {
        return Err(format!("range '{range}' out of bounds (1m..7d)"));
    }
    Ok(secs)
}

/// Merge buckets so at most `max` remain (counters/histograms summed,
/// gauges taken from the newest bucket of each group).
fn downsample_g(buckets: Vec<GBucket>, max: usize) -> Vec<GBucket> {
    if buckets.len() <= max {
        return buckets;
    }
    let group = buckets.len().div_ceil(max);
    let mut out = Vec::with_capacity(buckets.len() / group + 1);
    let mut it = buckets.into_iter();
    while let Some(mut first) = it.next() {
        let mut n = 1;
        while n < group {
            match it.next() {
                Some(b) => {
                    first.merge(&b);
                    n += 1;
                }
                None => break,
            }
        }
        out.push(first);
    }
    out
}

fn downsample_u(buckets: Vec<UBucket>, max: usize) -> Vec<UBucket> {
    if buckets.len() <= max {
        return buckets;
    }
    let group = buckets.len().div_ceil(max);
    let mut out = Vec::with_capacity(buckets.len() / group + 1);
    let mut it = buckets.into_iter();
    while let Some(mut first) = it.next() {
        let mut n = 1;
        while n < group {
            match it.next() {
                Some(b) => {
                    first.merge(&b);
                    n += 1;
                }
                None => break,
            }
        }
        out.push(first);
    }
    out
}

// ---------------------------------------------------------------------------
// Series derivation
// ---------------------------------------------------------------------------

/// Linear-interpolated percentile (ms) from cumulative bucket counts.
///
/// `bounds` are the finite upper bounds of the histogram the counts came from
/// (`DURATION_BUCKETS` for client query duration, `LATENCY_BUCKETS` for
/// per-upstream latency) — they must line up with `cum[..bounds.len()]`.
fn percentile_ms(cum: &[u64], p: f64, bounds: &[f64]) -> Option<f64> {
    let total = *cum.last().unwrap_or(&0);
    if total == 0 || cum.len() < 2 || bounds.is_empty() {
        return None;
    }
    let n = (cum.len() - 1).min(bounds.len());
    let target = (p * total as f64).ceil().max(1.0) as u64;
    for i in 0..n {
        if cum[i] >= target {
            let upper = bounds[i] * 1000.0;
            let lower = if i == 0 { 0.0 } else { bounds[i - 1] * 1000.0 };
            let prev = if i == 0 { 0 } else { cum[i - 1] };
            let frac = if cum[i] > prev {
                (target.saturating_sub(prev)) as f64 / (cum[i] - prev) as f64
            } else {
                0.5
            };
            return Some(lower + (upper - lower) * frac.clamp(0.0, 1.0));
        }
    }
    // Everything above the last finite bound: report the bound itself.
    Some(bounds[n - 1] * 1000.0)
}

/// `num / den` as a plain fraction; `None` while nothing has been measured
/// (an unmeasured average must never read as `0`).
fn ratio(num: u64, den: u64) -> Option<f64> {
    if den == 0 {
        None
    } else {
        Some(num as f64 / den as f64)
    }
}

fn ratio_pct(num: u64, den: u64) -> Option<f64> {
    if den == 0 {
        None
    } else {
        Some(100.0 * num as f64 / den as f64)
    }
}

/// Like [`ratio_pct`] but clamped to `<= 100%`.
///
/// Counters incremented at different moments of an attempt (`queries` at
/// attempt start, `timeouts`/`deadline` at attempt end) can straddle a bucket
/// boundary, so a single 1 s bucket may observe more completions than starts.
/// A percentage above 100 is meaningless on a dashboard: clamp it.
fn ratio_pct_capped(num: u64, den: u64) -> Option<f64> {
    ratio_pct(num.min(den), den)
}

fn responses(b: &GBucket) -> u64 {
    b.rcode.iter().sum()
}

fn global_series(buckets: &[GBucket], ts: &[u64]) -> Value {
    let mut series: Vec<(&str, Vec<Option<f64>>)> = vec![
        ("qps", Vec::with_capacity(buckets.len())),
        ("success_pct", Vec::with_capacity(buckets.len())),
        ("error_pct", Vec::with_capacity(buckets.len())),
        ("servfail_pct", Vec::with_capacity(buckets.len())),
        ("deadline_pct", Vec::with_capacity(buckets.len())),
        ("timeout_pct", Vec::with_capacity(buckets.len())),
        ("failover_per_min", Vec::with_capacity(buckets.len())),
        ("rate_limited_per_min", Vec::with_capacity(buckets.len())),
        ("acl_denied_per_min", Vec::with_capacity(buckets.len())),
        ("overload_per_min", Vec::with_capacity(buckets.len())),
        ("malformed_per_min", Vec::with_capacity(buckets.len())),
        ("cache_hit_pct", Vec::with_capacity(buckets.len())),
        ("p50_ms", Vec::with_capacity(buckets.len())),
        ("p95_ms", Vec::with_capacity(buckets.len())),
        ("p99_ms", Vec::with_capacity(buckets.len())),
        ("inflight", Vec::with_capacity(buckets.len())),
        ("tcp_open", Vec::with_capacity(buckets.len())),
        ("rss_mb", Vec::with_capacity(buckets.len())),
        ("cpu_pct", Vec::with_capacity(buckets.len())),
        ("fds", Vec::with_capacity(buckets.len())),
        ("healthy", Vec::with_capacity(buckets.len())),
        ("degraded", Vec::with_capacity(buckets.len())),
        ("down", Vec::with_capacity(buckets.len())),
        ("cache_entries", Vec::with_capacity(buckets.len())),
        ("tcp_conn_per_min", Vec::with_capacity(buckets.len())),
        ("queries", Vec::with_capacity(buckets.len())),
        ("packets_in", Vec::with_capacity(buckets.len())),
        ("packets_out", Vec::with_capacity(buckets.len())),
        ("avg_req_bytes", Vec::with_capacity(buckets.len())),
        ("avg_resp_bytes", Vec::with_capacity(buckets.len())),
        ("nxdomain_pct", Vec::with_capacity(buckets.len())),
        ("refused_pct", Vec::with_capacity(buckets.len())),
    ];

    for b in buckets {
        let w = b.secs.max(f64::MIN_POSITIVE);
        let resp = responses(b);
        let success = b.rcode[0] + b.rcode[3]; // NOERROR + NXDOMAIN
        let servfail = b.rcode[2];
        // Attempt-level ratios divide by attempts; fall back to `queries`
        // for buckets recorded before attempts were tracked (or when every
        // query hit cache and never reached an upstream).
        let attempt_den = if b.attempts > 0 {
            b.attempts
        } else {
            b.queries
        };
        let vals: [Option<f64>; 32] = [
            Some(b.queries as f64 / w),
            ratio_pct(success, resp),
            ratio_pct(resp.saturating_sub(success), resp),
            ratio_pct(servfail, resp),
            ratio_pct_capped(b.deadline, b.queries),
            ratio_pct_capped(b.timeouts, attempt_den),
            Some(b.failovers as f64 / w * 60.0),
            Some(b.rate_limited as f64 / w * 60.0),
            Some(b.acl_denied as f64 / w * 60.0),
            Some(b.overload as f64 / w * 60.0),
            Some(b.malformed as f64 / w * 60.0),
            ratio_pct(b.hits, b.hits + b.misses),
            percentile_ms(&b.hist, 0.50, DURATION_BUCKETS),
            percentile_ms(&b.hist, 0.95, DURATION_BUCKETS),
            percentile_ms(&b.hist, 0.99, DURATION_BUCKETS),
            Some(b.inflight),
            Some(b.tcp_open),
            Some(b.rss / 1_048_576.0),
            Some(b.cpu),
            Some(b.fds),
            Some(b.healthy),
            Some(b.degraded),
            Some(b.down),
            Some(b.cache_entries),
            Some(b.tcp_accepted as f64 / w * 60.0),
            Some(b.queries as f64),
            Some(b.packets_in as f64 / w),
            Some(b.packets_out as f64 / w),
            ratio(b.request_bytes, b.queries),
            ratio(b.response_bytes, resp),
            ratio_pct(b.rcode[3], resp),
            ratio_pct(b.rcode[5], resp),
        ];
        for (i, (_, v)) in series.iter_mut().enumerate() {
            v.push(vals[i]);
        }
    }

    // RCODES index: 0 NOERROR, 1 FORMERR, 2 SERVFAIL, 3 NXDOMAIN, 4 NOTIMP,
    // 5 REFUSED, 6 OTHER — `success = [0]+[3]`, `servfail = [2]` above.
    let mut out = serde_json::Map::new();
    for (name, vals) in series {
        out.insert(name.to_string(), points(ts, &vals));
    }
    Value::Object(out)
}

fn up_series(buckets: &[UBucket], ts: &[u64]) -> Value {
    let names = [
        "qps",
        "p50_ms",
        "p95_ms",
        "timeout_pct",
        "failover_per_min",
        "state",
    ];
    let mut cols: Vec<Vec<Option<f64>>> = vec![Vec::with_capacity(buckets.len()); names.len()];
    for b in buckets {
        let w = b.secs.max(f64::MIN_POSITIVE);
        let vals: [Option<f64>; 6] = [
            Some(b.queries as f64 / w),
            percentile_ms(&b.hist, 0.50, LATENCY_BUCKETS),
            percentile_ms(&b.hist, 0.95, LATENCY_BUCKETS),
            ratio_pct_capped(b.timeouts, b.queries),
            Some(b.failovers as f64 / w * 60.0),
            Some(b.state),
        ];
        for (i, col) in cols.iter_mut().enumerate() {
            col.push(vals[i]);
        }
    }
    let mut out = serde_json::Map::new();
    for (i, name) in names.iter().enumerate() {
        out.insert(name.to_string(), points(ts, &cols[i]));
    }
    Value::Object(out)
}

/// `[t, v]` pairs with JSON nulls for undefined rates.
fn points(ts: &[u64], vals: &[Option<f64>]) -> Value {
    let mut arr = Vec::with_capacity(ts.len());
    for (t, v) in ts.iter().zip(vals) {
        let v = match v {
            Some(v) if v.is_finite() => json!(round2(*v)),
            _ => Value::Null,
        };
        arr.push(json!([t, v]));
    }
    Value::Array(arr)
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_parsing() {
        assert_eq!(range_secs("5m").unwrap(), 300);
        assert_eq!(range_secs("15m").unwrap(), 900);
        assert_eq!(range_secs("1h").unwrap(), 3600);
        assert_eq!(range_secs("6h").unwrap(), 21600);
        assert_eq!(range_secs("24h").unwrap(), 86400);
        assert_eq!(range_secs("7d").unwrap(), 604800);
        assert!(range_secs("bogus").is_err());
        assert!(range_secs("0m").is_err());
        assert!(range_secs("30d").is_err());
    }

    #[test]
    fn percentile_interpolates_within_bounds() {
        // 10 samples: 5 below 10ms, 5 below 25ms.
        let mut cum = vec![0u64; HIST_LEN];
        // bucket bounds: 0.5,1,2.5,5,10,25,...
        cum[4] = 5; // <=10ms
        cum[5] = 10; // <=25ms
        for c in cum.iter_mut().skip(6) {
            *c = 10;
        }
        let p50 = percentile_ms(&cum, 0.5, DURATION_BUCKETS).unwrap();
        assert!(p50 > 5.0 && p50 <= 10.0, "p50={p50}");
        let p99 = percentile_ms(&cum, 0.99, DURATION_BUCKETS).unwrap();
        assert!(p99 > 10.0 && p99 <= 25.0, "p99={p99}");
        assert!(percentile_ms(&[0; HIST_LEN], 0.5, DURATION_BUCKETS).is_none());
    }

    #[test]
    fn upstream_percentile_uses_latency_buckets() {
        // LATENCY_BUCKETS: 1ms,2ms,5ms,10ms,... — a p50 sitting in the 2ms
        // bucket must interpolate within 1..=2ms, never within the *client*
        // duration buckets (0.5,1,2.5,...) which would be wrong here.
        let mut cum = vec![0u64; UP_HIST_LEN];
        cum[1] = 10; // <=2ms
        for c in cum.iter_mut().skip(2) {
            *c = 20;
        }
        let p50 = percentile_ms(&cum, 0.5, LATENCY_BUCKETS).unwrap();
        assert!(
            (1.0..=2.0).contains(&p50),
            "p50 should fall in the 1..=2ms latency bucket, got {p50}"
        );
        assert!(percentile_ms(&cum, 0.5, DURATION_BUCKETS).unwrap() != p50);
    }

    #[test]
    fn healthy_is_not_double_counted() {
        let m = Metrics::new();
        let h = HistoryStore::new();
        m.upstream_state.with_label_values(&["a"]).set(2);
        m.upstream_state.with_label_values(&["b"]).set(2);
        m.healthy_upstreams.set(2);
        h.record(&m); // baseline
        std::thread::sleep(std::time::Duration::from_millis(1100));
        h.record(&m); // opens a bucket carrying the gauges
        std::thread::sleep(std::time::Duration::from_millis(1100));
        h.record(&m); // closes it

        let q = h.query("5m").unwrap();
        let max_healthy = q["series"]["healthy"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p[1].as_f64())
            .fold(0.0f64, f64::max);
        assert_eq!(max_healthy, 2.0, "healthy must equal the real count");
    }

    #[test]
    fn timeout_pct_never_exceeds_100() {
        let m = Metrics::new();
        let h = HistoryStore::new();
        m.upstream_state.with_label_values(&["a"]).set(2);
        h.record(&m); // counter baseline (all zeros)
                      // 10 client queries, 15 upstream attempts (retries), 15 timeouts.
        m.queries_total.with_label_values(&["udp"]).inc_by(10);
        m.upstream_queries_total
            .with_label_values(&["a"])
            .inc_by(15);
        m.upstream_timeouts_total
            .with_label_values(&["a"])
            .inc_by(15);
        h.record(&m);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        h.record(&m);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        h.record(&m);

        let q = h.query("5m").unwrap();
        let pct = q["series"]["timeout_pct"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p[1].as_f64())
            .fold(0.0f64, f64::max);
        assert!(
            pct > 99.0 && pct <= 100.0,
            "timeout_pct must be attempt-based and <=100, got {pct}"
        );
    }

    #[test]
    fn records_real_counter_deltas_into_series() {
        let m = Metrics::new();
        let h = HistoryStore::new();
        h.record(&m);
        // Second sample after some traffic.
        m.queries_total.with_label_values(&["udp"]).inc_by(100);
        m.client_rcode_total
            .with_label_values(&["NOERROR"])
            .inc_by(95);
        m.client_rcode_total
            .with_label_values(&["SERVFAIL"])
            .inc_by(5);
        for _ in 0..100 {
            m.query_duration.observe(0.02);
        }
        std::thread::sleep(std::time::Duration::from_millis(1100));
        h.record(&m);
        // Third sample to close the 1s bucket (bucket closes on key change).
        std::thread::sleep(std::time::Duration::from_millis(1100));
        h.record(&m);

        let q = h.query("5m").unwrap();
        assert_eq!(q["source"], "native");
        let qps = q["series"]["qps"].as_array().unwrap();
        assert!(!qps.is_empty());
        // The series carries rates (queries/second), not raw counts: the
        // single recorded bucket must show ~100q over its ~1.1s window.
        let peak = qps
            .iter()
            .filter_map(|p| p[1].as_f64())
            .fold(0.0f64, f64::max);
        assert!(
            (50.0..=200.0).contains(&peak),
            "expected ~90 qps, got {peak}"
        );
        let p95 = q["series"]["p95_ms"].as_array().unwrap();
        assert!(
            p95.iter().any(|p| p[1].as_f64().is_some()),
            "p95 from real histogram"
        );
    }

    #[test]
    fn records_per_upstream_series() {
        let m = Metrics::new();
        let h = HistoryStore::new();
        m.upstream_state.with_label_values(&["a"]).set(2);
        m.upstream_queries_total
            .with_label_values(&["a"])
            .inc_by(10);
        h.record(&m);

        m.upstream_queries_total
            .with_label_values(&["a"])
            .inc_by(50);
        m.upstream_timeouts_total
            .with_label_values(&["a"])
            .inc_by(5);
        m.upstream_failovers_total
            .with_label_values(&["a"])
            .inc_by(2);
        for _ in 0..20 {
            m.upstream_latency.with_label_values(&["a"]).observe(0.03);
        }
        std::thread::sleep(std::time::Duration::from_millis(1100));
        h.record(&m);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        h.record(&m);

        let q = h.query("5m").unwrap();
        let a = q["upstreams"]["a"].clone();
        let peak_qps = a["qps"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p[1].as_f64())
            .fold(0.0f64, f64::max);
        assert!(
            (20.0..=100.0).contains(&peak_qps),
            "per-upstream qps peak, got {peak_qps}"
        );
        let p50 = a["p50_ms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p[1].as_f64().is_some());
        assert!(p50, "per-upstream p50 from real histogram");
        let to = a["timeout_pct"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p[1].as_f64())
            .fold(0.0f64, f64::max);
        assert!(to > 0.0, "per-upstream timeout pct, got {to}");
        let st = a["state"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p[1].as_f64())
            .next_back()
            .unwrap();
        assert_eq!(st, 2.0);
    }

    #[test]
    fn capped_ratio_never_exceeds_100() {
        // Bucket-boundary skew: 10 attempts started, but 14 completions
        // observed (5 from the previous bucket, 5 of these still in flight).
        assert_eq!(ratio_pct_capped(14, 10), Some(100.0));
        assert_eq!(ratio_pct_capped(4, 10), Some(40.0));
        assert_eq!(ratio_pct_capped(1, 0), None);
    }

    #[test]
    fn rejects_unknown_range() {
        let h = HistoryStore::new();
        assert!(h.query("nope").is_err());
    }

    #[test]
    fn downsample_limits_points() {
        let mut v = Vec::new();
        for i in 0..1000u64 {
            let mut b = GBucket::new(i * 1000);
            b.secs = 1.0;
            b.queries = 10;
            v.push(b);
        }
        let out = downsample_g(v, MAX_POINTS);
        assert!(out.len() <= MAX_POINTS);
        assert_eq!(
            out.iter().map(|b| b.queries).sum::<u64>(),
            10_000,
            "no queries lost"
        );
    }
}
