//! Reproducible DNS load generator for res.
//!
//! Measures achieved QPS, latency percentiles (P50/P95/P99), response codes
//! and failure rate against a running gateway. Synthetic query names are used;
//! no real customer data is involved.
//!
//! Example:
//! ```text
//! res-loadtest --server 127.0.0.1:53 --qps 5000 --duration 15 --window 32
//! ```

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const DEFAULT_MAX_SAMPLES: usize = 1_000_000;
const REQUEST_TIMEOUT: Duration = Duration::from_millis(2);

#[derive(Parser, Debug)]
#[command(
    name = "res-loadtest",
    about = "DNS load tester (UDP pipelined, optional TCP fraction)"
)]
struct Args {
    /// Target server (ip:port).
    #[arg(long, default_value = "127.0.0.1:53")]
    server: SocketAddr,
    /// Target queries per second (UDP and TCP combined).
    #[arg(long, default_value_t = 1000)]
    qps: u64,
    /// Test duration in seconds.
    #[arg(long, default_value_t = 10)]
    duration: u64,
    /// Total number of concurrent workers.
    #[arg(long, default_value_t = 4)]
    workers: usize,
    /// Pipelined outstanding queries per UDP worker.
    #[arg(long, default_value_t = 32)]
    window: usize,
    /// Per-query timeout in milliseconds.
    #[arg(long, default_value_t = 2000)]
    timeout_ms: u64,
    /// Fraction of query load sent over TCP (0.0 - 1.0). Mixed protocol
    /// traffic requires at least two workers.
    #[arg(long, default_value_t = 0.0)]
    tcp_frac: f64,
    /// Query name prefix.
    #[arg(long, default_value = "lt.example.com")]
    prefix: String,
    /// Also set the EDNS OPT record (advertise 4096 byte payloads).
    #[arg(long)]
    edns: bool,
    /// Cycle through this many distinct query names (0 = unique name per
    /// query). A small working set exercises the response cache; 0 models a
    /// never-repeating stream.
    #[arg(long, default_value_t = 0)]
    working_set: u64,
    /// Maximum latency observations retained (bounded per-worker reservoir sampling).
    #[arg(long, default_value_t = DEFAULT_MAX_SAMPLES)]
    max_samples: usize,
    /// Emit one machine-readable JSON result object instead of text.
    #[arg(long)]
    json: bool,
}

impl Args {
    fn validate(&self) -> Result<(usize, usize), String> {
        if self.qps == 0 {
            return Err("--qps must be greater than zero".into());
        }
        if self.duration == 0 {
            return Err("--duration must be greater than zero".into());
        }
        if self.workers == 0 || self.workers > 1024 {
            return Err("--workers must be between 1 and 1024".into());
        }
        if self.window == 0 || self.window > u16::MAX as usize {
            return Err("--window must be between 1 and 65535".into());
        }
        if self.timeout_ms == 0 {
            return Err("--timeout-ms must be greater than zero".into());
        }
        if !self.tcp_frac.is_finite() || !(0.0..=1.0).contains(&self.tcp_frac) {
            return Err("--tcp-frac must be a finite number from 0.0 to 1.0".into());
        }
        if self.tcp_frac > 0.0 && self.tcp_frac < 1.0 && self.workers < 2 {
            return Err("mixed TCP/UDP load requires --workers >= 2".into());
        }
        if self.max_samples == 0 {
            return Err("--max-samples must be greater than zero".into());
        }
        validate_prefix(&self.prefix)?;

        Ok(split_workers(self.workers, self.tcp_frac))
    }
}

fn validate_prefix(prefix: &str) -> Result<(), String> {
    let name = prefix.trim_end_matches('.');
    if name.is_empty() {
        return Err("--prefix must contain at least one label".into());
    }
    let mut wire_len = 1usize;
    for label in name.split('.') {
        if label.is_empty() {
            return Err("--prefix contains an empty label".into());
        }
        if label.len() > 63 {
            return Err("--prefix contains a label longer than 63 bytes".into());
        }
        wire_len = wire_len
            .checked_add(1 + label.len())
            .ok_or_else(|| "--prefix is too long".to_string())?;
    }
    // Generated names add one label of at most 32 bytes plus the root label.
    if wire_len + 33 > 255 {
        return Err("--prefix is too long for the generated query names".into());
    }
    Ok(())
}

fn split_workers(workers: usize, tcp_frac: f64) -> (usize, usize) {
    if tcp_frac <= 0.0 {
        (workers, 0)
    } else if tcp_frac >= 1.0 {
        (0, workers)
    } else {
        let tcp = ((workers as f64 * tcp_frac).round() as usize).clamp(1, workers - 1);
        (workers - tcp, tcp)
    }
}

#[derive(Debug)]
struct LatencySamples {
    values: Vec<f64>,
    observed: u64,
    limit: usize,
}

impl LatencySamples {
    fn new(limit: usize) -> Self {
        Self {
            values: Vec::with_capacity(limit.min(4096)),
            observed: 0,
            limit,
        }
    }

    fn record(&mut self, value: f64) {
        self.observed = self.observed.saturating_add(1);
        if self.values.len() < self.limit {
            self.values.push(value);
        } else {
            let slot = fastrand::u64(..self.observed);
            if slot < self.limit as u64 {
                self.values[slot as usize] = value;
            }
        }
    }

    fn merge_from(&mut self, other: &Self) {
        self.observed = self.observed.saturating_add(other.observed);
        let room = self.limit.saturating_sub(self.values.len());
        self.values.extend(other.values.iter().take(room).copied());
    }
}

#[derive(Debug)]
struct Stats {
    attempted: u64,
    sent: u64,
    received: u64,
    failed: u64,
    rcodes: BTreeMap<u8, u64>,
    latencies: LatencySamples,
    last_error: Option<String>,
}

impl Stats {
    fn new(sample_limit: usize) -> Self {
        Self {
            attempted: 0,
            sent: 0,
            received: 0,
            failed: 0,
            rcodes: BTreeMap::new(),
            latencies: LatencySamples::new(sample_limit),
            last_error: None,
        }
    }

    fn merge_from(&mut self, other: Stats) {
        self.attempted = self.attempted.saturating_add(other.attempted);
        self.sent = self.sent.saturating_add(other.sent);
        self.received = self.received.saturating_add(other.received);
        self.failed = self.failed.saturating_add(other.failed);
        for (rcode, count) in other.rcodes {
            *self.rcodes.entry(rcode).or_default() += count;
        }
        self.latencies.merge_from(&other.latencies);
        if other.last_error.is_some() {
            self.last_error = other.last_error;
        }
    }
}

fn account_udp_response(stats: &mut Stats, outstanding: &mut HashMap<u16, Instant>, packet: &[u8]) {
    if packet.len() < 2 {
        return;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let Some(sent_at) = outstanding.remove(&id) else {
        return;
    };
    match parse_response(packet, id) {
        Ok(rcode) => {
            stats.received += 1;
            *stats.rcodes.entry(rcode).or_default() += 1;
            stats
                .latencies
                .record(sent_at.elapsed().as_secs_f64() * 1000.0);
        }
        Err(ResponseError::Rcode(rcode)) => {
            stats.failed += 1;
            *stats.rcodes.entry(rcode).or_default() += 1;
        }
        Err(ResponseError::Malformed(reason)) => {
            stats.failed += 1;
            stats.last_error = Some(format!("malformed response: {reason}"));
        }
    }
}

#[derive(Serialize)]
struct LoadResult {
    timestamp: u64,
    server: String,
    system: String,
    target_qps: f64,
    duration_target_s: u64,
    duration_actual_s: f64,
    workers: usize,
    udp_workers: usize,
    tcp_workers: usize,
    udp_target_qps: f64,
    tcp_target_qps: f64,
    attempted: u64,
    sent: u64,
    received: u64,
    failed: u64,
    qps_attempted: f64,
    qps_sent: f64,
    qps_received: f64,
    failure_rate: f64,
    p50_ms: Option<f64>,
    p95_ms: Option<f64>,
    p99_ms: Option<f64>,
    p999_ms: Option<f64>,
    max_ms: Option<f64>,
    avg_ms: Option<f64>,
    latency_observed: u64,
    latency_samples: usize,
    latency_sample_limit: usize,
    rcodes: BTreeMap<String, u64>,
    last_error: Option<String>,
    errors: Vec<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(e) = run(args).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), String> {
    let (udp_workers, tcp_workers) = args.validate()?;
    let system = res::sysinfo::SystemInfo::collect().render();
    let duration = Duration::from_secs(args.duration);
    let udp_target_qps = args.qps as f64 * (1.0 - args.tcp_frac);
    let tcp_target_qps = args.qps as f64 * args.tcp_frac;
    let per_udp_qps = if udp_workers == 0 {
        0.0
    } else {
        udp_target_qps / udp_workers as f64
    };
    let per_tcp_qps = if tcp_workers == 0 {
        0.0
    } else {
        tcp_target_qps / tcp_workers as f64
    };

    if !args.json {
        println!(
            "loadtest target={} qps={} duration={}s workers={} (udp={udp_workers}, tcp={tcp_workers}) window={} prefix={} working_set={}",
            args.server,
            args.qps,
            args.duration,
            args.workers,
            args.window,
            args.prefix,
            args.working_set
        );
        println!("protocol targets: udp={udp_target_qps:.1} qps tcp={tcp_target_qps:.1} qps");
        println!("--- system (recorded for reproducibility) ---");
        print!("{system}");
    }

    let started_at = Instant::now();
    let deadline = started_at + duration;
    let total_workers = udp_workers + tcp_workers;
    let sample_limit = args.max_samples.max(total_workers);
    let per_worker_samples = sample_limit / total_workers;
    let args = std::sync::Arc::new(args);
    let mut handles = Vec::with_capacity(total_workers);

    for w in 0..udp_workers {
        let a = std::sync::Arc::clone(&args);
        let qps = per_udp_qps;
        let limit = per_worker_samples;
        handles.push((
            "udp",
            w,
            tokio::spawn(async move { udp_worker(w, qps, deadline, limit, a).await }),
        ));
    }
    for w in 0..tcp_workers {
        let a = std::sync::Arc::clone(&args);
        let qps = per_tcp_qps;
        let limit = per_worker_samples;
        handles.push((
            "tcp",
            w,
            tokio::spawn(async move { tcp_worker(w, qps, deadline, limit, a).await }),
        ));
    }

    let mut total = Stats::new(sample_limit);
    let mut errors = Vec::new();
    for (protocol, worker, handle) in handles {
        match handle.await {
            Ok(Ok(stats)) => total.merge_from(stats),
            Ok(Err(e)) => errors.push(format!("{protocol} worker {worker}: {e}")),
            Err(e) => errors.push(format!("{protocol} worker {worker} panicked: {e}")),
        }
    }
    let elapsed = started_at.elapsed().as_secs_f64();
    let result = build_result(
        &args,
        total,
        elapsed,
        udp_workers,
        tcp_workers,
        udp_target_qps,
        tcp_target_qps,
        system,
        errors,
    );

    if args.json {
        let body = serde_json::to_string_pretty(&result)
            .map_err(|e| format!("encode JSON result: {e}"))?;
        println!("{body}");
    } else {
        print_result(&result);
    }

    if !result.errors.is_empty() {
        return Err(result.errors.join("; "));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_result(
    args: &Args,
    total: Stats,
    elapsed: f64,
    udp_workers: usize,
    tcp_workers: usize,
    udp_target_qps: f64,
    tcp_target_qps: f64,
    system: String,
    errors: Vec<String>,
) -> LoadResult {
    let elapsed = elapsed.max(f64::EPSILON);
    let mut sorted = total.latencies.values;
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let failure_rate = if total.attempted == 0 {
        0.0
    } else {
        total.failed as f64 / total.attempted as f64
    };
    let rcodes = total
        .rcodes
        .into_iter()
        .map(|(code, count)| (rcode_name(code).to_string(), count))
        .collect();

    LoadResult {
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        server: args.server.to_string(),
        system,
        target_qps: args.qps as f64,
        duration_target_s: args.duration,
        duration_actual_s: elapsed,
        workers: args.workers,
        udp_workers,
        tcp_workers,
        udp_target_qps,
        tcp_target_qps,
        attempted: total.attempted,
        sent: total.sent,
        received: total.received,
        failed: total.failed,
        qps_attempted: total.attempted as f64 / elapsed,
        qps_sent: total.sent as f64 / elapsed,
        qps_received: total.received as f64 / elapsed,
        failure_rate,
        p50_ms: pct(&sorted, 50.0),
        p95_ms: pct(&sorted, 95.0),
        p99_ms: pct(&sorted, 99.0),
        p999_ms: pct(&sorted, 99.9),
        max_ms: sorted.last().copied(),
        avg_ms: avg(&sorted),
        latency_observed: total.latencies.observed,
        latency_samples: sorted.len(),
        latency_sample_limit: total.latencies.limit,
        rcodes,
        last_error: total.last_error,
        errors,
    }
}

fn print_result(result: &LoadResult) {
    println!("--- results ---");
    println!("timestamp:   {}", result.timestamp);
    println!("attempted:   {}", result.attempted);
    println!("sent:        {}", result.sent);
    println!("received:    {}", result.received);
    println!("failed:      {}", result.failed);
    println!("rcodes:      {:?}", result.rcodes);
    if let Some(error) = &result.last_error {
        println!("last_error:  {error}");
    }
    println!("qps_target:  {:.1}", result.target_qps);
    println!("qps_attempt: {:.1}", result.qps_attempted);
    println!("qps_sent:    {:.1}", result.qps_sent);
    println!("qps_achieved:{:.1}", result.qps_received);
    println!("elapsed_s:   {:.3}", result.duration_actual_s);
    println!("failure_rate:{:.4}%", result.failure_rate * 100.0);
    println!("p50_ms:      {}", format_opt(result.p50_ms));
    println!("p95_ms:      {}", format_opt(result.p95_ms));
    println!("p99_ms:      {}", format_opt(result.p99_ms));
    println!("p999_ms:     {}", format_opt(result.p999_ms));
    println!("max_ms:      {}", format_opt(result.max_ms));
    println!("avg_ms:      {}", format_opt(result.avg_ms));
    println!(
        "latency_samples: {} retained / {} observed (limit {})",
        result.latency_samples, result.latency_observed, result.latency_sample_limit
    );
}

fn format_opt(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |v| format!("{v:.3}"))
}

fn pct(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted.get(idx.min(sorted.len() - 1)).copied()
}

fn avg(v: &[f64]) -> Option<f64> {
    if v.is_empty() {
        None
    } else {
        Some(v.iter().sum::<f64>() / v.len() as f64)
    }
}

fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

/// Build a minimal recursive A query with a random id.
fn build_query(id: u16, name: &str, edns: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + name.len());
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    let ancount = if edns { 1u16 } else { 0 };
    if edns {
        buf[10..12].copy_from_slice(&ancount.to_be_bytes()); // ARCOUNT
    }
    for label in name.trim_end_matches('.').split('.') {
        let l = label.as_bytes();
        buf.push(l.len() as u8);
        buf.extend_from_slice(l);
    }
    buf.push(0);
    buf.extend_from_slice(&1u16.to_be_bytes()); // A
    buf.extend_from_slice(&1u16.to_be_bytes()); // IN
    if edns {
        // OPT root name, type 41, UDP payload 4096, TTL 0, RDLEN 0
        buf.push(0);
        buf.extend_from_slice(&41u16.to_be_bytes());
        buf.extend_from_slice(&4096u16.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
    }
    buf
}

#[derive(Debug, PartialEq, Eq)]
enum ResponseError {
    Malformed(&'static str),
    Rcode(u8),
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "malformed response: {reason}"),
            Self::Rcode(code) => write!(f, "DNS failure rcode {}", rcode_name(*code)),
        }
    }
}

fn parse_response(buf: &[u8], expected_id: u16) -> Result<u8, ResponseError> {
    if buf.len() < 12 {
        return Err(ResponseError::Malformed("short header"));
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != expected_id {
        return Err(ResponseError::Malformed("id mismatch"));
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        return Err(ResponseError::Malformed("QR bit not set"));
    }
    if (flags >> 11) & 0x0f != 0 {
        return Err(ResponseError::Malformed("unexpected opcode"));
    }
    if flags & 0x0200 != 0 {
        return Err(ResponseError::Malformed("truncated response"));
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount != 1 {
        return Err(ResponseError::Malformed("question count is not one"));
    }
    let question_end = skip_name(buf, 12).ok_or(ResponseError::Malformed("bad question name"))?;
    if question_end + 4 > buf.len() {
        return Err(ResponseError::Malformed("short question"));
    }
    if u16::from_be_bytes([buf[question_end], buf[question_end + 1]]) != 1
        || u16::from_be_bytes([buf[question_end + 2], buf[question_end + 3]]) != 1
    {
        return Err(ResponseError::Malformed("unexpected question type/class"));
    }

    let rcode = (flags & 0x000f) as u8;
    if matches!(rcode, 0 | 3) {
        Ok(rcode)
    } else {
        Err(ResponseError::Rcode(rcode))
    }
}

fn skip_name(buf: &[u8], start: usize) -> Option<usize> {
    let mut offset = start;
    let mut end = None;
    let mut jumps = 0usize;
    loop {
        let len = *buf.get(offset)?;
        match len & 0xc0 {
            0x00 => {
                offset += 1;
                if len == 0 {
                    return Some(end.unwrap_or(offset));
                }
                if len > 63 {
                    return None;
                }
                offset = offset.checked_add(len as usize)?;
                if offset > buf.len() {
                    return None;
                }
            }
            0xc0 => {
                let low = *buf.get(offset + 1)?;
                if end.is_none() {
                    end = Some(offset + 2);
                }
                jumps += 1;
                if jumps > 128 {
                    return None;
                }
                offset = usize::from(u16::from_be_bytes([len & 0x3f, low]));
                if offset >= buf.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
}

async fn udp_worker(
    worker: usize,
    qps: f64,
    deadline: Instant,
    sample_limit: usize,
    args: std::sync::Arc<Args>,
) -> Result<Stats, String> {
    let sock = UdpSocket::bind(if args.server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    .map_err(|e| format!("bind: {e}"))?;
    sock.connect(args.server)
        .await
        .map_err(|e| format!("connect: {e}"))?;

    let mut stats = Stats::new(sample_limit);
    let mut outstanding: HashMap<u16, Instant> = HashMap::new();
    let mut recv_buf = vec![0u8; 65535];
    let interval = Duration::from_secs_f64(1.0 / qps);
    let mut next_send = Instant::now();
    let mut seq: u16 = fastrand::u16(..);
    let per_worker_timeout = Duration::from_millis(args.timeout_ms);
    let mut name_seq: u64 = 0;

    while Instant::now() < deadline || !outstanding.is_empty() {
        // Send while the window allows and the pace permits.
        while Instant::now() >= next_send
            && Instant::now() < deadline
            && outstanding.len() < args.window
        {
            loop {
                seq = seq.wrapping_add(1);
                if !outstanding.contains_key(&seq) {
                    break;
                }
            }
            name_seq += 1;
            let name = if args.working_set > 0 {
                format!("ws{}.{}", name_seq % args.working_set, args.prefix)
            } else {
                format!("w{worker}-{name_seq}.{}", args.prefix)
            };
            let q = build_query(seq, &name, args.edns);
            stats.attempted += 1;
            match sock.send(&q).await {
                Ok(_) => {
                    stats.sent += 1;
                    outstanding.insert(seq, Instant::now());
                }
                Err(e) => {
                    stats.failed += 1;
                    stats.last_error = Some(format!("udp send: {e}"));
                }
            }
            next_send += interval;
            if next_send < Instant::now() - Duration::from_millis(100) {
                // Behind schedule after a stall: do not burst-catch-up blindly.
                next_send = Instant::now() + interval;
            }
        }

        if outstanding.is_empty() && Instant::now() >= deadline {
            break;
        }

        // Receive whatever arrives (short poll to keep the loop responsive and
        // let expired requests be accounted for promptly).
        match timeout(REQUEST_TIMEOUT, sock.recv(&mut recv_buf)).await {
            Ok(Ok(n)) => account_udp_response(&mut stats, &mut outstanding, &recv_buf[..n]),
            Ok(Err(e)) => return Err(format!("recv: {e}")),
            Err(_) => {}
        }
        loop {
            match sock.try_recv(&mut recv_buf) {
                Ok(n) => account_udp_response(&mut stats, &mut outstanding, &recv_buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("recv: {e}")),
            }
        }

        // Expire timed-out queries.
        let now = Instant::now();
        outstanding.retain(|_, sent| {
            if now.duration_since(*sent) > per_worker_timeout {
                stats.failed += 1;
                false
            } else {
                true
            }
        });
    }

    Ok(stats)
}

async fn tcp_worker(
    worker: usize,
    qps: f64,
    deadline: Instant,
    sample_limit: usize,
    args: std::sync::Arc<Args>,
) -> Result<Stats, String> {
    let mut stats = Stats::new(sample_limit);
    let interval = Duration::from_secs_f64(1.0 / qps);
    let mut seq: u16 = fastrand::u16(..);
    let mut name_seq: u64 = 0;
    let mut connection: Option<TcpStream> = None;
    let mut next_send = Instant::now();

    while Instant::now() < deadline {
        if next_send > Instant::now() {
            tokio::time::sleep(next_send - Instant::now()).await;
        }
        if Instant::now() >= deadline {
            break;
        }
        stats.attempted += 1;
        match one_tcp_query(&args, &mut seq, worker, &mut name_seq, &mut connection).await {
            Ok((elapsed, rcode)) => {
                stats.sent += 1;
                stats.received += 1;
                *stats.rcodes.entry(rcode).or_default() += 1;
                stats.latencies.record(elapsed.as_secs_f64() * 1000.0);
            }
            Err(error) => {
                if error.after_send {
                    stats.sent += 1;
                }
                stats.failed += 1;
                stats.last_error = Some(error.message);
            }
        }
        next_send += interval;
        if next_send < Instant::now() - Duration::from_millis(100) {
            next_send = Instant::now() + interval;
        }
    }
    Ok(stats)
}

struct TcpQueryError {
    after_send: bool,
    message: String,
}

impl TcpQueryError {
    fn before_send(message: impl Into<String>) -> Self {
        Self {
            after_send: false,
            message: message.into(),
        }
    }

    fn after_send(message: impl Into<String>) -> Self {
        Self {
            after_send: true,
            message: message.into(),
        }
    }
}

async fn one_tcp_query(
    args: &std::sync::Arc<Args>,
    seq: &mut u16,
    worker: usize,
    name_seq: &mut u64,
    connection: &mut Option<TcpStream>,
) -> Result<(Duration, u8), TcpQueryError> {
    let started = Instant::now();
    if connection.is_none() {
        let stream = timeout(
            Duration::from_millis(args.timeout_ms),
            TcpStream::connect(args.server),
        )
        .await
        .map_err(|_| TcpQueryError::before_send("connect timeout"))?
        .map_err(|e| TcpQueryError::before_send(format!("connect: {e}")))?;
        *connection = Some(stream);
    }
    let stream = connection
        .as_mut()
        .expect("connection was established above");

    *seq = seq.wrapping_add(1);
    *name_seq += 1;
    let id = *seq;
    let name = if args.working_set > 0 {
        format!("ws{}.{}", *name_seq % args.working_set, args.prefix)
    } else {
        format!("tcpw{worker}-{name_seq}.{}", args.prefix)
    };
    let q = build_query(id, &name, args.edns);

    let mut frame = Vec::with_capacity(2 + q.len());
    frame.extend_from_slice(&(q.len() as u16).to_be_bytes());
    frame.extend_from_slice(&q);

    let write_result = timeout(
        Duration::from_millis(args.timeout_ms),
        stream.write_all(&frame),
    )
    .await;
    match write_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            *connection = None;
            return Err(TcpQueryError::before_send(format!("write: {e}")));
        }
        Err(_) => {
            *connection = None;
            return Err(TcpQueryError::before_send("write timeout"));
        }
    }

    let mut len_buf = [0u8; 2];
    let read_len = timeout(
        Duration::from_millis(args.timeout_ms),
        stream.read_exact(&mut len_buf),
    )
    .await;
    if !matches!(read_len, Ok(Ok(_))) {
        *connection = None;
        let message = match read_len {
            Ok(Err(e)) => format!("read len: {e}"),
            Err(_) => "read timeout".to_string(),
            Ok(Ok(_)) => unreachable!(),
        };
        return Err(TcpQueryError::after_send(message));
    }
    let len = usize::from(u16::from_be_bytes(len_buf));
    if len < 12 {
        *connection = None;
        return Err(TcpQueryError::after_send("short frame"));
    }
    let mut resp = vec![0u8; len];
    let read_body = timeout(
        Duration::from_millis(args.timeout_ms),
        stream.read_exact(&mut resp),
    )
    .await;
    if !matches!(read_body, Ok(Ok(_))) {
        *connection = None;
        let message = match read_body {
            Ok(Err(e)) => format!("read body: {e}"),
            Err(_) => "read timeout".to_string(),
            Ok(Ok(_)) => unreachable!(),
        };
        return Err(TcpQueryError::after_send(message));
    }

    match parse_response(&resp, id) {
        Ok(rcode) => Ok((started.elapsed(), rcode)),
        Err(ResponseError::Rcode(rcode)) => Err(TcpQueryError::after_send(format!(
            "DNS failure rcode {}",
            rcode_name(rcode)
        ))),
        Err(ResponseError::Malformed(reason)) => Err(TcpQueryError::after_send(format!(
            "malformed response: {reason}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(id: u16, rcode: u8, truncated: bool) -> Vec<u8> {
        let q = build_query(id, "example.test", false);
        let mut resp = q;
        let mut flags = 0x8180u16 | u16::from(rcode);
        if truncated {
            flags |= 0x0200;
        }
        resp[2..4].copy_from_slice(&flags.to_be_bytes());
        resp
    }

    #[test]
    fn accepts_valid_answers_and_negative_answers() {
        assert_eq!(parse_response(&response(7, 0, false), 7), Ok(0));
        assert_eq!(parse_response(&response(7, 3, false), 7), Ok(3));
    }

    #[test]
    fn rejects_servfail_and_mismatched_messages() {
        assert_eq!(
            parse_response(&response(7, 2, false), 7),
            Err(ResponseError::Rcode(2))
        );
        assert_eq!(
            parse_response(&response(7, 0, false), 8),
            Err(ResponseError::Malformed("id mismatch"))
        );
        assert_eq!(
            parse_response(&response(7, 0, true), 7),
            Err(ResponseError::Malformed("truncated response"))
        );
    }

    #[test]
    fn rejects_malformed_question_section() {
        let mut resp = response(7, 0, false);
        resp[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            parse_response(&resp, 7),
            Err(ResponseError::Malformed("question count is not one"))
        );

        let mut resp = response(7, 0, false);
        resp.truncate(14);
        assert!(matches!(
            parse_response(&resp, 7),
            Err(ResponseError::Malformed(_))
        ));
    }

    #[test]
    fn worker_split_never_duplicates_or_drops_workers() {
        for workers in 1..=32 {
            for step in 0..=20 {
                let frac = step as f64 / 20.0;
                if frac > 0.0 && frac < 1.0 && workers < 2 {
                    continue;
                }
                let (udp, tcp) = split_workers(workers, frac);
                assert_eq!(udp + tcp, workers, "workers={workers} frac={frac}");
                if frac == 0.0 {
                    assert_eq!(tcp, 0);
                } else if frac == 1.0 {
                    assert_eq!(udp, 0);
                } else {
                    assert!(udp > 0 && tcp > 0);
                }
            }
        }
    }

    #[test]
    fn protocol_targets_sum_to_requested_qps() {
        let args = Args {
            server: "127.0.0.1:53".parse().unwrap(),
            qps: 10_000,
            duration: 1,
            workers: 8,
            window: 32,
            timeout_ms: 1000,
            tcp_frac: 0.25,
            prefix: "lt.example.com".into(),
            edns: false,
            working_set: 0,
            max_samples: 100,
            json: false,
        };
        let (udp, tcp) = args.validate().unwrap();
        assert_eq!((udp, tcp), (6, 2));
        let udp_qps = args.qps as f64 * (1.0 - args.tcp_frac);
        let tcp_qps = args.qps as f64 * args.tcp_frac;
        assert!((udp_qps + tcp_qps - args.qps as f64).abs() < f64::EPSILON);
    }

    #[test]
    fn invalid_arguments_are_rejected() {
        let base = || Args {
            server: "127.0.0.1:53".parse().unwrap(),
            qps: 100,
            duration: 1,
            workers: 2,
            window: 8,
            timeout_ms: 100,
            tcp_frac: 0.5,
            prefix: "lt.example.com".into(),
            edns: false,
            working_set: 0,
            max_samples: 100,
            json: false,
        };

        let mut args = base();
        args.tcp_frac = f64::NAN;
        assert!(args.validate().is_err());

        let mut args = base();
        args.qps = 0;
        assert!(args.validate().is_err());

        let mut args = base();
        args.workers = 1;
        assert!(args.validate().is_err());

        let mut args = base();
        args.prefix = format!("{}.example", "x".repeat(64));
        assert!(args.validate().is_err());
    }

    #[test]
    fn latency_reservoir_is_bounded_and_counts_all_observations() {
        let mut samples = LatencySamples::new(10);
        for i in 0..1000 {
            samples.record(i as f64);
        }
        assert_eq!(samples.observed, 1000);
        assert_eq!(samples.values.len(), 10);

        let mut merged = LatencySamples::new(100);
        merged.merge_from(&samples);
        assert_eq!(merged.observed, 1000);
        assert_eq!(merged.values.len(), 10);
    }

    #[test]
    fn udp_accounting_ignores_late_ids_and_counts_failures() {
        let mut stats = Stats::new(10);
        let mut outstanding = HashMap::new();
        outstanding.insert(7u16, Instant::now());

        account_udp_response(&mut stats, &mut outstanding, &response(8, 0, false));
        assert_eq!(stats.received, 0);
        assert!(outstanding.contains_key(&7));

        account_udp_response(&mut stats, &mut outstanding, &response(7, 0, false));
        assert_eq!(stats.received, 1);
        assert!(!outstanding.contains_key(&7));

        outstanding.insert(9u16, Instant::now());
        let mut malformed = response(9, 0, false);
        malformed.truncate(14);
        account_udp_response(&mut stats, &mut outstanding, &malformed);
        assert_eq!(stats.failed, 1);
        assert!(stats.last_error.is_some());
    }
}
