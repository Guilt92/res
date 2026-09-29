//! Reproducible DNS load generator for OutisDNS.
//!
//! Measures achieved QPS, latency percentiles (P50/P95/P99) and failure rate
//! against a running gateway. Synthetic query names are used; no real
//! customer data is involved.
//!
//! Example:
//! ```text
//! outisdns-loadtest --server 127.0.0.1:53 --qps 5000 --duration 15 --window 32
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

#[derive(Parser, Debug)]
#[command(
    name = "outisdns-loadtest",
    about = "DNS load tester (UDP pipelined, optional TCP fraction)"
)]
struct Args {
    /// Target server (ip:port).
    #[arg(long, default_value = "127.0.0.1:53")]
    server: SocketAddr,
    /// Target queries per second.
    #[arg(long, default_value_t = 1000)]
    qps: u64,
    /// Test duration in seconds.
    #[arg(long, default_value_t = 10)]
    duration: u64,
    /// Number of concurrent UDP workers.
    #[arg(long, default_value_t = 4)]
    workers: usize,
    /// Pipelined outstanding queries per worker.
    #[arg(long, default_value_t = 32)]
    window: usize,
    /// Per-query timeout in milliseconds.
    #[arg(long, default_value_t = 2000)]
    timeout_ms: u64,
    /// Fraction of queries sent over TCP (0.0 - 1.0).
    #[arg(long, default_value_t = 0.0)]
    tcp_frac: f64,
    /// Query name prefix.
    #[arg(long, default_value = "lt.example.com")]
    prefix: String,
    /// Also set the EDNS OPT record (advertise 4096 byte payloads).
    #[arg(long)]
    edns: bool,
}

#[derive(Default)]
struct Stats {
    sent: u64,
    received: u64,
    failed: u64,
    latencies_ms: Vec<f64>,
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
    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let tcp_workers = ((args.workers as f64) * args.tcp_frac).round() as usize;
    let udp_workers = args.workers.saturating_sub(tcp_workers).max(1);

    println!(
        "loadtest target={} qps={} duration={}s workers={} (udp={udp_workers}, tcp={tcp_workers}) window={} prefix={}",
        args.server, args.qps, args.duration, args.workers, args.window, args.prefix
    );
    println!("--- system (recorded for reproducibility) ---");
    print!("{}", outisdns::sysinfo::SystemInfo::collect().render());

    let per_udp_qps = args.qps as f64 / udp_workers as f64;
    let args = std::sync::Arc::new(args);
    let mut handles = Vec::new();

    for w in 0..udp_workers {
        let a = std::sync::Arc::clone(&args);
        let qps = per_udp_qps;
        handles.push(tokio::spawn(async move {
            udp_worker(w, qps, deadline, a).await
        }));
    }
    for w in 0..tcp_workers {
        let a = std::sync::Arc::clone(&args);
        let qps = args.qps as f64 / tcp_workers.max(1) as f64;
        handles.push(tokio::spawn(async move {
            tcp_worker(w, qps, deadline, a).await
        }));
    }

    let mut total = Stats::default();
    for h in handles {
        match h.await {
            Ok(Ok(s)) => {
                total.sent += s.sent;
                total.received += s.received;
                total.failed += s.failed;
                total.latencies_ms.extend(s.latencies_ms);
            }
            Ok(Err(e)) => eprintln!("worker error: {e}"),
            Err(e) => eprintln!("worker panicked: {e}"),
        }
    }

    total.latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let elapsed = args.duration as f64;
    let achieved = total.received as f64 / elapsed;
    let failure_rate = if total.sent == 0 {
        0.0
    } else {
        total.failed as f64 / total.sent as f64
    };

    println!("--- results ---");
    println!(
        "timestamp:  {}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    println!("sent:        {}", total.sent);
    println!("received:    {}", total.received);
    println!("failed:      {}", total.failed);
    println!("qps_target:  {:.1}", args.qps);
    println!("qps_achieved:{achieved:.1}");
    println!("failure_rate:{:.4}%", failure_rate * 100.0);
    println!("p50_ms:      {:.3}", pct(&total.latencies_ms, 50.0));
    println!("p95_ms:      {:.3}", pct(&total.latencies_ms, 95.0));
    println!("p99_ms:      {:.3}", pct(&total.latencies_ms, 99.0));
    println!(
        "max_ms:      {:.3}",
        total.latencies_ms.last().copied().unwrap_or(0.0)
    );
    println!("avg_ms:      {:.3}", avg(&total.latencies_ms));
    Ok(())
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn avg(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.iter().sum::<f64>() / v.len() as f64
}

/// Build a minimal recursive A (or AAAA-free) query with a random id.
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

async fn udp_worker(
    worker: usize,
    qps: f64,
    deadline: Instant,
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

    let mut stats = Stats::default();
    let mut outstanding: HashMap<u16, Instant> = HashMap::new();
    let mut recv_buf = vec![0u8; 65535];
    let interval = Duration::from_secs_f64(1.0 / qps.max(1.0));
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
            seq = seq.wrapping_add(1);
            name_seq += 1;
            let name = format!("w{worker}-{name_seq}.{}", args.prefix);
            let q = build_query(seq, &name, args.edns);
            match sock.send(&q).await {
                Ok(_) => {
                    stats.sent += 1;
                    outstanding.insert(seq, Instant::now());
                }
                Err(_) => stats.failed += 1,
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

        // Receive whatever arrives (short poll to keep the loop responsive).
        match timeout(Duration::from_millis(2), sock.recv(&mut recv_buf)).await {
            Ok(Ok(n)) => {
                if n >= 12 {
                    let id = u16::from_be_bytes([recv_buf[0], recv_buf[1]]);
                    if let Some(sent_at) = outstanding.remove(&id) {
                        stats.received += 1;
                        stats
                            .latencies_ms
                            .push(sent_at.elapsed().as_secs_f64() * 1000.0);
                    }
                }
            }
            Ok(Err(e)) => return Err(format!("recv: {e}")),
            Err(_) => {}
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
    args: std::sync::Arc<Args>,
) -> Result<Stats, String> {
    let mut stats = Stats::default();
    let interval = Duration::from_secs_f64(1.0 / qps.max(1.0));
    let mut seq: u16 = fastrand::u16(..);
    let mut name_seq: u64 = 0;

    while Instant::now() < deadline {
        let started = Instant::now();
        match one_tcp_query(&args, &mut seq, worker, &mut name_seq).await {
            Ok(elapsed) => {
                stats.sent += 1;
                stats.received += 1;
                stats.latencies_ms.push(elapsed.as_secs_f64() * 1000.0);
            }
            Err(_) => {
                stats.sent += 1;
                stats.failed += 1;
            }
        }
        let spent = started.elapsed();
        if spent < interval {
            tokio::time::sleep(interval - spent).await;
        }
    }
    Ok(stats)
}

async fn one_tcp_query(
    args: &std::sync::Arc<Args>,
    seq: &mut u16,
    worker: usize,
    name_seq: &mut u64,
) -> Result<Duration, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let started = Instant::now();
    let mut stream = timeout(
        Duration::from_millis(args.timeout_ms),
        TcpStream::connect(args.server),
    )
    .await
    .map_err(|_| "connect timeout".to_string())?
    .map_err(|e| format!("connect: {e}"))?;

    *seq = seq.wrapping_add(1);
    *name_seq += 1;
    let id = *seq;
    let name = format!("tcpw{worker}-{name_seq}.{}", args.prefix);
    let q = build_query(id, &name, args.edns);

    let mut frame = Vec::with_capacity(2 + q.len());
    frame.extend_from_slice(&(q.len() as u16).to_be_bytes());
    frame.extend_from_slice(&q);

    timeout(
        Duration::from_millis(args.timeout_ms),
        stream.write_all(&frame),
    )
    .await
    .map_err(|_| "write timeout".to_string())?
    .map_err(|e| format!("write: {e}"))?;

    let mut len_buf = [0u8; 2];
    timeout(
        Duration::from_millis(args.timeout_ms),
        stream.read_exact(&mut len_buf),
    )
    .await
    .map_err(|_| "read timeout".to_string())?
    .map_err(|e| format!("read len: {e}"))?;
    let len = usize::from(u16::from_be_bytes(len_buf));
    if len < 12 {
        return Err("short frame".into());
    }
    let mut resp = vec![0u8; len];
    timeout(
        Duration::from_millis(args.timeout_ms),
        stream.read_exact(&mut resp),
    )
    .await
    .map_err(|_| "read timeout".to_string())?
    .map_err(|e| format!("read body: {e}"))?;

    if u16::from_be_bytes([resp[0], resp[1]]) != id {
        return Err("id mismatch".into());
    }
    Ok(started.elapsed())
}
