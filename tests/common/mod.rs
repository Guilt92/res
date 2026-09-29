//! Shared helpers for the gateway integration tests.
//!
//! A "fake upstream" is a minimal DNS server (UDP + TCP on the same port)
//! that answers every query with a fixed A record, can be silenced to simulate
//! an outage, and can answer with TC=1 over UDP to exercise TCP fallback.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::{Name, RData, Record};
use outisdns::config::{AppConfig, Protocol, UpstreamConfig};
use outisdns::runtime::Gateway;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

/// Address returned by every fake upstream answer (TEST-NET-1).
pub const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

pub struct FakeUpstream {
    /// UDP + TCP address (both protocols share the port).
    pub addr: SocketAddr,
    pub hits: Arc<AtomicU64>,
    answering: Arc<AtomicBool>,
    truncate_udp: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
}

impl FakeUpstream {
    pub async fn start() -> Self {
        Self::start_with_answer(ANSWER).await
    }

    pub async fn start_with_answer(ip: Ipv4Addr) -> Self {
        // Bind TCP first, then UDP on the same port (independent port spaces),
        // so one address works for both protocols.
        let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
        let addr = tcp.local_addr().expect("tcp addr");
        let udp = UdpSocket::bind(addr).await.expect("bind udp");

        let hits = Arc::new(AtomicU64::new(0));
        let answering = Arc::new(AtomicBool::new(true));
        let truncate_udp = Arc::new(AtomicBool::new(false));

        let mut tasks = Vec::new();

        {
            let hits = Arc::clone(&hits);
            let answering = Arc::clone(&answering);
            let truncate_udp = Arc::clone(&truncate_udp);
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 65_535];
                loop {
                    let Ok((n, peer)) = udp.recv_from(&mut buf).await else {
                        break;
                    };
                    let Ok(query) = Message::from_vec(&buf[..n]) else {
                        continue;
                    };
                    if query.message_type != MessageType::Query {
                        continue;
                    }
                    hits.fetch_add(1, Ordering::SeqCst);
                    if !answering.load(Ordering::SeqCst) {
                        continue; // simulate a dead upstream: stay silent
                    }
                    let truncate = truncate_udp.load(Ordering::SeqCst);
                    if let Some(resp) = build_response(&query, truncate, ip) {
                        let _ = udp.send_to(&resp, peer).await;
                    }
                }
            }));
        }

        {
            let hits = Arc::clone(&hits);
            let answering = Arc::clone(&answering);
            tasks.push(tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = tcp.accept().await else {
                        break;
                    };
                    let hits = Arc::clone(&hits);
                    let answering = Arc::clone(&answering);
                    tokio::spawn(async move {
                        let _ = handle_tcp_conn(stream, &hits, &answering, ip).await;
                    });
                }
            }));
        }

        Self {
            addr,
            hits,
            answering,
            truncate_udp,
            tasks,
        }
    }

    /// Upstream config pointing at this fake (always the UDP protocol; the
    /// forwarder falls back to TCP on the same port when it sees TC=1).
    pub fn config(&self, name: &str) -> UpstreamConfig {
        UpstreamConfig {
            id: 0,
            name: name.to_string(),
            address: self.addr.ip(),
            port: self.addr.port(),
            protocol: Protocol::Udp,
            enabled: true,
            priority: 1,
            weight: 1,
            timeout_ms: None,
        }
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::SeqCst)
    }

    pub fn set_answering(&self, on: bool) {
        self.answering.store(on, Ordering::SeqCst);
    }

    pub fn set_truncate_udp(&self, on: bool) {
        self.truncate_udp.store(on, Ordering::SeqCst);
    }

    pub async fn stop(self) {
        for t in self.tasks {
            t.abort();
        }
    }
}

async fn handle_tcp_conn(
    mut stream: TcpStream,
    hits: &AtomicU64,
    answering: &AtomicBool,
    ip: Ipv4Addr,
) -> std::io::Result<()> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = usize::from(u16::from_be_bytes(len_buf));
    if len > 65_535 {
        return Ok(());
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    let Ok(query) = Message::from_vec(&body) else {
        return Ok(());
    };
    hits.fetch_add(1, Ordering::SeqCst);
    if !answering.load(Ordering::SeqCst) {
        return Ok(()); // dead upstream: close without answering
    }
    let Some(resp) = build_response(&query, false, ip) else {
        return Ok(());
    };
    let mut frame = Vec::with_capacity(2 + resp.len());
    frame.extend_from_slice(&(resp.len() as u16).to_be_bytes());
    frame.extend_from_slice(&resp);
    stream.write_all(&frame).await?;
    stream.flush().await
}

fn build_response(query: &Message, truncate: bool, ip: Ipv4Addr) -> Option<Vec<u8>> {
    let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.truncation = truncate;
    resp.queries = query.queries.clone();
    if !truncate {
        let q = query.queries.first()?;
        let name: Name = q.name().clone();
        resp.answers.push(Record::from_rdata(
            name,
            60,
            RData::A(hickory_proto::rr::rdata::A::from(ip)),
        ));
    }
    resp.to_vec().ok()
}

/// Gateway configuration for tests: loopback-only, ephemeral
/// ports, no rate limit / ACL surprises unless a test opts in.
pub fn base_config() -> AppConfig {
    let mut cfg = AppConfig::default();
    cfg.server.udp_addr = "127.0.0.1:0".parse().expect("addr");
    cfg.server.tcp_addr = "127.0.0.1:0".parse().expect("addr");
    cfg.server.api_addr = "127.0.0.1:0".parse().expect("addr");
    cfg.server.dashboard_dir = Some(std::env::temp_dir());
    cfg.server.shutdown_grace_ms = 500;
    cfg.acl.allowed_cidrs = vec!["127.0.0.0/8".to_string(), "::1/128".to_string()];
    cfg.ratelimit.enabled = false;
    cfg.health.enabled = false;
    cfg.cache.enabled = false;
    cfg.upstreams.clear();
    cfg
}

pub async fn start_gateway(cfg: AppConfig) -> Gateway {
    outisdns::runtime::start(cfg, None)
        .await
        .expect("gateway should start")
}

/// Start a gateway that persists configuration mutations to `path`.
pub async fn start_gateway_with_path(cfg: AppConfig, path: std::path::PathBuf) -> Gateway {
    outisdns::runtime::start(cfg, Some(path))
        .await
        .expect("gateway should start")
}

/// Send one A query over UDP and wait for a response (None on timeout/error).
pub async fn udp_query(server: SocketAddr, name: &str) -> Option<Message> {
    udp_query_timeout(server, name, Duration::from_secs(3)).await
}

pub async fn udp_query_timeout(server: SocketAddr, name: &str, wait: Duration) -> Option<Message> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.ok()?;
    sock.connect(server).await.ok()?;
    let query = outisdns::dns::msg::build_query(name, "A").ok()?;
    sock.send(&query).await.ok()?;
    let mut buf = vec![0u8; 65_535];
    match tokio::time::timeout(wait, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => Message::from_vec(&buf[..n]).ok(),
        _ => None,
    }
}

/// Send raw bytes over UDP and return whatever comes back (None = silence).
pub async fn udp_send_raw(server: SocketAddr, bytes: &[u8], wait: Duration) -> Option<Message> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.ok()?;
    sock.connect(server).await.ok()?;
    sock.send(bytes).await.ok()?;
    let mut buf = vec![0u8; 65_535];
    match tokio::time::timeout(wait, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => Message::from_vec(&buf[..n]).ok(),
        _ => None,
    }
}

/// Send one A query over TCP and wait for a response.
pub async fn tcp_query(server: SocketAddr, name: &str) -> Option<Message> {
    let mut stream = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(server))
        .await
        .ok()
        .and_then(|r| r.ok())?;
    let query = outisdns::dns::msg::build_query(name, "A").ok()?;
    let mut frame = Vec::with_capacity(2 + query.len());
    frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
    frame.extend_from_slice(&query);
    stream.write_all(&frame).await.ok()?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut len_buf))
        .await
        .ok()
        .and_then(|r| r.ok())?;
    let len = usize::from(u16::from_be_bytes(len_buf));
    if len > 65_535 {
        return None;
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut body))
        .await
        .ok()
        .and_then(|r| r.ok())?;
    Message::from_vec(&body).ok()
}

/// Minimal HTTP/1.1 client for the control-plane API tests.
pub async fn http(method: &str, addr: SocketAddr, path: &str, body: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("api connect");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(b) = body {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    stream.write_all(req.as_bytes()).await.expect("api write");
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.expect("api read");
    let text = String::from_utf8_lossy(&resp).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}
