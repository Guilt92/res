//! Shared helpers for the gateway integration tests.
//!
//! A "fake upstream" is a minimal DNS server (UDP + TCP on the same port)
//! that answers every query with a fixed A record, can be silenced to simulate
//! an outage, and can answer with TC=1 over UDP to exercise TCP fallback.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{Name, RData, Record};
use res::config::{AppConfig, Protocol, UpstreamConfig};
use res::runtime::Gateway;
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
    /// Answer NXDOMAIN (with an SOA in the authority section) instead of an
    /// A record — exercises RFC 2308 negative caching.
    nxdomain: Arc<AtomicBool>,
    /// Artificial response delay in milliseconds (simulates a slow upstream).
    delay_ms: Arc<AtomicUsize>,
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
        let nxdomain = Arc::new(AtomicBool::new(false));
        let delay_ms = Arc::new(AtomicUsize::new(0));

        let mut tasks = Vec::new();

        {
            let hits = Arc::clone(&hits);
            let answering = Arc::clone(&answering);
            let truncate_udp = Arc::clone(&truncate_udp);
            let nxdomain = Arc::clone(&nxdomain);
            let delay_ms = Arc::clone(&delay_ms);
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
                    let delay = delay_ms.load(Ordering::SeqCst);
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_millis(delay as u64)).await;
                    }
                    let truncate = truncate_udp.load(Ordering::SeqCst);
                    let nx = nxdomain.load(Ordering::SeqCst);
                    if let Some(resp) = build_response(&query, truncate, ip, nx) {
                        let _ = udp.send_to(&resp, peer).await;
                    }
                }
            }));
        }

        {
            let hits = Arc::clone(&hits);
            let answering = Arc::clone(&answering);
            let nxdomain = Arc::clone(&nxdomain);
            let delay_ms = Arc::clone(&delay_ms);
            tasks.push(tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = tcp.accept().await else {
                        break;
                    };
                    let hits = Arc::clone(&hits);
                    let answering = Arc::clone(&answering);
                    let nxdomain = Arc::clone(&nxdomain);
                    let delay_ms = Arc::clone(&delay_ms);
                    tokio::spawn(async move {
                        let _ =
                            handle_tcp_conn(stream, &hits, &answering, &nxdomain, &delay_ms, ip)
                                .await;
                    });
                }
            }));
        }

        Self {
            addr,
            hits,
            answering,
            truncate_udp,
            nxdomain,
            delay_ms,
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
            ..Default::default()
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

    pub fn set_nxdomain(&self, on: bool) {
        self.nxdomain.store(on, Ordering::SeqCst);
    }

    pub fn set_delay_ms(&self, ms: u64) {
        self.delay_ms.store(ms as usize, Ordering::SeqCst);
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
    nxdomain: &AtomicBool,
    delay_ms: &AtomicUsize,
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
    let delay = delay_ms.load(Ordering::SeqCst);
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay as u64)).await;
    }
    let Some(resp) = build_response(&query, false, ip, nxdomain.load(Ordering::SeqCst)) else {
        return Ok(());
    };
    let mut frame = Vec::with_capacity(2 + resp.len());
    frame.extend_from_slice(&(resp.len() as u16).to_be_bytes());
    frame.extend_from_slice(&resp);
    stream.write_all(&frame).await?;
    stream.flush().await
}

fn build_response(
    query: &Message,
    truncate: bool,
    ip: Ipv4Addr,
    nxdomain: bool,
) -> Option<Vec<u8>> {
    let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.truncation = truncate;
    resp.queries = query.queries.clone();
    if nxdomain {
        resp.metadata.response_code = ResponseCode::NXDomain;
        // RFC 2308: NXDOMAIN carries the zone SOA in the authority section;
        // its MINIMUM field is the negative-caching TTL.
        let q = query.queries.first()?;
        resp.authorities.push(Record::from_rdata(
            q.name().clone(),
            300,
            RData::SOA(hickory_proto::rr::rdata::SOA::new(
                Name::from_ascii("ns.fake.test.").unwrap(),
                Name::from_ascii("admin.fake.test.").unwrap(),
                1,
                7200,
                3600,
                1_209_600,
                30, // MINIMUM → negative TTL 30s
            )),
        ));
    } else if !truncate {
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

/// Paths to the committed self-signed test certificate (CN/SAN localhost and
/// 127.0.0.1). Never use these outside tests.
pub const TLS_CERT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/tls/localhost-cert.pem"
);
pub const TLS_KEY_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/tls/localhost-key.pem"
);
pub const TLS_CA_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/tls/ca-cert.pem"
);

/// Minimal DNS-over-TLS upstream for end-to-end certificate/SNI tests.
pub struct FakeTlsUpstream {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicU64>,
    tasks: Vec<JoinHandle<()>>,
}

impl FakeTlsUpstream {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tls");
        let addr = listener.local_addr().expect("tls addr");
        let config = res::tls::load_server_config(
            std::path::Path::new(TLS_CERT_PATH),
            std::path::Path::new(TLS_KEY_PATH),
        )
        .expect("test TLS identity");
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let hits = Arc::new(AtomicU64::new(0));
        let mut tasks = Vec::new();
        {
            let hits = Arc::clone(&hits);
            tasks.push(tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    let hits = Arc::clone(&hits);
                    tokio::spawn(async move {
                        let Ok(mut stream) = acceptor.accept(stream).await else {
                            return;
                        };
                        let mut len_buf = [0u8; 2];
                        if stream.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let len = usize::from(u16::from_be_bytes(len_buf));
                        let mut body = vec![0u8; len];
                        if stream.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        let Ok(query) = Message::from_vec(&body) else {
                            return;
                        };
                        hits.fetch_add(1, Ordering::SeqCst);
                        let Some(resp) = build_response(&query, false, ANSWER, false) else {
                            return;
                        };
                        let mut frame = Vec::with_capacity(2 + resp.len());
                        frame.extend_from_slice(&(resp.len() as u16).to_be_bytes());
                        frame.extend_from_slice(&resp);
                        let _ = stream.write_all(&frame).await;
                        let _ = stream.flush().await;
                    });
                }
            }));
        }
        Self { addr, hits, tasks }
    }

    pub fn config(&self, name: &str, server_name: &str) -> UpstreamConfig {
        UpstreamConfig {
            id: 0,
            name: name.to_string(),
            address: self.addr.ip(),
            port: self.addr.port(),
            protocol: Protocol::Tls,
            enabled: true,
            priority: 1,
            weight: 1,
            timeout_ms: None,
            tls_server_name: Some(server_name.to_string()),
            tls_ca_file: Some(std::path::PathBuf::from(TLS_CA_PATH)),
            ..Default::default()
        }
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::SeqCst)
    }

    pub async fn stop(self) {
        for t in self.tasks {
            t.abort();
        }
    }
}

/// Minimal no-auth SOCKS5 CONNECT proxy used to prove that upstream DNS
/// (including DoT) traverses the configured tunnel and never falls back to a
/// direct connection when the proxy is unavailable.
pub struct Socks5Proxy {
    pub addr: SocketAddr,
    pub connections: Arc<AtomicU64>,
    tasks: Vec<JoinHandle<()>>,
}

impl Socks5Proxy {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks");
        let addr = listener.local_addr().expect("socks addr");
        let connections = Arc::new(AtomicU64::new(0));
        let mut tasks = Vec::new();
        {
            let connections = Arc::clone(&connections);
            tasks.push(tokio::spawn(async move {
                loop {
                    let Ok((mut client, _)) = listener.accept().await else {
                        break;
                    };
                    let connections = Arc::clone(&connections);
                    tokio::spawn(async move {
                        let mut head = [0u8; 2];
                        if client.read_exact(&mut head).await.is_err() || head[0] != 5 {
                            return;
                        }
                        let mut methods = vec![0u8; usize::from(head[1])];
                        if client.read_exact(&mut methods).await.is_err() {
                            return;
                        }
                        if client.write_all(&[5, 0]).await.is_err() {
                            return;
                        }
                        let mut req = [0u8; 4];
                        if client.read_exact(&mut req).await.is_err() || req[1] != 1 {
                            return;
                        }
                        let target = match req[3] {
                            1 => {
                                let mut b = [0u8; 4];
                                if client.read_exact(&mut b).await.is_err() {
                                    return;
                                }
                                IpAddr::V4(Ipv4Addr::from(b))
                            }
                            4 => {
                                let mut b = [0u8; 16];
                                if client.read_exact(&mut b).await.is_err() {
                                    return;
                                }
                                IpAddr::V6(Ipv6Addr::from(b))
                            }
                            3 => {
                                let mut len = [0u8; 1];
                                if client.read_exact(&mut len).await.is_err() {
                                    return;
                                }
                                let mut name = vec![0u8; usize::from(len[0])];
                                if client.read_exact(&mut name).await.is_err() {
                                    return;
                                }
                                let Ok(name) = String::from_utf8(name) else {
                                    return;
                                };
                                let mut port = [0u8; 2];
                                if client.read_exact(&mut port).await.is_err() {
                                    return;
                                }
                                let port = u16::from_be_bytes(port);
                                let addrs =
                                    match tokio::net::lookup_host((name.as_str(), port)).await {
                                        Ok(addrs) => addrs.collect::<Vec<_>>(),
                                        Err(_) => return,
                                    };
                                match addrs.first() {
                                    Some(addr) => addr.ip(),
                                    None => return,
                                }
                            }
                            _ => return,
                        };
                        let mut port = [0u8; 2];
                        if client.read_exact(&mut port).await.is_err() {
                            return;
                        }
                        let port = u16::from_be_bytes(port);
                        let Ok(mut upstream) = TcpStream::connect((target, port)).await else {
                            let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                            return;
                        };
                        connections.fetch_add(1, Ordering::SeqCst);
                        let reply = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
                        if client.write_all(&reply).await.is_err() {
                            return;
                        }
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                    });
                }
            }));
        }
        Self {
            addr,
            connections,
            tasks,
        }
    }

    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::SeqCst)
    }

    pub async fn stop(self) {
        for t in self.tasks {
            t.abort();
        }
    }
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
    cfg.rrl.enabled = false;
    cfg.health.enabled = false;
    cfg.cache.enabled = false;
    cfg.upstreams.clear();
    // Tests intentionally start without credentials; the production default
    // is fail-closed, so opt in explicitly here.
    cfg.auth.allow_open_mode = true;
    cfg
}

pub async fn start_gateway(cfg: AppConfig) -> Gateway {
    res::runtime::start(cfg, None)
        .await
        .expect("gateway should start")
}

/// Start a gateway with password auth enabled (admin + optional viewer).
pub async fn start_gateway_with_passwords(
    cfg: AppConfig,
    admin_password: &str,
    viewer_password: Option<&str>,
) -> Gateway {
    let auth = std::sync::Arc::new(res::auth::AuthState::from_passwords(
        cfg.auth.clone(),
        Some(admin_password.to_string()),
        viewer_password.map(str::to_string),
    ));
    res::runtime::start_with_auth(cfg, None, auth)
        .await
        .expect("gateway should start")
}

/// Start a gateway that persists configuration mutations to `path`.
pub async fn start_gateway_with_path(cfg: AppConfig, path: std::path::PathBuf) -> Gateway {
    res::runtime::start(cfg, Some(path))
        .await
        .expect("gateway should start")
}

/// Send one A query over UDP and wait for a response (None on timeout/error).
pub async fn udp_query(server: SocketAddr, name: &str) -> Option<Message> {
    udp_query_timeout(server, name, Duration::from_secs(3)).await
}

/// Send a UDP query of the given record type (e.g. "ANY").
pub async fn udp_query_type(server: SocketAddr, name: &str, qtype: &str) -> Option<Message> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.ok()?;
    sock.connect(server).await.ok()?;
    let query = res::dns::msg::build_query(name, qtype).ok()?;
    sock.send(&query).await.ok()?;
    let mut buf = vec![0u8; 65_535];
    match tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => Message::from_vec(&buf[..n]).ok(),
        _ => None,
    }
}

pub async fn udp_query_timeout(server: SocketAddr, name: &str, wait: Duration) -> Option<Message> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.ok()?;
    sock.connect(server).await.ok()?;
    let query = res::dns::msg::build_query(name, "A").ok()?;
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
    let query = res::dns::msg::build_query(name, "A").ok()?;
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
    http_auth(method, addr, path, body, None).await
}

/// Like [`http`], with an optional `Authorization: Bearer <token>` header.
pub async fn http_auth(
    method: &str,
    addr: SocketAddr,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> (u16, String) {
    let mut headers = Vec::new();
    if let Some(t) = token {
        headers.push(("Authorization".to_string(), format!("Bearer {t}")));
    }
    http_headers(method, addr, path, body, &headers).await
}

/// HTTP request with arbitrary extra headers (Cookie, X-CSRF-Token, ...).
/// Returns `(status_code, response_body)`.
pub async fn http_headers(
    method: &str,
    addr: SocketAddr,
    path: &str,
    body: Option<&str>,
    extra_headers: &[(String, String)],
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("api connect");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
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

/// Extract a `Set-Cookie` value for `name` from a raw HTTP response string.
pub fn set_cookie(raw_response: &str, name: &str) -> Option<String> {
    for line in raw_response.split("\r\n") {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("set-cookie:")
            && lower.contains(&format!("{}=", name.to_ascii_lowercase()))
        {
            let value = line.split_once(':')?.1.trim();
            // "name=value; Path=/; ..."
            let cookie_pair = value.split(';').next()?.trim();
            let (_, v) = cookie_pair.split_once('=')?;
            return Some(v.to_string());
        }
    }
    None
}

/// Raw HTTP request returning the full response text (for Set-Cookie parsing).
pub async fn http_raw(
    method: &str,
    addr: SocketAddr,
    path: &str,
    body: Option<&str>,
    extra_headers: &[(String, String)],
) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("api connect");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
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
    String::from_utf8_lossy(&resp).into_owned()
}
