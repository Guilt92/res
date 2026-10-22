//! Outbound SOCKS5 / HTTP CONNECT transport for upstream DNS exchanges.
//!
//! This module deliberately implements only the small, testable subset needed
//! by the gateway: authenticated SOCKS5 TCP CONNECT + UDP ASSOCIATE, and HTTP
//! CONNECT with optional Basic authentication. It never resolves hostnames:
//! the configured proxy and every upstream are IP endpoints, so the DNS data
//! plane cannot recurse into itself while opening a query path.
//!
//! No secret is ever embedded in an error message. Errors carry a bounded
//! failure kind for metrics plus a detail string built from protocol data.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::config::{ProxyConfig, ProxyProtocol};

/// Bounded proxy failure kinds used as metric labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyErrorKind {
    Timeout,
    Network,
    Protocol,
    Auth,
    Rejected,
}

impl ProxyErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProxyErrorKind::Timeout => "timeout",
            ProxyErrorKind::Network => "network",
            ProxyErrorKind::Protocol => "protocol",
            ProxyErrorKind::Auth => "auth",
            ProxyErrorKind::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyError {
    pub kind: ProxyErrorKind,
    detail: String,
}

impl ProxyError {
    pub(crate) fn new(kind: ProxyErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    fn network(context: &str, e: std::io::Error) -> Self {
        Self::new(ProxyErrorKind::Network, format!("{context}: {e}"))
    }

    fn protocol(detail: impl Into<String>) -> Self {
        Self::new(ProxyErrorKind::Protocol, detail)
    }

    fn auth(detail: impl Into<String>) -> Self {
        Self::new(ProxyErrorKind::Auth, detail)
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proxy {}: {}", self.kind.as_str(), self.detail)
    }
}

impl std::error::Error for ProxyError {}

/// Established SOCKS5 UDP association. The TCP control connection must stay
/// alive for as long as datagrams are exchanged; dropping it invalidates the
/// relay mapping at the proxy.
#[derive(Debug)]
pub struct UdpAssociation {
    pub control: TcpStream,
    pub relay: SocketAddr,
}

/// Open a TCP tunnel to `target` through the configured proxy.
pub async fn connect_tcp(
    cfg: &ProxyConfig,
    target: SocketAddr,
    budget: Duration,
) -> Result<TcpStream, ProxyError> {
    let endpoint = cfg.endpoint();
    let protocol = cfg.protocol;
    let work = async move {
        let mut stream = TcpStream::connect(endpoint)
            .await
            .map_err(|e| ProxyError::network("connect proxy", e))?;
        let _ = stream.set_nodelay(true);
        match protocol {
            ProxyProtocol::Socks5 => {
                socks5_request(&mut stream, cfg, target, SocksCommand::Connect).await?;
            }
            ProxyProtocol::HttpConnect => {
                http_connect(&mut stream, cfg, target).await?;
            }
        }
        Ok(stream)
    };
    run_with_timeout(work, budget).await
}

/// Open a SOCKS5 UDP ASSOCIATE mapping. HTTP CONNECT cannot carry UDP and is
/// rejected by configuration validation before this is ever called.
pub async fn open_udp(cfg: &ProxyConfig, budget: Duration) -> Result<UdpAssociation, ProxyError> {
    if cfg.protocol != ProxyProtocol::Socks5 {
        return Err(ProxyError::new(
            ProxyErrorKind::Rejected,
            "UDP transport requires proxy.protocol = \"socks5\"",
        ));
    }
    let endpoint = cfg.endpoint();
    let work = async move {
        let mut stream = TcpStream::connect(endpoint)
            .await
            .map_err(|e| ProxyError::network("connect proxy", e))?;
        let _ = stream.set_nodelay(true);
        // 0.0.0.0:0 asks the proxy to choose the relay; the association is
        // scoped to this TCP control connection.
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let relay = socks5_request(&mut stream, cfg, target, SocksCommand::UdpAssociate).await?;
        let relay = if relay.ip().is_unspecified() {
            SocketAddr::new(endpoint.ip(), relay.port())
        } else {
            relay
        };
        if relay.port() == 0 {
            return Err(ProxyError::protocol(
                "proxy returned a UDP relay with port 0",
            ));
        }
        Ok(UdpAssociation {
            control: stream,
            relay,
        })
    };
    run_with_timeout(work, budget).await
}

async fn run_with_timeout<F, T>(work: F, budget: Duration) -> Result<T, ProxyError>
where
    F: std::future::Future<Output = Result<T, ProxyError>>,
{
    match timeout(budget, work).await {
        Ok(result) => result,
        Err(_) => Err(ProxyError::new(
            ProxyErrorKind::Timeout,
            "proxy handshake timed out",
        )),
    }
}

#[derive(Debug, Clone, Copy)]
enum SocksCommand {
    Connect,
    UdpAssociate,
}

impl SocksCommand {
    fn code(self) -> u8 {
        match self {
            SocksCommand::Connect => 0x01,
            SocksCommand::UdpAssociate => 0x03,
        }
    }
}

async fn socks5_request(
    stream: &mut TcpStream,
    cfg: &ProxyConfig,
    target: SocketAddr,
    command: SocksCommand,
) -> Result<SocketAddr, ProxyError> {
    let use_auth = !cfg.username.is_empty();
    let methods: &[u8] = if use_auth { &[0x02] } else { &[0x00] };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    stream
        .write_all(&greeting)
        .await
        .map_err(|e| ProxyError::network("SOCKS5 greeting write", e))?;

    let mut selection = [0u8; 2];
    stream
        .read_exact(&mut selection)
        .await
        .map_err(|e| ProxyError::network("SOCKS5 greeting read", e))?;
    if selection[0] != 0x05 {
        return Err(ProxyError::protocol(format!(
            "unexpected SOCKS version {}",
            selection[0]
        )));
    }
    match selection[1] {
        0x00 if !use_auth => {}
        0x02 if use_auth => {
            let user = cfg.username.as_bytes();
            let pass = cfg.password.as_bytes();
            let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
            auth.push(0x01);
            auth.push(user.len() as u8);
            auth.extend_from_slice(user);
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass);
            stream
                .write_all(&auth)
                .await
                .map_err(|e| ProxyError::network("SOCKS5 auth write", e))?;
            let mut reply = [0u8; 2];
            stream
                .read_exact(&mut reply)
                .await
                .map_err(|e| ProxyError::network("SOCKS5 auth read", e))?;
            if reply[0] != 0x01 {
                return Err(ProxyError::protocol(format!(
                    "unexpected SOCKS auth version {}",
                    reply[0]
                )));
            }
            if reply[1] != 0x00 {
                return Err(ProxyError::auth(format!(
                    "proxy rejected credentials (status {})",
                    reply[1]
                )));
            }
        }
        0xff => {
            return Err(ProxyError::auth(
                "proxy rejected every offered authentication method",
            ))
        }
        method => {
            return Err(ProxyError::auth(format!(
                "proxy selected unsupported authentication method {method:#04x}"
            )))
        }
    }

    let mut request = Vec::with_capacity(4 + 16 + 2);
    request.extend_from_slice(&[0x05, command.code(), 0x00]);
    encode_socks_addr(&mut request, target);
    stream
        .write_all(&request)
        .await
        .map_err(|e| ProxyError::network("SOCKS5 request write", e))?;

    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|e| ProxyError::network("SOCKS5 reply read", e))?;
    if head[0] != 0x05 {
        return Err(ProxyError::protocol(format!(
            "unexpected SOCKS reply version {}",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(ProxyError::new(
            ProxyErrorKind::Rejected,
            format!(
                "proxy CONNECT rejected with SOCKS reply code {:#04x}",
                head[1]
            ),
        ));
    }
    read_socks_addr(stream, head[3]).await
}

fn encode_socks_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

async fn read_socks_addr<R>(stream: &mut R, atyp: u8) -> Result<SocketAddr, ProxyError>
where
    R: AsyncRead + Unpin,
{
    let ip = match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            stream
                .read_exact(&mut b)
                .await
                .map_err(|e| ProxyError::network("SOCKS5 reply address read", e))?;
            IpAddr::V4(Ipv4Addr::from(b))
        }
        0x04 => {
            let mut b = [0u8; 16];
            stream
                .read_exact(&mut b)
                .await
                .map_err(|e| ProxyError::network("SOCKS5 reply address read", e))?;
            IpAddr::V6(Ipv6Addr::from(b))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|e| ProxyError::network("SOCKS5 reply name length read", e))?;
            let mut name = vec![0u8; usize::from(len[0])];
            stream
                .read_exact(&mut name)
                .await
                .map_err(|e| ProxyError::network("SOCKS5 reply name read", e))?;
            return Err(ProxyError::protocol(format!(
                "proxy returned a domain address ('{}'); an IP relay is required",
                String::from_utf8_lossy(&name)
            )));
        }
        other => {
            return Err(ProxyError::protocol(format!(
                "unsupported SOCKS5 address type {other:#04x}"
            )))
        }
    };
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .map_err(|e| ProxyError::network("SOCKS5 reply port read", e))?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

async fn http_connect(
    stream: &mut TcpStream,
    cfg: &ProxyConfig,
    target: SocketAddr,
) -> Result<(), ProxyError> {
    let authority = target.to_string();
    let mut req = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if !cfg.username.is_empty() {
        let raw = format!("{}:{}", cfg.username, cfg.password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| ProxyError::network("HTTP CONNECT write", e))?;

    // Read exactly one header block without over-reading any tunnel payload
    // (the connection is handed to the DNS/TLS layer immediately). One-byte
    // reads are fine here: this happens once per upstream exchange, and the
    // bound prevents a hostile proxy from growing memory.
    const MAX_HEADER: usize = 8 * 1024;
    let mut header = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        if header.len() >= MAX_HEADER {
            return Err(ProxyError::protocol(
                "HTTP proxy response headers exceed 8 KiB",
            ));
        }
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| ProxyError::network("HTTP CONNECT response read", e))?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&header)
        .map_err(|_| ProxyError::protocol("HTTP proxy response headers are not UTF-8"))?;
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| ProxyError::protocol("malformed HTTP proxy status line"))?;
    if (200..300).contains(&status) {
        return Ok(());
    }
    if status == 407 {
        return Err(ProxyError::auth(
            "HTTP proxy rejected proxy authentication (407)",
        ));
    }
    Err(ProxyError::new(
        ProxyErrorKind::Rejected,
        format!("HTTP CONNECT rejected with status {status}"),
    ))
}

/// SOCKS5 UDP request header size for one target (RSV/FRAG/ATYP/ADDR/PORT).
pub fn udp_header_len(target: SocketAddr) -> usize {
    4 + if target.is_ipv4() { 4 } else { 16 } + 2
}

/// Encapsulate one DNS payload for a SOCKS5 UDP relay.
pub fn encode_udp(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(udp_header_len(target) + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    encode_socks_addr(&mut out, target);
    out.extend_from_slice(payload);
    out
}

/// Decode one relay datagram and verify it belongs to the expected upstream.
/// A mismatched source is ignored by the caller (same policy as direct UDP:
/// late/spoofed datagrams never become client answers).
pub fn decode_udp(target: SocketAddr, packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < udp_header_len(target) {
        return None;
    }
    if packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return None;
    }
    let (ip, addr_len) = match packet[3] {
        0x01 if target.is_ipv4() => {
            let mut b = [0u8; 4];
            b.copy_from_slice(&packet[4..8]);
            (IpAddr::V4(Ipv4Addr::from(b)), 4)
        }
        0x04 if target.is_ipv6() => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&packet[4..20]);
            (IpAddr::V6(Ipv6Addr::from(b)), 16)
        }
        _ => return None,
    };
    let port_at = 4 + addr_len;
    let port = u16::from_be_bytes([packet[port_at], packet[port_at + 1]]);
    if ip != target.ip() || port != target.port() {
        return None;
    }
    Some(&packet[port_at + 2..])
}

/// Bind and connect the datagram socket used with a relay. Connecting the
/// socket makes the kernel reject datagrams from any other source.
pub async fn relay_socket(relay: SocketAddr) -> Result<UdpSocket, ProxyError> {
    let bind = if relay.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| ProxyError::network("bind UDP relay socket", e))?;
    socket
        .connect(relay)
        .await
        .map_err(|e| ProxyError::network("connect UDP relay", e))?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn udp_roundtrip_validates_source() {
        let target: SocketAddr = "192.0.2.53:53".parse().unwrap();
        let wire = encode_udp(target, b"dns");
        assert_eq!(decode_udp(target, &wire), Some(&b"dns"[..]));
        let other: SocketAddr = "192.0.2.54:53".parse().unwrap();
        assert_eq!(decode_udp(other, &wire), None);
        let mut fragmented = wire.clone();
        fragmented[2] = 1;
        assert_eq!(decode_udp(target, &fragmented), None);
    }

    async fn read_socks_request(stream: &mut TcpStream, require_auth: bool) -> (u8, SocketAddr) {
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], 5);
        let mut methods = vec![0u8; usize::from(head[1])];
        stream.read_exact(&mut methods).await.unwrap();
        let method = if require_auth { 2 } else { 0 };
        stream.write_all(&[5, method]).await.unwrap();
        if require_auth {
            let mut auth = [0u8; 2];
            stream.read_exact(&mut auth).await.unwrap();
            assert_eq!(auth[0], 1);
            let mut user = vec![0u8; usize::from(auth[1])];
            stream.read_exact(&mut user).await.unwrap();
            let mut plen = [0u8; 1];
            stream.read_exact(&mut plen).await.unwrap();
            let mut pass = vec![0u8; usize::from(plen[0])];
            stream.read_exact(&mut pass).await.unwrap();
            assert_eq!(&user, b"user");
            assert_eq!(&pass, b"pass");
            stream.write_all(&[1, 0]).await.unwrap();
        }
        let mut req = [0u8; 4];
        stream.read_exact(&mut req).await.unwrap();
        assert_eq!(req[0], 5);
        let mut addr = [0u8; 4];
        stream.read_exact(&mut addr).await.unwrap();
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await.unwrap();
        (
            req[1],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), u16::from_be_bytes(port)),
        )
    }

    async fn spawn_tcp_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 32];
            loop {
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).await.unwrap();
            }
        });
        addr
    }

    #[tokio::test]
    async fn socks5_authenticated_connect_traverses_to_target() {
        let echo = spawn_tcp_echo().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let (cmd, target) = read_socks_request(&mut control, true).await;
            assert_eq!(cmd, 1);
            assert_eq!(target, echo);
            let mut out = TcpStream::connect(target).await.unwrap();
            let mut bnd = Vec::new();
            encode_socks_addr(&mut bnd, out.local_addr().unwrap());
            control.write_all(&[5, 0, 0, bnd[0]]).await.unwrap();
            control.write_all(&bnd[1..]).await.unwrap();
            tokio::io::copy_bidirectional(&mut control, &mut out)
                .await
                .unwrap();
        });
        let cfg = ProxyConfig {
            enabled: true,
            protocol: ProxyProtocol::Socks5,
            address: proxy_addr.ip(),
            port: proxy_addr.port(),
            username: "user".into(),
            password: "pass".into(),
            connect_timeout_ms: 2_000,
        };
        let mut stream = connect_tcp(&cfg, echo, Duration::from_secs(2))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    }

    #[tokio::test]
    async fn socks5_udp_associate_relays_encapsulated_datagrams() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let udp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = relay.recv_from(&mut buf).await.unwrap();
            let target: SocketAddr = "192.0.2.53:53".parse().unwrap();
            assert_eq!(decode_udp(target, &buf[..n]), Some(&b"query"[..]));
            let packet = encode_udp(target, b"answer");
            relay.send_to(&packet, peer).await.unwrap();
        });
        tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let (cmd, _) = read_socks_request(&mut control, false).await;
            assert_eq!(cmd, 3);
            let mut bnd = Vec::new();
            encode_socks_addr(&mut bnd, relay_addr);
            control.write_all(&[5, 0, 0, bnd[0]]).await.unwrap();
            control.write_all(&bnd[1..]).await.unwrap();
            // Hold the control connection open for the association lifetime.
            let mut b = [0u8; 1];
            let _ = control.read(&mut b).await;
        });
        let cfg = ProxyConfig {
            enabled: true,
            protocol: ProxyProtocol::Socks5,
            address: proxy_addr.ip(),
            port: proxy_addr.port(),
            ..Default::default()
        };
        let assoc = open_udp(&cfg, Duration::from_secs(2)).await.unwrap();
        assert_eq!(assoc.relay, relay_addr);
        let _control = assoc.control;
        let sock = relay_socket(assoc.relay).await.unwrap();
        let target: SocketAddr = "192.0.2.53:53".parse().unwrap();
        sock.send(&encode_udp(target, b"query")).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = sock.recv(&mut buf).await.unwrap();
        assert_eq!(decode_udp(target, &buf[..n]), Some(&b"answer"[..]));
        udp_task.await.unwrap();
    }

    #[tokio::test]
    async fn http_connect_sends_basic_auth_and_tunnels() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(req.starts_with("CONNECT 192.0.2.53:53 HTTP/1.1\r\n"));
            assert!(req.contains("Proxy-Authorization: Basic "));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            stream.write_all(b"tunneled").await.unwrap();
        });
        let cfg = ProxyConfig {
            enabled: true,
            protocol: ProxyProtocol::HttpConnect,
            address: proxy_addr.ip(),
            port: proxy_addr.port(),
            username: "user".into(),
            password: "pass".into(),
            connect_timeout_ms: 2_000,
        };
        let mut stream = connect_tcp(
            &cfg,
            "192.0.2.53:53".parse().unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let mut got = [0u8; 8];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"tunneled");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_connect_rejects_407_without_leaking_password() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let cfg = ProxyConfig {
            enabled: true,
            protocol: ProxyProtocol::HttpConnect,
            address: proxy_addr.ip(),
            port: proxy_addr.port(),
            username: "user".into(),
            password: "super-secret".into(),
            connect_timeout_ms: 2_000,
        };
        let err = connect_tcp(
            &cfg,
            "192.0.2.53:53".parse().unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind, ProxyErrorKind::Auth);
        assert!(!err.to_string().contains("super-secret"));
    }
}
