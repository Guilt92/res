//! Upstream DNS exchange: query out, correlated response in.
//!
//! The gateway preserves the client's EDNS, DO bit, RD flag and question, but
//! replaces the DNS transaction id with a fresh unpredictable id for every
//! upstream exchange. Responses are validated by that id, message type and
//! question section before being accepted.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::config::{Protocol, ProxyConfig, UpstreamConfig};
use crate::dns::msg::{self, ParsedQuery, ResponseView};
use crate::metrics::Metrics;
use crate::proxy::{self, ProxyError};

/// Maximum DNS message size over TCP (2-byte length prefix).
pub const MAX_TCP_MESSAGE: usize = 65_535;
/// Maximum DNS message size over UDP without EDNS (RFC 1035).
pub const MAX_UDP_PLAIN: usize = 512;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExchangeError {
    #[error("timeout")]
    Timeout,
    #[error("network error: {0}")]
    Network(String),
    #[error("invalid response: {0}")]
    Invalid(String),
    #[error("{0}")]
    Proxy(ProxyError),
}

#[derive(Debug)]
pub struct ExchangeOk {
    pub response: Vec<u8>,
    pub view: ResponseView,
    pub latency: Duration,
    /// True when this exchange traversed the configured upstream proxy.
    pub proxied: bool,
    /// Time spent establishing the TCP tunnel / SOCKS association, separate
    /// from DNS response latency.
    pub proxy_connect_latency: Option<Duration>,
    /// Proxy protocol label for metrics (`socks5` / `http_connect`).
    pub proxy_protocol: Option<&'static str>,
}

/// Performs DNS exchanges with upstreams over UDP/TCP/DoT.
#[derive(Clone)]
pub struct Forwarder {
    /// Retry over TCP when an upstream UDP response is truncated (TC=1).
    pub tcp_fallback: bool,
    proxy: Option<Arc<ProxyConfig>>,
    metrics: Option<Arc<Metrics>>,
    /// Per-datagram receive ceiling from `server.max_udp_packet_size`.
    /// Bounds attacker-influenced EDNS advertisements to the operator's
    /// configured egress budget instead of allocating up to 64 KiB per query.
    udp_cap: usize,
}

impl std::fmt::Debug for Forwarder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forwarder")
            .field("tcp_fallback", &self.tcp_fallback)
            .field("proxied", &self.proxy.is_some())
            .finish()
    }
}

impl Forwarder {
    pub fn new(tcp_fallback: bool) -> Self {
        Self {
            tcp_fallback,
            proxy: None,
            metrics: None,
            udp_cap: 65_535,
        }
    }

    /// Build a forwarder from one data-plane configuration snapshot. The
    /// proxy is cloned through an `Arc`, so the per-query cost stays trivial.
    pub fn with_proxy(
        tcp_fallback: bool,
        proxy: Option<Arc<ProxyConfig>>,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        Self {
            tcp_fallback,
            proxy,
            metrics,
            udp_cap: 65_535,
        }
    }

    /// Apply the live `server.max_udp_packet_size` receive ceiling.
    pub fn with_udp_cap(mut self, cap: usize) -> Self {
        self.udp_cap = cap.clamp(super::forward::MIN_RECV_CAP, 65_535);
        self
    }

    /// Forwarder reflecting the *current* live configuration. Used by health
    /// and API probes so a proxy change applies without a restart.
    pub fn from_shared(shared: &crate::shared::Shared) -> Self {
        let rt = shared.rt.load();
        Self::with_proxy(
            rt.upstream_tcp_fallback,
            rt.proxy.clone(),
            Some(shared.metrics.clone()),
        )
        .with_udp_cap(rt.max_udp_packet_size)
    }

    async fn connect_stream(
        &self,
        target: SocketAddr,
        budget: Duration,
    ) -> Result<(TcpStream, Option<Duration>, Option<&'static str>), ExchangeError> {
        let Some(cfg) = &self.proxy else {
            let stream = TcpStream::connect(target)
                .await
                .map_err(|e| ExchangeError::Network(format!("connect: {e}")))?;
            let _ = stream.set_nodelay(true);
            return Ok((stream, None, None));
        };
        let proto = cfg.protocol.as_str();
        let limit = budget.min(Duration::from_millis(cfg.connect_timeout_ms));
        let start = Instant::now();
        match proxy::connect_tcp(cfg, target, limit).await {
            Ok(stream) => {
                let elapsed = start.elapsed();
                self.record_proxy_connect(proto, None, elapsed);
                Ok((stream, Some(elapsed), Some(proto)))
            }
            Err(e) => {
                self.record_proxy_connect(proto, Some(&e), start.elapsed());
                Err(ExchangeError::Proxy(e))
            }
        }
    }

    fn record_proxy_connect(&self, proto: &str, error: Option<&ProxyError>, elapsed: Duration) {
        let Some(metrics) = &self.metrics else { return };
        let result = error.map(|e| e.kind.as_str()).unwrap_or("success");
        metrics
            .proxy_connect_total
            .with_label_values(&[proto, result])
            .inc();
        if error.is_none() {
            metrics
                .proxy_connect_duration_seconds
                .with_label_values(&[proto])
                .observe(elapsed.as_secs_f64());
        }
    }

    fn record_tunnel_bytes(&self, direction: &str, bytes: usize) {
        if self.proxy.is_none() {
            return;
        }
        if let Some(metrics) = &self.metrics {
            metrics
                .proxy_tunnel_bytes_total
                .with_label_values(&[direction])
                .inc_by(bytes as u64);
        }
    }

    fn randomized_query(query: &ParsedQuery, raw: &[u8]) -> (ParsedQuery, Vec<u8>) {
        let mut wire = raw.to_vec();
        if wire.len() < 2 {
            return (query.clone(), wire);
        }
        let mut id = rand::random::<u16>();
        if id == query.id {
            id = id.wrapping_add(1);
        }
        wire[0..2].copy_from_slice(&id.to_be_bytes());
        let mut correlated = query.clone();
        correlated.id = id;
        (correlated, wire)
    }

    /// Exchange using the upstream's configured protocol.
    pub async fn exchange(
        &self,
        up: &UpstreamConfig,
        query: &ParsedQuery,
        raw: &[u8],
        budget: Duration,
    ) -> Result<ExchangeOk, ExchangeError> {
        self.exchange_with(up, query, raw, budget, up.protocol)
            .await
    }

    /// Exchange over an explicit transport (health checks probe both).
    pub async fn exchange_with(
        &self,
        up: &UpstreamConfig,
        query: &ParsedQuery,
        raw: &[u8],
        budget: Duration,
        proto: Protocol,
    ) -> Result<ExchangeOk, ExchangeError> {
        if let (Some(cfg), Some(metrics)) = (&self.proxy, &self.metrics) {
            let transport = match proto {
                Protocol::Udp => "udp",
                Protocol::Tcp => "tcp",
                Protocol::Tls => "tls",
            };
            metrics
                .proxy_requests_total
                .with_label_values(&[cfg.protocol.as_str(), transport])
                .inc();
        }
        match proto {
            Protocol::Udp => self.exchange_udp(up, query, raw, budget).await,
            Protocol::Tcp => self.exchange_tcp(up, query, raw, budget).await,
            Protocol::Tls => self.exchange_tls(up, query, raw, budget).await,
        }
    }

    async fn exchange_udp(
        &self,
        up: &UpstreamConfig,
        query: &ParsedQuery,
        raw: &[u8],
        budget: Duration,
    ) -> Result<ExchangeOk, ExchangeError> {
        if raw.len() > MAX_UDP_PLAIN && !query.has_edns {
            // A UDP payload beyond 512 without EDNS would be non-compliant.
            return Err(ExchangeError::Invalid(
                "query too large for plain UDP".into(),
            ));
        }
        if self.proxy.is_some() {
            return self.exchange_udp_proxy(up, query, raw, budget).await;
        }
        let (correlated, wire) = Self::randomized_query(query, raw);
        let target = SocketAddr::new(up.address, up.port);
        let bind: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().expect("v4 bind")
        } else {
            "[::]:0".parse().expect("v6 bind")
        };

        let start = Instant::now();
        let deadline = start + budget;

        let sock = UdpSocket::bind(bind)
            .await
            .map_err(|e| ExchangeError::Network(format!("bind: {e}")))?;
        sock.connect(target)
            .await
            .map_err(|e| ExchangeError::Network(format!("connect: {e}")))?;
        sock.send(&wire)
            .await
            .map_err(|e| ExchangeError::Network(format!("send: {e}")))?;

        // Receive buffer sized from the client's advertised EDNS payload
        // (RFC 6891: a server must not exceed it). Plain-UDP queries get the
        // DNS flag-day 1232 floor, which also survives servers that ignore
        // the 512-byte RFC 1035 limit. Bounded, far below the old fixed 64 KiB.
        //
        // One extra byte: `recv` filling it means the datagram is larger than
        // the client can receive — a detectable overflow instead of a silent
        // mid-record cut that the parser would only see as garbage.
        let expected = recv_buf_size(query).min(self.udp_cap);
        let mut buf = vec![0u8; expected + 1];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ExchangeError::Timeout);
            }
            let received = match timeout(remaining, sock.recv(&mut buf)).await {
                Err(_) => return Err(ExchangeError::Timeout),
                Ok(Err(e)) => return Err(ExchangeError::Network(format!("recv: {e}"))),
                Ok(Ok(n)) => n,
            };
            let oversized = received > expected;

            // Ignore packets that cannot be parsed or correlated (late
            // responses from a previous attempt, spoofed datagrams, ...).
            let view = match msg::parse_response(&buf[..received]) {
                Ok(v) => v,
                Err(_) => {
                    if oversized {
                        // Oversized *and* cut mid-record: the full message can
                        // never fit this client's UDP limit — answer TC=1 from
                        // the query so the client retries over TCP now, rather
                        // than waiting out the deadline for a packet we will
                        // never be able to parse.
                        let mut stub = msg::error_response(&correlated, msg::Rcode::NoError);
                        if stub.len() >= 4 {
                            stub[2] |= 0x02; // TC: truncated, retry over TCP
                        }
                        let view = match msg::parse_response(&stub) {
                            Ok(v) => v,
                            Err(_) => continue, // unreachable for our own stub
                        };
                        return Ok(ExchangeOk {
                            response: stub,
                            view,
                            latency: start.elapsed(),
                            proxied: false,
                            proxy_connect_latency: None,
                            proxy_protocol: None,
                        });
                    }
                    continue;
                }
            };
            if !msg::correlates(&correlated, &view) {
                continue;
            }

            if view.truncated && self.tcp_fallback && up.protocol == Protocol::Udp {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if !remaining.is_zero() {
                    if let Ok(ok) = self.exchange_tcp(up, query, raw, remaining).await {
                        return Ok(ExchangeOk {
                            response: ok.response,
                            view: ok.view,
                            latency: start.elapsed(),
                            proxied: ok.proxied,
                            proxy_connect_latency: ok.proxy_connect_latency,
                            proxy_protocol: ok.proxy_protocol,
                        });
                    }
                }
            }

            return Ok(ExchangeOk {
                response: buf[..received].to_vec(),
                view,
                latency: start.elapsed(),
                proxied: false,
                proxy_connect_latency: None,
                proxy_protocol: None,
            });
        }
    }

    /// SOCKS5 UDP ASSOCIATE path: one TCP control connection per attempt (a
    /// fresh unpredictable query id is still used inside the payload). The
    /// relay is connected so only the proxy can inject datagrams; each reply
    /// is additionally checked against the target address.
    async fn exchange_udp_proxy(
        &self,
        up: &UpstreamConfig,
        query: &ParsedQuery,
        raw: &[u8],
        budget: Duration,
    ) -> Result<ExchangeOk, ExchangeError> {
        let Some(cfg) = &self.proxy else {
            return Err(ExchangeError::Invalid("proxy missing".into()));
        };
        if cfg.protocol != crate::config::ProxyProtocol::Socks5 {
            return Err(ExchangeError::Proxy(ProxyError::new(
                crate::proxy::ProxyErrorKind::Rejected,
                "HTTP CONNECT cannot carry UDP DNS",
            )));
        }
        let (correlated, wire) = Self::randomized_query(query, raw);
        let target = SocketAddr::new(up.address, up.port);
        let start = Instant::now();
        let deadline = start + budget;
        let proto = cfg.protocol.as_str();
        let limit = budget.min(Duration::from_millis(cfg.connect_timeout_ms));
        let connect_start = Instant::now();
        let assoc = match proxy::open_udp(cfg, limit).await {
            Ok(a) => {
                let elapsed = connect_start.elapsed();
                self.record_proxy_connect(proto, None, elapsed);
                a
            }
            Err(e) => {
                self.record_proxy_connect(proto, Some(&e), connect_start.elapsed());
                return Err(ExchangeError::Proxy(e));
            }
        };
        let connect_latency = connect_start.elapsed();
        // Keep the TCP control connection alive for the whole exchange.
        let _control = assoc.control;
        let sock = proxy::relay_socket(assoc.relay)
            .await
            .map_err(ExchangeError::Proxy)?;
        let packet = proxy::encode_udp(target, &wire);
        sock.send(&packet)
            .await
            .map_err(|e| ExchangeError::Network(format!("proxy UDP send: {e}")))?;
        self.record_tunnel_bytes("sent", packet.len());

        let expected = recv_buf_size(query).min(self.udp_cap);
        let mut buf = vec![0u8; expected + 1 + proxy::udp_header_len(target)];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ExchangeError::Timeout);
            }
            let received = match timeout(remaining, sock.recv(&mut buf)).await {
                Err(_) => return Err(ExchangeError::Timeout),
                Ok(Err(e)) => return Err(ExchangeError::Network(format!("proxy UDP recv: {e}"))),
                Ok(Ok(n)) => n,
            };
            self.record_tunnel_bytes("received", received);
            let Some(payload) = proxy::decode_udp(target, &buf[..received]) else {
                continue;
            };
            let oversized = payload.len() > expected;
            let view = match msg::parse_response(payload) {
                Ok(v) => v,
                Err(_) => {
                    if oversized {
                        let mut stub = msg::error_response(&correlated, msg::Rcode::NoError);
                        if stub.len() >= 4 {
                            stub[2] |= 0x02;
                        }
                        let view = match msg::parse_response(&stub) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        return Ok(ExchangeOk {
                            response: stub,
                            view,
                            latency: start.elapsed(),
                            proxied: true,
                            proxy_connect_latency: Some(connect_latency),
                            proxy_protocol: Some(proto),
                        });
                    }
                    continue;
                }
            };
            if !msg::correlates(&correlated, &view) {
                continue;
            }
            if view.truncated && self.tcp_fallback && up.protocol == Protocol::Udp {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if !remaining.is_zero() {
                    if let Ok(ok) = self.exchange_tcp(up, query, raw, remaining).await {
                        return Ok(ExchangeOk {
                            response: ok.response,
                            view: ok.view,
                            latency: start.elapsed(),
                            proxied: true,
                            proxy_connect_latency: ok.proxy_connect_latency,
                            proxy_protocol: ok.proxy_protocol,
                        });
                    }
                }
            }
            return Ok(ExchangeOk {
                response: payload.to_vec(),
                view,
                latency: start.elapsed(),
                proxied: true,
                proxy_connect_latency: Some(connect_latency),
                proxy_protocol: Some(proto),
            });
        }
    }

    async fn exchange_tcp(
        &self,
        up: &UpstreamConfig,
        query: &ParsedQuery,
        raw: &[u8],
        budget: Duration,
    ) -> Result<ExchangeOk, ExchangeError> {
        if raw.len() > MAX_TCP_MESSAGE {
            return Err(ExchangeError::Invalid("query too large for TCP".into()));
        }
        let target = SocketAddr::new(up.address, up.port);
        let start = Instant::now();

        let result = timeout(budget, async {
            let (stream, proxy_latency, proxy_protocol) =
                self.connect_stream(target, budget).await?;
            let mut ok = self.exchange_framed(query, raw, stream).await?;
            ok.proxied = proxy_latency.is_some();
            ok.proxy_connect_latency = proxy_latency;
            ok.proxy_protocol = proxy_protocol;
            Ok(ok)
        })
        .await;

        finish_exchange(result, start)
    }

    /// DNS-over-TLS (RFC 7858): TCP framing inside a certificate-validated TLS
    /// session. There is no plaintext retry or downgrade: a handshake or
    /// identity failure is a hard upstream failure.
    async fn exchange_tls(
        &self,
        up: &UpstreamConfig,
        query: &ParsedQuery,
        raw: &[u8],
        budget: Duration,
    ) -> Result<ExchangeOk, ExchangeError> {
        if raw.len() > MAX_TCP_MESSAGE {
            return Err(ExchangeError::Invalid("query too large for TLS".into()));
        }
        let server_name = up
            .tls_server_name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .ok_or_else(|| {
                ExchangeError::Invalid(format!(
                    "upstream '{}' uses protocol tls without tls_server_name",
                    up.name
                ))
            })?;
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|e| ExchangeError::Invalid(format!("invalid tls_server_name: {e}")))?;
        let config = tls_client_config(up.tls_ca_file.as_deref())?;
        let target = SocketAddr::new(up.address, up.port);
        let start = Instant::now();

        let result = timeout(budget, async {
            let (stream, proxy_latency, proxy_protocol) =
                self.connect_stream(target, budget).await?;
            let mut stream = TlsConnector::from(config)
                .connect(server_name, stream)
                .await
                .map_err(|e| ExchangeError::Network(format!("tls handshake: {e}")))?;
            let mut ok = self.exchange_framed(query, raw, &mut stream).await?;
            ok.proxied = proxy_latency.is_some();
            ok.proxy_connect_latency = proxy_latency;
            ok.proxy_protocol = proxy_protocol;
            Ok(ok)
        })
        .await;

        finish_exchange(result, start)
    }

    /// Write one length-prefixed DNS query and read one correlated response.
    /// Latency is filled in by the caller around the complete exchange.
    async fn exchange_framed<S>(
        &self,
        query: &ParsedQuery,
        raw: &[u8],
        mut stream: S,
    ) -> Result<ExchangeOk, ExchangeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (correlated, wire) = Self::randomized_query(query, raw);
        let mut frame = Vec::with_capacity(2 + wire.len());
        frame.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        frame.extend_from_slice(&wire);
        stream
            .write_all(&frame)
            .await
            .map_err(|e| ExchangeError::Network(format!("write: {e}")))?;
        self.record_tunnel_bytes("sent", frame.len());

        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| ExchangeError::Network(format!("read len: {e}")))?;
        let len = usize::from(u16::from_be_bytes(len_buf));
        if len < 12 {
            return Err(ExchangeError::Invalid(format!("short frame ({len} bytes)")));
        }
        let mut resp = vec![0u8; len];
        stream
            .read_exact(&mut resp)
            .await
            .map_err(|e| ExchangeError::Network(format!("read body: {e}")))?;
        self.record_tunnel_bytes("received", 2 + len);

        let view = msg::parse_response(&resp).map_err(ExchangeError::Invalid)?;
        if !msg::correlates(&correlated, &view) {
            return Err(ExchangeError::Invalid(
                "response does not match query".into(),
            ));
        }
        Ok(ExchangeOk {
            response: resp,
            view,
            latency: Duration::ZERO,
            proxied: false,
            proxy_connect_latency: None,
            proxy_protocol: None,
        })
    }
}

/// Normalize the timeout result and stamp the measured latency on success.
fn finish_exchange(
    result: Result<Result<ExchangeOk, ExchangeError>, tokio::time::error::Elapsed>,
    start: Instant,
) -> Result<ExchangeOk, ExchangeError> {
    match result {
        Err(_) => Err(ExchangeError::Timeout),
        Ok(Ok(mut ok)) => {
            ok.latency = start.elapsed();
            Ok(ok)
        }
        Ok(Err(e)) => Err(e),
    }
}

/// Cache rustls client configs by CA bundle path. The trust roots are loaded
/// once per path; changing the PEM contents requires a process restart (the
/// same operational contract as other startup-loaded TLS material).
fn tls_client_config(ca_file: Option<&Path>) -> Result<Arc<rustls::ClientConfig>, ExchangeError> {
    static CACHE: OnceLock<Mutex<HashMap<Option<PathBuf>, Arc<rustls::ClientConfig>>>> =
        OnceLock::new();
    let key = ca_file.map(Path::to_path_buf);
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(config) = cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned()
    {
        return Ok(config);
    }
    let config = crate::tls::upstream_client_config(ca_file)
        .map_err(|e| ExchangeError::Invalid(format!("TLS client setup: {e:#}")))?;
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(key)
        .or_insert_with(|| Arc::clone(&config));
    Ok(config)
}

/// DNS flag day 2020 minimum safe UDP payload (also the receive floor for
/// plain-UDP exchanges: some servers exceed RFC 1035's 512 without EDNS).
const MIN_RECV_BUF: usize = 1232;

/// Lowest receive ceiling accepted by validation (512-byte legacy DNS is
/// lifted to the 1232-byte flag-day floor).
const MIN_RECV_CAP: usize = 1232;

/// Receive buffer size for one upstream UDP exchange: the client's advertised
/// EDNS payload clamped to a sane window, or the 1232-byte floor for
/// plain-UDP queries. Never larger than needed, never smaller than a
/// conformant response.
fn recv_buf_size(query: &ParsedQuery) -> usize {
    let advertised = query
        .edns_payload
        .map(|p| usize::from(p).max(MIN_RECV_BUF))
        .unwrap_or(MIN_RECV_BUF);
    advertised.min(MAX_TCP_MESSAGE)
}

/// Enforce the client's UDP response size limit: RFC 1035's 512-byte limit
/// for clients that did not advertise EDNS, or the client's advertised EDNS
/// payload when it is smaller than the response — and in all cases the
/// operator's `server.max_udp_packet_size` ceiling (bounds fragmentation for
/// every client, EDNS or not). Oversized responses are truncated (TC=1) so
/// the client retries over TCP for the full answer. When the response cannot
/// even be decoded (typically a datagram cut mid-record by the receive
/// buffer), a TC=1 stub built from the *query* is returned so the client
/// still learns to retry over TCP instead of us forwarding a packet we know
/// exceeds its limit.
pub fn enforce_client_udp_limit(
    response: Vec<u8>,
    transport_is_udp: bool,
    client_has_edns: bool,
    client_edns_payload: Option<u16>,
    server_udp_cap: u16,
    parsed_query: &ParsedQuery,
) -> Vec<u8> {
    if !transport_is_udp {
        return response;
    }
    let client_limit = if client_has_edns {
        // Honour the client's advertised size (RFC 6891 §6.2.4: a server
        // must not send more than the client can reassemble). Floor at 512
        // so a broken/zero advertisement still yields a usable answer.
        client_edns_payload
            .map(|p| usize::from(p).max(MAX_UDP_PLAIN))
            .unwrap_or(MAX_TCP_MESSAGE)
    } else {
        MAX_UDP_PLAIN
    };
    let limit = client_limit.min(usize::from(server_udp_cap).max(MAX_UDP_PLAIN));
    if response.len() <= limit {
        return response;
    }
    match Message::from_vec(&response) {
        Ok(m) => m
            .truncate()
            .to_vec()
            .unwrap_or_else(|_| tc_stub(parsed_query)),
        Err(_) => tc_stub(parsed_query),
    }
}

/// Minimal TC=1 response echoing the query (question + EDNS), telling the
/// client to retry over TCP.
fn tc_stub(parsed_query: &ParsedQuery) -> Vec<u8> {
    msg::truncated_response(parsed_query)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::msg;

    #[test]
    fn recv_buf_follows_edns_payload() {
        let plain = msg::parse_query(&msg::build_query("example.com", "A").unwrap()).unwrap();
        assert_eq!(recv_buf_size(&plain), MIN_RECV_BUF);

        let mut edns_q = msg::build_query("example.com", "A").unwrap();
        // Append a minimal OPT record (root name, type 41, payload 4096).
        // header(12) + question + OPT: name 0x00, type 41, class 4096, ttl 0,
        // rdlen 0.
        edns_q[10] = 0; // arcount high byte
        edns_q[11] = 1; // arcount = 1
        edns_q.extend_from_slice(&[
            0x00, // root name
            0x00, 0x29, // type OPT (41)
            0x10, 0x00, // class = payload 4096
            0x00, 0x00, 0x00, 0x00, // extended rcode + flags
            0x00, 0x00, // rdlen 0
        ]);
        let q = msg::parse_query(&edns_q).unwrap();
        assert!(q.has_edns);
        assert_eq!(q.edns_payload, Some(4096));
        assert_eq!(recv_buf_size(&q), 4096);

        // Tiny advertised payload is lifted to the flag-day floor.
        let mut tiny = msg::parse_query(&msg::build_query("example.com", "A").unwrap()).unwrap();
        tiny.edns_payload = Some(256);
        assert_eq!(recv_buf_size(&tiny), MIN_RECV_BUF);

        // The configured server egress cap also bounds the allocation even
        // when a client advertises a much larger EDNS payload.
        let forwarder = Forwarder::new(false).with_udp_cap(512);
        assert_eq!(forwarder.udp_cap, MIN_RECV_CAP);
        assert_eq!(recv_buf_size(&q).min(forwarder.udp_cap), MIN_RECV_CAP);
    }

    #[test]
    fn any_policy_refuses_locally() {
        use crate::config::{AnyPolicy, QueryConfig};
        let cfg = QueryConfig::default();
        assert_eq!(cfg.any_policy, AnyPolicy::Refuse);
        let forward = AnyPolicy::Forward;
        assert_eq!(forward, AnyPolicy::Forward);
        assert_ne!(forward, AnyPolicy::Refuse);
    }

    #[test]
    fn truncates_oversized_response_for_plain_udp_client() {
        let qbytes = msg::build_query("example.com", "A").unwrap();
        let mut msgout = Message::response(42, hickory_proto::op::OpCode::Query);
        let q = msg::parse_query(&qbytes).unwrap();
        msgout.queries = q.queries.clone();
        // Fake a > 512 byte answer by adding many TXT records.
        for i in 0..20 {
            let name = hickory_proto::rr::Name::from_ascii(format!("x{i}.example.com")).unwrap();
            msgout.answers.push(hickory_proto::rr::Record::from_rdata(
                name,
                300,
                hickory_proto::rr::RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![
                    "a".repeat(40)
                ])),
            ));
        }
        let bytes = msgout.to_vec().unwrap();
        assert!(bytes.len() > 512);
        let parsed = msg::parse_query(&msg::build_query("example.com", "A").unwrap()).unwrap();

        // EDNS client advertising a large payload: untouched.
        let out = enforce_client_udp_limit(bytes.clone(), true, true, Some(4096), 4096, &parsed);
        assert_eq!(out.len(), bytes.len());

        // Operator ceiling below the client's advertisement: truncated too
        // (`server.max_udp_packet_size` bounds fragmentation for everyone).
        let out = enforce_client_udp_limit(bytes.clone(), true, true, Some(4096), 512, &parsed);
        assert!(out.len() <= 512, "server cap must apply, got {}", out.len());
        let view = msg::parse_response(&out).unwrap();
        assert!(view.truncated);

        // EDNS client advertising a tiny payload: truncated to that size
        // (floored at the RFC 1035 512-byte minimum).
        let out = enforce_client_udp_limit(bytes.clone(), true, true, Some(256), 4096, &parsed);
        assert!(
            out.len() <= 512,
            "tiny EDNS payload must still respect the 512-byte floor, got {}",
            out.len()
        );
        let view = msg::parse_response(&out).unwrap();
        assert!(view.truncated);

        // Plain UDP client: truncated.
        let out = enforce_client_udp_limit(bytes, true, false, None, 4096, &parsed);
        assert!(out.len() <= 512);
        let view = msg::parse_response(&out).unwrap();
        assert!(view.truncated);

        // TCP client: untouched.
        let q2 = msg::build_query("example.com", "A").unwrap();
        let out = enforce_client_udp_limit(q2, false, false, None, 4096, &parsed);
        assert!(!out.is_empty());

        // Undecodable oversized datagram (cut mid-record upstream of us):
        // answer TC=1 built from the query instead of forwarding garbage or
        // the oversized bytes.
        let garbage = vec![0xA5u8; 600];
        let out = enforce_client_udp_limit(garbage, true, false, None, 4096, &parsed);
        let view = msg::parse_response(&out).unwrap();
        assert!(view.truncated, "TC stub must be marked truncated");
        let q = view.question.expect("stub echoes the question");
        assert_eq!(q.0, "example.com.");
    }
    async fn start_udp_peer() -> (UdpSocket, SocketAddr) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
        let addr = sock.local_addr().expect("peer addr");
        (sock, addr)
    }

    fn upstream(addr: SocketAddr, proto: Protocol) -> UpstreamConfig {
        UpstreamConfig {
            id: 1,
            name: "test".into(),
            address: addr.ip(),
            port: addr.port(),
            protocol: proto,
            enabled: true,
            ..Default::default()
        }
    }

    fn reply_for(query: &Message, id: u16) -> Vec<u8> {
        let mut msg = Message::response(id, query.op_code);
        msg.metadata.recursion_desired = query.metadata.recursion_desired;
        msg.metadata.recursion_available = true;
        msg.queries = query.queries.clone();
        if let Some(q) = query.queries.first() {
            msg.answers.push(hickory_proto::rr::Record::from_rdata(
                q.name().clone(),
                60,
                hickory_proto::rr::RData::A("192.0.2.53".parse().unwrap()),
            ));
        }
        msg.to_vec().expect("encode reply")
    }

    #[tokio::test]
    async fn udp_ignores_forged_id_and_question_before_valid_reply() {
        let (sock, addr) = start_udp_peer().await;
        let raw = msg::build_query("example.com", "A").unwrap();
        let parsed = msg::parse_query(&raw).unwrap();
        let (id_tx, id_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let (n, peer) = sock.recv_from(&mut buf).await.expect("receive query");
            let query = Message::from_vec(&buf[..n]).expect("decode query");
            id_tx.send(query.metadata.id).expect("send upstream id");
            let valid = reply_for(&query, query.metadata.id);

            // Same-source forgery with the wrong transaction id.
            let mut wrong_id = valid.clone();
            wrong_id[0] ^= 0x01;
            sock.send_to(&wrong_id, peer).await.expect("send wrong id");

            // Same-source forgery with the wrong question name (same length).
            let mut wrong_q = valid.clone();
            wrong_q[13] = b'f'; // example.com -> fxample.com
            sock.send_to(&wrong_q, peer)
                .await
                .expect("send wrong qname");

            // Only the correlated reply may be accepted.
            sock.send_to(&valid, peer).await.expect("send valid reply");
        });

        let forwarder = Forwarder::new(false);
        let ok = forwarder
            .exchange(
                &upstream(addr, Protocol::Udp),
                &parsed,
                &raw,
                Duration::from_secs(1),
            )
            .await
            .expect("valid reply must be accepted");

        let upstream_id = id_rx.await.expect("upstream id");
        assert_eq!(
            ok.view.id, upstream_id,
            "forged transaction id was accepted"
        );
        assert_ne!(
            ok.view.id, parsed.id,
            "client transaction id must not be forwarded upstream"
        );
        assert_eq!(
            ok.view.question.expect("question").0,
            "example.com.",
            "forged question was accepted"
        );
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn udp_discards_replies_from_a_different_source() {
        let (target, target_addr) = start_udp_peer().await;
        let (attacker, _attacker_addr) = start_udp_peer().await;
        let raw = msg::build_query("example.com", "A").unwrap();
        let parsed = msg::parse_query(&raw).unwrap();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

        let target_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let (n, peer) = target.recv_from(&mut buf).await.expect("receive query");
            let query = Message::from_vec(&buf[..n]).expect("decode query");
            ready_tx
                .send((peer, reply_for(&query, query.metadata.id)))
                .unwrap();
        });

        let up = upstream(target_addr, Protocol::Udp);
        let exchange = tokio::spawn(async move {
            Forwarder::new(false)
                .exchange(&up, &parsed, &raw, Duration::from_millis(300))
                .await
        });
        let (peer, valid) = ready_rx.await.expect("target received query");
        // A perfectly correlated reply from a different source must not
        // satisfy a connected UDP socket.
        attacker.send_to(&valid, peer).await.expect("spoofed send");

        let result = exchange.await.expect("exchange task");
        assert!(
            matches!(result, Err(ExchangeError::Timeout)),
            "reply from an unexpected source must be ignored, got {result:?}"
        );
        target_task.await.expect("target task");
    }

    #[tokio::test]
    async fn tcp_rejects_uncorrelated_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind tcp peer");
        let addr = listener.local_addr().expect("tcp peer addr");
        let raw = msg::build_query("example.com", "A").unwrap();
        let parsed = msg::parse_query(&raw).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.expect("read len");
            let len = usize::from(u16::from_be_bytes(len_buf));
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.expect("read query");
            let query = Message::from_vec(&body).expect("decode query");
            let resp = reply_for(&query, query.metadata.id.wrapping_add(1));
            let mut frame = Vec::with_capacity(2 + resp.len());
            frame.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            frame.extend_from_slice(&resp);
            stream.write_all(&frame).await.expect("write response");
        });

        let forwarder = Forwarder::new(false);
        let result = forwarder
            .exchange(
                &upstream(addr, Protocol::Tcp),
                &parsed,
                &raw,
                Duration::from_secs(1),
            )
            .await;
        assert!(
            matches!(&result, Err(ExchangeError::Invalid(reason)) if reason.contains("does not match")),
            "uncorrelated TCP response must be rejected, got {result:?}"
        );
        server.await.expect("server task");
    }
    #[tokio::test]
    async fn socks5_udp_proxy_carries_a_real_exchange_end_to_end() {
        use crate::config::{ProxyConfig, ProxyProtocol};
        use crate::proxy as px;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, UdpSocket};

        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = upstream.recv_from(&mut buf).await.unwrap();
            let query = Message::from_vec(&buf[..n]).unwrap();
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.metadata.recursion_available = true;
            resp.queries = query.queries.clone();
            upstream
                .send_to(&resp.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });

        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            control.write_all(&[5, 0]).await.unwrap();
            let mut head = [0u8; 10];
            control.read_exact(&mut head).await.unwrap();
            assert_eq!(&head[..], &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
            let mut reply = vec![5, 0, 0, 1];
            reply.extend_from_slice(
                &relay_addr
                    .ip()
                    .to_string()
                    .parse::<std::net::Ipv4Addr>()
                    .unwrap()
                    .octets(),
            );
            reply.extend_from_slice(&relay_addr.port().to_be_bytes());
            control.write_all(&reply).await.unwrap();
            // Keep the SOCKS control connection alive while the client uses
            // the association.
            let mut one = [0u8; 1];
            let _ = control.read(&mut one).await;
        });

        let relay_addr_copy = relay_addr;
        let relay_loop = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = relay.recv_from(&mut buf).await.unwrap();
            let target = upstream_addr;
            let payload = px::decode_udp(target, &buf[..n]).expect("encapsulated query");
            let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            up.send_to(payload, target).await.unwrap();
            let mut answer = vec![0u8; 4096];
            let (an, _) = up.recv_from(&mut answer).await.unwrap();
            let packet = px::encode_udp(target, &answer[..an]);
            relay.send_to(&packet, peer).await.unwrap();
            assert_eq!(relay.local_addr().unwrap(), relay_addr_copy);
        });

        let cfg = ProxyConfig {
            enabled: true,
            protocol: ProxyProtocol::Socks5,
            address: proxy_addr.ip(),
            port: proxy_addr.port(),
            connect_timeout_ms: 2_000,
            ..Default::default()
        };
        let forwarder = Forwarder::with_proxy(false, Some(Arc::new(cfg)), None);
        let up = UpstreamConfig {
            id: 1,
            name: "via-proxy".into(),
            address: upstream_addr.ip(),
            port: upstream_addr.port(),
            protocol: Protocol::Udp,
            ..Default::default()
        };
        let raw = msg::build_query("example.com", "A").unwrap();
        let parsed = msg::parse_query(&raw).unwrap();
        let ok = forwarder
            .exchange(&up, &parsed, &raw, Duration::from_secs(2))
            .await
            .expect("proxied exchange");
        assert!(ok.proxied);
        assert_eq!(ok.proxy_protocol, Some("socks5"));
        assert!(ok.proxy_connect_latency.is_some());
        assert_eq!(ok.view.rcode, msg::Rcode::NoError);

        upstream_task.await.unwrap();
        relay_task.await.unwrap();
        relay_loop.await.unwrap();
    }
}
