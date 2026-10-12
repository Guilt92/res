//! Upstream DNS exchange: raw query out, correlated response in.
//!
//! The gateway forwards the client's original bytes untouched (EDNS, DO bit,
//! RD flag, etc. are preserved). Responses are validated by transaction id,
//! message type and question section before being accepted.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::config::{Protocol, UpstreamConfig};
use crate::dns::msg::{self, ParsedQuery, ResponseView};

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
}

impl ExchangeError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, ExchangeError::Timeout | ExchangeError::Network(_))
    }
}

pub struct ExchangeOk {
    pub response: Vec<u8>,
    pub view: ResponseView,
    pub latency: Duration,
}

/// Performs DNS exchanges with upstreams over UDP/TCP.
#[derive(Debug, Clone, Copy)]
pub struct Forwarder {
    /// Retry over TCP when an upstream UDP response is truncated (TC=1).
    pub tcp_fallback: bool,
}

impl Forwarder {
    pub fn new(tcp_fallback: bool) -> Self {
        Self { tcp_fallback }
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
        match proto {
            Protocol::Udp => self.exchange_udp(up, query, raw, budget).await,
            Protocol::Tcp => self.exchange_tcp(up, query, raw, budget).await,
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
        sock.send(raw)
            .await
            .map_err(|e| ExchangeError::Network(format!("send: {e}")))?;

        // Receive buffer sized from the client's advertised EDNS payload
        // (RFC 6891: a server must not exceed it). Plain-UDP queries get the
        // DNS flag-day 1232 floor, which also survives servers that ignore
        // the 512-byte RFC 1035 limit. Bounded, far below the old fixed 64 KiB.
        let mut buf = vec![0u8; recv_buf_size(query)];
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

            // Ignore packets that cannot be parsed or correlated (late
            // responses from a previous attempt, spoofed datagrams, ...).
            let view = match msg::parse_response(&buf[..received]) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if !msg::correlates(query, &view) {
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
                        });
                    }
                }
            }

            return Ok(ExchangeOk {
                response: buf[..received].to_vec(),
                view,
                latency: start.elapsed(),
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
            let mut stream = TcpStream::connect(target)
                .await
                .map_err(|e| ExchangeError::Network(format!("connect: {e}")))?;
            let _ = stream.set_nodelay(true);

            let mut frame = Vec::with_capacity(2 + raw.len());
            frame.extend_from_slice(&(raw.len() as u16).to_be_bytes());
            frame.extend_from_slice(raw);
            stream
                .write_all(&frame)
                .await
                .map_err(|e| ExchangeError::Network(format!("write: {e}")))?;

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

            let view = msg::parse_response(&resp).map_err(ExchangeError::Invalid)?;
            if !msg::correlates(query, &view) {
                return Err(ExchangeError::Invalid(
                    "response does not match query".into(),
                ));
            }
            Ok(ExchangeOk {
                response: resp,
                view,
                latency: Duration::ZERO,
            })
        })
        .await;

        match result {
            Err(_) => Err(ExchangeError::Timeout),
            Ok(Ok(mut ok)) => {
                ok.latency = start.elapsed();
                Ok(ok)
            }
            Ok(Err(e)) => Err(e),
        }
    }
}

/// DNS flag day 2020 minimum safe UDP payload (also the receive floor for
/// plain-UDP exchanges: some servers exceed RFC 1035's 512 without EDNS).
const MIN_RECV_BUF: usize = 1232;

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

/// Enforce the RFC 1035 512-byte limit for clients that did not advertise
/// EDNS over UDP by converting the response into a truncated one (TC=1), which
/// makes the client retry over TCP where the full answer is served.
pub fn enforce_client_udp_limit(
    response: Vec<u8>,
    transport_is_udp: bool,
    client_has_edns: bool,
) -> Vec<u8> {
    if !transport_is_udp || client_has_edns || response.len() <= MAX_UDP_PLAIN {
        return response;
    }
    match Message::from_vec(&response) {
        Ok(m) => m.truncate().to_vec().unwrap_or(response),
        Err(_) => response,
    }
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

        // EDNS client: untouched.
        let out = enforce_client_udp_limit(bytes.clone(), true, true);
        assert_eq!(out.len(), bytes.len());

        // Plain UDP client: truncated.
        let out = enforce_client_udp_limit(bytes, true, false);
        assert!(out.len() <= 512);
        let view = msg::parse_response(&out).unwrap();
        assert!(view.truncated);

        // TCP client: untouched.
        let q2 = msg::build_query("example.com", "A").unwrap();
        let out = enforce_client_udp_limit(q2, false, false);
        assert!(!out.is_empty());
    }
}
