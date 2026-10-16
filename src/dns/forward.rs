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
        //
        // One extra byte: `recv` filling it means the datagram is larger than
        // the client can receive — a detectable overflow instead of a silent
        // mid-record cut that the parser would only see as garbage.
        let expected = recv_buf_size(query);
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
                        let mut stub = msg::error_response(query, msg::Rcode::NoError);
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
                        });
                    }
                    continue;
                }
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
    let mut stub = msg::error_response(parsed_query, msg::Rcode::NoError);
    if stub.len() >= 4 {
        stub[2] |= 0x02; // TC
    }
    stub
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
    fn any_policy_refuses_locally() {
        use crate::config::{AnyPolicy, QueryConfig};
        let cfg = QueryConfig::default();
        assert_eq!(cfg.any_policy, AnyPolicy::Forward);
        let refuse = AnyPolicy::Refuse;
        assert_eq!(refuse, AnyPolicy::Refuse);
        assert_ne!(refuse, AnyPolicy::Forward);
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
}
