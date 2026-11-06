//! Client address resolution for the HTTP control plane.
//!
//! The socket peer is the only address that cannot be forged, so it is the
//! default. `X-Forwarded-For` is honoured **only** when the direct peer is
//! inside an operator-configured `server.trusted_proxies` network, and even
//! then only the part of the header appended by trusted hops is believed:
//! the chain is walked from the right and the first entry that is not itself
//! a trusted proxy is the client. Anything further left was supplied by the
//! client (or an untrusted hop) and is ignored, so a spoofed
//! `X-Forwarded-For: 1.2.3.4` cannot reset a per-IP rate limit or lockout.

use std::net::IpAddr;

use axum::http::HeaderMap;
use ipnet::IpNet;

/// Fold IPv4-mapped IPv6 (`::ffff:a.b.c.d`) onto plain IPv4.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn is_trusted(ip: IpAddr, trusted: &[IpNet]) -> bool {
    let ip = canonical(ip);
    trusted.iter().any(|n| n.contains(&ip))
}

/// Parse one `X-Forwarded-For` element (`1.2.3.4`, `::1`, `[::1]`,
/// `[::1]:443`, `1.2.3.4:5678`). `None` for anything else.
fn parse_hop(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(canonical(ip));
    }
    if let Ok(sa) = raw.parse::<std::net::SocketAddr>() {
        return Some(canonical(sa.ip()));
    }
    let inner = raw.strip_prefix('[')?.strip_suffix(']')?;
    inner.parse::<IpAddr>().ok().map(canonical)
}

/// Resolve the effective client address for a request.
///
/// `peer` is the TCP peer. Returns `peer` (canonicalised) unless the peer is
/// a trusted proxy and the forwarded chain is well formed.
pub fn resolve(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let peer = canonical(peer);
    if trusted.is_empty() || !is_trusted(peer, trusted) {
        return peer;
    }
    let mut hops: Vec<&str> = Vec::new();
    for v in headers.get_all("x-forwarded-for") {
        match v.to_str() {
            Ok(s) => hops.extend(s.split(',')),
            // A non-ASCII header is malformed: do not guess.
            Err(_) => return peer,
        }
    }
    let mut last = None;
    for raw in hops.iter().rev() {
        match parse_hop(raw) {
            // A malformed hop breaks the chain of trust: fall back to the
            // proxy itself rather than believe anything left of it.
            None => return last.unwrap_or(peer),
            Some(ip) if is_trusted(ip, trusted) => last = Some(ip),
            Some(ip) => return ip,
        }
    }
    // Every hop was a trusted proxy (or the header is absent).
    last.unwrap_or(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(v: &[&str]) -> Vec<IpNet> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }
    fn hdr(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", v.parse().unwrap());
        h
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn untrusted_peer_cannot_spoof() {
        let t = nets(&["10.0.0.0/8"]);
        let got = resolve(ip("203.0.113.9"), &hdr("1.2.3.4"), &t);
        assert_eq!(got, ip("203.0.113.9"));
    }

    #[test]
    fn empty_trust_list_never_reads_header() {
        assert_eq!(
            resolve(ip("10.0.0.1"), &hdr("1.2.3.4"), &[]),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn trusted_peer_uses_forwarded_client() {
        let t = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve(ip("10.0.0.1"), &hdr("198.51.100.7"), &t),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn spoofed_left_entries_are_ignored() {
        let t = nets(&["10.0.0.0/8"]);
        // Client sent "1.2.3.4"; the proxy appended the real peer.
        let got = resolve(ip("10.0.0.1"), &hdr("1.2.3.4, 198.51.100.7"), &t);
        assert_eq!(got, ip("198.51.100.7"));
    }

    #[test]
    fn chain_of_trusted_proxies_is_skipped() {
        let t = nets(&["10.0.0.0/8", "192.168.0.0/16"]);
        let got = resolve(
            ip("10.0.0.1"),
            &hdr("9.9.9.9, 198.51.100.7, 192.168.1.1"),
            &t,
        );
        assert_eq!(got, ip("198.51.100.7"));
    }

    #[test]
    fn missing_or_all_trusted_header_falls_back() {
        let t = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve(ip("10.0.0.1"), &HeaderMap::new(), &t),
            ip("10.0.0.1")
        );
        assert_eq!(
            resolve(ip("10.0.0.1"), &hdr("10.0.0.5, 10.0.0.6"), &t),
            ip("10.0.0.5")
        );
    }

    #[test]
    fn malformed_hop_falls_back_to_proxy() {
        let t = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve(ip("10.0.0.1"), &hdr("1.2.3.4, not-an-ip"), &t),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn ipv6_and_mapped_addresses() {
        let t = nets(&["fd00::/8", "10.0.0.0/8"]);
        assert_eq!(
            resolve(ip("fd00::1"), &hdr("2001:db8::5"), &t),
            ip("2001:db8::5")
        );
        assert_eq!(
            resolve(ip("fd00::1"), &hdr("[2001:db8::6]:443"), &t),
            ip("2001:db8::6")
        );
        // IPv4-mapped peer is matched against IPv4 trust networks.
        assert_eq!(
            resolve(ip("::ffff:10.0.0.1"), &hdr("198.51.100.7"), &t),
            ip("198.51.100.7")
        );
        // Mapped client address is canonicalised.
        assert_eq!(
            resolve(ip("10.0.0.1"), &hdr("::ffff:198.51.100.8"), &t),
            ip("198.51.100.8")
        );
    }

    #[test]
    fn multiple_header_lines_are_joined_in_order() {
        let t = nets(&["10.0.0.0/8"]);
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", "1.2.3.4".parse().unwrap());
        h.append("x-forwarded-for", "198.51.100.7".parse().unwrap());
        assert_eq!(resolve(ip("10.0.0.1"), &h, &t), ip("198.51.100.7"));
    }
}
