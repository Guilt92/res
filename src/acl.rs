//! Access control lists.
//!
//! Evaluation happens before any forwarding work. The rules are fail-closed:
//! an empty allow list denies everything, so an unconfigured res instance
//! can never become an open resolver.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AclConfig {
    /// Networks allowed to use the resolver. Empty = deny everyone.
    pub allowed_cidrs: Vec<String>,
    /// Networks always denied (evaluated first).
    pub denied_cidrs: Vec<String>,
}

impl Default for AclConfig {
    fn default() -> Self {
        Self {
            allowed_cidrs: vec![
                "127.0.0.0/8".into(),
                "::1/128".into(),
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
                "169.254.0.0/16".into(),
                "fc00::/7".into(),
            ],
            denied_cidrs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    Allow,
    Deny,
}

/// Parsed, ready-to-evaluate ACL (built once per configuration swap).
#[derive(Debug, Clone, Default)]
pub struct AclRules {
    allowed: Vec<IpNet>,
    denied: Vec<IpNet>,
}

impl AclRules {
    pub fn parse(cfg: &AclConfig) -> Result<Self, String> {
        let parse_list = |list: &[String], what: &str| -> Result<Vec<IpNet>, String> {
            list.iter()
                .map(|s| {
                    s.trim()
                        .parse::<IpNet>()
                        .map_err(|e| format!("invalid {what} CIDR '{s}': {e}"))
                })
                .collect()
        };
        Ok(Self {
            allowed: parse_list(&cfg.allowed_cidrs, "allowed")?,
            denied: parse_list(&cfg.denied_cidrs, "denied")?,
        })
    }

    pub fn decide(&self, client: IpAddr) -> AclDecision {
        if self.denied.iter().any(|n| n.contains(&client)) {
            return AclDecision::Deny;
        }
        if self.allowed.is_empty() {
            return AclDecision::Deny;
        }
        if self.allowed.iter().any(|n| n.contains(&client)) {
            return AclDecision::Allow;
        }
        // IPv4-mapped IPv6 (`::ffff:a.b.c.d`, common on dual-stack sockets):
        // also match the embedded IPv4 address against the IPv4 rules, so a
        // client reaching the listener via the mapped form is not wrongly
        // denied (or allowed, if only v6 rules match the mapped form itself).
        if let Some(v4) = mapped_v4(client) {
            let v4 = IpAddr::V4(v4);
            if self.denied.iter().any(|n| n.contains(&v4)) {
                return AclDecision::Deny;
            }
            if self.allowed.iter().any(|n| n.contains(&v4)) {
                return AclDecision::Allow;
            }
        }
        AclDecision::Deny
    }

    pub fn allowed_count(&self) -> usize {
        self.allowed.len()
    }

    pub fn denied_count(&self) -> usize {
        self.denied.len()
    }
}

/// Extract the IPv4 address out of an IPv4-mapped IPv6 address
/// (`::ffff:a.b.c.d`), if any.
fn mapped_v4(ip: IpAddr) -> Option<std::net::Ipv4Addr> {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        IpAddr::V4(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rules(allowed: &[&str], denied: &[&str]) -> AclRules {
        AclRules::parse(&AclConfig {
            allowed_cidrs: allowed.iter().map(|s| s.to_string()).collect(),
            denied_cidrs: denied.iter().map(|s| s.to_string()).collect(),
        })
        .unwrap()
    }

    #[test]
    fn allows_member_of_allowed_cidr() {
        let r = rules(&["10.0.0.0/8"], &[]);
        assert_eq!(r.decide(ip("10.1.2.3")), AclDecision::Allow);
        assert_eq!(r.decide(ip("11.1.2.3")), AclDecision::Deny);
    }

    #[test]
    fn denied_wins_over_allowed() {
        let r = rules(&["10.0.0.0/8"], &["10.5.0.0/16"]);
        assert_eq!(r.decide(ip("10.1.2.3")), AclDecision::Allow);
        assert_eq!(r.decide(ip("10.5.9.9")), AclDecision::Deny);
    }

    #[test]
    fn empty_allow_list_denies_everyone() {
        let r = rules(&[], &[]);
        assert_eq!(r.decide(ip("127.0.0.1")), AclDecision::Deny);
        assert_eq!(r.decide(ip("8.8.8.8")), AclDecision::Deny);
    }

    #[test]
    fn ipv6_rules() {
        let r = rules(&["::1/128", "2001:db8::/32"], &[]);
        assert_eq!(r.decide(ip("::1")), AclDecision::Allow);
        assert_eq!(r.decide(ip("2001:db8::1")), AclDecision::Allow);
        assert_eq!(r.decide(ip("2001:dead::1")), AclDecision::Deny);
    }

    #[test]
    fn invalid_cidr_rejected() {
        let cfg = AclConfig {
            allowed_cidrs: vec!["10.0.0.0/99".into()],
            denied_cidrs: vec![],
        };
        assert!(AclRules::parse(&cfg).is_err());
        let cfg = AclConfig {
            allowed_cidrs: vec!["10.0.0.0".into()],
            denied_cidrs: vec![],
        };
        assert!(AclRules::parse(&cfg).is_err());
    }

    #[test]
    fn default_config_is_private_only() {
        let r = AclRules::parse(&AclConfig::default()).unwrap();
        assert_eq!(r.decide(ip("192.168.1.10")), AclDecision::Allow);
        assert_eq!(
            r.decide(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            AclDecision::Deny
        );
    }

    #[test]
    fn ipv4_mapped_clients_match_v4_rules() {
        // Dual-stack listeners see IPv4 clients as ::ffff:a.b.c.d; they must
        // match the IPv4 allow rules, not be denied by the family mismatch.
        let r = rules(&["10.0.0.0/8", "::1/128"], &[]);
        assert_eq!(r.decide(ip("::ffff:10.1.2.3")), AclDecision::Allow);
        // ... and a denied v4 subnet still denies the mapped form.
        let r = rules(&["0.0.0.0/0"], &["10.5.0.0/16"]);
        assert_eq!(r.decide(ip("::ffff:10.5.9.9")), AclDecision::Deny);
        assert_eq!(r.decide(ip("::ffff:10.1.2.3")), AclDecision::Allow);
        // Public mapped address stays denied with default config.
        let r = AclRules::parse(&AclConfig::default()).unwrap();
        assert_eq!(r.decide(ip("::ffff:8.8.8.8")), AclDecision::Deny);
        // Non-mapped IPv6 is unaffected.
        assert_eq!(r.decide(ip("2001:db8::1")), AclDecision::Deny);
    }

    #[test]
    fn public_cidr_can_be_allowed_explicitly() {
        let r = rules(&["203.0.113.0/24", "2001:db8::/32"], &[]);
        assert_eq!(r.decide(ip("203.0.113.55")), AclDecision::Allow);
        assert_eq!(r.decide(ip("203.0.114.1")), AclDecision::Deny);
        assert_eq!(r.decide(ip("2001:db8::55")), AclDecision::Allow);
        assert_eq!(r.decide(ip("2001:db9::1")), AclDecision::Deny);
    }

    #[test]
    fn cidr_boundaries_are_exact() {
        let r = rules(&["192.0.2.0/24"], &[]);
        assert_eq!(r.decide(ip("192.0.2.0")), AclDecision::Allow);
        assert_eq!(r.decide(ip("192.0.2.255")), AclDecision::Allow);
        assert_eq!(r.decide(ip("192.0.1.255")), AclDecision::Deny);
        assert_eq!(r.decide(ip("192.0.3.0")), AclDecision::Deny);
    }

    #[test]
    fn counts() {
        let r = rules(&["10.0.0.0/8", "192.168.0.0/16"], &["10.5.0.0/16"]);
        assert_eq!(r.allowed_count(), 2);
        assert_eq!(r.denied_count(), 1);
    }
}
