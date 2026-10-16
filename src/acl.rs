//! Access control lists.
//!
//! Evaluation happens before any forwarding work. The rules are fail-closed:
//! an empty allow list denies everything, so an unconfigured res instance
//! can never become an open resolver.
//!
//! Configuration supports two shapes:
//!
//! * **Entries** (preferred): `[[acl.entries]]` rows with `cidr`, `action`
//!   (`allow`/`deny`) and `enabled`. Disabled entries are retained but never
//!   evaluated. Bare IPv4/IPv6 addresses are accepted and normalised to host
//!   CIDRs (`/32`, `/128`).
//! * **Legacy lists** (still accepted on load): `allowed_cidrs` / `denied_cidrs`
//!   string arrays. Used only when `entries` is empty; synthesised into
//!   always-enabled entries.
//!
//! Duplicate entries and the same network appearing in both an allow and a
//! deny entry are rejected at parse time (conflict), never silently resolved.

use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Action of one ACL entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AclAction {
    Allow,
    Deny,
}

impl AclAction {
    pub fn as_str(self) -> &'static str {
        match self {
            AclAction::Allow => "allow",
            AclAction::Deny => "deny",
        }
    }
}

fn default_true() -> bool {
    true
}

/// One structured ACL entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclEntry {
    /// Stable identifier. Derived from `action:cidr` on legacy import and on
    /// first parse; preserved across edits of other fields.
    #[serde(default)]
    pub id: String,
    /// CIDR network or bare IPv4/IPv6 address.
    pub cidr: String,
    /// Allow or deny clients matching `cidr`.
    pub action: AclAction,
    /// Disabled entries stay in the configuration but are never evaluated.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl AclEntry {
    /// Canonical content-derived id (`allow:10.0.0.0/8`).
    pub fn derive_id(action: AclAction, cidr: &str) -> String {
        format!("{}:{}", action.as_str(), cidr.trim())
    }

    /// Ensure the entry has a stable id (assign one when missing).
    pub fn with_derived_id(mut self) -> Self {
        if self.id.is_empty() {
            self.id = Self::derive_id(self.action, &self.cidr);
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AclConfig {
    /// Structured entries (preferred). When non-empty this list is
    /// authoritative and the legacy fields are ignored.
    pub entries: Vec<AclEntry>,
    /// Legacy flat allow list (used only when `entries` is empty).
    pub allowed_cidrs: Vec<String>,
    /// Legacy flat deny list (used only when `entries` is empty).
    pub denied_cidrs: Vec<String>,
}

impl Default for AclConfig {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
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

impl AclConfig {
    /// Effective entries: the structured list when present, otherwise the
    /// legacy lists synthesised into always-enabled entries (ids derived).
    pub fn effective_entries(&self) -> Vec<AclEntry> {
        if !self.entries.is_empty() {
            return self
                .entries
                .iter()
                .map(|e| e.clone().with_derived_id())
                .collect();
        }
        let mut out = Vec::with_capacity(self.allowed_cidrs.len() + self.denied_cidrs.len());
        for s in &self.allowed_cidrs {
            out.push(
                AclEntry {
                    id: String::new(),
                    cidr: s.clone(),
                    action: AclAction::Allow,
                    enabled: true,
                }
                .with_derived_id(),
            );
        }
        for s in &self.denied_cidrs {
            out.push(
                AclEntry {
                    id: String::new(),
                    cidr: s.clone(),
                    action: AclAction::Deny,
                    enabled: true,
                }
                .with_derived_id(),
            );
        }
        out
    }

    /// Replace the configuration with a structured entry list, clearing the
    /// legacy fields so only one format is ever serialised.
    pub fn set_entries(&mut self, entries: Vec<AclEntry>) {
        self.entries = entries.into_iter().map(AclEntry::with_derived_id).collect();
        self.allowed_cidrs.clear();
        self.denied_cidrs.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    Allow,
    Deny,
}

/// Parse a CIDR network or bare IPv4/IPv6 address into a host/network CIDR.
pub fn normalize_cidr(s: &str) -> Result<IpNet, String> {
    let t = s.trim();
    if let Ok(net) = t.parse::<IpNet>() {
        return Ok(net);
    }
    if let Ok(ip) = t.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => Ok(IpNet::V4(
                ipnet::Ipv4Net::new(v4, 32).map_err(|e| format!("invalid host '{s}': {e}"))?,
            )),
            IpAddr::V6(v6) => Ok(IpNet::V6(
                ipnet::Ipv6Net::new(v6, 128).map_err(|e| format!("invalid host '{s}': {e}"))?,
            )),
        };
    }
    Err(format!("invalid CIDR or IP address '{s}'"))
}

/// Parsed, ready-to-evaluate ACL (built once per configuration swap).
#[derive(Debug, Clone, Default)]
pub struct AclRules {
    allowed: Vec<IpNet>,
    denied: Vec<IpNet>,
}

impl AclRules {
    pub fn parse(cfg: &AclConfig) -> Result<Self, String> {
        let entries = cfg.effective_entries();

        // Conflict / duplicate validation before any evaluation data is built.
        let mut seen: HashSet<(AclAction, String)> = HashSet::new();
        let mut allow_nets: HashSet<IpNet> = HashSet::new();
        let mut deny_nets: HashSet<IpNet> = HashSet::new();
        for e in &entries {
            let net = normalize_cidr(&e.cidr)?;
            let key = (e.action, net.to_string());
            if !seen.insert(key) {
                return Err(format!(
                    "duplicate ACL entry: {} {}",
                    e.action.as_str(),
                    net
                ));
            }
            match e.action {
                AclAction::Allow => {
                    if deny_nets.contains(&net) {
                        return Err(format!(
                            "ACL conflict: {net} appears in both an allow and a deny entry"
                        ));
                    }
                    allow_nets.insert(net);
                }
                AclAction::Deny => {
                    if allow_nets.contains(&net) {
                        return Err(format!(
                            "ACL conflict: {net} appears in both an allow and a deny entry"
                        ));
                    }
                    deny_nets.insert(net);
                }
            }
        }

        let mut allowed = Vec::new();
        let mut denied = Vec::new();
        for e in &entries {
            if !e.enabled {
                continue;
            }
            // Re-parse (cheap; validation already succeeded above).
            let net = normalize_cidr(&e.cidr)?;
            match e.action {
                AclAction::Allow => allowed.push(net),
                AclAction::Deny => denied.push(net),
            }
        }
        Ok(Self { allowed, denied })
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
            entries: Vec::new(),
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
            entries: Vec::new(),
            allowed_cidrs: vec!["10.0.0.0/99".into()],
            denied_cidrs: vec![],
        };
        assert!(AclRules::parse(&cfg).is_err());
        let cfg = AclConfig {
            entries: Vec::new(),
            allowed_cidrs: vec!["not-a-thing".into()],
            denied_cidrs: vec![],
        };
        assert!(AclRules::parse(&cfg).is_err());
    }

    #[test]
    fn bare_ip_is_accepted_and_normalised() {
        let r = rules(&["192.0.2.10"], &[]);
        assert_eq!(r.decide(ip("192.0.2.10")), AclDecision::Allow);
        assert_eq!(r.decide(ip("192.0.2.11")), AclDecision::Deny);
        let r = rules(&["2001:db8::5"], &[]);
        assert_eq!(r.decide(ip("2001:db8::5")), AclDecision::Allow);
        assert_eq!(r.decide(ip("2001:db8::6")), AclDecision::Deny);
    }

    #[test]
    fn duplicate_entries_rejected() {
        let cfg = AclConfig {
            entries: vec![
                AclEntry {
                    id: String::new(),
                    cidr: "10.0.0.0/8".into(),
                    action: AclAction::Allow,
                    enabled: true,
                },
                AclEntry {
                    id: String::new(),
                    cidr: "10.0.0.0/8".into(),
                    action: AclAction::Allow,
                    enabled: true,
                },
            ],
            allowed_cidrs: vec![],
            denied_cidrs: vec![],
        };
        let err = AclRules::parse(&cfg).unwrap_err();
        assert!(err.contains("duplicate"), "{err}");
    }

    #[test]
    fn allow_deny_conflict_rejected() {
        let cfg = AclConfig {
            entries: vec![
                AclEntry {
                    id: String::new(),
                    cidr: "10.0.0.0/8".into(),
                    action: AclAction::Allow,
                    enabled: true,
                },
                AclEntry {
                    id: String::new(),
                    cidr: "10.0.0.0/8".into(),
                    action: AclAction::Deny,
                    enabled: true,
                },
            ],
            allowed_cidrs: vec![],
            denied_cidrs: vec![],
        };
        let err = AclRules::parse(&cfg).unwrap_err();
        assert!(err.contains("conflict"), "{err}");
    }

    #[test]
    fn disabled_entries_are_not_evaluated() {
        let cfg = AclConfig {
            entries: vec![
                AclEntry {
                    id: String::new(),
                    cidr: "10.0.0.0/8".into(),
                    action: AclAction::Allow,
                    enabled: false, // disabled: not evaluated
                },
                AclEntry {
                    id: String::new(),
                    cidr: "192.0.2.0/24".into(),
                    action: AclAction::Allow,
                    enabled: true,
                },
            ],
            allowed_cidrs: vec![],
            denied_cidrs: vec![],
        };
        let r = AclRules::parse(&cfg).unwrap();
        assert_eq!(r.allowed_count(), 1);
        assert_eq!(r.decide(ip("10.1.2.3")), AclDecision::Deny);
        assert_eq!(r.decide(ip("192.0.2.5")), AclDecision::Allow);
    }

    #[test]
    fn entries_take_precedence_over_legacy_lists() {
        let cfg = AclConfig {
            entries: vec![AclEntry {
                id: String::new(),
                cidr: "203.0.113.0/24".into(),
                action: AclAction::Allow,
                enabled: true,
            }],
            allowed_cidrs: vec!["10.0.0.0/8".into()],
            denied_cidrs: vec![],
        };
        let r = AclRules::parse(&cfg).unwrap();
        assert_eq!(r.allowed_count(), 1);
        assert_eq!(r.decide(ip("203.0.113.1")), AclDecision::Allow);
        assert_eq!(
            r.decide(ip("10.1.2.3")),
            AclDecision::Deny,
            "legacy ignored"
        );
    }

    #[test]
    fn set_entries_clears_legacy_fields() {
        let mut cfg = AclConfig::default();
        assert!(!cfg.allowed_cidrs.is_empty());
        cfg.set_entries(vec![AclEntry {
            id: String::new(),
            cidr: "192.0.2.1".into(),
            action: AclAction::Allow,
            enabled: true,
        }]);
        assert!(cfg.allowed_cidrs.is_empty());
        assert!(cfg.denied_cidrs.is_empty());
        assert_eq!(cfg.entries.len(), 1);
        assert!(!cfg.entries[0].id.is_empty(), "id derived on set");
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
