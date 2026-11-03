# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **ACL deny always wins on every address form.** Client addresses are now
  canonicalized once at ingress (IPv4-mapped IPv6 `::ffff:a.b.c.d` → plain
  IPv4) and that same address is used for ACL evaluation, rate limiting, RRL
  and traffic statistics. Previously an IPv6 allow rule matching the mapped
  form (for example `::ffff:0:0/96`) could admit an embedded IPv4 address
  before its IPv4 deny rule was consulted.
- **ACL conflict detection ignores disabled entries.** A disabled entry is
  never evaluated, so it may overlap an enabled rule (or another disabled
  entry) without being rejected. This lets operators stage and disable rules
  before enabling them. Enabled entries still reject duplicates and
  allow/deny conflicts. Migration: no config change needed; the new rule only
  *permits* configurations that were previously rejected.

### Changed defaults

*(Documented here as they are introduced.)*

