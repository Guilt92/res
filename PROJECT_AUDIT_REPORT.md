# res Security and Quality Audit

- Date: 2026-10-21
- Repository: `/home/outis/work-github/res`
- Branch: `main`
- Implementation commit: `23bbae9` — `security: harden DNS cache, upstream correlation, and panel auth`
- Scope: DNS data plane, cache/single-flight, forwarding/failover, management API, dashboard, configuration and deployment defaults
- Result: no unresolved critical defect found in the tested paths; three cache/correlation weaknesses were fixed and covered by regression tests. The gateway is suitable for a private/trusted-network forwarder, not as an open internet-facing resolver.

## Executive Summary

The gateway is a forwarding DNS proxy, not a validating recursive resolver. Its
primary security boundary is the client ACL plus the trust placed in configured
upstreams. The audit found that the data plane already rejected malformed
packets, bound replies to the upstream source, checked transaction ids and
question identity, and enforced strict TTLs. The significant issues were around
what could share a cache entry and how much unpredictability an off-path attacker
had to defeat.

Fixed in this audit:

1. Queries carrying EDNS options could read a shared cache entry populated by a
   different client. This could leak client-specific answers or mix ECS-scoped
   data. Such queries now bypass both the response cache and single-flight.
2. The client's transaction id was forwarded unchanged to upstreams, reducing
   off-path spoofing resistance to source-port entropy only. A fresh,
   unpredictable id is now generated for every upstream exchange, and the
   response is correlated against that id before being accepted.
3. The RD bit was not part of the cache key. A non-recursive response could be
   reused for a recursive query (or vice versa). RD is now part of the key.

The existing viewer read-only enforcement, CSRF/session handling, ACL
fail-closed behavior, bounded listeners, TCP fallback and response-size limits
were reviewed and regression-tested. Remaining risks are documented below rather
than silently accepted: no DNSSEC validation, no response rate limiting,
plaintext upstream transport, open-mode API/configuration defaults, and no
query-name case randomization.

## Trust Model

- **Client to gateway:** untrusted input. Parsed with `hickory-proto`, checked
  for message type/opcode/question count, then passed through ACL, rate limit,
  ANY policy and cache admission.
- **Gateway to upstream:** configured upstreams are trusted for correctness.
  UDP uses a connected socket, TCP uses a connected stream, and responses are
  correlated by transaction id and question.
- **Panel/API client to control plane:** authenticated by session cookie or
  bearer token; mutations additionally require admin role and, for cookie auth,
  a CSRF token.
- **Dashboard to API:** same-origin `fetch`; no third-party script is loaded.
- **Host/container:** the binary has no TLS and does not trust
  `X-Forwarded-For`; TLS and proxy-level controls are deployment
  responsibilities.

## Changes Made

### DNS data plane

- Added `ParsedQuery.has_edns_options` and used it in cache admission:
  `use_cache = cache.enabled && !dnssec_ok && !has_edns_options`.
  Option-bearing queries (ECS, COOKIE, padding, unknown options) never enter
  the cache or single-flight.
- Added RD to `CacheKey`; the key is now lowercased name + qtype + qclass + CD +
  RD.
- Replaced the client transaction id before every upstream UDP/TCP exchange
  with a fresh 16-bit value from the OS-backed `rand` thread RNG. The id is
  guaranteed to differ from the client id, and correlation uses the rewritten
  id. The client id is restored during response alignment.
- Kept the existing exact question check: lowercased name, qtype and qclass
  must match the client query. Source address/port is constrained by connected
  sockets.
- Preserved show-path alignment: cache bytes and upstream bytes are rewritten
  to the current client's id, RD/CD bits, question casing and EDNS OPT
  advertisement.
- Preserved TTL semantics: no TTL extension beyond advertised values, TTLs
  decrement on hits, and negative caching remains bounded.

### Verification and API

- Added `src/dns/msg.rs` tests for wrong id/name/qtype/qclass, short/query
  packets, compression-pointer loops, cache-key case/class/type/CD/RD
  isolation, and EDNS option detection.
- Added `src/dns/forward.rs` tests for same-source wrong-id/wrong-question
  forgery, replies from a different source, and uncorrelated TCP responses.
- Added `src/failover.rs` tests for failover after a mismatched response and
  retained the client-visible response invariant.
- Added `src/dns/pipeline.rs` test proving ECS queries bypass the shared cache
  and do not consume a plain entry.
- Added `tests/gateway.rs` test proving a viewer can read but cannot clear
  cache, replace ACL, create an upstream, or rotate the admin password; the
  admin can still perform the mutation.
- Enforced an 8-character minimum on password rotation at the API, not only in
  the dashboard.
- Added COOP, `X-Permitted-Cross-Domain-Policies`, Permissions-Policy and
  no-store/no-cache headers for `/api/*` and `/metrics`.
- Restored the structured upstream score breakdown while retaining
  `score_value` for scripted clients.

### Dashboard

- Session token is stored only in `sessionStorage`; legacy
  `localStorage["res-admin-token"]` is removed at startup and on save/logout.
- Logout and authentication failure clear the token and password fields.
- Open mode is detected with the public `/api/status` probe instead of assuming
  open mode from an auth 401.
- Viewer role gates mutation controls and `umgApi()` rejects non-GET calls with
  `this session is read-only`; the API independently rejects the same writes.
- Responsive layout, 18-section navigation, mobile overflow, IPv6 address
  wrapping, login focus/inert handling and retry behavior were corrected.

## Findings

| ID | Severity | Area | Finding | Status |
| --- | --- | --- | --- | --- |
| DNS-01 | High | Cache isolation | EDNS option queries shared a cache entry with option-free queries; ECS/COOKIE replies can be client-specific | Fixed: option queries bypass cache and single-flight |
| DNS-02 | High | Upstream correlation | Client transaction id was forwarded unchanged, leaving only OS source-port entropy against off-path spoofing | Fixed: fresh random id per upstream exchange |
| DNS-03 | Medium | Cache isolation | RD was absent from the cache key; recursive and non-recursive replies could mix | Fixed: RD added to `CacheKey` |
| DNS-04 | Medium | DNSSEC | No signature validation; DO/CD and DNSSEC records are passed through | Accepted/documented; DO queries bypass cache |
| DNS-05 | Medium | Availability/reflection | No Response Rate Limiting. Per-IP buckets can be bypassed with spoofed sources; UDP is inherently reflectable | Accepted/documented; keep ACL private and do not expose publicly |
| DNS-06 | Medium | Amplification/policy | `ANY` defaults to `forward`; AXFR/IXFR are not explicitly blocked | Accepted/documented; set `any_policy = "refuse"` and block zone transfers at the policy/firewall layer |
| DNS-07 | Low | Response parsing | Question-less (`QDCOUNT=0`) responses are accepted when id and source match | Accepted/documented; an on-path/trusted upstream can already forge the answer |
| DNS-08 | Low | Spoofing entropy | Query-name case randomization (0x20) is not implemented | Accepted/documented; transaction id is now randomized |
| DNS-09 | Low | Cache content | A cached reply may retain unsolicited EDNS options supplied by an upstream | Accepted/documented; option-bearing queries do not populate the cache |
| DNS-10 | Low | Cache identity | EDNS version/TSIG/AD are not separate cache keys | Accepted/documented; DO and option-bearing queries bypass, CD/RD are keyed |
| DNS-11 | Medium | Transport | Upstream DNS is plaintext UDP/TCP with no DoT/DoH and no certificate validation | Accepted; deploy only on a trusted path or add a TLS proxy |
| API-01 | High (conditional) | Control plane | With no password/token, API mutations are open; default bind is often `0.0.0.0` and metrics are public by default | Deployment risk; documented and warned at startup |
| API-02 | Medium | Authentication | Password rotation accepted one-character passwords | Fixed: 8..=1024 characters enforced server-side |
| API-03 | Low | Browser security | No CSP because the dashboard is an inline SPA | Accepted/documented; COOP/frame/referrer/MIME protections are set |
| PANEL-01 | Low | Session storage | Legacy bearer token could persist in `localStorage` beyond a tab | Fixed: sessionStorage only, legacy key removed |
| PANEL-02 | Medium | RBAC verification | Viewer controls were disabled in UI but backend denial lacked a dedicated regression test | Verified and covered by integration test |
| QA-01 | Low | Score API | `list_upstreams` replaced the score object with a scalar, breaking factor display | Fixed: object retained, scalar exposed as `score_value` |

## DNS Lifecycle Review

### 1. Receive and parse

- UDP payloads are bounded by `server.max_udp_packet_size`; oversized input is
  dropped before parsing.
- `parse_query` rejects packets shorter than a DNS header, non-query messages,
  unsupported opcodes, zero questions and multiple questions.
- Malformed names/records are rejected by `hickory-proto`; malformed clients do
  not reach cache or upstream forwarding.
- EDNS is parsed, including DO, advertised payload and options. Duplicate OPT
  records are collapsed by the parser rather than returned as FORMERR; this is
  documented as a compatibility decision.

### 2. Admission

- ACL is evaluated before forwarding. Deny wins; an empty allow set is
  fail-closed; IPv4-mapped IPv6 clients are matched against embedded IPv4 rules.
- Per-IP/global token buckets are applied before ANY/cache/forward work.
- `ANY` can be refused locally (`NOTIMP`) or forwarded according to
  `query.any_policy`.
- Cache lookup happens only after admission, so denied/throttled clients cannot
  turn cache hits into a bypass of those controls.

### 3. Cache and single-flight

- The key is lowercased name, qtype, qclass, CD and RD.
- `DO=1` queries bypass the shared cache because the resolver does not validate
  DNSSEC.
- Any EDNS option bypasses cache and single-flight. This is deliberately
  conservative: even padding causes a bypass, reducing hit rate for clients
  such as `dig`, but it prevents cross-client ECS/COOKIE reuse.
- Plain EDNS (OPT with no options) can use the same entry as a non-EDNS query;
  alignment adds or removes OPT so a client never receives another client's
  advertisement.
- The cache stores raw upstream bytes before show-path alignment; each hit
  rewrites id, RD/CD, question casing and OPT. This preserves one entry for
  many clients without serving the wrong id.
- Cached entries are bounded by entry count and memory, use FIFO eviction, and
  expire at the minimum advertised TTL. Negative entries require an SOA and are
  capped by `negative_max_ttl_secs`.
- Single-flight uses the same key and is skipped for every cache-bypassing
  query class.

### 4. Forwarding and correlation

- A new transaction id is generated per attempt; the rest of the client packet
  (question, RD, CD, DO, EDNS) is preserved.
- UDP uses `connect()`, so the kernel filters datagrams from other source
  addresses/ports. The receive loop ignores unparsable or uncorrelated
  datagrams and keeps waiting until the attempt budget expires.
- TCP connects to the configured upstream, writes a length-prefixed query and
  rejects a response whose id/question does not match.
- Truncated UDP responses can be retried over TCP with the configured fallback.
- Responses whose question omits the question section are accepted after id and
  connected-source checks; this is a documented compatibility trade-off.

### 5. Response handling

- Failover returns a correlated response; the pipeline aligns it to the
  original client query before serving.
- If alignment fails, the client gets SERVFAIL rather than a mis-wired packet.
- Client UDP size limits are enforced after alignment; oversized responses are
  truncated with TC=1 so the client retries over TCP.
- The receive buffer is sized from the client's advertised EDNS payload, with a
  1232-byte floor and a hard 65,535-byte ceiling.

### 6. Failover and exhaustion

- Attempts are bounded by the overall query deadline, per-attempt timeout and
  attempt budget; an upstream is not retried within one query.
- Mismatched/invalid replies count as failed attempts and trigger failover; the
  forged bytes are never surfaced.
- Exhaustion returns SERVFAIL and records the failure reason.

## Availability and Abuse Resistance

Implemented bounds:

- `max_udp_packet_size` (default 4096) caps client and upstream UDP payloads.
- `max_inflight_udp` (default 8192) and `max_tcp_connections` (default 512)
  bound concurrency.
- `max_queries_per_tcp_conn` and `tcp_idle_timeout_ms` bound TCP use.
- Cache entry and memory caps bound memory; traffic/event rings are bounded.
- API concurrency is bounded (256 in-flight, 5 s wait, then 503).

Residual abuse paths:

- No RRL and no per-source cryptographic challenge; spoofed-source UDP traffic
  can bypass per-IP limits and turn the gateway into a reflector if exposed.
- `ANY` forwarding can amplify unless policy is changed to `refuse`.
- AXFR/IXFR are not rejected by policy; a trusted upstream could return large
  zone data to an allowed client.
- Rate-limit state is bounded, so an attacker rotating source addresses can
  evict tracking entries (by design, not a correctness bug).

## Privacy

- `monitoring.client_ip_privacy` defaults to masked; `top_clients` and
  `top_domains` are bounded and FIFO-evicted.
- ECS-bearing queries bypass the cache, so client subnet data does not populate
  a shared entry. The gateway forwards the client's EDNS options upstream; this
  is required for ECS but means the upstream sees the subnet.
- API config export redacts the bearer token for viewers; credentials are stored
  as argon2 hashes beside the config with restrictive permissions.

## Deployment and Configuration

- Default ACL is private/reserved only; it is not an open resolver unless the
  operator adds public CIDRs.
- The sample bind addresses are broad (`0.0.0.0`). Firewall port 53 and the API
  port; do not expose the API without TLS and authentication.
- With no password/API token the gateway starts in legacy open-read/token mode
  and warns. This is intended for development only.
- `protect_metrics` is false by default; scrape `/metrics` only on a protected
  network or enable protection.
- `secure_cookies` must be enabled behind HTTPS; the binary does not terminate
  TLS.
- Compose credentials are plaintext by project requirement; rotate them and do
  not reuse them outside this deployment.
- The `docker-compose.yml` publishes DNS on port 53; on hosts where
  systemd-resolved owns 53, use the documented `RES_DNS_PUBLISH` override.

## Verification

Commands run from `/home/outis/work-github/res`:

```console
$ cargo fmt --all -- --check
$ cargo clippy --all-targets -- -D warnings
$ cargo test --all-targets --quiet
$ cargo build --release
```

Results:

- Formatting: pass.
- Clippy with warnings denied: pass.
- Tests: 229 library tests + 69 integration tests, all pass (298 total).
- Release build: pass.

Targeted tests:

- `dns::msg::tests` (25 tests): pass.
- `dns::forward::tests` (6 tests): pass.
- `dns::pipeline::tests::edns_option_queries_bypass_the_shared_cache`: pass.
- `failover::tests::uncorrelated_response_fails_over_to_a_valid_upstream`: pass.
- `gateway::auth_viewer_cannot_mutate_configuration`: pass.
- `gateway::auth_rotate_password_rejects_short_password`: pass.

Live loopback checks (gateway on `127.0.0.1:15354`, mock upstreams on
`127.0.0.1:15300/15301`):

- UDP and TCP `example.com A`: NOERROR with the client's transaction id
  restored; no protocol errors.
- Two plain queries: first cache miss, second hit; one entry.
- Mixed-case name: hit on the same lowercased key.
- RD=1 and RD=0: separate entries; repeated RD=0 hit its own entry.
- Two ECS queries: cache entries/hits/misses unchanged; no cross-client cache
  use.
- Plain EDNS OPT without options can share the option-free entry; the OPT
  advertisement is rewritten per client.
- Dashboard: 18 sections/18 links, desktop body width 1440, mobile body width
  390, IPv6 addresses wrap without page overflow, no page JS errors.
- Viewer: role banner visible, mutation controls disabled, guard message
  `this session is read-only`, config editor read-only; backend returns 403.
- Open mode: login overlay hidden, chip `no auth`, page auth
  `authentication disabled`, sign-out hidden.

## Residual Risk and Priorities

1. **Do not expose this gateway as an open public resolver.** Keep the ACL
   private, set `any_policy = "refuse"` if not required, and block AXFR/IXFR.
2. **DNSSEC:** validation is upstream-dependent. If clients require authenticated
   denial/existence, deploy a validating resolver in front of or behind this
   gateway, or add validation as a separate project.
3. **Abuse:** add network-level RRL/scrubbing if the service is reachable by
   untrusted networks. The application token bucket is not a substitute for
   spoofing-resistant rate limiting.
4. **Transport:** use a trusted network path or a TLS-capable upstream proxy;
   the binary itself has no DoT/DoH.
5. **Control plane:** never run open mode on `0.0.0.0`; enable TLS at a reverse
   proxy, `secure_cookies`, and `protect_metrics`.
6. **Compatibility trade-offs:** question-less responses, 0x20 case
   randomization, cached unsolicited EDNS options and extended-rcode
   classification remain documented limitations.

## Repository State

- Implementation commit: `23bbae9` — `security: harden DNS cache, upstream correlation, and panel auth`.
- This report and `PANEL_8081_AUDIT_AND_IMPROVEMENTS.md` are committed in the
  follow-up documentation commit; inspect `git log -2` for both hashes.
- No remote push was performed for either commit. The repository was not
  contacted for write operations.
- Pre-existing untracked files `bench/audit.sh`, `bench/bench-cache.toml` and
  `tags` were intentionally left untouched.
- Validation was run against the implementation commit before the report
  commits were created.

## Limitations of This Audit

- IPv6 client traffic could not be tested because IPv6 is disabled on the host;
  IPv6 display/config/DOM behavior was tested.
- Docker Compose was not started because port 53 is owned by systemd-resolved
  and existing credentials/state must not be overwritten. Container findings are
  static review only.
- Off-host spoofing, packet capture, real packet loss and external DNS behavior
  were not tested; spoofing/correlation tests use isolated loopback peers.
- `cargo audit`/`cargo deny` were not available in the environment, so no
  automated CVE database scan was performed.
- Passing tests do not prove production readiness; the deployment risks above
  remain operator responsibilities.
