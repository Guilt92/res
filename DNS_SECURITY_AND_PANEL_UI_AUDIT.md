# res DNS Security and Panel UI Audit

- Date: 2026-10-22
- Repository: `/home/outis/work-github/res`
- Branch: `main`
- Scope: DNS data plane, cache/single-flight, forwarding/failover, management API, dashboard, configuration, deployment defaults and container image
- Result: no unresolved critical defect found in the tested paths. The gateway is now fail-closed by default, rejects zone transfers and non-query upstream responses, avoids sharing client-specific cache entries, enforces authentication/TLS for the control plane, and ships a hardened Compose/image posture. It remains a forwarding-only gateway, not a validating recursive resolver.
- Prior reports recovered from `bc4437d` (`PROJECT_AUDIT_REPORT.md`, `PANEL_8081_AUDIT_AND_IMPROVEMENTS.md`) were reviewed. Their stale no-TLS/no-open-mode/ANY-forward findings have been superseded; their accepted limitations are retained below where still true.

## Executive Summary

The gateway is a forwarding DNS proxy. Its primary security boundary is the
client ACL plus the trust placed in configured upstreams. This audit exercised
the complete request path: client parsing, ACL/rate limiting, cache and
single-flight, upstream selection, strict response correlation, failover,
response alignment, management authentication/RBAC, dashboard behavior, and
the container startup path.

Significant fixes in this audit:

1. **Strict upstream response acceptance.** Responses are fully decoded, must
   have QR=1 and Query opcode, exactly one question matching the client, and no
   trailing bytes. Question-less responses are no longer accepted.
2. **No RD=0 cache access.** Iterative queries cannot read or populate the
   recursive cache, closing a cache-snooping path.
3. **Zone transfers refused locally.** `AXFR`/`IXFR` never reach an upstream.
4. **Safer query policy.** `ANY` defaults to local `REFUSED`; forwarding it is
   an explicit opt-in.
5. **Client-specific EDNS data is no longer shared.** EDNS-option queries
   bypass the cache and single-flight. Upstream-added options (ECS/COOKIE) are
   stripped before an option-free client receives a response, including cache
   hits.
6. **Fail-closed control plane.** Missing credentials stop startup unless
   `[auth].allow_open_mode = true` is explicitly configured for development.
   The container entrypoint no longer generates or prints a password.
7. **Management TLS and DoT.** The management API can terminate HTTPS itself,
   and upstream `protocol = "tls"` uses certificate verification through
   rustls. No plaintext fallback exists when TLS is configured.
8. **Deployment hardening.** The image excludes credentials/backups, Compose
   uses a read-only root filesystem, `/tmp` tmpfs, `no-new-privileges`, and an
   authenticated Prometheus scrape.
9. **Panel usability/accessibility.** Sticky header/sidebar behavior was
   repaired, scroll-spy thresholds corrected, sections made keyboard-operable
   and collapsible with persisted state, secondary panels collapsed by default,
   and the mobile drawer given a focus trap and body lock.

## Trust Model and Architecture Boundary

- **Client to gateway:** untrusted input. Parsed with `hickory-proto`, bounded
  by UDP/TCP limits, then checked by ACL, rate limiting, query policy, and
  cache admission.
- **Gateway to upstream:** configured upstreams are trusted for correctness.
  UDP uses connected sockets; TCP/DoT responses are correlated by transaction
  ID and exact question. TLS upstreams require `tls_server_name` and verify the
  certificate chain unless a private CA file is configured.
- **Control plane:** session cookie or bearer token; mutations require admin
  role and, for cookie sessions, the CSRF double-submit token. Viewer sessions
  are read-only in both the API and UI.
- **Dashboard:** same-origin inline SPA; no third-party scripts.
- **Forwarding-only boundary:** the gateway does not recurse, traverse the DNS
  root, or validate DNSSEC. It preserves DNSSEC records and flags and does not
  claim to authenticate upstream data. Local DNSSEC validation and trust
  anchors are explicitly out of scope.

## Changes Made

### DNS data plane

- `src/dns/msg.rs`
  - `parse_response` now fully decodes upstream bytes with `Message::read` /
    `BinDecoder`; rejects QR=0, non-Query opcodes, QDCOUNT != 1, malformed
    questions, and trailing bytes.
  - `correlates(None)` returns false, so question-less cached/upstream replies
    cannot be accepted.
  - Response alignment strips upstream EDNS options for option-free clients
    after collapsing duplicate OPT records. The OPT record itself, extended
    rcode/version, payload size and DO bit are preserved for the requesting
    client.
- `src/dns/pipeline.rs`
  - RD=0 queries bypass both cache lookup and cache insertion/single-flight.
  - `AXFR`/`IXFR` are refused locally with
    `query_errors_total["zone_transfer_refused"]`.
  - `ANY` follows `query.any_policy`; default is `refuse`.
  - Cache hits are aligned to the current client before serving.
- `src/config.rs`
  - `AnyPolicy` default is `Refuse`.
  - `RES_PROTECT_METRICS` is accepted as an explicit true/false override and
    invalid values are ignored with a warning.
- `config/res.toml`
  - Sample policy uses `any_policy = "refuse"`, `allow_open_mode = false`, and
    documented TLS/DoT examples.
- `config/res.toml.backup`
  - Aligned with the hardened sample: `any_policy = "refuse"`, explicit
    `allow_open_mode = false`, cache byte cap, probe sample count, and DoT/TLS
    comments. A corrupted primary config can no longer fall back to ANY
    forwarding by default.

### Authentication, transport and control plane

- Fail-closed startup when no password, credentials file, or API token exists,
  unless `allow_open_mode` is explicitly enabled.
- Minimum password length enforced at the API and startup; lockout/rate
  limiting; constant-time token comparison.
- Management HTTPS with rustls, HSTS, forced `Secure` cookies when TLS is
  active, and no silent plaintext downgrade.
- DoT upstreams with SNI, certificate verification, optional private CA, and
  TCP/TC fallback semantics.
- `/metrics` can require a principal; Compose enables this and Prometheus sends
  the bearer token.

### Deployment

- `.dockerignore` excludes `config/res.credentials`,
  `config/res.toml.backup`, `bench/`, target/build artifacts, and tests/docs.
- `Dockerfile` no longer copies `config/` into the builder stage; only
  `config/res.toml` reaches the final image.
- `docker/entrypoint.sh` refuses to start without credentials and never
  generates/prints a password.
- `docker-compose.yml`
  - `RES_API_TOKEN` and `RES_PROTECT_METRICS=true`.
  - `read_only: true`, `/tmp` tmpfs, `no-new-privileges:true`.
  - Prometheus scrape credential supplied as a bearer token.
- `deploy/prometheus.yml` sends the configured bearer token.

### Dashboard

- Fixed the real sticky-header regression: `overflow-x:hidden` on
  `html,body` was converted to `overflow-x:clip`, restoring sticky positioning
  at desktop and mobile widths.
- Section navigation:
  - Scroll-spy offset now follows the measured header height + 24 px.
  - Bottom-of-page explicitly activates the final section.
  - Nav clicks expand a collapsed target before scrolling.
- Sections are generated as accessible `<section>` elements with labelled
  headings, `aria-controls`, `aria-expanded`, and inert collapsed bodies.
- Collapse state persists in `localStorage["res-collapsed-sections"]`.
- Default posture: 9 critical sections expanded (DNS service, statistics, top
  clients, traffic, assessment, current upstream state, failover monitoring,
  upstreams, incident timeline); 9 routine management/history panels collapsed.
- Expanding a collapsed history panel redraws its canvases.
- Mobile drawer locks body scroll, makes page content inert, moves focus to the
  first nav link, traps Tab/Shift+Tab, closes on Escape/backdrop, and returns
  focus to the toggle.
- DoT form restores the conventional port 853 only when the port was not
  manually edited; switching back restores 53 under the same rule.
- IPv6 addresses render as full text and wrap inside table cards rather than
  widening the page.
- Viewer mutation controls are disabled and `umgApi()` rejects writes before
  sending; the API independently returns 403.

## Findings

| ID | Severity | Area | Finding | Status |
| --- | --- | --- | --- | --- |
| DNS-01 | High | Response parsing | Question-less upstream responses could be accepted by ID/source alone | Fixed: full decode, QDCOUNT=1, Query opcode, trailing-byte rejection |
| DNS-02 | Medium | Cache isolation | RD=0 queries could read recursive cache entries | Fixed: RD=0 bypasses read/write and single-flight |
| DNS-03 | Medium | Amplification | AXFR/IXFR could be forwarded | Fixed: locally refused and counted |
| DNS-04 | Medium | Amplification/policy | ANY defaulted to forwarding | Fixed: default `refuse`; explicit opt-in only |
| DNS-05 | Medium | Cache/privacy | Cached upstream bytes could carry ECS/COOKIE options to option-free clients | Fixed: options stripped during client alignment, including cache hits; regression-tested |
| DNS-06 | Medium | DNSSEC | No local signature validation | Accepted/out of scope; records/flags preserved; DO queries bypass cache |
| DNS-07 | Medium | Abuse | No Response Rate Limiting | Accepted; ACL/token buckets are not spoofing-resistant; keep private |
| DNS-08 | Low | Spoofing entropy | No 0x20 name-case randomization | Accepted; transaction IDs randomized per exchange; use DoT/trusted path |
| DNS-09 | Medium | Transport | UDP/TCP upstreams are plaintext unless DoT is configured | Accepted; DoT supported and documented |
| API-01 | High (conditional) | Control plane | Open mode could expose mutations when no credentials were configured | Fixed: fail-closed default, explicit dev-only `allow_open_mode` |
| API-02 | Medium | Metrics | `/metrics` was public by default | Mitigated: Compose enables protection and sends a bearer token; still operator-configurable |
| API-03 | Low | Least privilege | The metrics bearer is the same admin API token | Accepted/documented; use a dedicated deployment secret and a restricted scrape network |
| API-04 | Low | Browser security | Inline SPA has no CSP | Accepted; `nosniff`, frame/referrer/COOP/Permissions-Policy and no-store headers are set |
| DEP-01 | High | Container startup | Entrypoint generated and logged an admin password | Fixed: explicit credentials or persisted hashes required; no password output |
| DEP-02 | Medium | Container privilege | Writable root filesystem and default privilege gain | Fixed in Compose: read-only root, `/tmp` tmpfs, `no-new-privileges` |
| DEP-03 | Medium | Build context | Credentials/backup/bench could enter the image context | Fixed: `.dockerignore`; builder no longer copies `config/` |
| DEP-04 | Low | Fallback safety | `res.toml.backup` still had ANY forwarding | Fixed: backup aligned with hardened defaults |
| PANEL-01 | Medium | Layout | `overflow-x:hidden` broke sticky header/sidebar behavior | Fixed: `overflow-x:clip`; verified sticky top matches header |
| PANEL-02 | Low | Navigation | Scroll-spy offset and final section selection were wrong | Fixed: measured header height + bottom detection |
| PANEL-03 | Low | Accessibility | Collapsible sections/mobile drawer lacked complete focus/ARIA handling | Fixed: labelled regions, inert bodies, persisted state, focus trap |
| PANEL-04 | Low | Information architecture | All 18 sections expanded on first load | Fixed: 9 critical sections expanded, 9 secondary collapsed by default |

## Verification

Commands run from the repository root:

```console
$ cargo fmt --all -- --check
$ cargo clippy --all-targets -- -D warnings
$ cargo test --all-targets --quiet
$ cargo build --release
$ docker-compose config --quiet
$ sh -n docker/entrypoint.sh
$ docker build --progress=plain --network=host \
    --build-arg HTTP_PROXY="$HTTP_PROXY" \
    --build-arg HTTPS_PROXY="$HTTPS_PROXY" \
    --build-arg ALL_PROXY="$ALL_PROXY" \
    --build-arg NO_PROXY="$NO_PROXY" \
    -t res:audit-test .
```

Results:

- Formatting: pass.
- Clippy with warnings denied: pass.
- Tests: **237 library + 76 integration = 313**, all pass.
- Release build: pass.
- Compose configuration validation: pass.
- Entrypoint shell syntax: pass.
- Docker image build: pass (`res:audit-test`,
  image `d832113a0c5f`). The first build attempt timed out because Docker did
  not inherit the host proxy; passing the declared proxy build args succeeded.
- Untracked `bench/audit.sh` and `bench/bench-cache.toml` were preserved and
  are excluded from the image context.

Targeted regression coverage added or updated:

- `dns::msg::tests::align_strips_upstream_edns_options_for_option_free_clients`
- `dns::pipeline::tests::cache_hit_strips_upstream_edns_options_for_option_free_clients`
- `dns::pipeline::tests::rd_zero_queries_never_read_or_write_the_cache`
- `dns::pipeline::tests::zone_transfers_are_refused_locally`
- `dns::msg::tests` strict response/question/opcode/trailing-byte cases
- Integration coverage for fail-closed startup, auth/RBAC, TLS/DoT, panel API
  contracts and hardened query policy
- The shared-tier integration test now uses 100 independent queries instead of
  20; the assertion was not weakened, only the sample size was made reliable
  after an empty-lower-tier sample flaked once.

### Live and browser checks

- **Fail-closed process:** with no password, token, credentials file, or open
  mode, startup exits `1` with the expected “no control-plane credentials”
  error.
- **Container entrypoint:** `docker run --rm res:audit-test` exits `1` with
  “refusing to start without credentials” and no password in output.
- **Container runtime:** image started with `--read-only --tmpfs /tmp
  --security-opt no-new-privileges`; `/api/health` returned `200`,
  `/api/status` returned `401` without authentication, and auth info reported
  password auth enabled. `/etc/res` contained only `res.toml`; no credentials,
  backup, or bench files were present.
- **Metrics/API auth:** with `RES_API_TOKEN` and `RES_PROTECT_METRICS=true`:
  - `/metrics`: `401` without auth, `200` with bearer.
  - `/api/status`: `401` without auth, `200` with bearer.
- **EDNS live check:** a mock upstream returned a CLIENT-SUBNET option.
  - Repeated option-free EDNS queries (`dig +edns=0 +nocookie`) returned an OPT
    with `udp: 1232` and **no** CLIENT-SUBNET.
  - A non-EDNS query received no OPT.
  - Option-bearing queries remain cache-bypassing; the pipeline test confirms
    the cached path strips the option.
- **Dashboard (Chromium/Playwright):**
  - 18 sections / 18 nav links at 390, 800, 980, 1100 and 1440 px.
  - No duplicate IDs, missing nav targets, missing labelled regions, invalid
    `aria-controls`, page errors, or horizontal body overflow.
  - Sticky header and sidebar top offsets remain locked while scrolling
    (`overflow-x: clip`).
  - Default 9 expanded / 9 collapsed sections; nav clicks expand targets;
    collapse state survives reload.
  - Collapsed history chart canvases redraw on expansion with nonzero width.
  - Mobile drawer: body scroll locked, content inert, focus trapped, Escape
    closes and restores focus to the toggle.
  - Viewer session: read-only banner, disabled mutation controls, server rejects
    writes with “this session is read-only”.
  - Latest-release open-mode instance (`allow_open_mode=true` only): login
    overlay hidden, chip `no auth`, sign-out hidden, no JS errors at 390 px.
- **Packaging:** image build and standalone container run were verified; the
  full Compose stack was not started because port 53 is owned by
  systemd-resolved and existing state/credentials must not be overwritten.

## Residual Risks and Priorities

1. **Do not expose this gateway as an open public resolver.** Keep the ACL
   private; add network-level RRL/scrubbing if untrusted networks can reach UDP.
2. **DNSSEC is not validated locally.** Use a validating resolver in front of
   or behind this gateway when authenticated denial/existence is required.
3. **Use DoT or a trusted path.** Plain UDP/TCP upstream transport is still the
   default unless an upstream explicitly sets `protocol = "tls"`.
4. **Metrics token scope.** The bundled metrics bearer is also the admin API
   token. Treat it as a high-value secret, scrape over a private network, and
   consider a dedicated metrics credential as future work.
5. **CSP.** The inline dashboard has no Content-Security-Policy. Moving to
   hashed/nonced assets would allow a strict policy.
6. **Root bind.** The container runs as root to bind port 53; Compose mitigates
   with a read-only root, tmpfs `/tmp`, and `no-new-privileges`, but a capability
   drop/`CAP_NET_BIND_SERVICE` setup would reduce impact further.
7. **Image healthcheck port.** The image healthcheck probes `127.0.0.1:53`.
   Deployments overriding the DNS listen port must override the healthcheck.
8. **Compose credentials are plaintext by requirement.** They are confined to
   `docker-compose.yml` and the Prometheus web config; rotate them together.
9. **Browser coverage.** Chromium/Playwright only; no Firefox/Safari, real
   mobile devices, screenshot diffing, or axe accessibility score.
10. **IPv6 traffic.** Host IPv6 is disabled; IPv6 rendering/config/DOM behavior
    was tested but not real IPv6 client traffic.
11. **Dependency CVE scan.** `cargo audit`/`cargo deny` are unavailable in this
    environment, so no automated advisory database scan was performed.
12. **Docker build proxy dependence.** In this environment Docker required
    explicit host proxy build args; the documented build command assumes
    network/proxy access to crates.io.

## Repository State

- Current HEAD: `17f4035` (`test: make shared-tier integration sample reliable`).
- Implementation commits in this audit:
  - `7855fcd` fail-closed control-plane credentials
  - `cbf3f3e` management HTTPS and DNS-over-TLS upstreams
  - `747dea0` strict DNS response validation and cache admission
  - `af3c4ed` DNS safety documentation
  - `a50725e` dashboard navigation/section controls
  - `3b1c02f` strip upstream EDNS options for option-free clients
  - `05e2d20` container and metrics deployment defaults
  - `1950821` collapse secondary dashboard sections by default
  - `4c8f914` align fallback config with hardened defaults
  - `faabc39` cached EDNS option stripping test
  - `17f4035` shared-tier test reliability
- This report is the final documentation commit; no push was performed.
- Pre-existing untracked `bench/audit.sh` and `bench/bench-cache.toml` remain
  untouched.

## Limitations of This Audit

- Forwarding-only behavior was exercised against loopback mock upstreams; no
  external recursive resolver, adversarial network path, or production traffic
  was available.
- IPv6 client traffic, off-host spoofing, packet capture, packet loss, and real
  volumetric DDoS tests were not possible.
- Full Compose deployment was not started because port 53 is already owned by
  the host resolver and existing state must be retained.
- Passing tests reduce risk but do not prove production readiness; ACL,
  upstream trust, secrets management, network isolation, and DNSSEC policy
  remain operator responsibilities.
