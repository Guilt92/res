# Hardening Report — `res` DNS gateway

Baseline: `371c48b` (review report). Result: `e20bd89` + this report. Branch `main`, **nothing pushed**.

Status labels: **CONFIRMED-FIXED** (change made and verified by a test or runtime check) · **CONFIRMED-TESTED** (behaviour verified, no change needed) · **NOT TESTED** · **REMAINING ISSUE**.

## 1. Executive Summary

All P0 items, the P1/P2/P3 items and the DNS-port-153 testing rule were implemented and verified. The full test suite is green on stable Rust (431 tests) and on the declared MSRV 1.88 (431 tests), `cargo clippy -D warnings`, `cargo fmt --check` and `cargo audit` are clean, and the dashboard passes 18 Playwright tests (7 viewports × 2 themes plus behaviour tests). DNS UDP/TCP (IPv4 and IPv6) was exercised on port **153 only**.

Not done / not verifiable here: the GitHub Actions workflow has never run on GitHub, Docker/Compose was not run, and `dashboard/app.js` is only partly modularised (see §10).

## 2. Implemented Changes

| Item | Status | Where |
|---|---|---|
| 1.1 Lockout keyed by (account, client IP), atomic reservation, bounded/evicting table | CONFIRMED-FIXED | `src/auth.rs` |
| 1.2 Secret-preserving config import, secret-free export, `clear_secrets` | CONFIRMED-FIXED | `src/config.rs`, `src/api/config_routes.rs` |
| 1.3 Dependency advisories | CONFIRMED-FIXED | `Cargo.toml/lock`, `src/tls.rs` |
| 2.1 Static assets: memory cache, ETag/304, gzip/br, cache headers, async I/O | CONFIRMED-FIXED | `src/api/assets.rs` |
| 2.2 Root-sensitive tests | CONFIRMED-FIXED | `src/auth.rs`, `tests/gateway.rs` |
| 2.3 CI | CONFIRMED-FIXED (written); workflow itself NOT TESTED on GitHub | `.github/workflows/ci.yml`, `tests/e2e/` |
| 3.1 Trusted proxies | CONFIRMED-FIXED | `src/api/client_ip.rs`, `server.trusted_proxies` |
| 3.2 IPv4-mapped canonicalisation in `clear_login_rate` | CONFIRMED-FIXED | `src/auth.rs` |
| 3.3 Upstream-name validation | CONFIRMED-FIXED | `src/config.rs::validate_upstream_name` |
| 3.4 Session management | CONFIRMED-FIXED | `src/auth.rs`, `src/api/auth_routes.rs` |
| 4.1 Split oversized files | partly done (see §10) | `src/api/*`, `dashboard/js/format.js` |
| 4.2 `fetch_update` deprecation | CONFIRMED-FIXED | `src/dns/listener.rs` |
| 4.3 MSRV verification | CONFIRMED-FIXED (code change needed) | `src/failover.rs`, `src/upstream/health.rs` |
| 4.4 Touch targets | CONFIRMED-FIXED | `dashboard/app.css` |

## 3. Security Improvements

- **Lockout (1.1).** Key = (lower-cased username, canonical IP). The failed-attempt budget is *reserved before* argon2 runs, in the same critical section as the lock check; a success removes it. Eviction order when the 4096-entry table is full: expired entries → unlocked entries (oldest window) → only then the lock expiring soonest. Per-IP rate limit is now one atomic check-and-count (`begin_login_attempt`). Argon2 double-verification and dummy-hash timing equalisation untouched. Tests (`src/auth.rs`, `tests/control_plane_auth.rs`): cross-IP prevention, same-IP lock, correct login after other-IP failures, success clears counter, expiry and recovery (clock aged deterministically), failure-window reset, mapped-IPv6 shares IPv4 lock, 16 parallel guesses against a budget of 3 → exactly 3 reach verification, 40 parallel attempts against a limit of 5 → exactly 5 allowed, active lock survives a flood of 4,296 other keys, table bounded. **CONFIRMED-FIXED**; the original attack (5 anonymous failures lock `admin`) is now covered by `attacker_lockout_does_not_lock_the_admin_on_another_address` over HTTP.
- **Secrets (1.2).** Export omits the proxy password **and** `server.api_token` for every role (behaviour change: admins previously received the token). Import keeps an omitted secret; a non-empty one replaces it; a changed `proxy.username` never inherits the old password; `clear_secrets: ["proxy_password","api_token"]` removes explicitly; unknown values are rejected. Response and audit event list `secrets_preserved`. Persist-first is unchanged (`commit_config`). `tests/config_import.rs` (8 tests): round trip, no leak, replacement, username change, explicit clear, bad clear value, failed (invalid) import, persistence failure (runtime unchanged, file intact). **CONFIRMED-FIXED**.
- **Trusted proxies (3.1).** `server.trusted_proxies` (default empty). `X-Forwarded-For` is read only when the TCP peer is inside the list, walked right-to-left, believing only hops appended by trusted proxies; malformed/non-ASCII chains fall back to the proxy. Audit events carry `client` (effective) and `peer` (socket). Affects control-plane login limits/lockout/audit only — **not** DNS ACLs or DNS rate limits. A `/0` entry produces a config warning. Tests: 9 unit tests (IPv4, IPv6, mapped, bracketed, multi-header, spoof) + 4 HTTP tests (untrusted peer cannot spoof; per-forwarded-client limit; forged left hops cannot reset a limit; audit records both). **CONFIRMED-FIXED**.
- **Sessions (3.4).** `auth.session_idle_timeout` (default 30m, `0` = off, refreshed by activity), per-account cap 16 + global cap 1024 (oldest of that account / overall), dead sessions pruned on insert, `DELETE /api/auth/sessions` (admin + CSRF for cookies; keeps the caller's own session; viewers get 403), `revoke_user`, password rotation still revokes all. Sessions remain in memory and are lost on restart — documented in README. Cookie flags (`HttpOnly; SameSite=Strict`, `Secure` with TLS/config) and CSRF double-submit unchanged (verified by existing tests). **CONFIRMED-FIXED**.
- **Upstream names (3.3).** Unicode letters/digits plus ``space _ - . : @ + / ( ) [ ] # , = ~``; no control/markup characters, no leading/trailing or doubled spaces; the shipped `config/res.toml` is tested to remain valid; client-side `escapeHtml` is retained. **Compatibility note:** an existing config with other characters is now rejected at load.

## 4. Bugs Fixed

| Bug (from `PROJECT_REVIEW.md`) | Status |
|---|---|
| C1 admin lockout DoS | CONFIRMED-FIXED |
| C2 import deletes proxy password | CONFIRMED-FIXED |
| C6 `clear_login_rate` not canonicalised | CONFIRMED-FIXED (test over native v4, native v6, mapped→v4, v4→mapped) |
| C7 root-sensitive tests (and stray `/etc/res.credentials`) | CONFIRMED-FIXED — failure is induced with a missing directory / a regular file in place of the directory, so it is identical for root and non-root; temp dirs are cleaned by a drop guard. Verified as root and as user `nobody`. |
| S1 eviction weakening lock counters | CONFIRMED-FIXED (eviction order above) |
| S2 concurrent-guess race | CONFIRMED-FIXED |
| S3 no trusted-proxy support | CONFIRMED-FIXED |
| P1 uncached/uncompressed/blocking static serving | CONFIRMED-FIXED |
| S6 symlink escape from the dashboard dir | CONFIRMED-FIXED (canonicalised path must stay in the dashboard root; test) |
| D1 RUSTSEC-2026-0385 + warnings | CONFIRMED-FIXED (§8) |
| Q4 deprecated `fetch_update` | CONFIRMED-FIXED |
| MSRV 1.88 did not compile (new finding) | CONFIRMED-FIXED — two `with_label_values(&[&String, &str])` array inferences accepted by new rustc but not 1.88 |
| Two leftovers from my earlier root-run tests (`/etc/res.credentials`) | removed; not recreated after the test fix |

## 5. Dashboard Changes

The existing redesign was preserved. Changes: header/toolbar controls ≥ 44 px on ≤ 980 px or coarse-pointer devices (`min-height/min-width: 44px`; section/collapse toggles keep their size and gain an invisible 44 px hit area; secondary header bar grows to fit); formatting helpers moved to `dashboard/js/format.js` and `app.js` is loaded as an ES module (`<script type="module">`, CSP `script-src 'self'` unchanged). Verified: the Playwright test asserts every visible header/toolbar button/select at 375 px is ≥ 44×44. A visual check at 768 px (light) looked correct; no overflow in any run.

## 6. Tests Executed and Results

All as actually run; the test machine is a 2-vCPU Linux VM.

| Check | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets --locked -- -D warnings` (stable 1.99.1) | clean |
| `cargo +1.88.0 clippy --all-targets --locked -- -D warnings` | clean |
| `cargo build --release --locked` (HEAD `e20bd89`) | success |
| `cargo test --locked --no-fail-fast` (stable, run as root) | **314** lib + 8 loadtest + 8 `config_import` + 7 `control_plane_auth` + 93 `gateway` + 1 `static_assets` = **431 passed, 0 failed** |
| Same on **Rust 1.88.0** | **431 passed, 0 failed** |
| Fixed root-sensitive tests as user `nobody` | `set_admin_password_*` 2/2, `persist_failure_is_reported_and_audited` 1/1, `persistence_failure_keeps_runtime_secrets…` 1/1 passed (the rest of the suite was run as root only) |
| `cargo audit --file Cargo.lock` | exit 0, 0 vulnerabilities, 0 warnings (223 crates, 1409 advisories) |
| `cargo tree` | `ctutils 0.4.8`, `tokio 1.53.3`; `rustls-pemfile` and `base64 0.21` no longer in the tree |
| DNS functional on **127.0.0.1:153** (mock upstreams, release binary): A/AAAA/MX/TXT + unknown name over UDP **and** TCP | all `NOERROR`, 0.3–1.4 ms |
| DNS functional on **[::1]:153** UDP + TCP | both `NOERROR` |
| JS: `node --check` all dashboard files, ESLint `no-undef` | no errors (2 pre-existing `no-unused-vars` warnings in `app.js`) |
| Playwright (Chromium 141): 320, 375, 430, 768, 1024, 1366, 1920 px × light and dark; plus theme persistence, sidebar navigation (every section), mobile drawer (keyboard focus containment, Escape, touch tap, 44 px targets), ETag/no-store | **18 passed**; no horizontal overflow, `data-js-errors=0`, no console errors, no failed requests (the pre-login `401` on `/api/auth/session` is expected and filtered) |
| Authentication/authorisation, proxy export/import, trusted proxy, IPv4/IPv6 | covered by the Rust tests above |

**Port-53 safety.** No process was bound to, or probed on, port 53 by me. Before each runtime test I confirmed nothing listened on 153; listeners were `127.0.0.1:153` and `[::1]:153` only, stopped afterwards (verified free). Cargo integration tests bind `127.0.0.1:0` (ephemeral). The only `:53` strings in tests are upstream *destination* values that are never bound. `tests/e2e/start-gateway.sh` refuses port 53. No existing service was touched and Docker Compose was not run (its port was not changed).

## 7. Performance Results

Single 2-vCPU VM running the load generator, two mock upstreams and the gateway together (so the numbers are a lower bound, not a capacity claim). `bench/run.sh` with `BENCH_UDP_PORT=153`, 10 s per level, 10 % TCP:

| Target | Achieved (received) | Failed | p50 / p95 / p99 |
|---|---|---|---|
| 1,000 qps | 1,000 | 0 / 10,000 | 0.32 / 0.68 / 1.64 ms |
| 5,000 qps | 4,998 | 4 / 49,992 (0.008 %) | 0.75 / 1.98 / 3.40 ms |
| 10,000 qps | 7,462 (box saturated) | 3 / 74,887 (0.004 %) | 4.16 / 34.5 / 55.1 ms |

The handful of failures are TCP (`early eof` / `connection reset`); I did **not** investigate the cause (the bench config closes a TCP connection after 1,000 queries and the generator pipelines 32 in flight, which may explain it — unverified).

Dashboard assets (`/app.js`, Python client, 4 connections × 500 requests — client-bound, indicative only): identity 138,481 B ≈ 2.4k req/s; gzip 37,298 B ≈ 3.0k req/s; brotli 34,849 B ≈ 2.9k req/s; `If-None-Match` → 304 ≈ 4.4k req/s sequential. Cold-load payload (br): `index.html` 40,900→9,377 B, `app.js` 138,481→34,849 B, `app.css` 53,781→10,575 B. No before/after timing against the old handler was taken (the old binary was not kept).

## 8. Dependencies Updated

| Crate | From → To | Reason |
|---|---|---|
| `ctutils` | 0.4.3 → 0.4.8 | RUSTSEC-2026-0385 (via `argon2`) |
| `tokio` | 1.53.1 → 1.53.3 | RUSTSEC-2026-0386 (patched ≥ 1.53.3; the project does not call `AsyncFd` directly) |
| `yoke-derive` | 0.8.3 → 0.8.4 | yanked |
| `rustls-pemfile` 1.0.4 | removed | unmaintained (RUSTSEC-2025-0134); replaced by `rustls::pki_types::pem` (no new crate); also removes `base64 0.21` |
| `flate2` 1.1.10 (`rust_backend`), `brotli` 9.1.1 | added | static-asset compression (plus `miniz_oxide`, `simd-adler32`, `alloc-stdlib`, `brotli-decompressor`) |

Resolved by `cargo audit` and `cargo tree` on the final lockfile, not assumed. Dev tooling only: `tests/e2e/package.json` (Playwright 1.56.1, ESLint 9.39.1) — not part of the dashboard runtime.

## 9. MSRV Compatibility

`rust-version = "1.88"` is **kept and now verified**: `cargo +1.88.0 build/clippy/test --locked --all-targets` pass. The first attempt failed on two array-literal inferences in `src/failover.rs` and `src/upstream/health.rs` (fixed with `.as_str()`); no dependency required a newer compiler (`flate2` needs 1.67, `brotli` 1.59). The deprecated `fetch_update` was replaced by an explicit compare-exchange loop because its replacement `try_update` does not exist on 1.88. The Dockerfile's `rust:1.97` builder is newer than the MSRV and left unchanged; README states the MSRV and CI has an MSRV job.

## 10. Remaining Issues

| Item | Status |
|---|---|
| GitHub Actions workflow `ci.yml` was never executed on GitHub (its commands were run locally; action versions/pins are unverified) | NOT TESTED |
| Docker image/Compose build and stack | NOT TESTED (not run, per the isolation rule) |
| Only the 3 fixed tests were run as non-root; the full suite was run as root | NOT TESTED as non-root |
| `dashboard/app.js` still ~3,086 lines — only pure helpers were extracted (`js/format.js`); the rest depends on shared mutable state and was not split to avoid regressions | REMAINING ISSUE |
| `src/config.rs` (~2.5k lines) and `tests/gateway.rs` (4.6k) not split | REMAINING ISSUE |
| No account-wide throttle: a botnet using many source IPs gets `max_failed_attempts` guesses per IP (bounded by argon2 cost and the per-IP limit). This is the deliberate cost of removing the lockout DoS | REMAINING ISSUE (design trade-off) |
| When *every* slot in the lockout table is an active lock, the soonest-expiring lock is evicted (needs ≥ 4,096 simultaneously locked pairs) | REMAINING ISSUE (accepted) |
| Proxy password still stored in plaintext in `res.toml` (mode 0600); sessions lost on restart (documented) | REMAINING ISSUE |
| Admin "revoke other sessions" is API-only (no dashboard button, to avoid adding UI) | REMAINING ISSUE |
| Possible TCP failures (0.004–0.008 %) under load test — cause not investigated | REMAINING ISSUE / NOT TESTED |
| Viewer-role UI walk-through and a visual comparison against a reference screenshot (none supplied) | NOT TESTED |
| 2 pre-existing ESLint `no-unused-vars` warnings in `app.js` | REMAINING ISSUE (cosmetic) |
| Upstream names with characters outside the new set will fail validation at load (breaking for such configs) | REMAINING ISSUE (compat note, in CHANGELOG) |

## 11. Git Commits

All local on `main`; **no push, no amend, no history rewrite**.

| Hash | Message |
|---|---|
| `c4cb0bf` | fix(security): per-client login lockout, secret-preserving import, trusted proxies, session lifecycle |
| `8d8ce49` | build(deps): resolve RUSTSEC advisories, drop rustls-pemfile |
| `092eb3e` | perf(dashboard): async in-memory static assets with ETag, gzip/brotli and caching |
| `c486b51` | fix(msrv): build on Rust 1.88, replace deprecated fetch_update |
| `a983322` | feat(dashboard): 44px touch targets, ES module split of formatting helpers |
| `b57d00b` | ci: fmt, clippy, build, tests, MSRV, cargo audit, JS lint and Playwright smoke tests |
| `9f4ef0c` | refactor(api): split api/mod.rs into acl, cache, config_routes, policy, proxy, upstreams |
| `e20bd89` | docs: sessions, trusted proxies, secret handling, MSRV, CI and test-port policy |
| (this report) | docs: add HARDENING_REPORT.md |

## 12. Production Readiness Assessment

For a trusted-network or loopback deployment (the documented default) the project is **production-ready**: the P0 blockers are fixed with regression tests, dependencies are audit-clean, the MSRV is real, the control plane is safer behind a reverse proxy, and the dashboard is verified in both themes at all required widths. Before relying on it internet-facing: run the CI workflow once on GitHub, exercise the Docker stack in an isolated environment, run the load test on dedicated hardware and look into the rare TCP failures, and decide whether the account-level brute-force trade-off (per-IP only) and plaintext proxy password at rest are acceptable for your threat model. Port 53 was never touched; production Compose port settings were left for you to configure.
