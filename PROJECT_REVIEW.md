# PROJECT_REVIEW — `res` DNS gateway

Review date: 2026-11-06 · Reviewed revision: `bdeb570` (branch `main`, clean tree at start)
Reviewer environment: Linux, Rust 1.99.1 (installed outside the project), Node 22 + Playwright/Chromium (installed in a scratch directory, not in the project).

**Conventions.** Every finding is tagged:

- **CONFIRMED-RUNTIME**: reproduced against a running instance or a failing/passing test.
- **CONFIRMED-CODE**: established by reading the code; not reproduced at runtime.
- **POTENTIAL**: a plausible risk that depends on deployment or conditions I did not test.
- **OPTIONAL**: an improvement, not a defect.

Findings marked **FIXED** were corrected after the review in a separate dashboard commit (see §3 and §11). Everything else is **unchanged** — this was an inspection task and no Rust source, config, or dependency was modified.

---

## 1. Executive Summary

`res` is a Rust (axum/tokio/hickory-proto) DNS forwarding gateway: UDP/TCP listeners, tiered upstream pools with health checks and failover, a response cache, ACLs and rate limiting, optional SOCKS5/HTTP proxying and DoT upstreams, a REST control plane with a vanilla-JS dashboard, Prometheus metrics, and Grafana provisioning. Configuration is a single TOML file (no database).

**Overall: solid engineering, close to production-ready for a loopback/trusted-network deployment, with a small number of real defects that should be fixed before exposing the control plane.**

- Build (release) and `cargo clippy --all-targets` succeed with one deprecation warning.
- 273/274 unit tests, 92/93 integration tests and 8/8 loadtest-bin tests pass when run as root; the two failures are artefacts of running as root and **pass as an unprivileged user** (see §10).
- Security posture is above average: fail-closed auth, argon2 with dummy-hash timing equalisation, CSRF double-submit, strict CSP, path-traversal-safe static serving, metrics token. Verified at runtime where noted.
- The dashboard light/dark/responsive redesign **was already committed at HEAD (`bdeb570`)**; this task verified it in a real browser rather than re-implementing it. 14 viewport×theme combinations show no horizontal overflow and no JS errors. Three dashboard defects were found and fixed (§3).

Top issues (details below):

| # | Severity | Issue | Status |
|---|---|---|---|
| C1 | Medium | Unauthenticated attacker can lock the admin account out with 5 bad logins | open |
| C2 | Medium | Config export → import silently deletes the proxy password | open |
| C3 | Low–Med | Closed mobile drawer's 20 controls stay keyboard-focusable (off-screen) | **FIXED** |
| C4 | Low | Upstream names injected unescaped into chart legend/tooltip HTML | **FIXED** |
| D1 | Low | `cargo audit`: 1 advisory (RUSTSEC-2026-0385, `ctutils` via `argon2`) + 3 warnings | open |
| P1 | Low–Med | Static dashboard assets: no cache headers, no compression, blocking disk read per request | open |

No Critical or High findings were confirmed.

---

## 2. Project Architecture Review

**Layout** (72 tracked files, ~35.6k lines):

| Area | Files | Notes |
|---|---|---|
| Data plane | `src/dns/{listener,pipeline,forward,msg}.rs`, `src/upstream/*`, `src/failover.rs`, `src/selection.rs`, `src/cache.rs`, `src/acl.rs`, `src/ratelimit.rs`, `src/proxy.rs`, `src/tls.rs` | UDP/TCP listeners → ACL/rate-limit precheck → cache → upstream selection → bounded failover |
| Control plane | `src/api/mod.rs` (3.7k lines), `src/api/prom.rs`, `src/auth.rs`, `src/shared.rs`, `src/config.rs`, `src/persist.rs` | axum router; `route_layer` guards for read vs. admin; atomic config writes with 3 backup generations |
| Observability | `src/metrics.rs`, `src/history.rs`, `src/traffic.rs`, `src/events.rs`, `deploy/` (Prometheus, alert rules, 6 generated Grafana dashboards) | |
| Dashboard | `dashboard/{index.html,app.js,app.css,boot.js}` + Shabnam fonts | Vanilla JS, canvas charts, no build step, no npm dependencies |
| Tooling | `src/bin/{loadtest,mock-upstream,hotpath-bench}.rs`, `bench/`, `Dockerfile`, `docker-compose.yml`, `docker/entrypoint.sh` | |
| Tests | `tests/gateway.rs` (4.6k lines, 93 tests), ~274 unit tests inline | |

**Strengths (verified by reading code and/or exercising it):**

- State is shared through `Arc<Shared>` with `ArcSwap` config snapshots, so the hot path reads config lock-free; mutations serialise on one async mutex with optimistic concurrency (`generation`) and "last usable upstream" confirmation.
- Config mutation is persist-first: write temp → fsync → rename; on failure the live config is unchanged (the `persist_failure_*` integration test covers it and passes as non-root).
- Admin password rotation is persist-first as well (`auth.rs: set_admin_password`).
- Bounded everything: sessions (1024), lockout table (4096), login-IP table (8192), API in-flight semaphore with 503 `busy`, argon2 on the blocking pool.
- Dashboard is served by a hand-written fallback instead of `ServeDir` (dotfiles/`..` refused, JSON 404 for unknown `/api/*`).

**Architectural concerns:** see C1/C2 (auth/config design), P1 (static serving), Q1–Q3 (file size and string-templated UI).

---

## 3. Confirmed Bugs and Issues

### C1 — Anonymous attacker can lock out the admin account — Medium — CONFIRMED-RUNTIME — open

- **Where:** `src/auth.rs` `AuthState::login` (≈L411), `record_failure` (≈L570); handler `login` in `src/api/mod.rs` (≈L730).
- **What:** Lockout state is keyed only by lower-cased username. Five failed logins for `admin` from *any* source lock that account for `lockout_duration` (default 15 min), after which even the correct password is rejected. The default usernames (`admin`, `viewer`) are the shipped defaults in `config/res.toml`, so they are easy to guess.
- **Evidence:** Against the running server: 5 × `POST /api/auth/login` with a wrong password → 5×401; the 6th request with the **correct** password → `429 {"code":"locked","error":"too many failed attempts; try again in 899s"}`. (The per-IP limit of 30/min does not prevent this, since 5 attempts suffice.)
- **Impact:** Trivial denial of control-plane access (not of DNS service). Existing sessions keep working, but a logged-out admin cannot sign back in for 15 min, repeatably.
- **Fix:** Key lockout on `(username, client IP)` or add a per-IP failure counter that gates *before* the per-user one; or make lockout a progressive delay rather than a hard block; keep per-IP throttling as the primary brute-force defence. Add a test for "attacker lockout does not block a different IP".

### C2 — Config export → import silently deletes the proxy password — Medium — CONFIRMED-RUNTIME — open

- **Where:** `src/api/mod.rs` `export_config` (≈L1482, clears `proxy.password` for all roles) and `import_config` (≈L1520, applies the parsed TOML as-is); `src/config.rs` `ProxyConfig.password` (≈L369).
- **What:** The password is never exported ("never leave the process"), but import has no merge step: a TOML without `password` replaces the live value with the empty string, and persists that.
- **Evidence:** Set proxy `username=u1`, `password=sekret` via `PUT /api/proxy` → `password_set:true`, and `password = "sekret"` present in `res.toml`. `GET /api/config` → exported TOML contains no `password`. `PUT /api/config` with that exact export → `status:ok`; afterwards `GET /api/proxy` → `password_set:false` and the `password` line is gone from `res.toml`.
- **Impact:** The documented backup/restore/edit workflow breaks an authenticated proxy without any warning; DNS-over-proxy then fails auth.
- **Fix:** In `import_config`, when the imported `proxy.password` is empty and `proxy.username` is unchanged, carry over the current password (same for `api_token`-style secrets); or reject with an explicit warning. Add an integration test for the round trip.
- **Related (Low, CONFIRMED-RUNTIME):** the proxy password is stored in plaintext in `res.toml` (file mode `0600`, verified). Acceptable if documented; consider env-only like `RES_API_TOKEN`/metrics token.

### C3 — Closed mobile navigation drawer remained keyboard-focusable — Low–Medium (accessibility) — CONFIRMED-RUNTIME — **FIXED**

- **Where:** `dashboard/app.css`, `@media (max-width:980px) .sidenav`.
- **What:** The off-canvas drawer was hidden only with `transform`, so `visibility` stayed `visible`, there was no `inert`/`aria-hidden`, and it kept a large `box-shadow`.
- **Evidence (before):** At 375 px, tabbing through the page focused 20 off-screen controls (`x ≤ 0`: the collapse button and 19 nav links) while the drawer was closed; the closed drawer's shadow was visible as a grey band on the left edge of the viewport (seen in screenshot).
- **Fix applied:** closed state is `visibility:hidden` (delayed by the transition so the slide-out still animates) and the shadow only applies to `.open`.
- **Evidence (after):** 0 off-screen focus stops in 40 Tab presses; closed drawer `visibility: hidden`, `box-shadow: none`; open drawer works, `aria-expanded` toggles, Escape closes, navigating via a drawer link closes it.

### C4 — Unescaped upstream names in chart legend and tooltip — Low — CONFIRMED-RUNTIME — **FIXED**

- **Where:** `dashboard/app.js` chart legend (`legendEl.innerHTML`, ≈L1138) and tooltip (`tip.innerHTML`, ≈L1188). `src/config.rs` validates upstream names only for emptiness and length (≤64), not characters.
- **Evidence (before):** creating an upstream named `<b id=pwn>x</b>` made `document.getElementById('pwn')` exist in the dashboard DOM. After the fix the element is absent.
- **Impact:** Admin-supplied (or config-file-supplied) HTML injection. Script execution is prevented by the CSP (`script-src 'self'`, no inline), so impact was HTML/layout spoofing, not code execution. All other `innerHTML` sites I inspected (`barRows`, `statRows`, client table, upstream table, `nameList`) already escape.
- **Fix applied:** wrapped both with `escapeHtml(...)`.
- **Remaining recommendation (OPTIONAL):** also restrict upstream names server-side to a safe charset.

### C5 — Idle metrics showed a red "▼ 0.0 vs prev" trend — Low (UI correctness) — CONFIRMED-RUNTIME — **FIXED**

- **Where:** `dashboard/app.js` `trendEl()` (≈L1003): the flat-threshold test used `<`, so `cur = prev = 0` fell through to the "decrease" branch.
- **Evidence (before):** on an idle gateway the QPS tile displayed a red "▼ 0.0 vs prev". After: "→ 0.0" with class `flat`.
- **Fix applied:** `<` → `<=`.

### C6 — `clear_login_rate` does not canonicalise the client IP — Low — CONFIRMED-CODE — open

- **Where:** `src/auth.rs` `clear_login_rate` (≈L400) vs. `check_login_rate`/`record_login_attempt`, which call `canonical_ip`.
- **Impact:** For an IPv4-mapped IPv6 peer (`::ffff:a.b.c.d`, possible on a dual-stack listener) the counter recorded under the canonical IPv4 key is not cleared after a successful login. Effect: a legitimate user's counter is not reset. Not reproduced at runtime.
- **Fix:** call `canonical_ip(ip)` in `clear_login_rate`.

### C7 — Unit test writes outside the sandbox when run as root — Low (test hygiene) — CONFIRMED-RUNTIME — open

- **Where:** `src/auth.rs` test `set_admin_password_persist_first_preserves_on_failure` (≈L896).
- **What:** It relies on `/proc/1/root/etc/res` being unwritable. As root it is writable, the assertion fails, and the test **creates `/etc/res.credentials`** (`credentials_path` replaces the file name of the given path). I observed this file after my root test run and removed it.
- **Fix:** use a path under a temp dir made read-only, or a path under a regular file (`ENOTDIR`) so the failure is independent of privileges. Same root-sensitivity in `tests/gateway.rs::persist_failure_is_reported_and_audited` (uses `chmod 0555`).

---

## 4. Security Assessment

**Verified working at runtime** (against the running binary):

- Unauthenticated `GET /api/status` → 401; `GET /metrics` without token → 401, with `Authorization: Bearer <token>` → 200.
- Path traversal: `GET /../cfg/res.toml` and `/%2e%2e/cfg/res.credentials` (sent with `--path-as-is`) → 404.
- Security headers present on every response: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, CSP (`default-src 'none'; script-src 'self'; style-src 'self'; …; frame-ancestors 'none'`), `Referrer-Policy: no-referrer`, COOP, Permissions-Policy. `Cache-Control: no-store` on `/api/*` and `/metrics`.
- Session cookie is `HttpOnly; SameSite=Strict` (+`Secure` when enabled); CSRF token required for cookie-authenticated mutations (code + integration tests passing).
- Login: per-IP rate limit, argon2 verification on every path (dummy hash for unknown users), credential length bounds, config directory/credential files mode `0600` (verified).
- The dashboard needs no inline styles/scripts: CSP `style-src 'self'` and zero `style="…"` attributes in `index.html`/`app.js` (grep).

**Findings:**

| ID | Severity | Type | Summary |
|---|---|---|---|
| C1 | Medium | CONFIRMED-RUNTIME | Admin lockout DoS (above) |
| C2 | Medium | CONFIRMED-RUNTIME | Import erases proxy password (integrity) |
| S1 | Low | POTENTIAL | **Lockout-table eviction.** `record_failure` evicts the oldest entry when 4096 usernames are tracked. An attacker with many source IPs (to evade the 30/min per-IP cap) could flood random usernames and evict the `admin` failure counter, weakening brute-force protection. Needs ≥4096 distinct usernames within the lockout window. Mitigate by never evicting entries that are currently locked/near threshold, and by throttling per IP first. |
| S2 | Low | POTENTIAL | **Concurrent-guess race.** `login()` checks lockout, releases the mutex, runs argon2, then records the failure. N parallel requests can all pass the check before the first failure is recorded. Bounded in practice by the per-IP limit and the API concurrency semaphore. |
| S3 | Low | CONFIRMED-CODE | **No trusted-proxy support.** `ClientAddr` deliberately uses only the socket peer. Behind a reverse proxy (which the README recommends for non-loopback exposure) all users share one IP, so the per-IP login limit and audit `client` field become per-proxy. |
| S4 | Low | CONFIRMED-CODE | Sessions are in-memory only (lost on restart), with no idle timeout (absolute TTL 720 min). Soonest-expiring eviction at 1024 sessions. Acceptable; document it. |
| S5 | Low | CONFIRMED-RUNTIME | Proxy password stored plaintext in `res.toml` (mode 0600). |
| S6 | Info | CONFIRMED-CODE | `dashboard_fallback` follows symlinks inside `dashboard_dir` (traversal via `..` and dotfiles is blocked, symlinks are not). Only relevant if an untrusted party can create files in the dashboard directory. |
| D1 | Low | CONFIRMED-RUNTIME | `cargo audit` (advisory DB: 1409 advisories, 216 crates): **1 vulnerability** — RUSTSEC-2026-0385 `ctutils 0.4.3` "non-constant-time mask generation and u128 comparisons", fix `>=0.4.4`; reached via `argon2 0.6.0 → blake2/password-hash → ctutils`. Warnings: `rustls-pemfile 1.0.4` unmaintained (RUSTSEC-2025-0134; also the reason for the duplicate `base64 0.21`), `tokio 1.53.1` unsound `AsyncFd::new` (RUSTSEC-2026-0386; I did not check whether this project or its dependencies call `AsyncFd::new`), `yoke-derive 0.8.3` yanked. I did not assess exploitability in argon2's usage. Fix: `cargo update -p ctutils` (and bump tokio/yoke-derive); replace `rustls-pemfile` with `rustls-pki-types` PEM parsing. |
| S7 | Info | not tested | Docker/Compose hardening (read-only rootfs, non-root UID, limits), TLS listener, Prometheus/Grafana placeholders. Docker is not installed here; these were reviewed by reading only. README states the Grafana/Prometheus credentials are development placeholders that must be changed before exposure. |

---

## 5. Performance Assessment

No load test was executed (`res-loadtest`/`bench/` exist but need a representative environment; not run), so no throughput/latency numbers are claimed.

| ID | Severity | Type | Finding |
|---|---|---|---|
| P1 | Low–Medium | CONFIRMED-RUNTIME (headers) / CONFIRMED-CODE (blocking read) | **Dashboard assets are neither cached nor compressed.** `GET /app.js` returns `Content-Length: 140664` with no `Cache-Control`, `ETag`, `Last-Modified` or `Content-Encoding`. Payload per cold load: `app.js` 141 KB + `app.css` 53 KB + `index.html` 41 KB + 3 TTF fonts ≈ 257 KB, re-fetched in full every visit. `dashboard_fallback` (`src/api/mod.rs` ≈L553) also uses blocking `std::fs::read` inside an async handler on every request. Fix: `tokio::fs`/`spawn_blocking` or an in-memory cache loaded at startup; add `ETag` + `Cache-Control: no-cache` (or `max-age` for fonts) and gzip/br (`tower-http` compression feature). |
| P2 | Info | CONFIRMED-CODE | Dashboard polls `/api/status`/`/api/stats` every 2 s per open tab; each request takes an API semaphore permit. Fine for a few operators; many open tabs would count against the in-flight cap (503 `busy` is returned if exhausted). |
| P3 | Info | CONFIRMED-CODE | Argon2 verification runs on the blocking pool (good) but each login does **two** hashes (real+dummy by design). |
| P4 | Info | observed | Dashboard charts are canvas-based and re-render on a 2 s cadence; no jank noticed in headless Chromium, but I did not profile. |

---

## 6. Code Quality and Maintainability

- **Q1 (Low) — oversized files:** `src/api/mod.rs` (3,681 lines), `tests/gateway.rs` (4,639), `src/config.rs` (2,206), `dashboard/app.js` (3,137, a single script). Splitting by resource (upstreams, acl, cache, proxy, auth, config) and the dashboard into ES modules would ease review.
- **Q2 (Low) — string-templated UI:** `app.js` builds markup with `innerHTML` string concatenation at ~49 sites and relies on every author remembering `escapeHtml`. C4 shows one miss. Prefer `textContent`/DOM builders or a tiny `h()` helper that escapes by default.
- **Q3 (Info):** no JS linting, type-checking, or automated browser test in the repo (the dashboard has no `package.json`). `boot.js` contains a headless-CI error probe (`data-js-errors`) but no CI config exists to use it.
- **Q4 (Low):** `cargo clippy --all-targets` → 1 warning: `src/dns/listener.rs:32` uses `Atomic::fetch_update`, deprecated in the toolchain I used (1.99.1) in favour of `try_update`. `Cargo.toml` declares `rust-version = "1.88"` and the Dockerfile builds with `rust:1.97`; I only built with 1.99.1, so the MSRV claim is **unverified**. If you switch to `try_update` the MSRV rises. Recommend adding a CI job on the declared MSRV or raising `rust-version`.
- **Q5 (Info):** duplicate crate versions (`base64`, `getrandom`×3, `rand`, `thiserror`, `syn`, `winnow`) — mostly transitive; `rustls-pemfile` is the removable one.
- Positives: extensive doc comments explaining invariants, typed API errors, consistent audit-event recording, no `unsafe` in `src/` (grep: 0).

---

## 7. Missing or Incomplete Implementations

- **M1:** No trusted-proxy / `X-Forwarded-For` handling (S3).
- **M2:** No persistence of sessions across restarts; no explicit "revoke all sessions" API (a `logout_all` exists but is documented as a test helper).
- **M3:** No local DNSSEC validation, no recursion — **by design** (README says so).
- **M4:** No CI configuration (build, clippy, tests, `cargo audit`, container build) checked into the repository.
- **M5:** Dashboard header has no global search or notification centre. The application has no such backend feature, and the redesign correctly does not add non-functional controls. Not a defect.
- **M6:** Redesign reference screenshot: **none was attached to the task**, so the visual comparison was done against the stated design goals only. The redesign was already present at HEAD.

---

## 8. Recommendations and Improvements

Ordered by value:

1. Fix C1 (lockout keyed by IP+user) and C2 (preserve secrets on import); add regression tests.
2. `cargo update` for `ctutils` (RUSTSEC-2026-0385), tokio and yoke-derive; drop `rustls-pemfile`; add `cargo audit`/`cargo deny` to CI.
3. Cache + compress static dashboard assets and stop blocking the runtime in `dashboard_fallback` (P1).
4. Make the two root-sensitive tests privilege-independent (C7) so `cargo test` is reliable in containers/CI running as root.
5. Add trusted-proxy configuration (`trusted_proxies` CIDR list) before recommending reverse-proxy deployment (S3).
6. Server-side character whitelist for upstream names; keep client-side escaping as defence in depth (C4).
7. Replace `innerHTML` templates with escaping-by-default helpers, and add a Playwright smoke test (login → each section renders → no console errors → no horizontal overflow at 320/768/1366) to CI.
8. Mobile touch targets (OPTIONAL, measured at 375 px): theme toggle 36×27, `select` controls 28 px high, Refresh 27 px, section toggles 30×30. They satisfy WCAG 2.2 AA minimum target size (24 px) but are below the common 44 px touch guideline.
9. Split `api/mod.rs` and `app.js` into modules (Q1).
10. Verify or raise the declared MSRV (Q4).

---

## 9. Production Readiness Assessment

| Dimension | Assessment |
|---|---|
| Functional correctness | Good: 365+ automated tests green (as non-root); DNS probe against the live binary returned `NOERROR` in 12.5 ms (single query, not a benchmark). |
| Security | Good defaults (loopback bind, no default credentials, strict headers). Fix C1/C2 and update the vulnerable crate before exposing beyond loopback. |
| Resilience | Good: persist-first config, backup generations, fallback to defaults on broken config, bounded tables. |
| Observability | Good: Prometheus metrics, alert rules, Grafana dashboards (not executed here), structured JSON logs. |
| Performance | Unmeasured (no load test run). Static serving is unoptimised (P1). |
| Operability | Docker stack not executed here (no Docker). No CI in the repo. |
| UI/UX | Responsive light/dark dashboard verified in Chromium; three defects fixed. |

**Verdict:** suitable for production on a trusted network/loopback after addressing C1, C2 and D1; add CI and a load-test baseline before relying on it for internet-facing duty.

---

## 10. Testing Results

All commands were run from `/root/res` with `CARGO_TARGET_DIR` pointing to a scratch directory (nothing written into the project tree). Toolchain installed via rustup into `~/.cargo` (outside the project).

| Command | Result |
|---|---|
| `cargo build --release --locked` | **Success** (4m32s); 1 deprecation warning (`listener.rs:32`) |
| `cargo clippy --all-targets --locked` | **Success**, 1 warning (same deprecation) |
| `cargo test --locked --no-fail-fast` (as **root**) | lib: **273 passed, 1 failed**; `res-loadtest`: 8 passed; `tests/gateway.rs`: **92 passed, 1 failed**; others 0 tests |
| Failing tests re-run as user `nobody` (test binaries copied out) | `auth::tests::set_admin_password_*` **2/2 passed**; `persist_failure_is_reported_and_audited` **1/1 passed** → failures are root artefacts (C7), not product bugs |
| `cargo audit --file Cargo.lock` | 1 vulnerability + 3 warnings (D1) |
| Live server (release binary, run as `nobody`, loopback, temp config copy) | `/api/health` ok; login/session OK; 401 on unauthenticated reads and metrics; traversal → 404; `res probe` → `NOERROR` |
| Runtime reproductions | C1 (lockout), C2 (proxy password round trip), C4 (HTML injection) reproduced; C3/C5 observed in browser |
| Playwright + Chromium headless: 7 viewports × light/dark (320×568, 375×812, 430×932, 768×1024, 1024×768, 1366×768, 1920×1080) = **14 runs** | **After fixes:** no horizontal overflow in any run (`scrollWidth == clientWidth`), no elements overflowing outside scroll containers, `data-js-errors = 0`, no failed requests. The only console message is the expected `401` from the pre-login `/api/auth/session` probe. |
| Browser interaction checks (375 px) | Drawer opens/closes (button, Escape, backdrop, link navigation); `aria-expanded` updates; theme menu → Dark sets `data-theme`, `localStorage["res-theme-pref"]`, `meta theme-color`; **preference persists across reload** with the correct theme applied at first paint; visible focus ring (2 px solid) on keyboard focus |
| Not executed | Docker/Compose stack, Grafana/Prometheus, TLS listener with real certs, load/benchmark tools, DoT/SOCKS upstream paths beyond what the test suite covers, viewer-role UI walk-through, a visual comparison with a reference screenshot (none supplied) |

Test side effect to disclose: running the unit tests as root created `/etc/res.credentials` outside the project (C7); I deleted it afterwards. No project file was modified by the review.

---

## 11. Prioritized Action Plan

| Priority | Action | Findings | Effort |
|---|---|---|---|
| P0 (before exposing the API) | Key login lockout by IP+user / progressive delay; add test | C1, S1, S2 | S |
| P0 | Preserve proxy password (secrets) on config import; add round-trip test | C2 | S |
| P0 | `cargo update` for `ctutils`≥0.4.4, tokio, yoke-derive; re-run audit | D1 | S |
| P1 | Cache/compress/async-read dashboard assets | P1 | S–M |
| P1 | Add CI: build, clippy, tests (non-root), `cargo audit`, Playwright smoke test | M4, Q3 | M |
| P1 | Make the two root-sensitive tests privilege-independent | C7 | S |
| P2 | Trusted-proxy support | S3, M1 | M |
| P2 | Canonicalise IP in `clear_login_rate` | C6 | XS |
| P2 | Upstream-name charset validation; escaping-by-default UI helper | C4, Q2 | S–M |
| P3 | Replace `rustls-pemfile`; verify/raise MSRV; address `fetch_update` deprecation | D1, Q4 | S |
| P3 | Larger touch targets on mobile; split large files | §8 items 8–9, Q1 | M |

### Already addressed after this review (dashboard commit)

| Finding | Change | Files |
|---|---|---|
| C3 | Closed drawer `visibility:hidden`; shadow only when open | `dashboard/app.css` |
| C4 | `escapeHtml` for legend and tooltip series names | `dashboard/app.js` |
| C5 | Flat-trend threshold `<` → `<=` | `dashboard/app.js` |

Everything else above remains **open** and untouched.
