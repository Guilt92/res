# Panel 8081 Audit and Improvements

- Date: 2026-10-21
- Target: built-in dashboard served by `res` on API port `8081`
- Implementation commit: `23bbae9` — `security: harden DNS cache, upstream correlation, and panel auth`
- Test harness: loopback gateway at `127.0.0.1:8081`, DNS at `127.0.0.1:15354`, mock upstreams at `127.0.0.1:15300/15301`
- Browser: Chromium via Playwright, desktop 1440x900 and mobile 390x844

## Summary

The dashboard is a single-file SPA (`dashboard/index.html`) served by the same
process as the API. The audit covered authentication/session behavior, viewer
RBAC, token storage, rendered data, responsive layout, focus handling and the
main operator workflows. The visual redesign preserved existing element ids and
event handlers so the API contract and operator habits did not change.

The most important security fixes are outside the visual layer:

- bearer tokens are no longer persisted in `localStorage`;
- logout/auth failure clear token and password fields;
- open mode is detected with a positive `/api/status` probe instead of being
  inferred from an authentication failure;
- viewer mutation controls are disabled in the UI and the API independently
  returns 403;
- password rotation now enforces a minimum length on the server.

The UI work fixed mobile overflow, a visible Sign out button caused by a CSS
`[hidden]` override, IPv6 address wrapping in dense tables, broken open-mode
login behavior, duplicated live timers, and login focus/inert/retry handling.

## Scope and Evidence

Reviewed:

- `dashboard/index.html` (markup, CSS, JavaScript, fetch/session behavior)
- `src/api/mod.rs` authentication, session, CSRF, RBAC and security headers
- `tests/gateway.rs` integration coverage for viewer/admin behavior
- live UI flows at 1440 and 390 pixels
- open-mode gateway on `127.0.0.1:8082`

Evidence is intentionally kept outside the repository in
`/tmp/res-panel-8081/shots/` and the JavaScript checks listed below. Test
credentials are stored in `/tmp/res-panel-8081/res.credentials` and are not
reproduced in this report.

## Authentication and Session Model

- Login uses `POST /api/auth/login`; the server sets an HttpOnly,
  SameSite=Strict session cookie and a readable CSRF cookie.
- Cookie-authenticated mutations require the CSRF double-submit header.
- The viewer role can read all dashboard/API data but every mutation is
  rejected by the backend with 403, independent of the disabled HTML controls.
- `sessionStorage` is used only for the optional legacy bearer token. The
  server session cookie remains HttpOnly.
- `localStorage["res-admin-token"]` is removed at startup and again whenever a
  token is saved. This prevents a token from surviving tab close or being
  readable by a later viewer session.
- `authNeeded()` and `doLogout()` clear the token from memory/sessionStorage,
  clear the token input and clear the password field.
- Session expiry (401), failed login, lockout (429), network failure and open
  mode each have distinct UI states.
- Open mode is confirmed by `/api/status` returning 200 when
  `/api/auth/session` returns 401/404. A failed status request shows the retry
  overlay instead of guessing that the gateway is open.

## Dashboard Changes

### Layout and navigation

- Added a skip link and a two-row header with brand, session/role chip, refresh
  and sign-out controls.
- Wrapped the existing 18 `h2` sections in `.panel-section` elements and
  generated a sticky sidebar with 18 navigation links and scroll spy.
- Added page facts: config source/path, generation, auth mode and role.
- Added a responsive mobile navigation toggle, backdrop, section navigation and
  a layout that does not overflow at 390 px.
- Header height is measured with a `ResizeObserver` and exposed as
  `--header-h` so sticky elements stay aligned.

### Login and session UX

- Login card now has proper form semantics, labels, autocomplete hints, a
  password reveal control, loading state and error messaging.
- The app shell is inert while the login overlay is open; focus moves into the
  dialog, is trapped there, and is restored on close.
- Body scroll is locked while the dialog is open.
- Invalid credentials clear the password and restore focus; lockout and
  connection failures show actionable messages.
- A retry button distinguishes “API unreachable” from “wrong password”.
- Open mode hides the login overlay and sign-out control, shows the `no auth`
  chip and `authentication disabled` page fact.

### Viewer experience

- Viewer sessions show a persistent banner explaining that monitoring and
  diagnostics are available but configuration, cache, ACL and upstream
  mutations are disabled.
- Static mutation controls are disabled, the config editor is read-only, and
  dynamic mutation controls are gated by the same role check.
- `umgApi()` rejects non-GET calls with `this session is read-only` before
  sending a request.
- `applyConfig()` reports `read-only session — configuration changes are
  disabled` and returns without sending a write.

### Data rendering and correctness

- IP addresses are rendered as text and wrap inside tables; IPv6 no longer
  forces the page wider than the viewport.
- Upstream rows show the structured score object and its factors again; the API
  keeps `score_value` as a scalar for scripts.
- Client/ACL/upstream identifiers and names are escaped before HTML insertion;
  the main server-derived innerHTML sinks were reviewed. The remaining inline
  SPA means a Content-Security-Policy is still not set.
- Live timers are started once and stopped on logout/navigation; the refresh
  button now performs one refresh instead of stacking timers.
- `[hidden]{display:none!important}` was added so components that rely on the
  `hidden` attribute (notably Sign out) cannot be overridden by component
  display rules.
- Added a favicon and fixed mobile body overflow.

### Accessibility and responsiveness

- Skip link, focus-visible styles, dialog focus trap, restored focus, labels and
  button titles.
- Keyboard-operable mobile nav with backdrop/Escape handling (where applicable).
- Responsive KPI grids, stat rows, tables, config editor and toolbar controls.
- Tables that cannot fit horizontally scroll inside their card instead of
  widening the document.

## Verification

### Playwright checks

Desktop (`check-final.js`):

- Legacy `localStorage` token was removed on load.
- Admin login succeeded; page fact showed `admin · full access`.
- 18 panel sections and 18 sidebar links were present.
- Body width equaled viewport width (1440), no horizontal page overflow.
- Saving a token wrote only `sessionStorage`, reload preserved it, logout
  removed it, and the token/password inputs were empty.
- Viewer login showed `viewer · read-only` and the role banner.
- IPv6 client address displayed in full with a 342 px cell; the table scrolled
  inside its card (1141 px scroll width) without widening the body.
- No page JavaScript errors.

Mobile (`check-final.js`, 390x844):

- Body width equaled viewport width (390).
- Header height was 132 px and the mobile layout did not overflow.
- IPv6 cell width was 230 px; the table scrolled internally (891 px).
- No page JavaScript errors.

Viewer (`check-viewer2.js` and earlier checks):

- `canWrite()` returned false; config editor was read-only.
- `umg-name`, `umg-submit`, `acl-cidr`, `acl-add`, `cache-clear`, `cache-save`,
  `hlt-save`, `sel-save` and `cfg-apply` were disabled.
- `umgApi("POST", "/api/cache/clear", ...)` rejected with
  `this session is read-only`.
- `applyConfig()` left the message `read-only session — configuration changes
  are disabled`.
- Backend integration test `auth_viewer_cannot_mutate_configuration` confirmed
  403 for cache clear, ACL replacement, upstream creation and admin password
  rotation; admin cache clear succeeded.

Open mode (`check-open.js` / final combined check):

- Login overlay hidden.
- Auth chip `no auth`; page fact `authentication disabled`.
- Sign-out hidden; mutation UI available.

### Server-side checks

```console
$ cargo fmt --all -- --check
$ cargo clippy --all-targets -- -D warnings
$ cargo test --all-targets --quiet
$ cargo build --release
```

- Formatting: pass.
- Clippy with warnings denied: pass.
- 229 library + 69 integration tests: all pass.
- Release build: pass.
- Dashboard-specific tests and the API security-header test pass.

## Security Notes and Remaining Gaps

- **No CSP:** the dashboard is an inline HTML/CSS/JS application. A strict CSP
  would require a nonce/hash build step. `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP,
  Permissions-Policy and API no-store headers are set.
- **No TLS in the binary:** use a reverse proxy and set
  `[auth].secure_cookies = true`. Tokens/session cookies must not traverse
  plaintext networks.
- **Open mode:** with no password/token the API is intentionally open. Never
  bind that mode to `0.0.0.0` on an untrusted network.
- **Metrics:** `/metrics` is public by default; enable `protect_metrics` or
  restrict it at the network/reverse-proxy layer.
- **Bearer tokens in the dashboard:** sessionStorage protects against tab-close
  persistence, but any XSS in the same origin could read the token. The HttpOnly
  session cookie is the preferred authentication path; avoid using the legacy
  token box unless scripts require it.
- **Browser matrix:** Chromium/Playwright only. Firefox/Safari and real mobile
  devices were not exercised.
- **IPv6 traffic:** host IPv6 is disabled; only IPv6 rendering/config was tested,
  not client connections over IPv6.
- **No screenshot diffing or axe audit:** visual checks were manual/assertion
  based; automated accessibility scoring was not run.

## Files Changed

- `dashboard/index.html` — layout, navigation, login/session handling, viewer
  gating, responsive fixes, IPv6 rendering, token storage, favicon.
- `src/api/mod.rs` — security headers, no-store for API/metrics, password
  minimum, score contract.
- `tests/gateway.rs` — viewer RBAC, password minimum, score shape, security
  header assertions.
- `README.md` — documented cache/EDNS behavior and DNS security limitations.

## Conclusion

The panel is materially more robust and usable: authentication state is explicit,
viewer writes are blocked in both UI and API, tokens do not persist in
`localStorage`, mobile layout no longer overflows, and the 18 operator sections
are navigable at desktop and phone widths. It is not a hardened public-facing
console until TLS, a strict CSP/build step, and network-level protection are
added.
