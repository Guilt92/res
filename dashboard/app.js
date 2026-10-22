"use strict";
/* =========================================================================
 * State
 * ====================================================================== */
const RANGES = ["5m","15m","1h","6h","24h","7d"];
const PALETTE = ["#4cc2ff","#7ee787","#ffa657","#ff7b72","#d2a8ff","#79c0ff","#e3b341","#f778ba","#56d364","#a5d6ff"];
const $ = id => document.getElementById(id);

const state = {
  range: "5m",
  // `native` (default): this gateway's own history — always its own data.
  // `auto` falls back to Prometheus when configured, which may be scraping a
  // *different* instance in a multi-gateway setup.
  source: "native",
  auto: true,
  hist: null,          // last /api/timeseries payload
  histAt: 0,
  status: null, stats: null, upstreams: [], upState: null,
  generation: null,
  clients: null, clientSort: "requests",
  events: [], monitoring: null,
  focus: null,         // focused upstream name
  filter: "all",
  apiFails: 0, lastOk: 0,
  upColors: {},
  histTimer: null, curTimer: null, monTimer: null, cfgTimer: null, sessionTimer: null,
  timersStarted: false,
};

/* =========================================================================
 * Layout: section wrappers, navigation, responsive shell
 * ====================================================================== */
const SECTION_IDS = {
  "DNS service": "dns-service",
  "Service statistics": "service-statistics",
  "Top clients": "top-clients",
  "Traffic": "traffic",
  "Assessment": "assessment",
  "Process & capacity": "process-capacity",
  "DNS service history": "dns-service-history",
  "Upstream history": "upstream-history",
  "Process history": "process-history",
  "Current upstream state": "current-upstream-state",
  "Failover monitoring": "failover-monitoring",
  "Upstreams": "upstreams",
  "Upstream DNS management": "upstream-dns-management",
  "Client ACL": "client-acl",
  "Cache": "cache",
  "Health checks & selection": "health-checks-selection",
  "Incident timeline": "incident-timeline",
  "Configuration": "configuration",
};
const NAV_GROUPS = [
  ["Overview", [["dns-service","DNS service"],["assessment","Assessment"]]],
  ["Traffic", [["service-statistics","Service statistics"],["top-clients","Top clients"],["traffic","Traffic"]]],
  ["Resolver", [["current-upstream-state","Current upstream state"],["failover-monitoring","Failover monitoring"],["upstreams","Upstreams"],["upstream-dns-management","Upstream DNS management"]]],
  ["Protection", [["client-acl","Client ACL"],["cache","Cache"],["health-checks-selection","Health checks & selection"]]],
  ["Observability", [["dns-service-history","DNS service history"],["upstream-history","Upstream history"],["incident-timeline","Incident timeline"]]],
  ["System", [["process-capacity","Process & capacity"],["process-history","Process history"],["configuration","Configuration"]]],
];

function sectionTitle(h2){
  const clone = h2.cloneNode(true);
  for (const sub of clone.querySelectorAll(".sub")) sub.remove();
  return clone.textContent.trim();
}
const COLLAPSE_KEY = "res-collapsed-sections";
// First load is an overview: live service health, assessment, resolver state
// and incidents. High-volume tables, histories and management stay one click
// away instead of competing with the primary signal.
const DEFAULT_COLLAPSED_SECTIONS = new Set([
  "service-statistics", "top-clients", "traffic",
  "process-capacity", "dns-service-history", "upstream-history",
  "process-history", "upstream-dns-management", "client-acl", "cache",
  "health-checks-selection", "configuration",
]);
function readCollapsedSections(){
  try {
    const stored = localStorage.getItem(COLLAPSE_KEY);
    if (stored === null) return new Set(DEFAULT_COLLAPSED_SECTIONS);
    const value = JSON.parse(stored);
    return new Set(Array.isArray(value) ? value.filter(x => typeof x === "string") : []);
  } catch(_) { return new Set(DEFAULT_COLLAPSED_SECTIONS); }
}
function persistCollapsedSections(){
  const ids = navSections().filter(sec => sec.classList.contains("collapsed")).map(sec => sec.id);
  try { localStorage.setItem(COLLAPSE_KEY, JSON.stringify(ids)); } catch(_) {}
}
function applySectionCollapsed(sec, collapsed){
  sec.classList.toggle("collapsed", collapsed);
  const btn = sec.querySelector(".sec-toggle");
  const body = sec.querySelector(".section-body");
  if (btn){
    btn.setAttribute("aria-expanded", String(!collapsed));
    btn.setAttribute("aria-label", (collapsed ? "Expand " : "Collapse ") + (btn.dataset.title || "section"));
    btn.title = collapsed ? "Expand section" : "Collapse section";
  }
  if (body) body.inert = collapsed;
}
function toggleSection(sec, collapsed){
  applySectionCollapsed(sec, collapsed);
  persistCollapsedSections();
  if (!collapsed) requestAnimationFrame(() => drawAllCharts());
}
function expandSection(id){
  const sec = document.getElementById(id);
  if (sec && sec.classList.contains("collapsed")) toggleSection(sec, false);
}
function buildSections(){
  const main = $("content");
  const collapsed = readCollapsedSections();
  const headings = Array.from(main.children).filter(el => el.tagName === "H2");
  let index = 0;
  for (const h2 of headings){
    const title = sectionTitle(h2);
    const sec = document.createElement("section");
    sec.className = "panel-section";
    sec.id = SECTION_IDS[title] || ("section-" + (++index));
    h2.parentNode.insertBefore(sec, h2);

    const sub = h2.querySelector(":scope > .sub");
    const label = document.createElement("span");
    label.className = "sec-title";
    label.id = sec.id + "-title";
    while (h2.firstChild && h2.firstChild !== sub) label.appendChild(h2.firstChild);
    h2.insertBefore(label, h2.firstChild);
    h2.setAttribute("aria-labelledby", label.id);
    sec.setAttribute("aria-labelledby", label.id);

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "sec-toggle";
    toggle.dataset.title = title;
    toggle.setAttribute("aria-controls", sec.id + "-body");
    h2.appendChild(toggle);

    sec.appendChild(h2);
    const body = document.createElement("div");
    body.className = "section-body";
    body.id = sec.id + "-body";
    let node = sec.nextSibling;
    while (node){
      if (node.nodeType === 1 && (node.tagName === "H2" || node.tagName === "FOOTER")) break;
      const next = node.nextSibling;
      body.appendChild(node);
      node = next;
    }
    sec.appendChild(body);
    toggle.addEventListener("click", () => {
      toggleSection(sec, !sec.classList.contains("collapsed"));
    });
    applySectionCollapsed(sec, collapsed.has(sec.id));
  }
}
function buildNav(){
  const links = $("sidenav-links");
  let n = 0;
  for (const [group, items] of NAV_GROUPS){
    const wrap = document.createElement("div");
    wrap.className = "nav-group";
    const title = document.createElement("div");
    title.className = "nav-group-title";
    title.textContent = group;
    wrap.appendChild(title);
    for (const [id, label] of items){
      const a = document.createElement("a");
      a.className = "nav-link";
      a.href = "#" + id;
      a.dataset.section = id;
      const idx = document.createElement("span");
      idx.className = "nav-idx";
      idx.textContent = String(++n).padStart(2, "0");
      const text = document.createElement("span");
      text.textContent = label;
      a.appendChild(idx); a.appendChild(text);
      wrap.appendChild(a);
    }
    links.appendChild(wrap);
  }
}
function navSections(){
  return Array.from(document.querySelectorAll("#content .panel-section"));
}
function setActiveSection(id){
  for (const a of document.querySelectorAll("#sidenav-links .nav-link")){
    const on = a.dataset.section === id;
    a.classList.toggle("active", on);
    if (on) a.setAttribute("aria-current", "location");
    else a.removeAttribute("aria-current");
  }
}
let navFrame = null;
function updateActiveSection(){
  navFrame = null;
  const sections = navSections();
  if (!sections.length) return;
  // At the bottom of the document the last section can never cross the
  // normal trigger line, so select it explicitly. Otherwise clicking a
  // short trailing section (e.g. Configuration) leaves the previous entry
  // highlighted even though the target is fully visible.
  const atBottom = window.innerHeight + window.scrollY >=
    document.documentElement.scrollHeight - 3;
  if (atBottom){ setActiveSection(sections[sections.length - 1].id); return; }
  const y = window.scrollY + ($("top").offsetHeight || 0) + 24;
  let current = sections[0];
  for (const sec of sections){
    if (sec.getBoundingClientRect().top + window.scrollY <= y) current = sec;
    else break;
  }
  setActiveSection(current.id);
}
function syncHeaderHeight(){
  const h = $("top").offsetHeight;
  if (h) document.documentElement.style.setProperty("--header-h", h + "px");
}
const NAV_COLLAPSE_KEY = "res-nav-collapsed";
function applyNavCollapsed(collapsed, persist){
  document.body.classList.toggle("nav-collapsed", collapsed);
  const closeBtn = $("side-collapse"), openBtn = $("side-reopen");
  if (closeBtn) closeBtn.setAttribute("aria-expanded", String(!collapsed));
  if (openBtn) openBtn.hidden = !collapsed;
  if (persist){
    try { localStorage.setItem(NAV_COLLAPSE_KEY, collapsed ? "1" : "0"); } catch(_) {}
  }
  requestAnimationFrame(() => drawAllCharts());
}
function initNavCollapsed(){
  let collapsed = false;
  try { collapsed = localStorage.getItem(NAV_COLLAPSE_KEY) === "1"; } catch(_) {}
  applyNavCollapsed(collapsed, false);
  $("side-collapse").addEventListener("click", () => {
    applyNavCollapsed(true, true);
    requestAnimationFrame(() => $("side-reopen").focus());
  });
  $("side-reopen").addEventListener("click", () => {
    applyNavCollapsed(false, true);
    requestAnimationFrame(() => $("side-collapse").focus());
  });
}
function wireNavigation(){
  syncHeaderHeight();
  initNavCollapsed();
  if (window.ResizeObserver) new ResizeObserver(() => syncHeaderHeight()).observe($("top"));
  updateActiveSection();
  window.addEventListener("scroll", () => {
    if (navFrame == null) navFrame = requestAnimationFrame(updateActiveSection);
  }, {passive:true});
  window.addEventListener("hashchange", () => {
    const id = location.hash.replace(/^#/, "");
    if (id && document.getElementById(id)){
      expandSection(id);
      setActiveSection(id);
    }
  });
  for (const a of document.querySelectorAll("#sidenav-links .nav-link")){
    a.addEventListener("click", () => {
      expandSection(a.dataset.section);
      setActiveSection(a.dataset.section);
      closeSidebar();
    });
  }
  const toggle = $("nav-toggle");
  toggle.addEventListener("click", () => {
    if ($("sidenav").classList.contains("open")) closeSidebar();
    else openSidebar();
  });
  $("nav-backdrop").addEventListener("click", closeSidebar);
  window.addEventListener("resize", () => {
    if (window.innerWidth > 980) closeSidebar();
    syncHeaderHeight();
  });
  window.addEventListener("keydown", e => {
    if (e.key === "Escape" && $("sidenav").classList.contains("open")){
      closeSidebar();
      return;
    }
    if (e.key !== "Tab" || !$("sidenav").classList.contains("open")) return;
    const links = [...document.querySelectorAll("#sidenav-links a[href], #sidenav button:not([disabled])")];
    if (!links.length) return;
    const first = links[0], last = links[links.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || active === $("nav-toggle"))){
      e.preventDefault(); last.focus();
    } else if (!e.shiftKey && (active === last || active === $("nav-toggle"))){
      e.preventDefault(); first.focus();
    }
  });
  if (location.hash){
    const id = location.hash.replace(/^#/, "");
    expandSection(id);
    const el = document.getElementById(id);
    if (el) setTimeout(() => el.scrollIntoView(), 0);
  }
}
let navReturnFocus = null;
function openSidebar(){
  navReturnFocus = document.activeElement;
  $("sidenav").classList.add("open");
  $("nav-toggle").setAttribute("aria-expanded","true");
  $("nav-toggle").setAttribute("aria-label","Close navigation");
  $("nav-backdrop").hidden = false;
  document.body.classList.add("nav-open");
  $("content").setAttribute("inert","");
  const first = document.querySelector("#sidenav-links .nav-link");
  if (first) requestAnimationFrame(() => first.focus());
}
function closeSidebar(){
  const hadFocus = $("sidenav").contains(document.activeElement);
  $("sidenav").classList.remove("open");
  $("nav-toggle").setAttribute("aria-expanded","false");
  $("nav-toggle").setAttribute("aria-label","Open navigation");
  $("nav-backdrop").hidden = true;
  document.body.classList.remove("nav-open");
  $("content").removeAttribute("inert");
  if (hadFocus || navReturnFocus === $("nav-toggle")){
    try { $("nav-toggle").focus(); } catch(_) {}
  }
  navReturnFocus = null;
}
function setBanner(id, on){
  const el = $(id);
  if (!el) return;
  el.hidden = !on;
  el.style.display = on ? "block" : "none";
}

/* Series metadata: label, unit, color for every canonical series key. */
const META = {
  qps:            ["Query rate","qps","#4cc2ff"],
  queries:        ["Requests","","#4cc2ff"],
  packets_in:     ["Packets in","","#79c0ff"],
  packets_out:    ["Packets out","","#ffa657"],
  avg_req_bytes:  ["Avg request","B","#4cc2ff"],
  avg_resp_bytes: ["Avg response","B","#7ee787"],
  success_pct:    ["Success","%","#7ee787"],
  error_pct:      ["Errors","%","#ff7b72"],
  servfail_pct:   ["SERVFAIL","%","#ffa657"],
  nxdomain_pct:   ["NXDOMAIN","%","#d2a8ff"],
  refused_pct:    ["REFUSED","%","#ff7b72"],
  deadline_pct:   ["Deadline","%","#d2a8ff"],
  timeout_pct:    ["Upstream timeout","%","#ff7b72"],
  failover_per_min:["Failovers","/min","#e3b341"],
  rate_limited_per_min:["Rate limited","/min","#d2a8ff"],
  acl_denied_per_min:["ACL denied","/min","#79c0ff"],
  overload_per_min:["Overload","/min","#f85149"],
  malformed_per_min:["Malformed","/min","#8b949e"],
  cache_hit_pct:  ["Hit ratio","%","#7ee787"],
  p50_ms:         ["P50","ms","#7ee787"],
  p95_ms:         ["P95","ms","#ffa657"],
  p99_ms:         ["P99","ms","#ff7b72"],
  inflight:       ["UDP in-flight","","#4cc2ff"],
  tcp_open:       ["TCP conns","","#79c0ff"],
  rss_mb:         ["RSS","MB","#d2a8ff"],
  cpu_pct:        ["CPU","%","#ffa657"],
  fds:            ["FDs","","#e3b341"],
  healthy:        ["Healthy","","#7ee787"],
  degraded:       ["Degraded","","#e3b341"],
  recovering:     ["Recovering","","#388bfd"],
  down:           ["Unhealthy","","#ff7b72"],
  cache_entries:  ["Entries","","#7ee787"],
  tcp_conn_per_min:["TCP accepts","/min","#79c0ff"],
};

/* Chart definitions: canvas id -> series keys (global) or per-upstream key. */
const CHARTS = [
  {id:"ch-qps",      keys:["qps"]},
  {id:"ch-requests", keys:["queries"]},
  {id:"ch-lat",      keys:["p50_ms","p95_ms","p99_ms"]},
  {id:"ch-success",  keys:["success_pct","error_pct"]},
  {id:"ch-packets",  keys:["packets_in","packets_out"]},
  {id:"ch-size",     keys:["avg_req_bytes","avg_resp_bytes"]},
  {id:"ch-errors",   keys:["servfail_pct","deadline_pct","timeout_pct"]},
  {id:"ch-rcodes",   keys:["servfail_pct","nxdomain_pct","refused_pct"]},
  {id:"ch-failovers",keys:["failover_per_min"]},
  {id:"ch-policy",   keys:["rate_limited_per_min","acl_denied_per_min","overload_per_min","malformed_per_min"]},
  {id:"ch-avail",    keys:["healthy","degraded","recovering","down"], step:true},
  {id:"ch-uplat",    up:"p95_ms"},
  {id:"ch-uptimeout",up:"timeout_pct"},
  {id:"ch-upqps",    up:"qps"},
  {id:"ch-cpu",      keys:["cpu_pct"]},
  {id:"ch-rss",      keys:["rss_mb"]},
  {id:"ch-fds",      keys:["fds"]},
  {id:"ch-load",     keys:["inflight","tcp_open"]},
  {id:"ch-cache",    keys:["cache_hit_pct"]},
];

/* =========================================================================
 * Helpers
 * ====================================================================== */
function authHeaders(extra){
  const h = Object.assign({}, extra || {});
  const tok = umgToken();
  if (tok) h["Authorization"] = "Bearer " + tok;
  return h;
}
async function getJSON(path, timeoutMs=6000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(path, {signal: ctl.signal, cache: "no-store", credentials: "same-origin",
      headers: authHeaders()});
    if (r.status === 401) {
      authNeeded();
      const j = await r.json().catch(() => ({}));
      const e = new Error(j.error || "authentication required");
      e.status = 401;
      throw e;
    }
    if (!r.ok) throw new Error("HTTP " + r.status + " for " + path);
    return await r.json();
  } finally { clearTimeout(t); }
}

/* ---------- session / login ---------- */
const AUTH = { needed: false, open: false, role: null, user: null,
  passwordAuth: false, tokenAuth: false };
let loginReturnFocus = null;

function canWrite(){ return !AUTH.needed && (AUTH.open || AUTH.role === "admin"); }
function isViewer(){ return AUTH.role === "viewer"; }
function setAppInert(on){
  for (const el of [$("top"), document.querySelector(".app-shell")]){
    if (!el) continue;
    if (on){
      el.setAttribute("inert","");
      el.setAttribute("aria-hidden","true");
    } else {
      el.removeAttribute("inert");
      el.removeAttribute("aria-hidden");
    }
  }
}
function loginMessage(text, cls){
  const msg = $("login-msg");
  msg.textContent = text || "";
  msg.className = cls || "";
}
function setLoginBusy(on){
  for (const [id, idle] of [["login-go","Sign in"],["login-token-go","Use API token"]]){
    const b = $(id);
    b.disabled = on;
    b.setAttribute("aria-busy", on ? "true" : "false");
    b.textContent = on ? "Signing in…" : idle;
  }
}
function applyLoginMode(passwordAuth, tokenAuth){
  AUTH.passwordAuth = !!passwordAuth;
  AUTH.tokenAuth = !!tokenAuth;
  $("login-password-block").hidden = !AUTH.passwordAuth;
  $("login-token-block").hidden = !AUTH.tokenAuth;
  $("login-go").hidden = !AUTH.passwordAuth;
  $("login-token-go").hidden = !AUTH.tokenAuth;
  $("login-or").hidden = !(AUTH.passwordAuth && AUTH.tokenAuth);
  $("login-subtitle").textContent = AUTH.passwordAuth
    ? "Use the admin or viewer account configured for this gateway."
    : "Enter the API token configured as server.api_token.";
}
function showLogin(){
  const ov = $("login-ov");
  const wasOpen = ov.classList.contains("on");
  if (!wasOpen){
    loginReturnFocus = document.activeElement;
    ov.classList.add("on");
    document.body.classList.add("modal-open");
  }
  setAppInert(true);
  $("login-retry").hidden = true;
  if (!wasOpen){
    let target;
    if (!AUTH.passwordAuth && AUTH.tokenAuth) target = $("login-token");
    else target = $("login-user").value.trim() ? $("login-pass") : $("login-user");
    setTimeout(() => { try { target.focus(); } catch(_){} }, 0);
  }
}
function hideLogin(){
  $("login-ov").classList.remove("on");
  document.body.classList.remove("modal-open");
  setAppInert(false);
  setLoginBusy(false);
  $("login-retry").hidden = true;
  if (loginReturnFocus && typeof loginReturnFocus.focus === "function"){
    try { loginReturnFocus.focus(); } catch(_){}
  }
  loginReturnFocus = null;
}
function authNeeded(){
  AUTH.needed = true; AUTH.role = null; AUTH.user = null; AUTH.open = false;
  umgSetToken("");
  const t = $("umg-token"); if (t) t.value = "";
  stopLiveTimers();
  renderAuthChip();
  showLogin();
}
async function checkSession(silent){
  try {
    const r = await fetch("/api/auth/session", {cache:"no-store", credentials:"same-origin",
      headers: authHeaders()});
    if (r.ok){
      const j = await r.json().catch(() => ({}));
      AUTH.needed = false; AUTH.open = false;
      AUTH.role = j.role || null; AUTH.user = j.username || null;
      hideLogin(); renderAuthChip();
      return true;
    }
    if (r.status === 401 || r.status === 404){
      // The public capability probe distinguishes open mode from password
      // and token-only deployments. Never infer open mode from a 401 alone.
      const info = await fetch("/api/auth/info", {cache:"no-store", credentials:"same-origin"});
      if (info.ok){
        const j = await info.json().catch(() => ({}));
        applyLoginMode(j.password_auth, j.token_auth);
        if (j.open_mode){
          AUTH.needed = false; AUTH.open = true; AUTH.role = "admin"; AUTH.user = null;
          hideLogin(); renderAuthChip();
          return true;
        }
        // A rejected bearer token must not be retried forever.
        if (umgToken()){ umgSetToken(""); const t = $("umg-token"); if (t) t.value = ""; }
        AUTH.needed = true; AUTH.open = false; AUTH.role = null; AUTH.user = null;
        renderAuthChip(); showLogin();
        return false;
      }
      throw new Error("auth info HTTP " + info.status);
    }
    throw new Error("session HTTP " + r.status);
  } catch(e){
    if (silent) return true;
    AUTH.needed = true; AUTH.open = false; AUTH.role = null; AUTH.user = null;
    stopLiveTimers();
    renderAuthChip(); showLogin();
    loginMessage("Control-plane API unreachable: " + e.message, "");
    $("login-retry").hidden = false;
    return false;
  }
}
async function doTokenLogin(){
  const tok = $("login-token").value.trim();
  if (!tok){
    loginMessage("Enter the API token.", "");
    $("login-token").focus();
    return;
  }
  loginMessage("", "");
  setLoginBusy(true);
  try {
    const r = await fetch("/api/auth/session", {cache:"no-store", credentials:"same-origin",
      headers: {"Authorization": "Bearer " + tok}});
    if (!r.ok){
      loginMessage(r.status === 401 ? "The API token was rejected." : ("Token check failed (HTTP " + r.status + ")."), "");
      return;
    }
    const j = await r.json().catch(() => ({}));
    umgSetToken(tok);
    AUTH.needed = false; AUTH.open = false;
    AUTH.role = j.role || "admin"; AUTH.user = j.username || "(api_token)";
    $("login-token").value = "";
    loginMessage("", "");
    hideLogin(); renderAuthChip();
    await startPortal();
  } catch(e){
    loginMessage("Token check failed: " + e.message, "");
    $("login-retry").hidden = false;
  } finally {
    setLoginBusy(false);
  }
}
async function doLogin(){
  const user = $("login-user").value.trim();
  const pass = $("login-pass").value;
  if (!user || !pass){
    loginMessage("Enter both a username and a password.", "");
    (user ? $("login-pass") : $("login-user")).focus();
    return;
  }
  loginMessage("", "");
  setLoginBusy(true);
  try {
    const r = await fetch("/api/auth/login", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      credentials: "same-origin",
      body: JSON.stringify({username: user, password: pass}),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok){
      if (r.status === 401) loginMessage("Incorrect username or password.", "");
      else if (r.status === 429) loginMessage(j.error || "Too many attempts — wait before trying again.", "");
      else loginMessage(j.error || ("Login failed (HTTP " + r.status + ")."), "");
      $("login-pass").value = "";
      $("login-pass").focus();
      return;
    }
    AUTH.needed = false; AUTH.open = false;
    AUTH.role = j.role || null; AUTH.user = j.username || null;
    $("login-pass").value = "";
    loginMessage("", "");
    hideLogin();
    renderAuthChip();
    await startPortal();
  } catch(e){
    loginMessage("Login failed: " + e.message, "");
    $("login-retry").hidden = false;
  } finally {
    setLoginBusy(false);
  }
}
async function retryConnection(){
  loginMessage("Reconnecting…", "ok");
  $("login-retry").hidden = true;
  const ok = await checkSession();
  if (ok){
    await startPortal();
  }
}
async function doLogout(){
  stopLiveTimers();
  try {
    await fetch("/api/auth/session", {method:"DELETE", credentials:"same-origin", headers: csrfHeaders()});
  } catch(_){}
  umgSetToken("");
  const t = $("umg-token"); if (t) t.value = "";
  AUTH.needed = true; AUTH.open = false; AUTH.role = null; AUTH.user = null;
  renderAuthChip();
  if (document.activeElement) document.activeElement.blur();
  showLogin();
}
function applyRoleGating(){
  const viewer = isViewer();
  document.body.dataset.role = AUTH.role || "";
  const ids = [
    "umg-name","umg-address","umg-port","umg-protocol","umg-priority","umg-weight",
    "umg-tls-name","umg-tls-ca",
    "umg-timeout","umg-probe-interval","umg-probe-timeout","umg-expect-rcode",
    "umg-enabled","umg-confirm","umg-probes","umg-submit",
    "acl-cidr","acl-action","acl-enabled","acl-add",
    "cache-enabled","cache-min","cache-max","cache-negmax","cache-maxent","cache-maxmem",
    "cache-save","cache-clear",
    "hlt-enabled","hlt-interval","hlt-timeout","hlt-fail","hlt-rec","hlt-minsucc",
    "hlt-tcp","hlt-dwell","hlt-probes","hlt-save",
    "sel-strategy","sel-latref","sel-tier","sel-lshare","sel-degraded","sel-minsamples","sel-save",
    "cfg-apply",
  ];
  for (const id of ids){
    const el = $(id);
    if (!el) continue;
    if (viewer){
      if (!el.dataset.readonlyLocked){
        el.dataset.readonlyLocked = "1";
        el.dataset.readonlyOriginal = el.disabled ? "1" : "0";
      }
      el.disabled = true;
    } else if (el.dataset.readonlyLocked){
      if (el.dataset.readonlyOriginal !== "1") el.disabled = false;
      delete el.dataset.readonlyLocked;
      delete el.dataset.readonlyOriginal;
    }
  }
  const cfg = $("cfg-text");
  if (cfg){
    if (viewer) cfg.setAttribute("readonly","");
    else cfg.removeAttribute("readonly");
  }
}
function renderAuthChip(){
  const el = $("auth-chip");
  if (!el) return;
  if (AUTH.open){
    el.textContent = "no auth";
    el.title = "Authentication is disabled on this gateway";
    el.style.color = "var(--faint)";
    el.style.cursor = "";
  } else if (AUTH.role){
    el.textContent = AUTH.user && AUTH.user !== AUTH.role
      ? AUTH.user + " · " + AUTH.role : AUTH.role;
    el.title = "Signed in";
    el.style.color = "#7ee787";
    el.style.cursor = "";
  } else {
    el.textContent = "signed out";
    el.title = "Sign in to the control plane";
    el.style.color = "#e3b341";
    el.style.cursor = "pointer";
  }
  $("logout-btn").hidden = !AUTH.role || AUTH.open;
  $("nav-mode").textContent = AUTH.open ? "open mode" : (AUTH.role || "locked");
  $("page-auth").textContent = AUTH.open ? "authentication disabled"
    : AUTH.role ? (AUTH.role === "admin" ? "admin · full access" : "viewer · read-only") : "signed out";
  const roleBanner = $("role-banner");
  if (roleBanner){
    roleBanner.hidden = !isViewer();
    roleBanner.innerHTML = isViewer()
      ? "<b>Viewer session.</b> Monitoring and diagnostics are available; configuration, cache, ACL and upstream mutations are disabled here and independently rejected by the API."
      : "";
  }
  applyRoleGating();
}

function startLiveTimers(){
  if (state.timersStarted) return;
  state.timersStarted = true;
  state.curTimer = setInterval(() => { if (state.auto) fetchCurrent(); }, 2000);
  state.monTimer = setInterval(() => { if (state.auto) fetchMonitoring(); }, 30000);
  state.cfgTimer = setInterval(() => {
    if (state.auto && AUTH.role){
      loadAcl(); loadCache(); loadHealthSelection();
    }
  }, 15000);
  state.sessionTimer = setInterval(() => { checkSession(true); }, 60000);
  scheduleHistory();
}
function stopLiveTimers(){
  for (const key of ["curTimer","monTimer","cfgTimer","sessionTimer","histTimer"]){
    if (state[key]) clearInterval(state[key]);
    state[key] = null;
  }
  state.timersStarted = false;
}
async function startPortal(){
  await Promise.all([fetchCurrent(), fetchMonitoring()]);
  await Promise.all([fetchHistory(), loadConfig()]);
  await Promise.all([loadAcl(), loadCache(), loadHealthSelection()]);
  startLiveTimers();
}
async function refreshAll(){
  const btn = $("refresh-btn");
  btn.disabled = true;
  btn.textContent = "Refreshing…";
  try {
    await Promise.allSettled([fetchCurrent(), fetchMonitoring(), fetchHistory(),
      loadConfig(), loadAcl(), loadCache(), loadHealthSelection()]);
  } finally {
    btn.disabled = false;
    btn.textContent = "Refresh now";
  }
}
/* Double-submit CSRF: read the csrf cookie (set alongside the session) and
   echo it in the X-CSRF-Token header on every state-changing request. */
function csrfToken(){
  const m = document.cookie.match(/(?:^|;\s*)res_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}
function csrfHeaders(){
  const h = {};
  const t = csrfToken();
  if (t) h["X-CSRF-Token"] = t;
  return h;
}

const pad = n => String(n).padStart(2, "0");
function fmtClock(ms){ const d=new Date(ms); return pad(d.getHours())+":"+pad(d.getMinutes())+":"+pad(d.getSeconds()); }
function fmtClockShort(ms){
  const d=new Date(ms);
  if (state.range==="24h"||state.range==="7d")
    return pad(d.getMonth()+1)+"-"+pad(d.getDate())+" "+pad(d.getHours())+":"+pad(d.getMinutes());
  return pad(d.getHours())+":"+pad(d.getMinutes());
}
function fmtAgo(secs){
  if (secs==null) return "never";
  if (secs < 60) return secs+"s ago";
  if (secs < 3600) return Math.floor(secs/60)+"m ago";
  if (secs < 86400) return Math.floor(secs/3600)+"h ago";
  return Math.floor(secs/86400)+"d ago";
}
function fmtUptime(secs){
  const d=Math.floor(secs/86400), h=Math.floor(secs%86400/3600), m=Math.floor(secs%3600/60);
  if (d) return d+"d "+h+"h";
  if (h) return h+"h "+m+"m";
  return m+"m "+(secs%60)+"s";
}
/* `null`/undefined means "not measured yet" — never render it as a number.
   Zero is only ever shown when the gateway actually counted zero. */
function fmtVal(v, unit){
  if (v==null || !isFinite(v)) return "N/A";
  if (unit==="B") return fmtBytes(v);
  const a = Math.abs(v);
  let s;
  if (unit==="%" || unit==="ms") s = a<10 ? v.toFixed(1) : v.toFixed(a<100?1:0);
  else if (unit==="qps") s = a<10 ? v.toFixed(1) : v.toFixed(0);
  else if (unit==="MB") s = v.toFixed(0);
  else s = a<10 ? v.toFixed(1) : v.toFixed(0);
  return s + (unit==="%" ? "%" : unit==="ms" ? "ms" : unit==="MB" ? "MB" : unit==="qps" ? "" : "");
}
/* Percent with an explicit "N/A" when there is no denominator. */
function fmtPct(v, digits){
  if (v==null || !isFinite(v)) return "N/A";
  return (v*100).toFixed(digits==null?1:digits)+"%";
}
function seriesFrom(payload, key){
  return (payload && payload.series && payload.series[key]) || [];
}
function lastVal(points){
  for (let i=points.length-1;i>=0;i--) if (points[i][1]!=null) return points[i][1];
  return null;
}
function prevVal(points){
  let seen=false;
  for (let i=points.length-1;i>=0;i--){
    if (points[i][1]==null) continue;
    if (seen) return points[i][1];
    seen=true;
  }
  return null;
}
function median(arr){
  if (!arr.length) return null;
  const a=[...arr].sort((x,y)=>x-y), m=Math.floor(a.length/2);
  return a.length%2 ? a[m] : (a[m-1]+a[m])/2;
}
function trendEl(cur, prev, unit, invertGood){
  if (cur==null || prev==null) return {txt:"", cls:"flat"};
  const d = cur - prev;
  if (Math.abs(d) < Math.abs(cur)*0.03) return {txt:"→ "+fmtVal(cur,unit), cls:"flat"};
  const arrow = d>0 ? "▲" : "▼";
  const good = invertGood ? d<0 : d>0;
  return {txt: arrow+" "+fmtVal(Math.abs(d),unit)+" vs prev", cls: good?"up":"dn"};
}

/* =========================================================================
 * Canvas charts (zero dependencies)
 * ====================================================================== */
const chartHover = {};   // id -> {xs, series, box}

function niceMax(v){
  if (!isFinite(v) || v<=0) return 1;
  const e = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v/e;
  return (n<=1?1:n<=2?2:n<=5?5:10)*e;
}

function drawChart(def){
  const canvas = $(def.id);
  if (!canvas) return;
  const wrap = canvas.parentElement;
  const legendEl = wrap.querySelector('[data-legend="'+def.id+'"]');

  // Assemble series.
  let series = [];
  if (def.up) {
    const ups = state.hist && state.hist.upstreams ? state.hist.upstreams : {};
    const names = Object.keys(ups).sort();
    names.forEach((n,i) => {
      const pts = ups[n] && ups[n][def.up];
      if (pts) series.push({name:n, color:state.upColors[n]||PALETTE[i%PALETTE.length], points:pts, step:true});
    });
  } else {
    for (const key of def.keys){
      const meta = META[key] || [key,"","#8b949e"];
      series.push({name:meta[0], color:meta[2], points:seriesFrom(state.hist, key), step:!!def.step});
    }
  }
  if (state.focus){
    series = series.filter(s => s.name===state.focus || !def.up);
  }

  const old = wrap.querySelector(".nodata");
  if (old) old.remove();
  const hasData = series.some(s => s.points.some(p => p[1]!=null));
  canvas.style.display = hasData ? "block" : "none";
  if (!hasData){
    legendEl.innerHTML = "";
    const d = document.createElement("div");
    d.className = "nodata";
    d.textContent = state.hist
      ? "No data — no samples in this window (" + (state.hist.source||"?") + " source)"
      : "No data — waiting for first history fetch…";
    wrap.appendChild(d);
    delete chartHover[def.id];
    return;
  }
  canvas.style.display = "block";

  const dpr = window.devicePixelRatio || 1;
  const W = canvas.clientWidth || 400, H = canvas.clientHeight || 220;
  canvas.width = Math.round(W*dpr); canvas.height = Math.round(H*dpr);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr,0,0,dpr,0,0);
  ctx.clearRect(0,0,W,H);

  const L=44, R=8, T=6, B=20;
  const pw = W-L-R, ph = H-T-B;

  // Domains.
  let t0=Infinity, t1=-Infinity, v0=0, v1=-Infinity;
  for (const s of series) for (const p of s.points){
    if (p[0]<t0) t0=p[0];
    if (p[0]>t1) t1=p[0];
    if (p[1]!=null && p[1]>v1) v1=p[1];
  }
  if (t1<=t0){ t1 = t0+1000; }
  if (v1<=0) v1 = 1;
  v1 = niceMax(v1);

  const X = t => L + (t-t0)/(t1-t0)*pw;
  const Y = v => T + ph - (v-v0)/(v1-v0)*ph;

  // Grid + Y labels.
  ctx.strokeStyle = "#1c2634"; ctx.fillStyle = "#7f90a6";
  ctx.font = '10px "Shabnam", sans-serif'; ctx.textAlign = "right";
  const unit = META[(def.keys&&def.keys[0]) || ""] ? META[def.keys[0]][1] : "";
  for (let i=0;i<=4;i++){
    const v = v0 + (v1-v0)*i/4, y = Y(v);
    ctx.beginPath(); ctx.moveTo(L,y); ctx.lineTo(W-R,y); ctx.stroke();
    ctx.fillText(fmtAxis(v, def), L-5, y+3);
  }
  // X labels.
  ctx.textAlign = "center";
  const ticks = 5;
  for (let i=0;i<=ticks;i++){
    const t = t0 + (t1-t0)*i/ticks, x = X(t);
    ctx.fillText(fmtClockShort(t), Math.min(Math.max(x, L+24), W-R-24), H-6);
  }

  // Series lines.
  for (const s of series){
    ctx.strokeStyle = s.color;
    ctx.lineWidth = s.name===state.focus ? 2.4 : 1.6;
    ctx.beginPath();
    let pen = false;
    for (let i=0;i<s.points.length;i++){
      const p = s.points[i];
      if (p[1]==null){ pen = false; continue; }
      const x = X(p[0]), y = Y(p[1]);
      if (!pen){ ctx.moveTo(x,y); pen = true; }
      else if (s.step){ ctx.lineTo(x, Y(s.points[i-1] && s.points[i-1][1]!=null ? s.points[i-1][1] : p[1])); ctx.lineTo(x,y); }
      else ctx.lineTo(x,y);
    }
    ctx.stroke();
    // Last-value dot.
    for (let i=s.points.length-1;i>=0;i--){
      if (s.points[i][1]!=null){
        ctx.fillStyle = s.color;
        ctx.beginPath(); ctx.arc(X(s.points[i][0]), Y(s.points[i][1]), 2.4, 0, 7); ctx.fill();
        break;
      }
    }
  }

  // Legend.
  legendEl.innerHTML = series.map(s => {
    const lv = lastVal(s.points);
    const m = Object.values(META).find(v => v[0]===s.name);
    const u = def.up ? (def.up.endsWith("_ms")?"ms":def.up.endsWith("_pct")?"%":"") : (m?m[1]:"");
    return '<span><i style="background:'+s.color+'"></i>'+s.name+
      ' <span class="lv">'+fmtVal(lv,u)+'</span></span>';
  }).join("");

  chartHover[def.id] = {xs: series, t0, t1, L, R, W, box: canvas.getBoundingClientRect()};
}

function fmtAxis(v, def){
  if (def.keys){
    const u = META[def.keys[0]] ? META[def.keys[0]][1] : "";
    if (u==="%") return v.toFixed(v<10?1:0)+"%";
    if (u==="ms") return v<10?v.toFixed(1):v.toFixed(0);
    if (u==="MB") return v.toFixed(0);
    if (u==="B") return v>=1024 ? (v/1024).toFixed(v>=10240?0:1)+"k" : v.toFixed(0);
  }
  if (v>=1000) return (v/1000).toFixed(v>=10000?0:1)+"k";
  return v<10 ? v.toFixed(1) : v.toFixed(0);
}

/* Tooltip on hover. */
const tip = $("tip");
document.addEventListener("mousemove", e => {
  let hit = null;
  for (const [id, h] of Object.entries(chartHover)){
    const canvas = $(id);
    if (!canvas || canvas.style.display==="none") continue;
    const r = canvas.getBoundingClientRect();
    if (e.clientX>=r.left && e.clientX<=r.right && e.clientY>=r.top && e.clientY<=r.bottom){
      hit = {h, x: e.clientX-r.left, r};
      break;
    }
  }
  if (!hit){ tip.style.display="none"; return; }
  const {h, x} = hit;
  const pw = h.W - h.L - h.R;
  const frac = Math.min(Math.max((x-h.L)/pw, 0), 1);
  const t = h.t0 + frac*(h.t1-h.t0);
  // nearest shared timestamp across series
  let bestT = null, bestD = Infinity;
  for (const s of h.xs) for (const p of s.points){
    const d = Math.abs(p[0]-t);
    if (d<bestD){ bestD=d; bestT=p[0]; }
  }
  if (bestT==null){ tip.style.display="none"; return; }
  let html = '<div class="tt">'+fmtClock(bestT)+'</div>';
  for (const s of h.xs){
    const p = s.points.find(p => p[0]===bestT);
    const v = p ? p[1] : null;
    if (v==null) continue;
    html += '<div class="row"><span><i style="background:'+s.color+'"></i>'+s.name+'</span><b>'+fmtVal(v,"")+'</b></div>';
  }
  tip.innerHTML = html;
  tip.style.display = "block";
  const tw = tip.offsetWidth;
  tip.style.left = Math.min(e.clientX+14, window.innerWidth-tw-8)+"px";
  tip.style.top = (e.clientY+14)+"px";
});
document.addEventListener("mouseleave", () => tip.style.display="none");

/* =========================================================================
 * KPIs + assessment
 * ====================================================================== */
function fmtBytes(n){
  if (n==null || !isFinite(n)) return "N/A";
  if (n >= 1048576) return (n/1048576).toFixed(1)+" MB";
  if (n >= 1024) return (n/1024).toFixed(1)+" KB";
  return Math.round(n)+" B";
}
function intOf(v){ return (v==null || !isFinite(v)) ? 0 : v; }

function tilesHTML(list, primary){
  return list.map(k => {
    const cls = ["kpi", primary ? "primary" : "", k.cls || "", k.quiet ? "quiet" : ""]
      .filter(Boolean).join(" ");
    const state = k.state
      ? '<span class="kpi-state '+k.state.cls+'">'+k.state.txt+'</span>' : "";
    const t = k.t ? '<div class="t '+k.t.cls+'">'+k.t.txt+'</div>'
      : (primary ? '<div class="t"></div>' : "");
    const spark = k.spark
      ? '<canvas class="kpi-spark" data-spark="'+k.spark+'" aria-hidden="true"></canvas>' : "";
    return '<div class="'+cls+'"><div class="kpi-head"><div class="k">'+k.k+'</div>'+
      state+'</div><div class="v">'+k.v+'</div>'+t+spark+'</div>';
  }).join("");
}

function renderKpis(){
  const st = state.status, s = state.stats, h = state.hist;
  if (!st || !s){ return; }
  const t = s.traffic || {};
  const rc = s.rcode || {};
  const qpsL = lastVal(seriesFrom(h,"qps"));
  const p95L = lastVal(seriesFrom(h,"p95_ms"));
  const qpsP = prevVal(seriesFrom(h,"qps"));
  const p95P = prevVal(seriesFrom(h,"p95_ms"));
  const toPct = lastVal(seriesFrom(h,"timeout_pct"));
  const measured = s.success_rate != null;
  const errorPct = measured && s.error_rate != null ? s.error_rate * 100 : null;
  const errorKnown = errorPct != null;
  const errorText = !errorKnown ? "N/A"
    : errorPct === 0 ? "0%"
    : errorPct < 0.01 ? "<0.01%"
    : errorPct < 1 ? errorPct.toFixed(2)+"%"
    : errorPct.toFixed(1)+"%";
  const successState = !errorKnown ? {cls:"quiet", txt:"no data"}
    : errorPct > 1 ? {cls:"crit", txt:"failing"}
    : errorPct > 0 ? {cls:"warn", txt:"errors"}
    : {cls:"good", txt:"healthy"};
  const p95State = s.latency.p95_ms == null ? {cls:"quiet", txt:"no samples"}
    : s.latency.p95_ms > 1000 ? {cls:"crit", txt:"slow"}
    : s.latency.p95_ms > 300 ? {cls:"warn", txt:"elevated"}
    : {cls:"good", txt:"normal"};
  const cacheOff = !s.cache.enabled;
  const cacheRate = s.cache.hit_ratio == null ? null : s.cache.hit_ratio * 100;
  const cacheState = cacheOff ? {cls:"quiet", txt:"disabled"}
    : cacheRate == null ? {cls:"warn", txt:"no data"}
    : cacheRate >= 50 ? {cls:"good", txt:"warm"}
    : cacheRate >= 20 ? {cls:"quiet", txt:"steady"}
    : {cls:"warn", txt:"cold"};
  const idle = intOf(s.queries_total) === 0;

  /* ---- DNS service: six primary health/traffic cards ---- */
  const primary = [
    {k:"Queries", v:String(intOf(s.queries_total)), spark:"queries",
      state: idle ? {cls:"quiet", txt:"idle"} : null,
      t:{txt:intOf(s.queries_udp)+" udp · "+intOf(s.queries_tcp)+" tcp", cls:"flat"}},
    {k:"Success", v: measured ? (s.success_rate*100).toFixed(1)+"%" : "N/A",
      cls: successState.cls, state: successState, spark:"success_pct",
      t: measured ? {txt:intOf(s.success_count)+" ok", cls:"flat"}
                  : {txt:"no responses yet", cls:"flat"}},
    {k:"P95 now", v:fmtVal(s.latency.p95_ms,"ms"), cls:p95State.cls, state:p95State,
      spark:"p95_ms", t:trendEl(p95L, p95P, "ms", true)},
    {k:"QPS", v:fmtVal(s.qps,"qps"), spark:"qps",
      state: idle ? {cls:"quiet", txt:"idle"} : {cls:"good", txt:"live"},
      t:trendEl(qpsL, qpsP, "qps", false)},
    {k:"Cache hit", v: cacheOff ? "off" : cacheRate == null ? "N/A" : cacheRate.toFixed(0)+"%",
      cls:cacheState.cls, state:cacheState, spark:"cache_hit_pct",
      t:{txt:s.cache.entries+" entries", cls:"flat"}},
    {k:"Error rate", v:errorText,
      cls: !errorKnown ? "quiet" : errorPct > 1 ? "crit" : errorPct > 0 ? "warn" : "good",
      state: !errorKnown ? {cls:"quiet", txt:"no data"}
        : errorPct > 1 ? {cls:"crit", txt:">1%"}
        : errorPct > 0 ? {cls:"warn", txt:"observed"}
        : {cls:"good", txt:"none"},
      spark:"error_pct",
      t:{txt:intOf(s.error_count)+" failed queries", cls: s.error_count ? "dn":"flat"}},
  ];
  $("kpis").innerHTML = tilesHTML(primary, true);

  /* ---- Detailed counters stay behind an explicit disclosure ---- */
  const detail = [
    {k:"Responses", v:String(intOf(s.responses_total)),
      quiet:intOf(s.responses_total)===0,
      t:{txt: measured ? intOf(s.success_count)+" ok" : "no responses yet", cls:"flat"}},
    {k:"P50 / P99", v:fmtVal(s.latency.p50_ms,"ms")+' <small>/</small> '+fmtVal(s.latency.p99_ms,"ms"),
      quiet: s.latency.p50_ms == null,
      t: measured ? undefined : {txt:"no samples yet", cls:"flat"}},
    {k:"Timeouts (hist)", v: toPct==null?"N/A":toPct.toFixed(1)+"%",
      cls:(toPct||0)>1?"bad":"", quiet:toPct==null,
      t:{txt:intOf(s.query_errors.deadline)+" deadline", cls:s.query_errors.deadline?"dn":"flat"}},
    {k:"SERVFAIL", v:String(intOf(rc.SERVFAIL)), cls:rc.SERVFAIL>0?"bad":"",
      quiet:intOf(rc.SERVFAIL)===0, t:{txt:"client answers", cls:"flat"}},
    {k:"NXDOMAIN", v:String(intOf(rc.NXDOMAIN)), quiet:intOf(rc.NXDOMAIN)===0,
      t:{txt:"client answers", cls:"flat"}},
    {k:"REFUSED", v:String(intOf(rc.REFUSED)), cls:rc.REFUSED>0?"bad":"",
      quiet:intOf(rc.REFUSED)===0, t:{txt:"acl + upstream", cls:"flat"}},
    {k:"UDP packets", v:String(intOf(t.udp_packets_received)),
      quiet:intOf(t.udp_packets_received)===0,
      t:{txt:intOf(t.udp_packets_sent)+" sent", cls:"flat"}},
    {k:"Bytes in / out", v:fmtBytes(t.request_bytes)+" <small>/</small> "+fmtBytes(t.response_bytes),
      quiet:!intOf(t.request_bytes) && !intOf(t.response_bytes),
      t:t.avg_request_bytes==null
          ? {txt:"no queries yet", cls:"flat"}
          : {txt:"avg "+fmtBytes(t.avg_request_bytes)+" / "+fmtBytes(t.avg_response_bytes), cls:"flat"}},
    {k:"Failovers", v:String(intOf(s.failovers)), quiet:intOf(s.failovers)===0,
      t:{txt:"lifetime", cls:"flat"}},
    {k:"Rate limited", v:String(intOf(s.rate_limited)), cls:s.rate_limited>0?"bad":"",
      quiet:intOf(s.rate_limited)===0, t:{txt:"lifetime", cls:"flat"}},
    {k:"ACL denied", v:String(intOf(s.acl_denied)), cls:s.acl_denied>0?"bad":"",
      quiet:intOf(s.acl_denied)===0, t:{txt:"lifetime", cls:"flat"}},
    {k:"Malformed", v:String(intOf(s.malformed)), cls:s.malformed>0?"bad":"",
      quiet:intOf(s.malformed)===0, t:{txt:"packets", cls:"flat"}},
    {k:"Overload", v:String(intOf(s.overload_dropped)), cls:s.overload_dropped>0?"bad":"",
      quiet:intOf(s.overload_dropped)===0, t:{txt:"in-flight drops", cls:"flat"}},
  ];
  $("kpis-detail").innerHTML = tilesHTML(detail, false);
  $("kpi-detail-count").textContent = detail.length;

  /* ---- Process & capacity (secondary) ---- */
  const infra = [
    {k:"Upstreams", v:st.upstreams.healthy+" <small>/</small> "+st.upstreams.total,
      cls: st.upstreams.healthy===0?"bad":st.upstreams.degraded>0?"":"good",
      t:{txt:(st.upstreams.unhealthy||0)+" unhe · "+(st.upstreams.recovering||0)+" recov · "+st.upstreams.degraded+" degr", cls: (st.upstreams.unhealthy||st.upstreams.down)?"dn":"flat"}},
    {k:"In-flight", v:st.inflight.udp, t:{txt:st.inflight.tcp_connections+" tcp", cls:"flat"}},
    {k:"CPU", v:s.resources_cpu!=null?s.resources_cpu+"%":"N/A", t:{txt:"of one core", cls:"flat"}},
    {k:"Memory", v:(s.resources_rss!=null?(s.resources_rss/1048576).toFixed(0)+" <small>MB</small>":"N/A")},
    {k:"Open FDs", v:s.resources_fds!=null?s.resources_fds:"N/A", t:{txt:"process handles", cls:"flat"}},
  ];
  $("kpis-infra").innerHTML = tilesHTML(infra, false);
  drawKpiSparks();
}

/* Tiny dependency-free sparklines for the primary cards. */
function drawKpiSparks(){
  const dpr = window.devicePixelRatio || 1;
  for (const canvas of document.querySelectorAll(".kpi-spark[data-spark]")){
    if (!canvas.getClientRects().length) continue;
    const key = canvas.dataset.spark;
    const pts = seriesFrom(state.hist, key).filter(p => p && p[1] != null).slice(-64);
    const W = Math.round(canvas.clientWidth || 0), H = Math.round(canvas.clientHeight || 0);
    if (!W || !H) continue;
    canvas.width = Math.round(W*dpr); canvas.height = Math.round(H*dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr,0,0,dpr,0,0);
    ctx.clearRect(0,0,W,H);
    if (pts.length < 2) continue;
    let min = Infinity, max = -Infinity;
    for (const p of pts){ if (p[1] < min) min = p[1]; if (p[1] > max) max = p[1]; }
    if (max === min){ max = min + 1; min -= 1; }
    const pad = 3;
    const X = i => i/(pts.length-1)*W;
    const Y = v => pad + (1-(v-min)/(max-min))*(H-pad*2);
    const color = (META[key] && META[key][2]) || "#5cc8ff";
    ctx.beginPath();
    pts.forEach((p,i) => { if (i) ctx.lineTo(X(i),Y(p[1])); else ctx.moveTo(X(i),Y(p[1])); });
    ctx.lineTo(X(pts.length-1),H); ctx.lineTo(X(0),H); ctx.closePath();
    ctx.globalAlpha = .13; ctx.fillStyle = color; ctx.fill(); ctx.globalAlpha = 1;
    ctx.beginPath();
    pts.forEach((p,i) => { if (i) ctx.lineTo(X(i),Y(p[1])); else ctx.moveTo(X(i),Y(p[1])); });
    ctx.strokeStyle = color; ctx.lineWidth = 1.5; ctx.lineJoin = "round"; ctx.stroke();
    const lx = X(pts.length-1), ly = Y(pts[pts.length-1][1]);
    ctx.beginPath(); ctx.arc(lx,ly,2.2,0,Math.PI*2); ctx.fillStyle = color; ctx.fill();
  }
}

/* =========================================================================
 * Traffic (top clients / domains / question types — real counters only)
 * ====================================================================== */
function barRows(rows, denom){
  if (!rows.length) return "";
  const max = Math.max.apply(null, rows.map(r => r.value)) || 1;
  const d = (denom && denom > 0) ? denom : rows.reduce((a,r) => a + r.value, 0) || 1;
  return rows.map((r,i) => {
    const pct = Math.max(r.value > 0 ? 1.5 : 0, r.value / max * 100);
    const share = r.value / d * 100;
    return '<div class="br">'+
      '<span class="lab" title="'+escapeHtml(r.label)+'">'+escapeHtml(r.label)+'</span>'+
      '<span class="val">'+r.value+'<i>'+(r.value>0 ? share.toFixed(1)+"%" : "")+'</i></span>'+
      '<span class="track"><span class="fill" style="width:'+pct.toFixed(1)+
        '%;background:'+PALETTE[i%PALETTE.length]+'"></span></span>'+
      '</div>';
  }).join("");
}
function metaBits(bits){
  return bits.filter(Boolean).map(b =>
    '<span>'+b[0]+': <b>'+escapeHtml(String(b[1]))+'</b></span>').join("");
}

function renderTraffic(){
  const s = state.stats;
  if (!s) return;
  const t = s.traffic || {};
  const priv = t.client_ip_privacy || "masked";
  const chip = $("privacy-chip");
  chip.textContent = "ip: " + priv;
  chip.className = "chip " + (priv === "off" ? "stale" : "native");
  chip.title = priv === "masked"
    ? "Client addresses are shown with the host part hidden (IPv4 → 10.x.x.x)."
    : priv === "full"
      ? "Client addresses are shown in full (client_ip_privacy = full)."
      : "Client addresses are not tracked or exposed (client_ip_privacy = off).";

  const domains = t.domains || {};
  const drows = Array.isArray(t.top_domains) ? t.top_domains : [];

  // --- top queried names ---
  if (!drows.length){
    $("dm-list").innerHTML = '<div class="empty">No queried names recorded yet</div>';
    $("dm-meta").innerHTML = metaBits([
      ["tracked","0 / "+intOf(domains.cap)], ["requests","0"]]);
  } else {
    $("dm-list").innerHTML = barRows(
      drows.map(r => ({label:String(r.domain), value:intOf(r.count)})),
      intOf(domains.recorded_requests));
    $("dm-meta").innerHTML = metaBits([
      ["tracked", intOf(domains.tracked_keys)+" / "+intOf(domains.cap)],
      ["requests", intOf(domains.recorded_requests)],
      ["skipped", intOf(domains.skipped_requests)]
    ]) + (intOf(domains.skipped_requests) > 0
      ? '<span class="warnbit">table full — '+intOf(domains.skipped_requests)+' unattributed</span>' : "");
  }

  // --- question types ---
  const qt = t.query_type || {};
  const qrows = Object.keys(qt)
    .map(k => ({label:k, value:intOf(qt[k])}))
    .filter(r => r.value > 0)
    .sort((a,b) => b.value - a.value || a.label.localeCompare(b.label));
  const qsum = Object.keys(qt).reduce((a,k) => a + intOf(qt[k]), 0);
  if (!qrows.length){
    $("qt-list").innerHTML = '<div class="empty">No parsed queries yet — every query-type counter is 0</div>';
    $("qt-meta").innerHTML = metaBits([["parsed queries","0"], ["counters", Object.keys(qt).length]]);
  } else {
    $("qt-list").innerHTML = barRows(qrows, qsum);
    $("qt-meta").innerHTML = metaBits([
      ["parsed queries", qsum], ["counters", Object.keys(qt).length]]);
  }

  // --- transport + response codes ---
  const transport = [
    {label:"UDP queries", value:intOf(s.queries_udp)},
    {label:"TCP queries", value:intOf(s.queries_tcp)},
    {label:"UDP packets in", value:intOf(t.udp_packets_received)},
    {label:"UDP packets out", value:intOf(t.udp_packets_sent)},
  ].filter(r => r.value > 0);
  $("tr-list").innerHTML = transport.length
    ? barRows(transport, Math.max(intOf(s.queries_udp) + intOf(s.queries_tcp),
                                  intOf(t.udp_packets_received), 1))
    : '<div class="empty">No packets received yet</div>';

  const rc = s.rcode || {};
  const rrows = Object.keys(rc)
    .map(k => ({label:k, value:intOf(rc[k])}))
    .filter(r => r.value > 0)
    .sort((a,b) => b.value - a.value || a.label.localeCompare(b.label));
  const rsum = intOf(s.responses_total);
  $("rc-list").innerHTML = rrows.length
    ? barRows(rrows, rsum)
    : '<div class="empty">No responses sent yet</div>';

  $("tr-meta").innerHTML = metaBits([
    ["bytes in", fmtBytes(t.request_bytes)],
    ["bytes out", fmtBytes(t.response_bytes)],
    ["avg request", t.avg_request_bytes==null ? "N/A" : fmtBytes(t.avg_request_bytes)],
    ["avg response", t.avg_response_bytes==null ? "N/A" : fmtBytes(t.avg_response_bytes)]
  ]);
  $("traffic-meta").textContent =
    "bounded in-memory tables · " +
    (priv === "off" ? "client addresses are not tracked" :
      "client addresses shown as " + (priv === "masked" ? "network prefix only" : "full"));
}

/* =========================================================================
 * Service statistics / packet statistics (key-value lists from /api/stats)
 * ====================================================================== */
function statRows(list){
  return list.map(x => {
    const na = (x.v === "N/A" || x.v == null);
    const cls = na ? "v na" : (x.cls ? "v " + x.cls : "v");
    return '<div class="sr"><span class="k">' + escapeHtml(x.k) +
      '</span><span class="' + cls + '">' + x.v + '</span></div>';
  }).join("");
}
function pctStr(v, digits){
  if (v == null || !isFinite(v)) return "N/A";
  return (v*100).toFixed(digits==null?1:digits) + "%";
}

function renderStatsBlocks(){
  const s = state.stats;
  if (!s) return;
  const t = s.traffic || {}, rc = s.rcode || {}, qe = s.query_errors || {};

  $("svc-stats").innerHTML = statRows([
    {k:"Queries", v:String(intOf(s.queries_total))},
    {k:"UDP / TCP", v:intOf(s.queries_udp)+" / "+intOf(s.queries_tcp)},
    {k:"Responses", v:String(intOf(s.responses_total))},
    {k:"Success", v:String(intOf(s.success_count)), cls:intOf(s.success_count)?"good":""},
    {k:"Errors", v:String(intOf(s.error_count)), cls:intOf(s.error_count)?"bad":""},
    {k:"SERVFAIL", v:String(intOf(rc.SERVFAIL)), cls:intOf(rc.SERVFAIL)?"bad":""},
    {k:"NXDOMAIN", v:String(intOf(rc.NXDOMAIN))},
    {k:"REFUSED", v:String(intOf(rc.REFUSED)), cls:intOf(rc.REFUSED)?"bad":""},
    {k:"Deadline exceeded", v:String(intOf(qe.deadline)), cls:intOf(qe.deadline)?"bad":""},
    {k:"No upstreams / upstream fail",
      v:intOf(qe.no_upstreams)+" / "+intOf(qe.upstream_failure)},
    {k:"Not-implemented", v:String(intOf(qe.notimp))},
    {k:"Malformed", v:String(intOf(s.malformed)), cls:intOf(s.malformed)?"bad":""},
    {k:"Rate limited", v:String(intOf(s.rate_limited)), cls:intOf(s.rate_limited)?"bad":""},
    {k:"ACL denied", v:String(intOf(s.acl_denied))},
    {k:"Overload drops", v:String(intOf(s.overload_dropped)), cls:intOf(s.overload_dropped)?"bad":""},
    {k:"Cache", v: !s.cache.enabled ? "off"
        : intOf(s.cache.hits)+" / "+intOf(s.cache.misses)+" · "+pctStr(s.cache.hit_ratio,0)},
  ]);

  $("lat-stats").innerHTML = statRows([
    {k:"Success rate", v:pctStr(s.success_rate)},
    {k:"Error rate", v:pctStr(s.error_rate), cls:s.error_rate>0.01?"bad":""},
    {k:"Timeout rate (deadline)", v:pctStr(s.timeout_rate),
      cls:(s.timeout_rate||0)>0?"bad":""},
    {k:"Failovers per query", v:pctStr(s.failover_rate),
      cls:(s.failover_rate||0)>0?"bad":""},
    {k:"QPS (live)", v:fmtVal(s.qps,"qps")},
    {k:"Latency avg", v:fmtVal(s.latency.avg_ms,"ms")},
    {k:"Latency p50 / p95",
      v:fmtVal(s.latency.p50_ms,"ms")+" / "+fmtVal(s.latency.p95_ms,"ms")},
    {k:"Latency p99", v:fmtVal(s.latency.p99_ms,"ms")},
    {k:"Latency samples", v:String(intOf(s.latency.samples))},
    {k:"Timeouts (count)", v:String(intOf(s.timeout_count))},
    {k:"Failovers (count)", v:String(intOf(s.failovers))},
  ]);

  const rsum = intOf(s.responses_total);
  const rcRows = ["NOERROR","NXDOMAIN","SERVFAIL","REFUSED","FORMERR","NOTIMP","OTHER"]
    .map(k => {
      const n = intOf(rc[k]);
      const share = rsum ? " · " + (n/rsum*100).toFixed(1) + "%" : "";
      const bad = n > 0 && k !== "NOERROR" && k !== "NXDOMAIN";
      return {k, v:String(n)+share, cls:bad?(k==="SERVFAIL"?"bad":""):""};
    });
  rcRows.push({k:"responses total", v:String(rsum)});
  $("rcode-stats").innerHTML = statRows(rcRows);

  const reqSeen = intOf(t.request_bytes) > 0;
  const respSeen = intOf(t.response_bytes) > 0;
  $("pkt-stats").innerHTML = statRows([
    {k:"UDP packets in", v:String(intOf(t.udp_packets_received))},
    {k:"UDP packets out", v:String(intOf(t.udp_packets_sent))},
    {k:"Request bytes", v:fmtBytes(t.request_bytes)},
    {k:"Response bytes", v:fmtBytes(t.response_bytes)},
    {k:"Avg request payload",
      v:t.avg_request_bytes==null?"N/A":fmtBytes(t.avg_request_bytes)},
    {k:"Avg response payload",
      v:t.avg_response_bytes==null?"N/A":fmtBytes(t.avg_response_bytes)},
    {k:"Largest request",
      v:reqSeen ? fmtBytes(intOf(t.max_request_bytes)) : "N/A"},
    {k:"Largest response",
      v:respSeen ? fmtBytes(intOf(t.max_response_bytes)) : "N/A"},
    {k:"Oversized packets", v:String(intOf(t.oversized_packets)),
      cls:intOf(t.oversized_packets)?"bad":""},
    {k:"TCP connections",
      v:intOf(s.tcp.connections)+" accepted · "+intOf(s.tcp.rejected)+" rejected"},
    {k:"Requests counted", v:t.clients ? String(intOf(t.clients.recorded_requests)) : "N/A"},
    {k:"Unattributed (table full)",
      v:t.clients ? String(intOf(t.clients.skipped_requests)) : "N/A",
      cls:t.clients && intOf(t.clients.skipped_requests)>0?"bad":""},
  ]);
}

/* =========================================================================
 * Top clients table (per-client outcomes from /api/clients)
 * ====================================================================== */
function renderClientTable(){
  const s = state.stats;
  if (!s) return;
  const t = s.traffic || {};
  const priv = t.client_ip_privacy || "masked";
  const meta = t.clients || {};
  const c = state.clients;
  for (const th of document.querySelectorAll("#cl-table th.sortable")){
    th.classList.toggle("on", th.getAttribute("data-sort") === state.clientSort);
  }
  if (priv === "off"){
    $("cl-rows").innerHTML =
      '<tr><td colspan="12" class="empty">Client-address tracking is disabled ' +
      '(client_ip_privacy = "off")</td></tr>';
    $("cl-table-meta").innerHTML = metaBits([["tracking","off"],["cap", intOf(meta.cap)]]);
    return;
  }
  const rows = (c && Array.isArray(c.rows)) ? c.rows : [];
  if (!rows.length){
    $("cl-rows").innerHTML =
      '<tr><td colspan="12" class="empty">No client addresses recorded yet — ' +
      'every per-client counter is 0</td></tr>';
    $("cl-table-meta").innerHTML = metaBits([
      ["tracked","0 / "+intOf(meta.cap)], ["requests","0"], ["privacy",priv]]);
    return;
  }
  $("cl-rows").innerHTML = rows.map(r => {
    const failed = intOf(r.failed), timeouts = intOf(r.timeouts);
    return '<tr>'+
      '<td class="mono ip">'+escapeHtml(String(r.client))+'</td>'+
      '<td class="num">'+intOf(r.requests)+'</td>'+
      '<td class="num">'+(r.share==null?"N/A":(r.share*100).toFixed(1)+"%")+'</td>'+
      '<td class="num">'+fmtVal(r.rps,"qps")+'</td>'+
      '<td class="num" style="color:'+(intOf(r.ok)?"#7ee787":"inherit")+'">'+intOf(r.ok)+'</td>'+
      '<td class="num" style="color:'+(failed?"#e3b341":"inherit")+'">'+failed+'</td>'+
      '<td class="num" style="color:'+(timeouts?"#ff7b72":"inherit")+'">'+timeouts+'</td>'+
      '<td class="num">'+intOf(r.rate_limited)+'</td>'+
      '<td class="num">'+intOf(r.acl_denied)+'</td>'+
      '<td class="num">'+fmtVal(r.avg_ms,"ms")+'</td>'+
      '<td class="num">'+fmtVal(r.p95_ms,"ms")+'</td>'+
      '<td class="num">'+fmtBytes(r.bytes)+'</td>'+
    '</tr>';
  }).join("");
  $("cl-table-meta").innerHTML = metaBits([
    ["privacy", priv],
    ["sort", state.clientSort],
    ["tracked", intOf(meta.tracked_keys)+" / "+intOf(meta.cap)],
    ["recorded", intOf(meta.recorded_requests)],
    ["skipped", intOf(meta.skipped_requests)]
  ]) + (intOf(meta.skipped_requests) > 0
    ? '<span class="warnbit">table full — '+intOf(meta.skipped_requests)+' unattributed</span>'
    : "");
}

/* =========================================================================
 * Current upstream state + failover monitoring
 * ====================================================================== */
function nameList(arr){
  if (!arr || !arr.length) return '<div class="empty">none</div>';
  return arr.map(n =>
    '<div class="br"><span class="lab">'+escapeHtml(String(n))+'</span></div>').join("");
}

function renderUpState(){
  const st = state.upState;
  if (!st) return;
  $("up-state").innerHTML = statRows([
    {k:"Total upstreams", v:String(intOf(st.total))},
    {k:"Healthy", v:String(intOf(st.healthy)), cls:intOf(st.healthy)?"good":"bad"},
    {k:"Degraded", v:String(intOf(st.degraded)), cls:intOf(st.degraded)?"bad":""},
    {k:"Recovering", v:String(intOf(st.recovering)), cls:intOf(st.recovering)?"":""},
    {k:"Unhealthy", v:String(intOf(st.unhealthy)), cls:intOf(st.unhealthy)?"bad":""},
    {k:"Disabled", v:String(intOf(st.disabled))},
    {k:"Eligible for selection", v:String((st.eligible||[]).length)},
    {k:"Receiving traffic now", v:String((st.in_use||[]).length)},
    {k:"Eligible but idle", v:String((st.idle||[]).length)},
    {k:"Avoided (unhealthy, others healthy)", v:String((st.avoided||[]).length),
      cls:intOf(st.avoided)?"bad":""},
    {k:"Pool rate", v:fmtVal(st.total_qps,"qps")},
    {k:"Emergency", v: st.emergency ? "YES — all SERVFAIL" : "no",
      cls: st.emergency ? "bad" : "good"},
  ]);
  $("up-eligible").innerHTML = nameList(st.eligible);
  $("up-avoided").innerHTML = nameList(st.avoided);
  $("up-inuse").innerHTML = nameList(st.in_use);
  $("up-idle").innerHTML = nameList(st.idle);
}

function fmtFailover(e){
  return escapeHtml(e.upstream || "?") + " → " + escapeHtml(e.reason || "failed") +
    " → fallback to " + escapeHtml(e.fallback || "?") +
    (e.extra_latency_ms != null ? " → +" + e.extra_latency_ms + "ms" : "");
}

function renderFailovers(){
  const s = state.stats;
  if (!s) return;
  const h = state.hist;
  const foMin = lastVal(seriesFrom(h, "failover_per_min"));
  const foEvents = state.events.filter(e => e.kind === "failover");
  const attemptsFailed = state.upstreams.reduce((a,u) => a + intOf(u.failures), 0);
  $("fo-stats").innerHTML = statRows([
    {k:"Failovers (lifetime)", v:String(intOf(s.failovers)),
      cls:intOf(s.failovers)?"bad":""},
    {k:"Failover rate", v:pctStr(s.failover_rate, 2)},
    {k:"Failovers/min (window)", v:foMin==null?"N/A":foMin.toFixed(1)},
    {k:"Client deadlines", v:String(intOf(s.timeout_count))},
    {k:"Failed upstream attempts", v:String(attemptsFailed), cls:attemptsFailed?"bad":""},
    {k:"Recent failover events", v:String(foEvents.length)},
  ]);
  const perUp = state.upstreams
    .map(u => ({label:u.name, value:intOf(u.failovers)}))
    .filter(r => r.value > 0);
  const foSum = perUp.reduce((a,r) => a + r.value, 0);
  $("fo-ups").innerHTML = perUp.length
    ? barRows(perUp, foSum)
    : '<div class="empty">No failovers recorded yet</div>';
  const recent = foEvents.slice(0, 8);
  $("fo-recent").innerHTML = recent.length
    ? recent.map(e =>
        '<div class="br"><span class="lab">'+fmtFailover(e)+'</span>'+
        '<span class="val">'+fmtClock(e.ts_ms)+'</span></div>').join("")
    : '<div class="empty">No failover events yet</div>';
  $("fo-meta").innerHTML = metaBits([
    ["ring", foEvents.length + " recent"],
    ["window", foMin==null ? "N/A" : foMin.toFixed(1) + "/min"]
  ]);
}


function renderVerdict(){
  const st = state.status, s = state.stats;
  const pill = $("verdict"), txt = $("verdict-text");
  if (!st || !s){ pill.className="pill warn"; txt.textContent="collecting…"; return; }
  let level = "ok", label = "HEALTHY";
  const cfgErr = st.config && st.config.error;
  const emergency = st.emergency && st.emergency.no_healthy_upstreams;
  const idle = !s.queries_total;
  if (emergency){ level="crit"; label="CRITICAL · NO HEALTHY UPSTREAM"; }
  else if (cfgErr){ level="warn"; label="DEGRADED · CONFIG FALLBACK"; }
  else if (s.error_rate != null && s.error_rate > 0.10){ level="crit"; label="CRITICAL · FAILING QUERIES"; }
  else if (s.error_rate != null && s.error_rate > 0.01){ level="warn"; label="DEGRADED · ERRORS >1%"; }
  else if (st.upstreams.down > 0){ level="warn"; label="DEGRADED · UPSTREAM DOWN"; }
  else if (st.upstreams.degraded > 0){ level="warn"; label="DEGRADED · UPSTREAM DEGRADED"; }
  else if (idle){ level="idle"; label="IDLE · NO QUERIES YET"; }
  pill.className = "pill " + level;
  txt.textContent = label;

  setBanner("emergency", emergency);
  // Explicit zero-traffic state: never let the tiles imply measurements that
  // do not exist yet.
  setBanner("notraffic", idle && state.apiFails < 2);
  $("uptime").textContent = fmtUptime(st.uptime_seconds);
  $("version").textContent = "v" + st.version;
  $("login-version").textContent = st.version;
  $("page-version").textContent = st.version;
  if (st.listeners && st.listeners.api) $("page-api").textContent = st.listeners.api;
}

function renderSignals(){
  const st = state.status, s = state.stats, h = state.hist;
  if (!st || !s) return;
  const S = [];
  const add = (level, tag, title, detail) => S.push({level, tag, title, detail});

  // 1. Is the gateway answering at all?
  const emergency = st.emergency && st.emergency.no_healthy_upstreams;
  if (emergency)
    add("crit","DOWN","Every upstream is DOWN","clients receive SERVFAIL — check the upstream table and health events");
  else if (st.config.error)
    add("warn","CONFIG","Running on "+st.config.source+" configuration","parse error: "+st.config.error);
  else
    add("ok","OK","Gateway is serving","udp "+st.listeners.udp+", api "+st.listeners.api+", v"+st.version);

  // 2. Latency vs baseline (nothing to compare until a query was answered).
  const p95pts = seriesFrom(h,"p95_ms");
  const p95vals = p95pts.filter(p=>p[1]!=null).map(p=>p[1]);
  const base = median(p95vals.slice(0,-1));
  const now = s.latency.p95_ms;
  if (now == null || !s.latency.samples)
    add("info","IDLE","No latency sample yet",
        "p50/p95/p99 are unavailable — the gateway has not answered a query yet");
  else if (base!=null && now > Math.max(100, base*2))
    add("warn","SLOW","Latency elevated: p95 "+fmtVal(now,"ms")+" vs baseline "+fmtVal(base,"ms"),
        "upstream congestion, health-check load or CPU saturation — see CPU chart and upstream p95");
  else
    add("ok","OK","Latency within baseline","p50 "+fmtVal(s.latency.p50_ms,"ms")+", p95 "+fmtVal(now,"ms")+", p99 "+fmtVal(s.latency.p99_ms,"ms"));

  // 3. Failure rate.
  if (!s.responses_total)
    add("info","IDLE","No responses yet",
        "success and failure rates are N/A — no request has been answered so far");
  else if (s.error_rate > 0.10)
    add("crit","FAIL", (s.error_rate*100).toFixed(1)+"% of responses are errors",
        "check the error-breakdown chart (deadline vs upstream failure) and recent failovers");
  else if (s.error_rate > 0.01)
    add("warn","ERR", (s.error_rate*100).toFixed(1)+"% error rate",""+s.error_count+" error responses since start");
  else
    add("ok","OK","Response success "+(s.success_rate*100).toFixed(1)+"%", s.error_count+" errors since start");

  // 4. Upstream health.
  if (st.upstreams.total===0)
    add("crit","NO UP","No upstreams configured","add at least one upstream via /api/upstreams");
  else if (st.upstreams.down>0)
    add("warn","FAILOVER", st.upstreams.down+" upstream DOWN"+(st.upstreams.down>1?"s":""),
        "traffic is failing over — see upstream table and failover timeline");
  else if (st.upstreams.degraded>0)
    add("warn","DEGRAD", st.upstreams.degraded+" upstream DEGRADED","failing health probes but still receiving traffic");
  else
    add("ok","OK", st.upstreams.healthy+"/"+st.upstreams.total+" upstreams healthy","active health checking "+(st.health_check.enabled?"on":"OFF"));

  // 5-7: window counters. An empty window is not evidence of "no timeouts",
  // it is an absence of measurement — say so instead of claiming a clean run.
  const wq = windowQueries(h);
  const idleWin = wq != null && wq < 1;

  // 5. Recent timeouts / deadlines (history window).
  const toLast = lastN(seriesFrom(h,"timeout_pct"), 3);
  const dlLast = lastN(seriesFrom(h,"deadline_pct"), 3);
  const toSum = toLast.reduce((a,v)=>a+(v||0),0), dlSum = dlLast.reduce((a,v)=>a+(v||0),0);
  if (dlSum>0)
    add("warn","TIMEOUT","Client deadline exceeded recently ("+dlSum.toFixed(1)+"% of queries)",
        "requests took longer than query.timeout — lower upstream timeout or investigate upstream latency");
  else if (toSum>0.5)
    add("warn","TIMEOUT","Upstream timeouts in window ("+toSum.toFixed(1)+"%)",
        "network loss / slow upstream — check per-upstream timeout chart");
  else if (idleWin)
    add("info","IDLE","No queries in window","timeout and deadline rates are N/A — nothing to measure");
  else
    add("ok","OK","No timeouts in window","0% deadline + upstream timeout over the last points");

  // 6. Failovers.
  const foLast = lastN(seriesFrom(h,"failover_per_min"), 5).reduce((a,v)=>a+(v||0),0);
  if (foLast>0)
    add("warn","FAILOV", "Failovers active ("+foLast.toFixed(1)+" in last points)",
        "queries are retrying on alternate upstreams — see timeline for exact transitions");
  else if (idleWin)
    add("info","IDLE","No queries in window","failover counter is 0 because nothing was attempted");
  else
    add("ok","OK","No failovers in window","single-attempt answers throughout");

  // 7. Admission control (rate limit / ACL / overload).
  const rl = lastN(seriesFrom(h,"rate_limited_per_min"),3).reduce((a,v)=>a+(v||0),0);
  const ac = lastN(seriesFrom(h,"acl_denied_per_min"),3).reduce((a,v)=>a+(v||0),0);
  const ov = lastN(seriesFrom(h,"overload_per_min"),3).reduce((a,v)=>a+(v||0),0);
  if (ov>0)
    add("crit","OVERLOAD","In-flight limit reached ("+ov.toFixed(1)+"/min drops)",
        "gateway saturated — check CPU chart, consider lowering max_inflight or scaling out");
  else if (rl>0)
    add("warn","THROTTLE","Rate limiting active ("+rl.toFixed(1)+"/min drops)",
        "clients exceed per_ip_qps "+st.rate_limit.per_ip_qps+" — see ratelimit config");
  else if (ac>0)
    add("info","ACL","ACL denied queries ("+ac.toFixed(1)+"/min)","clients outside allowed_cidrs receive REFUSED");
  else if (idleWin)
    add("info","IDLE","No queries in window","rate limit, ACL and overload counters are 0 — unexercised");
  else
    add("ok","OK","No admission-control drops","rate limit, ACL and overload counters are idle in window");

  // 8. Resources.
  const cpu = lastVal(seriesFrom(h,"cpu_pct"));
  if (cpu!=null && cpu>80)
    add("warn","CPU","CPU at "+cpu.toFixed(0)+"%","gateway-bound saturation — expect queueing at this level");
  else if (s.resources_cpu==null && cpu==null)
    add("info","RES","Resource gauges unavailable","CPU/RSS/FD readings are not available from this build");
  else
    add("info","RES","CPU "+fmtVal(s.resources_cpu!=null?s.resources_cpu:cpu,"%")+
        ", RSS "+(s.resources_rss!=null?((s.resources_rss/1048576).toFixed(0)+"MB"):"N/A")+
        ", FDs "+(s.resources_fds!=null?s.resources_fds:"N/A"),
        "resident runtime gauges sampled 1/s by the gateway");

  // 9. Cache.
  if (!s.cache.enabled)
    add("info","CACHE","Cache disabled","enable [cache] to absorb repeated queries");
  else if (s.cache.hits + s.cache.misses === 0)
    add("info","CACHE","Cache hit ratio unavailable","no cache read yet — hits and misses are both 0");
  else if (s.cache.hit_ratio<0.1)
    add("info","CACHE","Cache hit ratio "+(s.cache.hit_ratio*100).toFixed(0)+"%","working set may exceed max_entries or TTLs are short");
  else
    add("ok","OK","Cache "+(s.cache.entries>0?"warm":"empty")+" ("+(s.cache.hit_ratio*100).toFixed(0)+"% hits)", s.cache.entries+" / "+st.cache.max_entries+" entries");

  $("signals").innerHTML = S.map(x =>
    '<div class="sig '+x.level+'"><span class="st">'+x.tag+'</span>'+
    '<div class="tx"><b>'+x.title+'</b><span>'+x.detail+'</span></div></div>'
  ).join("");
}

function lastN(points, n){
  const vals = points.filter(p=>p[1]!=null).map(p=>p[1]);
  return vals.slice(-n);
}

/// Approximate number of queries in the loaded history window (summed qps
/// rates × bucket width). Returns `null` when no history is loaded, so callers
/// can distinguish "no traffic" from "not measured yet".
function windowQueries(h){
  if (!h || !h.series) return null;
  const step = h.step_seconds || 1;
  return seriesFrom(h,"qps").reduce((a,p) => a + (p[1]==null?0:p[1]*step), 0);
}

/* =========================================================================
 * Upstream table
 * ====================================================================== */
function protoLabel(u){
  return u.protocol + (u.protocol === "tls" && u.tls_server_name ? " ("+u.tls_server_name+")" : "");
}
function stateChip(u){
  if (!u.enabled) return '<span class="state disabled"><span class="d"></span>off</span>';
  return '<span class="state '+u.health+'"><span class="d"></span>'+u.health+'</span>';
}
function renderUpstreams(){
  // Score rank + human-readable "why" (reason) for the Score column: the
  // selection algorithm is multiplicative, so quote its actual factors.
  const ranked = state.upstreams.slice().sort((a,b) =>
    ((b.score && b.score.score) || 0) - ((a.score && a.score.score) || 0));
  const rankOf = {};
  ranked.forEach((u,i) => { rankOf[u.id] = i + 1; });
  const scoreReason = u => {
    const s = u.score;
    if (!s) return "no score yet";
    return "health "+s.health_factor+" × reliability "+s.reliability+
      " × latency "+s.latency_factor+" × probes "+s.probe_factor+
      " × weight "+s.weight+" = "+s.score;
  };
  const rows = state.upstreams.map((u,i) => {
    const color = state.upColors[u.name] || PALETTE[i%PALETTE.length];
    const hc = u.last_health_ok==null ? '<span class="tag">no probe yet</span>'
      : u.last_health_ok ? '<span class="tag ok">✓ ok</span>' : '<span class="tag bad">✗ fail</span>';
    const hlat = u.health_latency!=null ? " " + u.health_latency.toFixed(1) + "ms" : "";
    const use = u.eligible === false
      ? (u.enabled ? '<span class="tag bad">avoided</span>' : '<span class="tag">off</span>')
      : u.in_use ? '<span class="tag ok">in use</span>'
                 : '<span class="tag">idle</span>';
    return '<tr data-up="'+escapeHtml(u.name)+'" class="'+(state.focus===u.name?"focus":"")+'">'+
      '<td>'+stateChip(u)+'</td>'+
      '<td>'+use+'</td>'+
      '<td><span class="state '+u.health+'" style="text-transform:none"><span class="d" style="background:'+color+'"></span></span> '+escapeHtml(u.name)+'</td>'+
      '<td class="mono ip" style="color:var(--dim)">'+escapeHtml(u.address)+':'+u.port+' · '+escapeHtml(protoLabel(u))+'</td>'+
      '<td class="num">'+u.priority+'/'+u.weight+'</td>'+
      '<td class="num">'+fmtVal(u.qps,"qps")+'</td>'+
      '<td class="num">'+u.queries+'</td>'+
      '<td class="num">'+u.ok+'</td>'+
      '<td class="num" style="color:'+(u.failures>0?"#e3b341":"inherit")+'">'+u.failures+'</td>'+
      '<td class="num" style="color:'+(u.timeouts>0?"#ff7b72":"inherit")+'">'+u.timeouts+'</td>'+
      '<td class="num" style="color:'+(u.success_rate==null?"inherit":u.success_rate>=0.99?"#7ee787":u.success_rate>=0.95?"#e3b341":"#ff7b72")+'">'+
        (u.success_rate==null?"N/A":(u.success_rate*100).toFixed(1)+"%")+'</td>'+
      '<td class="num" style="color:'+(u.failure_rate==null?"inherit":u.failure_rate>0?"#ff7b72":"#7ee787")+'">'+
        (u.failure_rate==null?"N/A":(u.failure_rate*100).toFixed(1)+"%")+'</td>'+
      '<td class="num" style="color:'+(u.timeout_rate==null?"inherit":u.timeout_rate>0.01?"#ff7b72":"inherit")+'">'+
        (u.timeout_rate==null?"N/A":(u.timeout_rate*100).toFixed(1)+"%")+'</td>'+
      '<td class="num">'+fmtVal(u.latency.avg_ms,"ms")+'</td>'+
      '<td class="num">'+fmtVal(u.latency.p50_ms,"ms")+'</td>'+
      '<td class="num">'+fmtVal(u.latency.p95_ms,"ms")+'</td>'+
      '<td class="num">'+fmtVal(u.latency.p99_ms,"ms")+'</td>'+
      '<td class="num" style="color:'+(u.failovers>0?"#e3b341":"inherit")+'">'+u.failovers+'</td>'+
      '<td class="num mono" title="'+escapeHtml(scoreReason(u))+'" style="color:'+
        ((u.score&&u.score.score||0)>0?"#7ee787":"var(--dim)")+'">'+
        (u.score ? u.score.score.toFixed(3) : "—")+'</td>'+
      '<td class="num">'+(rankOf[u.id]||"—")+'</td>'+
      '<td class="num" title="completed health-check rounds">'+u.health_rounds+'</td>'+
      '<td class="mono" style="color:var(--dim)">'+fmtAgo(u.last_success_ago_secs)+'</td>'+
      '<td class="mono" style="color:'+(u.last_failure_ago_secs!=null&&u.last_failure_ago_secs<30?"#e3b341":"var(--dim)")+'">'+fmtAgo(u.last_failure_ago_secs)+'</td>'+
      '<td class="mono" style="color:var(--dim)">'+fmtAgo(u.last_state_change_ago_secs)+'</td>'+
      '<td class="mono" style="color:var(--dim)">'+fmtAgo(u.last_check_ago_secs)+'</td>'+
      '<td>'+hc+'<span class="mono" style="color:var(--faint);font-size:11px">'+hlat+'</span></td>'+
      '<td class="mono" style="color:var(--dim);max-width:260px;overflow:hidden;text-overflow:ellipsis">'+escapeHtml(u.last_error||"—")+'</td>'+
    '</tr>';
  });
  $("up-rows").innerHTML = rows.length
    ? rows.join("")
    : '<tr><td colspan="27" class="empty">no upstreams configured</td></tr>';
  for (const tr of $("up-rows").querySelectorAll("tr[data-up]")){
    tr.addEventListener("click", () => {
      const n = tr.getAttribute("data-up");
      state.focus = state.focus===n ? null : n;
      renderUpstreams(); drawAllCharts();
    });
  }
}
function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

/* =========================================================================
 * Timeline
 * ====================================================================== */
function eventSeverity(e){
  if (e.kind==="system") return e.action==="all_upstreams_down" ? "crit"
    : e.action==="all_upstreams_recovered" ? "ok"
    : e.action==="overload_dropped" ? "crit"
    : e.action==="query_deadline" || e.action==="rate_limited" ? "warn" : "info";
  if (e.kind==="health") return e.action==="transition" && e.to==="unhealthy" ? "crit"
    : (e.action==="round_failed" || (e.action==="probe" && e.to==="unhealthy")) ? "warn"
    : e.action==="transition" && (e.to==="healthy" || e.to==="recovering") ? "ok" : "info";
  if (e.kind==="failover") return "warn";
  return "info";
}
function fmtEvent(e, grp){
  const d = e.detail && typeof e.detail==="object" ? e.detail : {};
  if (e.kind==="failover"){
    let lat;
    if (grp && grp.length>1){
      const ls = grp.map(x => +x.extra_latency_ms || 0);
      const mn = Math.min.apply(null, ls), mx = Math.max.apply(null, ls);
      lat = mn===mx ? "+"+mn+"ms" : "+"+mn+"–"+mx+"ms";
    } else lat = "+"+e.extra_latency_ms+"ms";
    return escapeHtml(e.upstream)+" <b>"+escapeHtml(e.reason||"")+"</b> → fallback to "+
      escapeHtml(e.fallback||"?")+" ("+lat+", attempt "+e.attempts+")";
  }
  if (e.kind==="health"){
    if (e.action==="transition")
      return escapeHtml(e.upstream)+": "+e.from+" → <b>"+e.to+"</b>"+(e.reason?" ("+escapeHtml(e.reason)+")":"");
    if (e.action==="round_failed")
      return escapeHtml(e.upstream)+": health check failed"+(e.reason?" ("+escapeHtml(e.reason)+")":"");
    if (e.action==="probe")
      return escapeHtml(e.upstream)+": manual probe "+(d.success?"ok":"failed")+
        (d.latency_ms!=null?" ("+d.latency_ms+"ms)":"")+(e.reason?" ("+escapeHtml(e.reason)+")":"");
    return escapeHtml(e.upstream||"")+": "+escapeHtml(e.action)+(e.reason?" ("+escapeHtml(e.reason)+")":"");
  }
  if (e.kind==="config"){
    const bits = [];
    if (d.name) bits.push(d.name);
    if (d.id!=null && !d.name) bits.push("#"+d.id);
    if (d.upstreams!=null) bits.push(d.upstreams+" upstreams");
    if (d.persisted===false) bits.push("not persisted");
    if (d.outcome) bits.push(String(d.outcome));
    if (d.reason) bits.push(String(d.reason).slice(0,120));
    if (e.action==="persist_failed") bits.push(escapeHtml(d.error||""));
    return "config <b>"+escapeHtml(e.action)+"</b> "+bits.map(escapeHtml).join(" · ");
  }
  if (e.kind==="system"){
    const cnt = e.count ? '<span class="cnt">×'+e.count+(e.window_secs?" in "+e.window_secs+"s":"")+'</span>' : "";
    switch(e.action){
      case "all_upstreams_down": return "<b>ALL UPSTREAMS DOWN</b> — every client receives SERVFAIL"+cnt;
      case "all_upstreams_recovered": return "upstream pool recovered ("+d.healthy+"/"+d.total+" healthy)"+cnt;
      case "rate_limited": return "rate limiting dropped queries"+cnt+(d.client_ip?" — first <span class=\"mono\">"+escapeHtml(d.client_ip)+"</span>":"");
      case "acl_denied": return "ACL denied queries"+cnt+(d.client_ip?" — first <span class=\"mono\">"+escapeHtml(d.client_ip)+"</span>":"");
      case "query_deadline": return "client queries hit the total deadline"+cnt+(d.transport?" ("+d.transport+")":"");
      case "overload_dropped": return "in-flight limit reached — queries dropped"+cnt+(d.max_inflight?" (max "+d.max_inflight+")":"");
      default: return escapeHtml(e.action)+cnt;
    }
  }
  return escapeHtml(e.action||e.kind);
}
/// Collapse *adjacent* rows that describe the same thing (same kind, action,
/// upstream, transition and reason) into one row with a ×count badge, so a
/// failover storm doesn't bury the rest of the incident timeline. Real events,
/// display-only grouping — nothing is invented, only aggregated.
function groupEvents(list){
  const key = e => [e.kind, e.action||"", e.upstream||"", e.from||"", e.to||"",
                    e.reason||"", e.fallback||""].join("\u0001");
  const groups = [];
  for (const e of list){
    const g = groups[groups.length-1];
    if (g && g.key === key(e)) g.items.push(e);
    else groups.push({key: key(e), items: [e]});
  }
  return groups;
}
function renderEvents(){
  const list = state.events.filter(e => state.filter==="all" || e.kind===state.filter);
  if (!list.length){
    $("events").innerHTML = '<div class="empty">no '+(state.filter==="all"?"":state.filter+" ")+'events recorded yet</div>';
    return;
  }
  $("events").innerHTML = groupEvents(list).map(g => {
    const e = g.items[0];
    const sev = eventSeverity(e);
    let meta = "";
    if (g.items.length > 1){
      const newest = g.items[0].ts_ms, oldest = g.items[g.items.length-1].ts_ms;
      const span = Math.max(0, Math.round((newest - oldest)/1000));
      meta = ' <span class="cnt">×'+g.items.length+(span>0 ? ' over '+span+'s' : '')+'</span>';
    }
    return '<div class="ev '+sev+'"><span class="t">'+fmtClock(e.ts_ms)+'</span>'+
      '<span class="k">'+e.kind+'</span><span class="m">'+fmtEvent(e, g.items)+meta+'</span></div>';
  }).join("");
}

/* =========================================================================
 * Source chip / history fetch
 * ====================================================================== */
function updateSourceChip(){
  const chip = $("src-chip");
  const h = state.hist;
  if (!h){ chip.className="chip"; chip.textContent="—"; return; }
  const mon = state.monitoring && state.monitoring.prometheus;
  if (h.source==="prometheus"){
    const partial = (h.partial_errors||[]).length;
    chip.className="chip prom"+(partial?" stale":"");
    chip.textContent="prometheus · "+(h.points||0)+" pts"+(partial?" ("+partial+" err)":"");
    chip.title = "Source: "+(h.prometheus_url||"")+" (range "+h.range+", step "+h.step_seconds+"s)"+
      (h.queries_ok!=null?" — "+h.queries_ok+"/"+(h.queries_total||"?")+" queries ok":"")+
      (partial?"\n"+(h.partial_errors||[]).join("\n"):"");
  } else if (mon && mon.configured){
    chip.className="chip stale";
    chip.textContent="native (prom unreachable)";
    chip.title = "Prometheus configured ("+mon.url+") but unreachable — falling back to gateway-native history. Reason: "+(h.fallback_reason||"unknown");
  } else {
    chip.className="chip native";
    chip.textContent="native · "+(h.points||0)+" pts";
    chip.title = "Gateway-native in-memory history ("+h.bucket_source+" buckets) — no external dependency.";
  }
}

async function fetchHistory(){
  try {
    const q = "?range="+encodeURIComponent(state.range)+"&source="+encodeURIComponent(state.source);
    state.hist = await getJSON("/api/timeseries"+q, 12000);
    state.histAt = Date.now();
    const h = state.hist;
    const stepTxt = h.bucket_source ? h.bucket_source+" buckets" : "step "+h.step_seconds+"s";
    const partial = (h.partial_errors||[]);
    $("hist-meta").textContent =
      "range "+h.range+" · "+(h.points||0)+" points · "+stepTxt+
      " · source: "+h.source+(h.fallback_reason?" ("+h.fallback_reason+")":"")+
      (partial.length?" · "+partial.length+" prometheus query error(s)":"")+
      " · updated "+fmtClock(h.generated_ms||Date.now());
    $("hist-meta").title = partial.length ? partial.join("\n") : "";
    $("foot-ts").textContent = h.source + " · " + (h.points||0) + " pts";
    drawAllCharts();
    updateSourceChip();
    renderKpis(); renderSignals(); renderFailovers();
    maybeReady();
  } catch (e) {
    console.warn("history fetch failed", e);
    $("hist-meta").textContent = "history fetch failed: "+e.message;
    $("foot-ts").textContent = "error";
  }
}

function drawAllCharts(){ for (const def of CHARTS) drawChart(def); drawKpiSparks(); }

function historyInterval(){ return (state.range==="5m"||state.range==="15m") ? 5000 : 30000; }

function scheduleHistory(){
  if (state.histTimer) clearTimeout(state.histTimer);
  const loop = async () => {
    if (state.auto) await fetchHistory();
    state.histTimer = setTimeout(loop, historyInterval());
  };
  state.histTimer = setTimeout(loop, 0);
}

/* =========================================================================
 * Live section
 * ====================================================================== */
function setLiveState(stale){
  const badge = $("live-badge");
  if (!badge) return;
  badge.classList.toggle("stale", !!stale);
  $("live-text").textContent = stale ? "Stale" : "Live";
  badge.title = stale
    ? "Control-plane API unreachable; displayed values may be stale"
    : "Live data is refreshing";
}
async function fetchCurrent(){
  try {
    const [status, stats, ups, ev, cl] = await Promise.all([
      getJSON("/api/status"),
      getJSON("/api/stats"),
      getJSON("/api/upstreams"),
      getJSON("/api/events?limit=160"),
      getJSON("/api/clients?limit=25&sort="+encodeURIComponent(state.clientSort), 6000)
        .catch(() => null),
    ]);
    state.status = status;
    state.stats = stats;
    state.upstreams = ups.upstreams || [];
    state.upState = ups.state || null;
    syncGeneration(ups.generation);
    state.clients = cl;
    state.events = ev.events || [];
    state.upstreams.forEach((u,i) => {
      if (!(u.name in state.upColors)) state.upColors[u.name] = PALETTE[Object.keys(state.upColors).length % PALETTE.length];
    });
    // Extra resource gauges surfaced via /api/diagnostics (CPU/FD history is
    // in the timeseries payload; here we only need the latest values).
    try {
      const diag = await getJSON("/api/diagnostics");
      state.stats.resources_cpu = diag.resources.cpu_percent;
      state.stats.resources_rss = diag.resources.resident_memory_bytes;
      state.stats.resources_fds = diag.resources.open_fds;
    } catch (_) { /* diagnostics optional for the strip */ }

    state.apiFails = 0; state.lastOk = Date.now();
    setLiveState(false);
    setBanner("apiproblem", false);
    $("updated").textContent = "updated "+fmtClock(state.lastOk);
    renderVerdict(); renderKpis(); renderTraffic(); renderStatsBlocks();
    renderClientTable(); renderUpState(); renderFailovers();
    renderSignals(); renderUpstreams(); renderEvents(); renderUpstreamMgr();
    $("foot-ev").textContent = state.events.length + " recent";
    maybeReady();
  } catch (e) {
    state.apiFails++;
    setLiveState(true);
    $("updated").textContent = "API unreachable ("+state.apiFails+")";
    if (state.apiFails >= 2){ setBanner("apiproblem", true); renderVerdict(); }
  }
}

async function fetchMonitoring(){
  try { state.monitoring = await getJSON("/api/monitoring", 4000); updateSourceChip(); }
  catch (_) { /* non-fatal */ }
}

function maybeReady(){
  if (state.status && state.hist && !document.documentElement.hasAttribute("data-ready")){
    document.documentElement.setAttribute("data-ready","1");
    $("foot-ready").textContent = "render: ready at "+fmtClock(Date.now());
  }
}

/* =========================================================================
 * Config editor
 * ====================================================================== */
async function loadConfig(){
  try {
    const c = await getJSON("/api/config");
    $("cfg-text").value = maskTokenLine(c.toml || "");
    $("cfg-path").textContent = c.path || "(in-memory)";
    $("cfg-source").textContent = c.source || "—";
    $("cfg-error").textContent = c.error || "none";
  } catch (e){
    $("cfg-msg").textContent = "load failed: "+e.message;
    $("cfg-msg").className = "err";
  }
}
function maskTokenLine(toml){
  return toml.replace(/^(\s*api_token\s*=\s*).*$/gm, '$1"•••"');
}
async function applyConfig(){
  const msg = $("cfg-msg");
  if (!canWrite()){ msg.textContent = "read-only session — configuration changes are disabled"; msg.className = "err"; return; }
  msg.textContent = "applying…"; msg.className = "";
  const toml = $("cfg-text").value;
  const doPut = async (confirmFlag) => {
    const qs = [];
    if (state.generation != null) qs.push("generation=" + state.generation);
    if (confirmFlag) qs.push("confirm=true");
    const url = qs.length ? "/api/config?" + qs.join("&") : "/api/config";
    const r = await fetch(url, {
      method: "PUT",
      headers: Object.assign({"Content-Type":"application/json"}, csrfHeaders()),
      credentials: "same-origin",
      body: JSON.stringify({toml, persist: true}),
    });
    const j = await r.json().catch(()=>({}));
    if (!r.ok){
      const err = new Error(j.error || ("HTTP "+r.status));
      err.code = j.code || ""; err.status = r.status;
      throw err;
    }
    return j;
  };
  try {
    let j;
    try {
      j = await doPut(false);
    } catch (e){
      if (e.code === "confirm_required"){
        // Guardrail: the import would leave zero enabled upstreams.
        if (!window.confirm("Import refused by guardrails:\n\n"+e.message+"\n\nApply anyway?")){
          msg.textContent = "cancelled — "+e.message; msg.className = "warn"; return;
        }
        j = await doPut(true);
      } else if (e.status === 409){
        // Optimistic concurrency: someone changed the config since we loaded it.
        msg.textContent = "Configuration changed elsewhere — reloading; review and re-apply. ("+e.message+")";
        msg.className = "warn";
        await loadConfig(); await fetchCurrent();
        return;
      } else throw e;
    }
    msg.textContent = "applied"+(j.persisted?" + persisted":" (memory only)")+
      (j.persist_error?" — persist error: "+j.persist_error:"");
    msg.className = j.persist_error ? "err" : "ok";
    if (j.generation != null) syncGeneration(j.generation);
    await loadConfig(); await fetchCurrent();
  } catch (e){
    msg.textContent = "rejected: "+e.message; msg.className = "err";
  }
}

/* =========================================================================
 * Upstream DNS management (live add/edit/enable/disable/test/remove)
 * ====================================================================== */
const umg = { editId: null, pendingConfirm: null };
// Migrate away from the legacy persistent token: bearer secrets must not
// survive tab close or be readable by a later viewer session.
try { localStorage.removeItem("res-admin-token"); } catch(_){}
function umgToken(){ try { return sessionStorage.getItem("res-admin-token") || ""; } catch(_){ return ""; } }
function umgSetToken(t){
  try {
    localStorage.removeItem("res-admin-token");
    if (t) sessionStorage.setItem("res-admin-token", t);
    else sessionStorage.removeItem("res-admin-token");
  } catch(_){}
}
function umgMsg(text, cls){ const m = $("umg-msg"); m.textContent = text || ""; m.className = cls || ""; }
async function umgApi(method, path, body){
  if (method !== "GET" && !canWrite()){
    const err = new Error("this session is read-only");
    err.status = 403;
    throw err;
  }
  const h = csrfHeaders();
  if (body != null) h["Content-Type"] = "application/json";
  const tok = umgToken();
  if (tok) h["Authorization"] = "Bearer " + tok;
  const r = await fetch(path, {method, headers: h, credentials:"same-origin", body: body != null ? JSON.stringify(body) : undefined});
  const j = await r.json().catch(() => ({}));
  if (r.status === 401){ authNeeded(); }
  if (!r.ok){
    const err = new Error(j.error || ("HTTP " + r.status));
    err.code = j.code || ""; err.status = r.status;
    throw err;
  }
  return j;
}
function umgHandleError(e, what){
  if (e.status === 401){
    umgMsg(what+" rejected: admin token required or invalid — set it in the Admin token box above.", "err");
  } else if (e.code === "confirm_required"){
    umgMsg(what+" rejected: "+e.message, "warn");
  } else if (e.code === "conflict" && /stale configuration/.test(e.message)){
    umgMsg("Configuration changed elsewhere; reloading… ("+e.message+")", "warn");
    fetchCurrent();
  } else {
    umgMsg(what+" rejected: "+e.message, "err");
  }
}
function umgRenderMeta(){
  const st = state.status;
  const el = $("umg-meta");
  if (!st){ el.innerHTML = '<div class="empty" style="padding:6px 0">loading…</div>'; return; }
  const a = st.auth || {}, c = st.config || {}, u = st.upstreams || {};
  $("umg-auth").textContent = a.required ? "gateway requires a token" : "gateway: no token configured";
  el.innerHTML =
    '<div class="cfgmeta" style="padding-bottom:4px">'+
      '<span>generation <b style="color:var(--fg)">'+(state.generation != null ? state.generation : "—")+'</b></span>'+
      '<span>upstreams <b style="color:var(--fg)">'+(u.enabled!=null?u.enabled+"/"+u.total:(u.total!=null?u.total:"?"))+'</b> enabled</span>'+
      '<span>source '+(c.source||"—")+'</span>'+
      '<span>path '+(c.path ? escapeHtml(c.path) : "(in-memory)")+'</span>'+
    '</div>';
}
function renderUpstreamMgr(){
  umgRenderMeta();
  const rows = state.upstreams.map(u => {
    const hc = u.last_health_ok == null ? '<span class="tag">no probe yet</span>'
      : u.last_health_ok ? '<span class="tag ok">✓ '+(u.health_latency!=null?u.health_latency.toFixed(1)+"ms":"ok")+'</span>'
      : '<span class="tag bad">✗ fail</span>';
    const lat = u.latency && u.latency.avg_ms != null
      ? u.latency.avg_ms.toFixed(1)+"ms p95 "+(u.latency.p95_ms!=null?u.latency.p95_ms.toFixed(1):"—")+"ms" : "—";
    const sr = u.success_rate == null ? "N/A" : (u.success_rate*100).toFixed(1)+"%";
    const confirming = umg.pendingConfirm && umg.pendingConfirm.id === u.id;
    const acts = umg.editId === u.id
      ? '<button class="okbtn" data-act="canceledit">editing ↑</button>'
      : '<button data-act="edit">Edit</button>';
    const toggle = confirming
      ? '<button class="warnbtn" data-act="toggle-yes">'+(u.enabled?"Disable? Yes":"Enable? Yes")+'</button>'+
        '<button data-act="toggle-no">Cancel</button>'
      : '<button class="'+(u.enabled?"warnbtn":"okbtn")+'" data-act="toggle">'+(u.enabled?"Disable":"Enable")+'</button>';
    const rm = umg.removeId === u.id
      ? '<button class="danger" data-act="remove-yes">Confirm remove</button>'+
        '<button data-act="remove-no">Cancel</button>'
      : '<button class="danger" data-act="remove">Remove</button>';
    return '<tr data-id="'+u.id+'">'+
      '<td><span class="state '+u.health+'" style="text-transform:none"><span class="d"></span></span> '+escapeHtml(u.name)+'</td>'+
      '<td class="mono ip" style="color:var(--dim)">'+escapeHtml(u.address)+':'+u.port+' · '+escapeHtml(protoLabel(u))+'</td>'+
      '<td class="num">'+u.priority+'/'+u.weight+'</td>'+
      '<td>'+(u.enabled?stateChip(u):'<span class="state disabled"><span class="d"></span>off</span>')+'</td>'+
      '<td class="num mono">'+lat+'</td>'+
      '<td class="num" style="color:'+(u.success_rate==null?"inherit":u.success_rate>=0.99?"#7ee787":u.success_rate>=0.95?"#e3b341":"#ff7b72")+'">'+sr+'</td>'+
      '<td class="num">'+u.failures+'</td>'+
      '<td class="num">'+u.timeouts+'</td>'+
      '<td>'+hc+' <span class="mono" style="color:var(--faint);font-size:11px">'+fmtAgo(u.last_check_ago_secs)+'</span></td>'+
      '<td><div class="uact">'+acts+'<button data-act="test">Test</button>'+toggle+rm+'</div></td>'+
    '</tr>';
  });
  $("umg-rows").innerHTML = rows.length
    ? rows.join("")
    : '<tr><td colspan="10" class="empty">no upstreams configured — add one below</td></tr>';
}
function umgOpenForm(id){
  umg.editId = id || null;
  const u = id != null ? state.upstreams.find(x => x.id === id) : null;
  $("umg-form-title").textContent = u ? ("Edit upstream: "+u.name) : "Add upstream";
  $("umg-submit").textContent = u ? "Save changes" : "Add upstream";
  $("umg-name").value = u ? u.name : "";
  $("umg-address").value = u ? u.address : "";
  $("umg-port").value = u ? u.port : 53;
  delete $("umg-port").dataset.autoTls;
  $("umg-protocol").value = u ? (u.protocol || "udp") : "udp";
  $("umg-tls-name").value = (u && u.tls_server_name) ? u.tls_server_name : "";
  $("umg-tls-ca").value = (u && u.tls_ca_file) ? u.tls_ca_file : "";
  umg.origTls = !!(u && (u.tls_server_name || u.tls_ca_file));
  umgSyncTlsFields();
  $("umg-priority").value = u ? u.priority : 1;
  $("umg-weight").value = u ? u.weight : 1;
  $("umg-timeout").value = (u && u.timeout_ms != null) ? u.timeout_ms : "";
  $("umg-probe-interval").value = (u && u.probe_interval_ms != null) ? u.probe_interval_ms : "";
  $("umg-probe-timeout").value = (u && u.probe_timeout_ms != null) ? u.probe_timeout_ms : "";
  $("umg-expect-rcode").value = (u && u.expect_rcode) ? u.expect_rcode : "";
  $("umg-probes").value = (u && u.probes && u.probes.length)
    ? u.probes.map(p => (p.type || "?") + " " + (p.name || "")).join("\n")
    : "";
  // Remember what the server had so an emptied field can *clear* the
  // override instead of silently leaving the old value in place.
  umg.origExpectRcode = !!(u && u.expect_rcode);
  umg.origProbes = !!(u && u.probes && u.probes.length);
  umg.origTimeoutMs = (u && u.timeout_ms != null) ? u.timeout_ms : null;
  umg.origProbeIntervalMs = (u && u.probe_interval_ms != null) ? u.probe_interval_ms : null;
  umg.origProbeTimeoutMs = (u && u.probe_timeout_ms != null) ? u.probe_timeout_ms : null;
  $("umg-enabled").checked = u ? !!u.enabled : true;
  $("umg-confirm").checked = false;
  $("umg-form-d").open = true;
  $("umg-name").focus();
  renderUpstreamMgr();
}
function umgSyncTlsFields(){
  const tls = $("umg-protocol").value === "tls";
  const port = $("umg-port");
  $("umg-tls-name-wrap").hidden = !tls;
  $("umg-tls-ca-wrap").hidden = !tls;
  if (tls && parseInt(port.value, 10) === 53){
    port.value = 853;
    port.dataset.autoTls = "1";
  } else if (!tls && port.dataset.autoTls === "1" && parseInt(port.value, 10) === 853){
    port.value = 53;
    delete port.dataset.autoTls;
  }
}
function umgCloseForm(){
  umg.editId = null;
  $("umg-form-d").open = false;
  renderUpstreamMgr();
}
async function umgSubmit(){
  const name = $("umg-name").value.trim();
  const address = $("umg-address").value.trim();
  if (!name || !address){ umgMsg("name and address are required", "err"); return; }
  const body = {
    name, address,
    port: parseInt($("umg-port").value, 10) || 53,
    protocol: $("umg-protocol").value,
    priority: parseInt($("umg-priority").value, 10) || 1,
    weight: parseInt($("umg-weight").value, 10) || 1,
    enabled: $("umg-enabled").checked,
    confirm: $("umg-confirm").checked,
  };
  if (body.protocol === "tls"){
    body.tls_server_name = $("umg-tls-name").value.trim();
    const ca = $("umg-tls-ca").value.trim();
    if (ca) body.tls_ca_file = ca;
  } else if (umg.editId != null && umg.origTls){
    body.clear_tls = true;
  }
  const t = $("umg-timeout").value.trim();
  if (t) body.timeout_ms = parseInt(t, 10);
  else if (umg.editId != null && umg.origTimeoutMs != null) body.clear_timeout = true;
  const pi = $("umg-probe-interval").value.trim();
  if (pi) body.probe_interval_ms = parseInt(pi, 10);
  else if (umg.editId != null && umg.origProbeIntervalMs != null) body.clear_probe_interval_ms = true;
  const pt = $("umg-probe-timeout").value.trim();
  if (pt) body.probe_timeout_ms = parseInt(pt, 10);
  else if (umg.editId != null && umg.origProbeTimeoutMs != null) body.clear_probe_timeout_ms = true;
  const er = $("umg-expect-rcode").value.trim().toUpperCase();
  if (er) body.expect_rcode = er;
  else if (umg.editId != null && umg.origExpectRcode) body.clear_expect_rcode = true;
  const probesText = $("umg-probes").value.trim();
  if (probesText){
    const probes = [];
    let bad = "";
    for (const line of probesText.split("\n")){
      const s = line.trim();
      if (!s) continue;
      const parts = s.split(/\s+/);
      if (parts.length !== 2){ bad = s; break; }
      probes.push({type: parts[0], name: parts[1]});
    }
    if (bad){ umgMsg("probes: each line must be 'TYPE name' (e.g. 'A example.com') — offending line: "+bad, "err"); return; }
    body.probes = probes;
  } else if (umg.editId != null && umg.origProbes){
    body.clear_probes = true;
  }
  if (state.generation != null) body.generation = state.generation;
  const what = umg.editId != null ? "update" : "create";
  try {
    const j = umg.editId != null
      ? await umgApi("PATCH", "/api/upstreams/"+umg.editId, body)
      : await umgApi("POST", "/api/upstreams", body);
    umgMsg(what+" of '"+name+"' applied"+(j.persisted?" + persisted":" (memory only)")+
      (j.persist_error?" — persist error: "+j.persist_error:"")+
      " — effective immediately (generation "+j.generation+")", j.persist_error ? "err" : "ok");
    if (j.persist_error)
      umgMsg(what+" of '"+name+"' applied in memory but persist failed: "+j.persist_error+
        " — runtime and file now diverge until fixed (see timeline /logs)", "err");
    umgCloseForm();
    await fetchCurrent();
  } catch (e){ umgHandleError(e, what+" '"+name+"'"); }
}
async function umgRowAction(id, act){
  const u = state.upstreams.find(x => x.id === id);
  if (!u) return;
  if (act === "edit"){ umgOpenForm(id); return; }
  if (act === "canceledit"){ umgCloseForm(); return; }
  if (act === "test"){
    umgMsg("probing "+u.name+" ("+u.address+":"+u.port+" "+protoLabel(u)+")…", "");
    try {
      const j = await umgApi("POST", "/api/upstreams/"+id+"/test");
      const r = j.result || {};
      const ok = r.success;
      umgMsg("probe "+u.name+": "+(ok?"OK":"FAILED")+
        (r.latency_ms!=null?" in "+r.latency_ms.toFixed(1)+"ms":"")+
        (r.rcode!=null?" · rcode "+r.rcode:"")+
        (r.error?" · "+r.error:""), ok ? "ok" : "err");
      await fetchCurrent();
    } catch (e){ umgHandleError(e, "probe "+u.name); }
    return;
  }
  if (act === "toggle"){
    umg.pendingConfirm = {id, enabled: u.enabled};
    renderUpstreamMgr();
    return;
  }
  if (act === "toggle-no"){ umg.pendingConfirm = null; renderUpstreamMgr(); return; }
  if (act === "toggle-yes"){
    const next = !u.enabled;
    const body = {enabled: next, confirm: true};
    if (state.generation != null) body.generation = state.generation;
    umg.pendingConfirm = null;
    try {
      const j = await umgApi("PATCH", "/api/upstreams/"+id, body);
      umgMsg(u.name+(next?" enabled":" disabled")+" — effective immediately"+
        (j.persisted?" (persisted)":" (memory only)")+
        (j.persist_error?" — persist error: "+j.persist_error:""),
        j.persist_error ? "err" : "ok");
      await fetchCurrent();
    } catch (e){ umgHandleError(e, (next?"enable ":"disable ")+u.name); renderUpstreamMgr(); }
    return;
  }
  if (act === "remove"){ umg.removeId = id; renderUpstreamMgr(); return; }
  if (act === "remove-no"){ umg.removeId = null; renderUpstreamMgr(); return; }
  if (act === "remove-yes"){
    let path = "/api/upstreams/"+id+"?confirm=true";
    if (state.generation != null) path += "&generation="+state.generation;
    umg.removeId = null;
    try {
      const j = await umgApi("DELETE", path);
      umgMsg(u.name+" removed — effective immediately"+
        (j.persisted?" (persisted)":" (memory only)")+
        (j.persist_error?" — persist error: "+j.persist_error:""),
        j.persist_error ? "err" : "ok");
      await fetchCurrent();
    } catch (e){ umgHandleError(e, "remove "+u.name); renderUpstreamMgr(); }
  }
}
async function umgViewConfig(){
  try {
    const c = await getJSON("/api/config");
    const toml = c.toml || "";
    const lines = toml.split("\n");
    const out = [];
    let inUp = false;
    for (const line of lines){
      if (/^\s*\[\[upstreams\]\]/.test(line)) inUp = true;
      else if (/^\s*\[/.test(line)) inUp = false;
      if (inUp) out.push(line);
      else if (/^\s*(udp_addr|tcp_addr|api_addr)\s*=/.test(line)) out.push(line);
    }
    $("umg-cfgtext").textContent = out.length
      ? maskTokenLine(out.join("\n"))
      : maskTokenLine(toml);
    $("umg-cfgmeta").textContent = "from GET /api/config · source "+(c.source||"—")+
      " · path "+(c.path||"(in-memory)")+" · token value masked";
    $("umg-cfgview").open = true;
  } catch (e){
    umgMsg("failed to load active configuration: "+e.message, "err");
  }
}

/* =========================================================================
 * ACL management (live add/toggle/remove, applied at runtime)
 * ====================================================================== */
const aclState = { entries: [], generation: null };
/* One global config generation behind both trackers (upstreams + ACL/cache):
 * every API response that carries a generation refreshes both, so a mutation
 * in one section is never rejected as stale against a snapshot from another. */
function syncGeneration(g){
  if (g == null) return;
  state.generation = g;
  aclState.generation = g;
}
function aclMsg(text, cls){ const m = $("acl-msg"); m.textContent = text || ""; m.className = cls || ""; }
/* Run an ACL mutation; when the gateway answers confirm_required (409)
 * present the guardrail text and retry once with confirm:true. Returns the
 * API result, or null when the operator cancelled. */
async function aclSend(what, send){
  try {
    return await send(false);
  } catch(e){
    if (e.code === "confirm_required"){
      if (window.confirm(what+" refused by guardrails:\n\n"+e.message+"\n\nApply anyway?")){
        return await send(true);
      }
      aclMsg(what+" cancelled — "+e.message, "warn");
      return null;
    }
    throw e;
  }
}
async function loadAcl(){
  try {
    const j = await getJSON("/api/acl");
    aclState.entries = j.entries || [];
    syncGeneration(j.generation);
    renderAcl(j);
  } catch(e){
    if (e.status !== 401) aclMsg("load failed: "+e.message, "err");
  }
}
function renderAcl(j){
  const rows = aclState.entries.map(e =>
    '<tr data-id="'+escapeHtml(e.id)+'">'+
      '<td class="mono" style="color:var(--faint)">'+escapeHtml(e.id)+'</td>'+
      '<td class="mono ip">'+escapeHtml(e.cidr)+'</td>'+
      '<td><span class="tag '+(e.action==="deny"?"bad":"ok")+'">'+escapeHtml(e.action)+'</span></td>'+
      '<td>'+(e.enabled?'<span class="tag ok">on</span>':'<span class="tag">off</span>')+'</td>'+
      '<td style="color:var(--faint)">'+(e.source?escapeHtml(e.source):"—")+'</td>'+
      '<td><div class="uact">'+
        '<button data-act="acl-toggle">'+(e.enabled?"Disable":"Enable")+'</button>'+
        '<button class="danger" data-act="acl-remove">Remove</button>'+
      '</div></td>'+
    '</tr>');
  $("acl-rows").innerHTML = rows.length
    ? rows.join("")
    : '<tr><td colspan="6" class="empty">no entries — fail-closed (every query refused)</td></tr>';
  const s = $("acl-summary");
  if (j){
    s.innerHTML =
      '<div class="sr"><span class="k">effective allow rules</span><span class="v'+(j.allowed_count?"":" na")+'">'+(j.allowed_count ?? "—")+'</span></div>'+
      '<div class="sr"><span class="k">effective deny rules</span><span class="v'+(j.denied_count?"":" na")+'">'+(j.denied_count ?? "—")+'</span></div>'+
      '<div class="sr"><span class="k">total entries (incl. disabled)</span><span class="v">'+aclState.entries.length+'</span></div>'+
      '<div class="sr"><span class="k">config generation</span><span class="v">'+(j.generation ?? "—")+'</span></div>'+
      '<div class="sr"><span class="k">posture</span><span class="v '+(j.allowed_count?"good":"bad")+'">'+(j.allowed_count?"restricted":"FAIL-CLOSED")+'</span></div>';
  }
}
async function aclAdd(){
  aclMsg("adding…","");
  try {
    const r = await aclSend("add entry", confirmFlag => umgApi("POST", "/api/acl/entries", {
      cidr: $("acl-cidr").value.trim(),
      action: $("acl-action").value,
      enabled: $("acl-enabled").checked,
      generation: aclState.generation,
      confirm: confirmFlag,
    }));
    if (r === null) return;
    aclMsg("entry added and applied", "ok");
    $("acl-cidr").value = "";
    await loadAcl();
  } catch(e){ aclMsg("rejected: "+e.message, "err"); }
}
async function aclRowAction(id, act){
  const e = aclState.entries.find(x => x.id === id);
  if (!e) return;
  try {
    if (act === "acl-toggle"){
      const r = await aclSend((e.enabled?"disable ":"enable ")+e.cidr, confirmFlag =>
        umgApi("PATCH", "/api/acl/entries/"+encodeURIComponent(id), {
          enabled: !e.enabled, generation: aclState.generation, confirm: confirmFlag,
        }));
      if (r === null) return;
      aclMsg((e.enabled?"disabled ":"enabled ")+e.cidr+" (applied)", "ok");
    } else if (act === "acl-remove"){
      const r = await aclSend("remove "+e.cidr, confirmFlag =>
        umgApi("DELETE", "/api/acl/entries/"+encodeURIComponent(id)+"?generation="+aclState.generation+
          (confirmFlag?"&confirm=true":"")));
      if (r === null) return;
      aclMsg("removed "+e.cidr+" (applied)", "ok");
    }
    await loadAcl();
  } catch(err){ aclMsg("rejected: "+err.message, "err"); }
}

/* =========================================================================
 * Cache management (live settings + clear of the runtime cache)
 * ====================================================================== */
function cacheMsg(text, cls){ const m = $("cache-msg"); m.textContent = text || ""; m.className = cls || ""; }
async function loadCache(){
  try {
    const j = await getJSON("/api/cache");
    renderCache(j);
  } catch(e){ if (e.status !== 401) cacheMsg("load failed: "+e.message, "err"); }
}
function renderCache(j){
  const cs = (state.stats && state.stats.cache) || null;
  const hit = cs ? cs.hit_ratio : null;
  const hits = cs ? cs.hits : null;
  const misses = cs ? cs.misses : null;
  $("cache-stats").innerHTML =
    '<div class="sr"><span class="k">enabled</span><span class="v '+(j.enabled?"good":"bad")+'">'+(j.enabled?"yes":"no")+'</span></div>'+
    '<div class="sr"><span class="k">entries / capacity</span><span class="v">'+j.entries+' / '+j.max_entries+'</span></div>'+
    '<div class="sr"><span class="k">approx. memory</span><span class="v'+(j.memory_bytes?"":" na")+'">'+fmtBytes(j.memory_bytes||0)+' / '+fmtBytes(j.max_memory_bytes||0)+'</span></div>'+
    '<div class="sr"><span class="k">hits / misses</span><span class="v'+(hits==null?" na":"")+'">'+(hits==null?"N/A":hits+" / "+misses)+'</span></div>'+
    '<div class="sr"><span class="k">hit ratio</span><span class="v'+(hit==null?" na":"")+'">'+(hit==null?"N/A":(hit*100).toFixed(1)+"%")+'</span></div>'+
    '<div class="sr"><span class="k">evictions</span><span class="v'+(cs&&cs.evictions!=null?"":" na")+'">'+(cs&&cs.evictions!=null?cs.evictions:"N/A")+'</span></div>'+
    '<div class="sr"><span class="k">min TTL (skip threshold)</span><span class="v">'+j.min_ttl_secs+'s</span></div>'+
    '<div class="sr"><span class="k">max TTL (cap)</span><span class="v">'+j.max_ttl_secs+'s</span></div>'+
    '<div class="sr"><span class="k">negative max TTL</span><span class="v">'+j.negative_max_ttl_secs+'s</span></div>'+
    '<div class="sr"><span class="k">generation</span><span class="v">'+(j.generation ?? "—")+'</span></div>';
  $("cache-enabled").checked = !!j.enabled;
  $("cache-min").value = j.min_ttl_secs;
  $("cache-max").value = j.max_ttl_secs;
  $("cache-negmax").value = j.negative_max_ttl_secs;
  $("cache-maxent").value = j.max_entries;
  $("cache-maxmem").value = j.max_memory_bytes;
  syncGeneration(j.generation);
}
async function cacheSave(){
  cacheMsg("applying…","");
  try {
    const j = await umgApi("PUT", "/api/cache", {
      enabled: $("cache-enabled").checked,
      min_ttl_secs: parseInt($("cache-min").value, 10),
      max_ttl_secs: parseInt($("cache-max").value, 10),
      negative_max_ttl_secs: parseInt($("cache-negmax").value, 10),
      max_entries: parseInt($("cache-maxent").value, 10),
      max_memory_bytes: parseInt($("cache-maxmem").value, 10),
      generation: aclState.generation,
    });
    renderCache(j);
    cacheMsg("settings applied"+(j.persisted?" + persisted":"")+
      (j.persist_error?" — persist error: "+j.persist_error:""),
      j.persist_error ? "err" : "ok");
  } catch(e){ cacheMsg("rejected: "+e.message, "err"); }
}
async function cacheClear(){
  if (!confirm("Clear the runtime DNS cache? Active entries will be dropped; the next queries miss upstream.")) return;
  cacheMsg("clearing…","");
  try {
    const j = await umgApi("POST", "/api/cache/clear", {});
    cacheMsg("cleared "+j.entries_dropped+" entries ("+fmtBytes(j.memory_bytes_freed||0)+" freed)", "ok");
    await loadCache();
  } catch(e){ cacheMsg("rejected: "+e.message, "err"); }
}

/* =========================================================================
 * Health-check + selection policy (GET/PUT /api/health/config, /api/selection)
 * ====================================================================== */
function hltMsg(text, cls){ const m = $("hlt-msg"); m.textContent = text || ""; m.className = cls || ""; }
function selMsg(text, cls){ const m = $("sel-msg"); m.textContent = text || ""; m.className = cls || ""; }
/* `duration_ms` serialises as "5m" / "2s" / "1500ms" (one exact unit, or a
 * bare integer in ms); the PUT API takes plain millisecond numbers. */
function parseDurMs(s){
  if (typeof s === "number" && isFinite(s)) return s;
  const str = String(s == null ? "" : s).trim();
  if (!str) return null;
  if (/^\d+$/.test(str)) return parseInt(str, 10);
  const parts = str.match(/\d+(ms|s|m)/g);
  if (!parts || parts.join("") !== str) return null;
  let total = 0;
  for (const p of parts){
    const n = parseInt(p, 10);
    total += p.endsWith("ms") ? n : p.endsWith("m") ? n * 60000 : n * 1000;
  }
  return total;
}
function probesToLines(probes){
  return (probes || []).map(p => (p.type || "?") + " " + (p.name || "")).join("\n");
}
function parseProbeLines(text){
  const out = [];
  for (const raw of String(text || "").split("\n")){
    const line = raw.trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length !== 2) return null;
    out.push({type: parts[0], name: parts[1]});
  }
  return out;
}
async function loadHealthSelection(){
  try {
    const h = await getJSON("/api/health/config");
    const hc = h.health || {};
    $("hlt-enabled").checked = !!hc.enabled;
    $("hlt-interval").value = parseDurMs(hc.interval) ?? "";
    $("hlt-timeout").value = parseDurMs(hc.timeout) ?? "";
    $("hlt-fail").value = hc.failure_threshold;
    $("hlt-rec").value = hc.recovery_threshold;
    $("hlt-minsucc").value = hc.min_successes;
    $("hlt-tcp").checked = !!hc.tcp_probes;
    $("hlt-dwell").value = parseDurMs(hc.dwell) ?? 0;
    $("hlt-probes").value = probesToLines(hc.probes);
    syncGeneration(h.generation);
  } catch(e){ if (e.status !== 401) hltMsg("load failed: "+e.message, "err"); }
  try {
    const s = await getJSON("/api/selection");
    const sc = s.selection || {};
    if (sc.strategy) $("sel-strategy").value = sc.strategy;
    $("sel-latref").value = sc.latency_reference_ms;
    if (sc.tier_policy) $("sel-tier").value = sc.tier_policy;
    $("sel-lshare").value = sc.lower_tier_share;
    if (sc.degraded_policy) $("sel-degraded").value = sc.degraded_policy;
    $("sel-minsamples").value = sc.min_probe_samples;
    syncGeneration(s.generation);
  } catch(e){ if (e.status !== 401) selMsg("load failed: "+e.message, "err"); }
}
async function saveHealth(){
  hltMsg("applying…","");
  const probes = parseProbeLines($("hlt-probes").value);
  if (probes === null){
    hltMsg("probes: each line must be 'TYPE name' (e.g. 'A example.com')", "err"); return;
  }
  const body = {
    enabled: $("hlt-enabled").checked,
    interval_ms: parseInt($("hlt-interval").value, 10),
    timeout_ms: parseInt($("hlt-timeout").value, 10),
    failure_threshold: parseInt($("hlt-fail").value, 10),
    recovery_threshold: parseInt($("hlt-rec").value, 10),
    min_successes: parseInt($("hlt-minsucc").value, 10),
    tcp_probes: $("hlt-tcp").checked,
    dwell_ms: parseInt($("hlt-dwell").value, 10) || 0,
    probes,
    generation: aclState.generation,
  };
  if (Object.values(body).some(v => typeof v === "number" && !isFinite(v))){
    hltMsg("one of the numeric fields is missing or invalid", "err"); return;
  }
  try {
    const j = await umgApi("PUT", "/api/health/config", body);
    syncGeneration(j.generation);
    await loadHealthSelection();
    hltMsg("health settings applied"+(j.persisted?" + persisted":"")+
      (j.persist_error?" — persist error: "+j.persist_error:""),
      j.persist_error ? "err" : "ok");
  } catch(e){
    if (e.status === 409){ hltMsg("Configuration changed elsewhere; reloaded — review and re-apply. ("+e.message+")", "warn"); loadHealthSelection(); }
    else hltMsg("rejected: "+e.message, "err");
  }
}
async function saveSelection(){
  selMsg("applying…","");
  const body = {
    strategy: $("sel-strategy").value,
    latency_reference_ms: parseFloat($("sel-latref").value),
    tier_policy: $("sel-tier").value,
    lower_tier_share: parseFloat($("sel-lshare").value),
    degraded_policy: $("sel-degraded").value,
    min_probe_samples: parseInt($("sel-minsamples").value, 10),
    generation: aclState.generation,
  };
  if (Object.values(body).some(v => typeof v === "number" && !isFinite(v))){
    selMsg("one of the numeric fields is missing or invalid", "err"); return;
  }
  try {
    const j = await umgApi("PUT", "/api/selection", body);
    syncGeneration(j.generation);
    await loadHealthSelection();
    selMsg("selection policy applied"+(j.persisted?" + persisted":"")+
      (j.persist_error?" — persist error: "+j.persist_error:""),
      j.persist_error ? "err" : "ok");
    await fetchCurrent();
  } catch(e){
    if (e.status === 409){ selMsg("Configuration changed elsewhere; reloaded — review and re-apply. ("+e.message+")", "warn"); loadHealthSelection(); }
    else selMsg("rejected: "+e.message, "err");
  }
}

/* =========================================================================
 * Wiring
 * ====================================================================== */
function wire(){
  $("range-sel").addEventListener("change", e => {
    state.range = e.target.value;
    if (!RANGES.includes(state.range)) state.range = "5m";
    scheduleHistory();
  });
  $("source-sel").addEventListener("change", e => {
    const v = e.target.value;
    state.source = ["auto","native","prometheus"].includes(v) ? v : "auto";
    fetchHistory();
  });
  $("auto-chk").addEventListener("change", e => {
    state.auto = e.target.checked;
    $("updated").textContent = state.auto ? "resumed" : "paused";
  });
  $("tfilters").addEventListener("click", e => {
    const b = e.target.closest("button");
    if (!b) return;
    state.filter = b.getAttribute("data-f");
    for (const x of $("tfilters").children) x.classList.toggle("on", x===b);
    renderEvents();
  });
  // Sort the per-client table by any numeric column (server-side ordering
  // over the real counters, never over the masked labels).
  $("cl-table").addEventListener("click", e => {
    const th = e.target.closest("th.sortable");
    if (!th) return;
    state.clientSort = th.getAttribute("data-sort") || "requests";
    fetchCurrent();
  });
  $("cfg-apply").addEventListener("click", applyConfig);
  $("cfg-reload").addEventListener("click", loadConfig);
  // Upstream management
  $("umg-token").value = umgToken();
  $("umg-token-save").addEventListener("click", () => {
    umgSetToken($("umg-token").value.trim());
    umgMsg(umgToken() ? "admin token saved in this browser" : "admin token cleared", "ok");
  });
  $("umg-submit").addEventListener("click", umgSubmit);
  $("umg-cancel").addEventListener("click", umgCloseForm);
  $("umg-viewcfg").addEventListener("click", umgViewConfig);
  $("umg-rows").addEventListener("click", e => {
    const b = e.target.closest("button[data-act]");
    if (!b) return;
    const tr = b.closest("tr[data-id]");
    if (!tr) return;
    umgRowAction(parseInt(tr.getAttribute("data-id"), 10), b.getAttribute("data-act"));
  });
  // ACL
  $("acl-add").addEventListener("click", aclAdd);
  $("acl-reload").addEventListener("click", loadAcl);
  $("acl-cidr").addEventListener("keydown", e => { if (e.key === "Enter") aclAdd(); });
  $("acl-rows").addEventListener("click", e => {
    const b = e.target.closest("button[data-act]");
    if (!b) return;
    const tr = b.closest("tr[data-id]");
    if (!tr) return;
    aclRowAction(tr.getAttribute("data-id"), b.getAttribute("data-act"));
  });
  // Cache
  $("cache-clear").addEventListener("click", cacheClear);
  $("cache-reload").addEventListener("click", loadCache);
  $("cache-save").addEventListener("click", cacheSave);
  // Health checks & selection
  $("hlt-save").addEventListener("click", saveHealth);
  $("hlt-reload").addEventListener("click", loadHealthSelection);
  $("sel-save").addEventListener("click", saveSelection);
  $("sel-reload").addEventListener("click", loadHealthSelection);
  // Login / session
  $("login-form").addEventListener("submit", e => { e.preventDefault(); doLogin(); });
  $("umg-protocol").addEventListener("change", umgSyncTlsFields);
  $("umg-port").addEventListener("input", () => { delete $("umg-port").dataset.autoTls; });
  $("login-token-go").addEventListener("click", doTokenLogin);
  $("login-token").addEventListener("keydown", e => {
    if (e.key === "Enter"){ e.preventDefault(); doTokenLogin(); }
  });
  $("login-user").addEventListener("keydown", e => {
    if (e.key === "Enter"){ e.preventDefault(); $("login-pass").focus(); }
  });
  $("login-reveal").addEventListener("click", () => {
    const input = $("login-pass");
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    $("login-reveal").textContent = show ? "Hide" : "Show";
    $("login-reveal").setAttribute("aria-pressed", show ? "true" : "false");
    $("login-reveal").setAttribute("aria-label", show ? "Hide password" : "Show password");
    input.focus();
  });
  $("login-retry").addEventListener("click", retryConnection);
  $("login-ov").addEventListener("keydown", e => {
    if (e.key !== "Tab") return;
    const fields = Array.from($("login-ov").querySelectorAll(
      'input:not([disabled]),button:not([disabled]):not([hidden]),a[href]'))
      .filter(el => el.getClientRects().length > 0);
    if (!fields.length) return;
    const first = fields[0], last = fields[fields.length - 1];
    if (e.shiftKey && document.activeElement === first){ e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last){ e.preventDefault(); first.focus(); }
  });
  $("logout-btn").addEventListener("click", doLogout);
  $("auth-chip").addEventListener("click", () => {
    if (AUTH.open) return;
    if (AUTH.role) doLogout();
    else showLogin();
  });
  $("refresh-btn").addEventListener("click", () => { if (!AUTH.needed) refreshAll(); });
  window.addEventListener("resize", () => drawAllCharts());
}

async function main(){
  buildSections();
  buildNav();
  wireNavigation();
  wire();
  const authed = await checkSession();
  if (authed){
    await startPortal();
  }
  // Canvas axis labels use Shabnam: re-paint once the webfont has loaded.
  if (document.fonts && document.fonts.ready){
    document.fonts.ready.then(() => { if (state.hist) drawAllCharts(); }).catch(() => {});
  }
}
main();
