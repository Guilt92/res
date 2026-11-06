//! Control-plane authentication: username/password login, argon2id password
//! hashing, in-memory sessions with expiry, CSRF double-submit tokens,
//! viewer/admin RBAC, and login brute-force lockout.
//!
//! Credentials come from the environment (`RES_ADMIN_PASSWORD`,
//! `RES_VIEWER_PASSWORD`) or from a mode-0600 credentials file written next
//! to the configuration on first setup. Passwords are never stored in the
//! TOML configuration and never logged. With no password the control plane can
//! still authenticate via `server.api_token`; with neither, startup fails
//! unless the operator explicitly enables `[auth].allow_open_mode`.
//!
//! The DNS data plane never touches this module: authentication protects the
//! HTTP management plane only.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::config::AuthConfig;

/// Minimum accepted password length for environment/file provisioning.
pub const MIN_PASSWORD_LEN: usize = 8;
/// Hard cap on concurrent sessions (the oldest session is evicted).
const MAX_SESSIONS: usize = 1024;
/// Cap on concurrent sessions per account (that account's oldest is evicted),
/// so one account cannot push every other user's session out of the table.
const MAX_SESSIONS_PER_USER: usize = 16;
/// Hard cap on tracked failed-login (username, IP) pairs.
const MAX_LOCKOUTS: usize = 4096;
/// Hard cap on tracked per-IP login rate-limit entries (oldest window evicted).
const MAX_LOGIN_IPS: usize = 8192;

/// Fold IPv4-mapped IPv6 onto plain IPv4 so one client cannot hold two
/// lockout windows under dual-stack sockets.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}
/// Filename of the hashed-credential store next to the configuration file.
const CREDENTIALS_FILE: &str = "res.credentials";

/// RBAC role of an authenticated session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Full control: configuration mutations, upstream management, cache
    /// clears, ACL edits.
    Admin,
    /// Read-only: status, stats, events, history, upstream list.
    Viewer,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Viewer => "viewer",
        }
    }
}

/// One authenticated browser/API session.
#[derive(Debug, Clone)]
pub struct Session {
    pub username: String,
    pub role: Role,
    /// Per-session CSRF token (double-submit: echoed in `X-CSRF-Token` on
    /// every cookie-authenticated mutation).
    pub csrf: String,
    pub created: Instant,
    /// Last time the session was presented (drives the idle timeout).
    pub last_seen: Instant,
    pub expires: Instant,
}

/// A stored password (argon2id PHC string) for one account.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Credential {
    username: String,
    /// PHC-encoded argon2id hash; never a plaintext password.
    hash: String,
}

/// On-disk credentials document (mode 0600, next to the TOML config).
#[derive(Debug, Serialize, Deserialize)]
struct CredentialsFile {
    version: u32,
    admin: Credential,
    viewer: Option<Credential>,
}

/// Lockout key: (lower-cased username, canonical client IP).
type LockKey = (String, IpAddr);

/// Failed-login tracking for one (username, client IP) pair.
#[derive(Debug, Default)]
struct Lockout {
    failures: u32,
    window_start: Option<Instant>,
    locked_until: Option<Instant>,
}

/// Per-IP login attempt counter within a fixed one-minute window.
#[derive(Debug, Default)]
struct LoginIp {
    attempts: u32,
    window_start: Option<Instant>,
}

/// Mutable credential pair (admin + optional viewer), behind a mutex so
/// passwords can be rotated at runtime.
#[derive(Debug, Default)]
struct Credentials {
    admin: Option<Credential>,
    viewer: Option<Credential>,
}

#[derive(Debug)]
struct SessionTable {
    map: HashMap<String, Session>,
}

/// Outcome of a login attempt.
#[derive(Debug)]
pub enum LoginError {
    /// Unknown user or wrong password (same message: no user enumeration).
    InvalidCredentials,
    /// Too many recent failures for this account.
    Locked { retry_after_secs: u64 },
}

/// Authentication state of the control plane (process-local, in-memory
/// sessions; no database, no persistence of session tokens).
pub struct AuthState {
    cfg: AuthConfig,
    credentials: Mutex<Credentials>,
    sessions: Mutex<SessionTable>,
    lockouts: Mutex<HashMap<LockKey, Lockout>>,
    login_ips: Mutex<HashMap<IpAddr, LoginIp>>,
}

impl AuthState {
    /// Build from explicit passwords (used by tests and by the env loader).
    /// Returns a disabled state when both passwords are empty.
    pub fn from_passwords(
        cfg: AuthConfig,
        admin_password: Option<String>,
        viewer_password: Option<String>,
    ) -> Self {
        let admin = admin_password
            .filter(|p| !p.is_empty())
            .map(|p| Credential {
                username: cfg.username.clone(),
                hash: hash_password(&p),
            });
        let viewer = viewer_password
            .filter(|p| !p.is_empty())
            .map(|p| Credential {
                username: cfg.viewer_username.clone(),
                hash: hash_password(&p),
            });
        Self {
            cfg,
            credentials: Mutex::new(Credentials { admin, viewer }),
            sessions: Mutex::new(SessionTable {
                map: HashMap::new(),
            }),
            lockouts: Mutex::new(HashMap::new()),
            login_ips: Mutex::new(HashMap::new()),
        }
    }

    /// Production loader: environment passwords win (and are persisted to the
    /// credentials file); otherwise the credentials file is used. When
    /// neither is available the control plane is unauthenticated (a warning
    /// is emitted by the caller via [`AuthState::enabled`]).
    ///
    /// Fails closed: when a credentials file *exists* but cannot be read or
    /// parsed, startup is refused instead of silently downgrading to an
    /// unauthenticated control plane (only a genuinely absent file falls
    /// through to the no-password posture).
    pub fn load(cfg: AuthConfig, config_path: Option<&Path>) -> Result<Self, String> {
        let env_admin = nonempty_env("RES_ADMIN_PASSWORD");
        let env_viewer = nonempty_env("RES_VIEWER_PASSWORD");
        for (name, value) in [
            ("RES_ADMIN_PASSWORD", env_admin.as_deref()),
            ("RES_VIEWER_PASSWORD", env_viewer.as_deref()),
        ] {
            if let Some(password) = value {
                if password.len() < MIN_PASSWORD_LEN {
                    return Err(format!(
                        "{name} must be at least {MIN_PASSWORD_LEN} characters"
                    ));
                }
            }
        }
        if env_admin.is_some() || env_viewer.is_some() {
            let state = Self::from_passwords(cfg.clone(), env_admin.clone(), env_viewer.clone());
            // Persist hashes so a restart without the env vars still works.
            // Best effort: an unwritable directory must not block startup.
            if let Some(path) = config_path {
                if let Err(e) = state.save_credentials_file(path) {
                    tracing::warn!(event = "credentials_persist_failed", error = %e);
                }
            }
            return Ok(state);
        }
        if let Some(path) = config_path {
            let cred_path = Self::credentials_path(path);
            match std::fs::metadata(&cred_path) {
                Ok(_) => {
                    return Self::load_credentials_file(cfg, path).map_err(|e| {
                        format!(
                            "credentials file {} exists but is unusable ({e}); \
                             refusing to start with a possibly-unauthenticated control plane. \
                             Fix or remove the file, or set RES_ADMIN_PASSWORD.",
                            cred_path.display()
                        )
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // First run: no credentials yet; caller warns.
                }
                Err(e) => {
                    return Err(format!(
                        "cannot inspect credentials file {}: {e}",
                        cred_path.display()
                    ));
                }
            }
        }
        Ok(Self::from_passwords(cfg, None, None))
    }

    /// Path of the hashed-credentials file for a configuration path.
    pub fn credentials_path(config_path: &Path) -> PathBuf {
        config_path.with_file_name(CREDENTIALS_FILE)
    }

    fn save_credentials_file(&self, config_path: &Path) -> Result<(), String> {
        let creds = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        let doc = CredentialsFile {
            version: 1,
            admin: creds.admin.clone().ok_or("no admin password to persist")?,
            viewer: creds.viewer.clone(),
        };
        let path = Self::credentials_path(config_path);
        let json = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
        write_private(&path, &json)
    }

    fn load_credentials_file(cfg: AuthConfig, config_path: &Path) -> Result<Self, String> {
        let path = Self::credentials_path(config_path);
        let data = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let doc: CredentialsFile =
            serde_json::from_slice(&data).map_err(|e| format!("parse {}: {e}", path.display()))?;
        let mut admin = doc.admin;
        let mut viewer = doc.viewer;
        // The file wins for hashes; configured usernames win for display.
        admin.username = cfg.username.clone();
        if let Some(v) = viewer.as_mut() {
            v.username = cfg.viewer_username.clone();
        }
        Ok(Self {
            cfg,
            credentials: Mutex::new(Credentials {
                admin: Some(admin),
                viewer,
            }),
            sessions: Mutex::new(SessionTable {
                map: HashMap::new(),
            }),
            lockouts: Mutex::new(HashMap::new()),
            login_ips: Mutex::new(HashMap::new()),
        })
    }

    /// True when at least one password credential is configured.
    pub fn enabled(&self) -> bool {
        let creds = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        creds.admin.is_some() || creds.viewer.is_some()
    }

    pub fn admin_username(&self) -> Option<String> {
        self.credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .admin
            .as_ref()
            .map(|c| c.username.clone())
    }

    pub fn viewer_enabled(&self) -> bool {
        self.credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .viewer
            .is_some()
    }

    pub fn session_ttl(&self) -> Duration {
        Duration::from_millis(self.cfg.session_ttl_ms)
    }

    pub fn max_failed_attempts(&self) -> u32 {
        self.cfg.max_failed_attempts
    }

    pub fn secure_cookies(&self) -> bool {
        self.cfg.secure_cookies
    }

    /// True only when the operator explicitly opted into the unauthenticated
    /// development posture. The data plane never relies on this flag.
    pub fn open_mode_allowed(&self) -> bool {
        self.cfg.allow_open_mode
    }

    /// Force the `Secure` cookie flag on (used when the management listener
    /// itself terminates TLS). Never turns it back off.
    pub fn enable_secure_cookies(&mut self) {
        self.cfg.secure_cookies = true;
    }

    /// Atomically check **and** count one login attempt from `ip` against the
    /// per-IP limit (`login_rate_limit_per_minute` per fixed one-minute
    /// window). Returns `Ok(())` when the attempt may proceed, or
    /// `Err(retry_after_secs)` when the client is over the limit. Check and
    /// increment happen under one lock, so concurrent requests cannot all
    /// slip under the limit.
    pub fn begin_login_attempt(&self, ip: IpAddr) -> Result<(), u64> {
        let max = self.cfg.login_rate_limit_per_minute;
        // With rate limiting disabled the table serves no purpose; tracking
        // every source address would be an unbounded unauthenticated memory
        // sink, so skip it entirely.
        if max == 0 {
            return Ok(());
        }
        let ip = canonical_ip(ip);
        let now = Instant::now();
        let mut map = self.login_ips.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_LOGIN_IPS && !map.contains_key(&ip) {
            // Expired windows carry no information: drop them first, and
            // only then evict the entry with the oldest window.
            map.retain(|_, v| {
                v.window_start
                    .is_some_and(|s| now.saturating_duration_since(s).as_secs() < 60)
            });
            if map.len() >= MAX_LOGIN_IPS {
                if let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, v)| v.window_start.unwrap_or(now))
                    .map(|(k, _)| *k)
                {
                    map.remove(&oldest);
                }
            }
        }
        let e = map.entry(ip).or_default();
        if let Some(start) = e.window_start {
            if now.saturating_duration_since(start).as_secs() >= 60 {
                e.attempts = 0;
                e.window_start = None;
            }
        }
        if e.attempts >= max {
            let elapsed = e
                .window_start
                .map(|s| now.saturating_duration_since(s).as_secs())
                .unwrap_or(0);
            return Err((60u64.saturating_sub(elapsed)).max(1));
        }
        if e.window_start.is_none() {
            e.window_start = Some(now);
        }
        e.attempts = e.attempts.saturating_add(1);
        Ok(())
    }

    /// Drop the per-IP rate-limit counter for a client (called after a
    /// successful login so a legitimate user who mistyped once starts clean).
    /// The address is canonicalised exactly like [`Self::begin_login_attempt`].
    pub fn clear_login_rate(&self, ip: IpAddr) {
        self.login_ips
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&canonical_ip(ip));
    }

    /// Verify credentials and create a session on success.
    ///
    /// Lockout is keyed by *(canonical username, canonical client IP)*: after
    /// `max_failed_attempts` failures inside `lockout_window` that pair is
    /// rejected for `lockout_duration`. A different source address is never
    /// affected, so an anonymous attacker cannot lock the administrator out
    /// of their own account; brute force from one address is bounded by the
    /// pair lockout plus the per-IP rate limit.
    ///
    /// The lockout check and the failure *reservation* happen in one critical
    /// section before the (slow) password verification, so N concurrent
    /// requests cannot all be evaluated against a stale counter: at most
    /// `max_failed_attempts` guesses per window ever reach argon2. A
    /// successful login removes the reservation.
    ///
    /// The same error is returned for unknown users and wrong passwords.
    pub fn login(
        &self,
        username: &str,
        password: &str,
        ip: IpAddr,
    ) -> Result<(String, Session), LoginError> {
        let key: LockKey = (username.to_lowercase(), canonical_ip(ip));
        self.reserve_attempt(&key)?;

        let role = self.verify(username, password);
        match role {
            None => Err(LoginError::InvalidCredentials),
            Some(role) => {
                self.clear_failures(&key);
                let token = random_token();
                let csrf = random_token();
                let now = Instant::now();
                let username = match role {
                    Role::Admin => self
                        .credentials
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .admin
                        .as_ref()
                        .map(|c| c.username.clone())
                        .unwrap_or_else(|| self.cfg.username.clone()),
                    Role::Viewer => self
                        .credentials
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .viewer
                        .as_ref()
                        .map(|c| c.username.clone())
                        .unwrap_or_else(|| self.cfg.viewer_username.clone()),
                };
                let session = Session {
                    username,
                    role,
                    csrf,
                    created: now,
                    last_seen: now,
                    expires: now + self.session_ttl(),
                };
                let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
                sessions.insert(token.clone(), session.clone(), self.idle_timeout());
                Ok((token, session))
            }
        }
    }

    fn verify(&self, username: &str, password: &str) -> Option<Role> {
        let creds = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        // Exactly two argon2 verifications on *every* path (real or dummy),
        // including the success paths: response timing must not reveal which
        // account names exist, nor whether this attempt succeeded.
        let admin_ok = creds
            .admin
            .as_ref()
            .filter(|c| c.username.eq_ignore_ascii_case(username))
            .map(|c| verify_password(password, &c.hash))
            .unwrap_or_else(|| {
                let _ = verify_password(password, dummy_hash());
                false
            });
        let viewer_ok = creds
            .viewer
            .as_ref()
            .filter(|c| c.username.eq_ignore_ascii_case(username))
            .map(|c| verify_password(password, &c.hash))
            .unwrap_or_else(|| {
                let _ = verify_password(password, dummy_hash());
                false
            });
        if admin_ok {
            return Some(Role::Admin);
        }
        if viewer_ok {
            return Some(Role::Viewer);
        }
        None
    }

    /// Rotate the admin password. Returns `false` when no admin credential
    /// exists (cannot rotate a missing account).
    pub fn rotate_admin_password(&self, new_password: &str) -> bool {
        let hash = hash_password(new_password);
        let mut creds = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        match creds.admin.as_mut() {
            Some(admin) => {
                admin.hash = hash;
                true
            }
            None => false,
        }
    }

    /// Rotate the viewer password. Returns `false` when no viewer credential
    /// is configured.
    pub fn rotate_viewer_password(&self, new_password: &str) -> bool {
        let hash = hash_password(new_password);
        let mut creds = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        match creds.viewer.as_mut() {
            Some(viewer) => {
                viewer.hash = hash;
                true
            }
            None => false,
        }
    }

    /// Persist current credentials to the file next to `config_path`.
    /// Public wrapper used by the rotation endpoint.
    pub fn persist_credentials(&self, config_path: &Path) -> Result<(), String> {
        self.save_credentials_file(config_path)
    }

    /// Set the admin password, persisting the new credential to disk BEFORE
    /// updating in-memory state. If the disk write fails, in-memory state is
    /// unchanged and all sessions remain valid (a restart will reload the old
    /// credential from disk). This is the correct rotation order; the plain
    /// `rotate_admin_password` applies in-memory first and is only safe when
    /// persistence is guaranteed (e.g. in tests).
    pub fn set_admin_password(&self, config_path: &Path, new_password: &str) -> Result<(), String> {
        let hash = hash_password(new_password);
        let mut creds = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        let username = {
            let admin = creds
                .admin
                .as_mut()
                .ok_or("no admin password configured to rotate")?;
            admin.username.clone()
        };
        let doc = CredentialsFile {
            version: 1,
            admin: Credential {
                username,
                hash: hash.clone(),
            },
            viewer: creds.viewer.clone(),
        };
        let path = Self::credentials_path(config_path);
        let json = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
        write_private(&path, &json)?;
        creds.admin.as_mut().unwrap().hash = hash;
        Ok(())
    }

    /// Check the lockout for `key` and, if it is not locked, atomically count
    /// this attempt as a failure (a successful login removes it again via
    /// [`Self::clear_failures`]).
    fn reserve_attempt(&self, key: &LockKey) -> Result<(), LoginError> {
        let now = Instant::now();
        let mut lockouts = self.lockouts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(l) = lockouts.get(key) {
            if let Some(until) = l.locked_until {
                if until > now {
                    return Err(LoginError::Locked {
                        retry_after_secs: until.saturating_duration_since(now).as_secs().max(1),
                    });
                }
            }
        }
        Self::count_failure(&mut lockouts, key, &self.cfg, now);
        Ok(())
    }

    /// Count one failure for `key` in `lockouts`, keeping the table bounded.
    ///
    /// Eviction order when full: expired entries first, then unlocked entries
    /// (oldest window), and only as a last resort the lock that expires
    /// soonest. An attacker flooding fresh keys therefore cannot push a
    /// currently-locked key out of the table while cheaper victims exist.
    fn count_failure(
        lockouts: &mut HashMap<LockKey, Lockout>,
        key: &LockKey,
        cfg: &AuthConfig,
        now: Instant,
    ) {
        if lockouts.len() >= MAX_LOCKOUTS && !lockouts.contains_key(key) {
            let window = cfg.lockout_window_ms_duration();
            lockouts.retain(|_, v| {
                v.locked_until.is_some_and(|u| u > now)
                    || v.window_start
                        .is_some_and(|s| now.saturating_duration_since(s) <= window)
            });
            if lockouts.len() >= MAX_LOCKOUTS {
                let victim = lockouts
                    .iter()
                    .filter(|(_, v)| v.locked_until.is_none_or(|u| u <= now))
                    .min_by_key(|(_, v)| v.window_start.unwrap_or(now))
                    .map(|(k, _)| k.clone())
                    .or_else(|| {
                        lockouts
                            .iter()
                            .min_by_key(|(_, v)| v.locked_until.unwrap_or(now))
                            .map(|(k, _)| k.clone())
                    });
                if let Some(victim) = victim {
                    lockouts.remove(&victim);
                }
            }
        }
        let l = lockouts.entry(key.clone()).or_default();
        // Start a fresh window when the previous one has expired.
        if let Some(start) = l.window_start {
            if now.saturating_duration_since(start) > cfg.lockout_window_ms_duration()
                && l.locked_until.is_none_or(|u| u <= now)
            {
                l.failures = 0;
                l.window_start = None;
                l.locked_until = None;
            }
        }
        if l.window_start.is_none() {
            l.window_start = Some(now);
        }
        l.failures = l.failures.saturating_add(1);
        if l.failures >= cfg.max_failed_attempts {
            l.locked_until = Some(now + cfg.lockout_duration_ms_duration());
            tracing::warn!(event = "auth_locked", user = %key.0, client = %key.1);
        }
    }

    fn clear_failures(&self, key: &LockKey) {
        self.lockouts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }

    fn idle_timeout(&self) -> Option<Duration> {
        (self.cfg.session_idle_timeout_ms > 0)
            .then(|| Duration::from_millis(self.cfg.session_idle_timeout_ms))
    }

    /// Look up a live session by token. A session is rejected (and dropped)
    /// once its absolute lifetime has elapsed or, when an idle timeout is
    /// configured, once it has gone unused for that long. A successful lookup
    /// counts as activity and refreshes the idle clock.
    pub fn session(&self, token: &str) -> Option<Session> {
        let now = Instant::now();
        let idle = self.idle_timeout();
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let dead = sessions
            .map
            .get(token)
            .map(|s| s.is_dead(now, idle))
            .unwrap_or(false);
        if dead {
            sessions.map.remove(token);
            return None;
        }
        let s = sessions.map.get_mut(token)?;
        s.last_seen = now;
        Some(s.clone())
    }

    /// Invalidate a session (logout). Idempotent.
    pub fn logout(&self, token: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .remove(token);
    }

    /// Drop every session (password rotation, administrative revocation).
    pub fn logout_all(&self) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .clear();
    }

    /// Revoke every session except `keep` (the caller's own). Returns the
    /// number of sessions revoked.
    pub fn revoke_all_except(&self, keep: &str) -> usize {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let before = sessions.map.len();
        sessions.map.retain(|t, _| t == keep);
        before - sessions.map.len()
    }

    /// Revoke every session belonging to `username` (case-insensitive).
    /// Returns the number of sessions revoked.
    pub fn revoke_user(&self, username: &str) -> usize {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let before = sessions.map.len();
        sessions
            .map
            .retain(|_, s| !s.username.eq_ignore_ascii_case(username));
        before - sessions.map.len()
    }

    /// Number of live (not expired, not idle) sessions.
    pub fn session_count(&self) -> usize {
        let now = Instant::now();
        let idle = self.idle_timeout();
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .values()
            .filter(|s| !s.is_dead(now, idle))
            .count()
    }

    pub fn config(&self) -> &AuthConfig {
        &self.cfg
    }

    /// Test-only: pretend `age` has elapsed for every lockout entry.
    #[cfg(test)]
    pub(crate) fn age_lockouts_for_test(&self, age: Duration) {
        let back = |t: Instant| t.checked_sub(age).unwrap_or(t);
        for l in self
            .lockouts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values_mut()
        {
            l.window_start = l.window_start.map(back);
            l.locked_until = l.locked_until.map(back);
        }
    }

    /// Test-only: pretend `token`'s session was last used `age` ago.
    #[cfg(test)]
    pub(crate) fn age_session_for_test(&self, token: &str, age: Duration) {
        if let Some(s) = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .get_mut(token)
        {
            s.last_seen = s.last_seen.checked_sub(age).unwrap_or(s.last_seen);
        }
    }

    /// Test-only: count a failed login for (`user`, `ip`) without running
    /// argon2 (keeps the lockout-table bound tests fast).
    #[cfg(test)]
    pub(crate) fn record_failure_for_test(&self, user: &str, ip: IpAddr) {
        let key: LockKey = (user.to_lowercase(), canonical_ip(ip));
        let mut l = self.lockouts.lock().unwrap_or_else(|e| e.into_inner());
        Self::count_failure(&mut l, &key, &self.cfg, Instant::now());
    }
}

impl Session {
    fn is_dead(&self, now: Instant, idle: Option<Duration>) -> bool {
        self.expires <= now
            || idle.is_some_and(|i| now.saturating_duration_since(self.last_seen) >= i)
    }
}

impl SessionTable {
    /// Insert a session, keeping the table bounded without letting one
    /// account crowd out the others:
    ///
    /// 1. dead (expired/idle) sessions are pruned;
    /// 2. an account at `MAX_SESSIONS_PER_USER` loses its own oldest session;
    /// 3. at the global `MAX_SESSIONS` cap the oldest session overall goes.
    fn insert(&mut self, token: String, session: Session, idle: Option<Duration>) {
        let now = Instant::now();
        self.map.retain(|_, s| !s.is_dead(now, idle));
        let same_user: Vec<(&String, Instant)> = self
            .map
            .iter()
            .filter(|(_, s)| s.username.eq_ignore_ascii_case(&session.username))
            .map(|(t, s)| (t, s.created))
            .collect();
        if same_user.len() >= MAX_SESSIONS_PER_USER {
            if let Some(victim) = same_user
                .iter()
                .min_by_key(|(_, c)| *c)
                .map(|(t, _)| (*t).clone())
            {
                self.map.remove(&victim);
            }
        }
        if self.map.len() >= MAX_SESSIONS {
            if let Some(oldest) = self
                .map
                .iter()
                .min_by_key(|(_, s)| s.created)
                .map(|(t, _)| t.clone())
            {
                self.map.remove(&oldest);
            }
        }
        self.map.insert(token, session);
    }
}

fn hash_password(password: &str) -> String {
    Argon2::default()
        .hash_password(password.as_bytes())
        .expect("argon2 hash")
        .to_string()
}

fn verify_password(password: &str, phc: &str) -> bool {
    Argon2::default()
        .verify_password(password.as_bytes(), phc)
        .is_ok()
}

/// Valid argon2id PHC hash of an unguessable string; used to burn CPU on
/// unknown usernames so login timing does not reveal which users exist.
fn dummy_hash() -> &'static str {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password(&random_token()))
}

/// 256-bit URL-safe random token (session ids, CSRF tokens).
fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Write a private file (mode 0600 on unix) atomically enough for a
/// credentials store: temp file + rename.
fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("credentials.tmp");
    {
        use std::io::Write;
        let mut f =
            std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
        }
        f.write_all(data)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Temp directory removed on drop (also on panic).
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("res-{tag}-{}", random_token()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));

    fn cfg() -> AuthConfig {
        AuthConfig::default()
    }

    #[test]
    fn disabled_without_passwords() {
        let auth = AuthState::from_passwords(cfg(), None, None);
        assert!(!auth.enabled());
        assert!(auth.login("admin", "x", IP).is_err());
    }

    #[test]
    fn login_roundtrip_and_roles() {
        let auth = AuthState::from_passwords(
            cfg(),
            Some("correct horse".into()),
            Some("battery staple".into()),
        );
        assert!(auth.enabled());
        let (token, session) = auth.login("admin", "correct horse", IP).expect("login");
        assert_eq!(session.role, Role::Admin);
        assert_eq!(session.username, "admin");
        assert!(!session.csrf.is_empty());
        let got = auth.session(&token).expect("session");
        assert_eq!(got.role, Role::Admin);

        let (_, viewer) = auth
            .login("viewer", "battery staple", IP)
            .expect("viewer login");
        assert_eq!(viewer.role, Role::Viewer);

        assert!(auth.login("admin", "wrong", IP).is_err());
        assert!(auth.login("nobody", "correct horse", IP).is_err());
        // Unknown user and wrong password share the error variant.
        assert!(matches!(
            auth.login("nobody", "x", IP),
            Err(LoginError::InvalidCredentials)
        ));
    }

    #[test]
    fn logout_invalidates_session() {
        let auth = AuthState::from_passwords(cfg(), Some("pw".into()), None);
        let (token, _) = auth.login("admin", "pw", IP).unwrap();
        assert!(auth.session(&token).is_some());
        auth.logout(&token);
        assert!(auth.session(&token).is_none());
        // Idempotent.
        auth.logout(&token);
    }

    #[test]
    fn brute_force_lockout() {
        let mut c = cfg();
        c.max_failed_attempts = 3;
        let auth = AuthState::from_passwords(c, Some("pw".into()), None);
        for _ in 0..3 {
            assert!(matches!(
                auth.login("admin", "bad", IP),
                Err(LoginError::InvalidCredentials)
            ));
        }
        // Locked even with the correct password.
        assert!(matches!(
            auth.login("admin", "pw", IP),
            Err(LoginError::Locked { .. })
        ));
    }

    #[test]
    fn case_insensitive_usernames() {
        let auth = AuthState::from_passwords(cfg(), Some("pw".into()), None);
        let (_, s) = auth.login("ADMIN", "pw", IP).unwrap();
        assert_eq!(s.role, Role::Admin);
    }

    #[test]
    fn credentials_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("res-auth-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("res.toml");
        let auth = AuthState::from_passwords(cfg(), Some("s3cret".into()), Some("view".into()));
        auth.save_credentials_file(&cfg_path).unwrap();
        let loaded = AuthState::load_credentials_file(cfg(), &cfg_path).unwrap();
        assert!(loaded.enabled());
        assert!(loaded.viewer_enabled());
        let (_, s) = loaded.login("admin", "s3cret", IP).unwrap();
        assert_eq!(s.role, Role::Admin);
        // Path is res.credentials next to res.toml.
        assert!(AuthState::credentials_path(&cfg_path)
            .file_name()
            .unwrap()
            .eq("res.credentials"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn password_verify_accepts_only_correct() {
        let h = hash_password("top secret");
        assert!(verify_password("top secret", &h));
        assert!(!verify_password("top secre", &h));
        assert!(!verify_password("", &h));
    }

    #[test]
    fn login_rate_limit_per_ip() {
        let mut c = cfg();
        c.login_rate_limit_per_minute = 3;
        let auth = AuthState::from_passwords(c, Some("pw".into()), None);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..3 {
            auth.begin_login_attempt(ip).expect("within limit");
        }
        // 4th attempt is rate-limited.
        assert!(auth.begin_login_attempt(ip).is_err());
        // A different IP is unaffected.
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(auth.begin_login_attempt(other).is_ok());
        // Successful login clears the counter for that IP.
        auth.clear_login_rate(ip);
        assert!(auth.begin_login_attempt(ip).is_ok());
    }

    #[test]
    fn login_rate_limit_zero_disables() {
        let mut c = cfg();
        c.login_rate_limit_per_minute = 0;
        let auth = AuthState::from_passwords(c, Some("pw".into()), None);
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        for _ in 0..100 {
            auth.begin_login_attempt(ip).expect("disabled");
        }
    }

    #[test]
    fn rotate_admin_password_invalidates_old() {
        let auth = AuthState::from_passwords(cfg(), Some("old".into()), None);
        assert!(auth.login("admin", "old", IP).is_ok());
        assert!(auth.rotate_admin_password("new-secret"));
        // Old password no longer works.
        assert!(matches!(
            auth.login("admin", "old", IP),
            Err(LoginError::InvalidCredentials)
        ));
        // New password works.
        let (_, s) = auth.login("admin", "new-secret", IP).unwrap();
        assert_eq!(s.role, Role::Admin);
    }

    #[test]
    fn set_admin_password_persist_first_preserves_on_failure() {
        let auth = AuthState::from_passwords(cfg(), Some("old".into()), None);
        assert!(auth.login("admin", "old", IP).is_ok());
        // Deterministic for every user (including root): the parent directory
        // of the config path does not exist, so the credential file cannot be
        // created. Nothing is ever written outside the temp directory.
        let dir = TempDir::new("auth-persist-fail");
        let missing = dir.0.join("no-such-subdir").join("res.toml");
        let result = auth.set_admin_password(&missing, "new");
        assert!(
            result.is_err(),
            "persisting into a missing directory must fail"
        );
        assert!(
            !missing.parent().unwrap().exists(),
            "failed write must not create directories"
        );
        assert!(auth.login("admin", "old", IP).is_ok());
        assert!(matches!(
            auth.login("admin", "new", IP),
            Err(LoginError::InvalidCredentials)
        ));
    }

    #[test]
    fn set_admin_password_persist_first_succeeds() {
        use std::env::temp_dir;
        let auth = AuthState::from_passwords(cfg(), Some("old".into()), None);
        assert!(auth.login("admin", "old", IP).is_ok());
        let dir = temp_dir().join(format!("res_auth_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg_path = dir.join("res.toml");
        let _ = std::fs::write(&cfg_path, "[auth]\nusername = \"admin\"\n");
        let result = auth.set_admin_password(&cfg_path, "new-secret");
        assert!(
            result.is_ok(),
            "set_admin_password should succeed: {result:?}"
        );
        assert!(matches!(
            auth.login("admin", "old", IP),
            Err(LoginError::InvalidCredentials)
        ));
        assert!(auth.login("admin", "new-secret", IP).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_viewer_password_invalidates_old() {
        let auth =
            AuthState::from_passwords(cfg(), Some("admin-pw".into()), Some("view-old".into()));
        assert!(auth.login("viewer", "view-old", IP).is_ok());
        assert!(auth.rotate_viewer_password("view-new"));
        assert!(matches!(
            auth.login("viewer", "view-old", IP),
            Err(LoginError::InvalidCredentials)
        ));
        let (_, s) = auth.login("viewer", "view-new", IP).unwrap();
        assert_eq!(s.role, Role::Viewer);
    }

    #[test]
    fn rotate_missing_accounts_returns_false() {
        let auth = AuthState::from_passwords(cfg(), Some("pw".into()), None);
        assert!(!auth.rotate_viewer_password("x"));
        let no_admin = AuthState::from_passwords(cfg(), None, Some("v".into()));
        assert!(!no_admin.rotate_admin_password("x"));
    }

    #[test]
    fn lockout_table_is_bounded() {
        let mut c = cfg();
        c.max_failed_attempts = u32::MAX; // nothing actually locks
        let auth = AuthState::from_passwords(c, Some("pw".into()), None);
        // Insert more than MAX_LOCKOUTS distinct usernames via failed logins
        // (test helper skips argon2 so this stays fast).
        for i in 0..(MAX_LOCKOUTS + 50) {
            auth.record_failure_for_test(&format!("user{i}"), IP);
        }
        let n = auth
            .lockouts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        assert!(
            n <= MAX_LOCKOUTS,
            "lockout table must stay bounded, got {n}"
        );
    }

    #[test]
    fn secure_cookies_flag_is_exposed() {
        let mut c = cfg();
        assert!(!c.secure_cookies);
        c.secure_cookies = true;
        let auth = AuthState::from_passwords(c, Some("pw".into()), None);
        assert!(auth.secure_cookies());
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn lock_cfg(max: u32) -> AuthConfig {
        let mut c = cfg();
        c.max_failed_attempts = max;
        c
    }

    fn fail(auth: &AuthState, user: &str, from: IpAddr, n: u32) {
        for _ in 0..n {
            assert!(matches!(
                auth.login(user, "wrong", from),
                Err(LoginError::InvalidCredentials)
            ));
        }
    }

    #[test]
    fn lockout_is_per_ip_not_global() {
        let auth = AuthState::from_passwords(lock_cfg(3), Some("pw".into()), None);
        let attacker = ip("203.0.113.66");
        let admin = ip("198.51.100.10");
        fail(&auth, "admin", attacker, 3);
        // The attacker's address is locked out, even with the right password.
        assert!(matches!(
            auth.login("admin", "pw", attacker),
            Err(LoginError::Locked { .. })
        ));
        // The administrator on another address is unaffected.
        assert!(auth.login("admin", "pw", admin).is_ok());
    }

    #[test]
    fn same_ip_repeated_failures_lock_that_pair() {
        let auth =
            AuthState::from_passwords(lock_cfg(2), Some("pw".into()), Some("vw-pass".into()));
        let a = ip("192.0.2.1");
        fail(&auth, "admin", a, 2);
        assert!(matches!(
            auth.login("admin", "pw", a),
            Err(LoginError::Locked { .. })
        ));
        // Lockout is per account too: the viewer from the same address is a
        // different key and still gets its own attempts.
        assert!(auth.login("viewer", "vw-pass", a).is_ok());
    }

    #[test]
    fn correct_login_after_failures_from_another_ip() {
        let auth = AuthState::from_passwords(lock_cfg(3), Some("pw".into()), None);
        fail(&auth, "admin", ip("203.0.113.1"), 2);
        fail(&auth, "admin", ip("203.0.113.2"), 2);
        assert!(auth.login("admin", "pw", ip("198.51.100.5")).is_ok());
    }

    #[test]
    fn success_clears_the_pair_counter() {
        let auth = AuthState::from_passwords(lock_cfg(3), Some("pw".into()), None);
        let a = ip("192.0.2.7");
        fail(&auth, "admin", a, 2);
        assert!(auth.login("admin", "pw", a).is_ok());
        // Counter was reset: two more failures do not lock.
        fail(&auth, "admin", a, 2);
        assert!(auth.login("admin", "pw", a).is_ok());
    }

    #[test]
    fn lockout_expires_and_recovers() {
        let auth = AuthState::from_passwords(lock_cfg(2), Some("pw".into()), None);
        let a = ip("192.0.2.9");
        fail(&auth, "admin", a, 2);
        assert!(matches!(
            auth.login("admin", "pw", a),
            Err(LoginError::Locked { .. })
        ));
        // Default lockout is 15 minutes: still locked after 14, free after 16.
        auth.age_lockouts_for_test(Duration::from_secs(14 * 60));
        assert!(matches!(
            auth.login("admin", "pw", a),
            Err(LoginError::Locked { .. })
        ));
        auth.age_lockouts_for_test(Duration::from_secs(2 * 60));
        assert!(auth.login("admin", "pw", a).is_ok());
    }

    #[test]
    fn failure_window_expiry_resets_the_counter() {
        let auth = AuthState::from_passwords(lock_cfg(3), Some("pw".into()), None);
        let a = ip("192.0.2.11");
        fail(&auth, "admin", a, 2);
        auth.age_lockouts_for_test(Duration::from_secs(16 * 60)); // window is 15 min
        fail(&auth, "admin", a, 2); // would be the 4th failure without the reset
        assert!(auth.login("admin", "pw", a).is_ok());
    }

    #[test]
    fn mapped_ipv6_shares_the_ipv4_lock() {
        let auth = AuthState::from_passwords(lock_cfg(2), Some("pw".into()), None);
        fail(&auth, "admin", ip("192.0.2.33"), 2);
        assert!(matches!(
            auth.login("admin", "pw", ip("::ffff:192.0.2.33")),
            Err(LoginError::Locked { .. })
        ));
    }

    #[test]
    fn concurrent_guesses_cannot_exceed_the_failure_budget() {
        // 16 parallel wrong guesses against a budget of 3: the reservation is
        // taken before argon2 runs, so at most 3 may ever be evaluated.
        let auth = std::sync::Arc::new(AuthState::from_passwords(
            lock_cfg(3),
            Some("pw".into()),
            None,
        ));
        let a = ip("192.0.2.50");
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let auth = auth.clone();
                std::thread::spawn(move || auth.login("admin", "wrong", a))
            })
            .collect();
        let (mut invalid, mut locked) = (0, 0);
        for h in handles {
            match h.join().unwrap() {
                Err(LoginError::InvalidCredentials) => invalid += 1,
                Err(LoginError::Locked { .. }) => locked += 1,
                Ok(_) => panic!("wrong password must never succeed"),
            }
        }
        assert_eq!(
            invalid, 3,
            "only the budgeted guesses may reach verification"
        );
        assert_eq!(locked, 13);
        assert!(matches!(
            auth.login("admin", "pw", a),
            Err(LoginError::Locked { .. })
        ));
    }

    #[test]
    fn concurrent_rate_limit_is_exact() {
        let mut c = cfg();
        c.login_rate_limit_per_minute = 5;
        let auth = std::sync::Arc::new(AuthState::from_passwords(c, Some("pw".into()), None));
        let a = ip("192.0.2.60");
        let handles: Vec<_> = (0..40)
            .map(|_| {
                let auth = auth.clone();
                std::thread::spawn(move || auth.begin_login_attempt(a).is_ok())
            })
            .collect();
        let allowed = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(allowed, 5);
    }

    #[test]
    fn eviction_never_drops_active_locks_while_cheaper_victims_exist() {
        let auth = AuthState::from_passwords(lock_cfg(1), Some("pw".into()), None);
        let victim = ip("192.0.2.100");
        // A real lock for the administrator's own pair.
        auth.record_failure_for_test("admin", victim);
        assert!(matches!(
            auth.login("admin", "pw", victim),
            Err(LoginError::Locked { .. })
        ));
        // Flood with distinct keys: with max=1 each of these is also "locked",
        // so relax: use a config where flood entries are merely counted.
        let mut c = cfg();
        c.max_failed_attempts = 2;
        let auth2 = AuthState::from_passwords(c, Some("pw".into()), None);
        auth2.record_failure_for_test("admin", victim);
        auth2.record_failure_for_test("admin", victim); // locked
        for i in 0..(MAX_LOCKOUTS + 200) {
            let a = IpAddr::V4(std::net::Ipv4Addr::from(0xC000_0000u32 + i as u32));
            auth2.record_failure_for_test("flood", a);
        }
        let n = auth2.lockouts.lock().unwrap().len();
        assert!(n <= MAX_LOCKOUTS, "table bounded, got {n}");
        assert!(
            matches!(
                auth2.login("admin", "pw", victim),
                Err(LoginError::Locked { .. })
            ),
            "the active lock must survive a flood of unlocked entries"
        );
    }

    #[test]
    fn lockout_table_capacity_with_all_locked_entries_stays_bounded() {
        let auth = AuthState::from_passwords(lock_cfg(1), Some("pw".into()), None);
        for i in 0..(MAX_LOCKOUTS + 100) {
            let a = IpAddr::V4(std::net::Ipv4Addr::from(0x0A00_0000u32 + i as u32));
            auth.record_failure_for_test("x", a);
        }
        assert!(auth.lockouts.lock().unwrap().len() <= MAX_LOCKOUTS);
    }

    #[test]
    fn clear_login_rate_canonicalizes_addresses() {
        let mut c = cfg();
        c.login_rate_limit_per_minute = 1;
        let auth = AuthState::from_passwords(c, Some("pw".into()), None);
        for (spent, clear) in [
            ("192.0.2.1", "192.0.2.1"),
            ("2001:db8::1", "2001:db8::1"),
            ("192.0.2.2", "::ffff:192.0.2.2"),
            ("::ffff:192.0.2.3", "192.0.2.3"),
        ] {
            let (spent, clear) = (ip(spent), ip(clear));
            auth.begin_login_attempt(spent).expect("first attempt");
            assert!(
                auth.begin_login_attempt(spent).is_err(),
                "limit reached for {spent}"
            );
            auth.clear_login_rate(clear);
            assert!(
                auth.begin_login_attempt(spent).is_ok(),
                "clearing {clear} must reset the counter of {spent}"
            );
        }
    }

    #[test]
    fn idle_sessions_expire_and_activity_refreshes() {
        let auth = AuthState::from_passwords(cfg(), Some("pw".into()), None); // idle = 30 min
        let (active, _) = auth.login("admin", "pw", IP).unwrap();
        let (idle, _) = auth.login("admin", "pw", IP).unwrap();
        auth.age_session_for_test(&active, Duration::from_secs(20 * 60));
        auth.age_session_for_test(&idle, Duration::from_secs(31 * 60));
        assert!(
            auth.session(&active).is_some(),
            "20 min idle is within the timeout"
        );
        // The lookup above counted as activity: it survives another 20 min.
        auth.age_session_for_test(&active, Duration::from_secs(20 * 60));
        assert!(
            auth.session(&active).is_some(),
            "activity refreshes the idle clock"
        );
        assert!(
            auth.session(&idle).is_none(),
            "unused session must be idle-expired"
        );
        assert_eq!(auth.session_count(), 1);
    }

    #[test]
    fn idle_timeout_zero_disables() {
        let mut c = cfg();
        c.session_idle_timeout_ms = 0;
        let auth = AuthState::from_passwords(c, Some("pw".into()), None);
        let (t, _) = auth.login("admin", "pw", IP).unwrap();
        auth.age_session_for_test(&t, Duration::from_secs(10 * 60 * 60));
        assert!(auth.session(&t).is_some());
    }

    #[test]
    fn revoke_all_except_keeps_only_the_callers_session() {
        let auth = AuthState::from_passwords(cfg(), Some("pw".into()), Some("vw-pass".into()));
        let (keep, _) = auth.login("admin", "pw", IP).unwrap();
        let (other, _) = auth.login("admin", "pw", IP).unwrap();
        let (viewer, _) = auth.login("viewer", "vw-pass", IP).unwrap();
        assert_eq!(auth.revoke_all_except(&keep), 2);
        assert!(auth.session(&keep).is_some());
        assert!(auth.session(&other).is_none());
        assert!(auth.session(&viewer).is_none());
    }

    #[test]
    fn revoke_user_only_touches_that_account() {
        let auth = AuthState::from_passwords(cfg(), Some("pw".into()), Some("vw-pass".into()));
        let (admin, _) = auth.login("admin", "pw", IP).unwrap();
        let (viewer, _) = auth.login("viewer", "vw-pass", IP).unwrap();
        assert_eq!(auth.revoke_user("VIEWER"), 1);
        assert!(auth.session(&viewer).is_none());
        assert!(auth.session(&admin).is_some());
    }

    #[test]
    fn per_user_session_cap_evicts_own_oldest_only() {
        let auth = AuthState::from_passwords(cfg(), Some("pw".into()), Some("vw-pass".into()));
        let (viewer, _) = auth.login("viewer", "vw-pass", IP).unwrap();
        let mut admin_tokens = Vec::new();
        for _ in 0..(MAX_SESSIONS_PER_USER + 3) {
            let (t, _) = auth.login("admin", "pw", IP).unwrap();
            admin_tokens.push(t);
        }
        assert!(
            auth.session(&viewer).is_some(),
            "other accounts keep their session"
        );
        assert!(
            auth.session(&admin_tokens[0]).is_none(),
            "oldest admin session evicted"
        );
        assert!(auth.session(admin_tokens.last().unwrap()).is_some());
        assert_eq!(auth.session_count(), MAX_SESSIONS_PER_USER + 1);
    }
}
