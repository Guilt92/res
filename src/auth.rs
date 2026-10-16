//! Control-plane authentication: username/password login, argon2id password
//! hashing, in-memory sessions with expiry, CSRF double-submit tokens,
//! viewer/admin RBAC, and login brute-force lockout.
//!
//! Credentials come from the environment (`RES_ADMIN_PASSWORD`,
//! `RES_VIEWER_PASSWORD`) or from a mode-0600 credentials file written next
//! to the configuration on first setup. Passwords are never stored in the
//! TOML configuration and never logged. When no password is configured the
//! control plane falls back to the legacy `server.api_token` behaviour (or a
//! fully open development posture with a startup warning).
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

/// Hard cap on concurrent sessions (oldest-expiring session is evicted).
const MAX_SESSIONS: usize = 1024;
/// Hard cap on tracked failed-login accounts (oldest window is evicted).
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

/// Failed-login tracking for one username (case-insensitive key).
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
    lockouts: Mutex<HashMap<String, Lockout>>,
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

    /// Per-IP login rate limit. Returns `Ok(())` when the attempt may
    /// proceed, or `Err(retry_after_secs)` when the client has exceeded
    /// `login_rate_limit_per_minute` within the current one-minute window.
    /// Call once per attempt before verifying credentials.
    pub fn check_login_rate(&self, ip: IpAddr) -> Result<(), u64> {
        let max = self.cfg.login_rate_limit_per_minute;
        if max == 0 {
            return Ok(());
        }
        let ip = canonical_ip(ip);
        let now = Instant::now();
        let mut map = self.login_ips.lock().unwrap_or_else(|e| e.into_inner());
        // Bound the table: evict the entry with the oldest window.
        if map.len() >= MAX_LOGIN_IPS && !map.contains_key(&ip) {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, v)| v.window_start.unwrap_or(now))
                .map(|(k, _)| *k)
            {
                map.remove(&oldest);
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
        Ok(())
    }

    /// Count one login attempt from `ip` (call after [`Self::check_login_rate`]).
    pub fn record_login_attempt(&self, ip: IpAddr) {
        // With rate limiting disabled the table serves no purpose; tracking
        // every source address would be an unbounded unauthenticated memory
        // sink, so skip it entirely.
        if self.cfg.login_rate_limit_per_minute == 0 {
            return;
        }
        let ip = canonical_ip(ip);
        let now = Instant::now();
        let mut map = self.login_ips.lock().unwrap_or_else(|e| e.into_inner());
        // Bound the table here too: this path runs even when the check
        // above was skipped for any reason.
        if map.len() >= MAX_LOGIN_IPS && !map.contains_key(&ip) {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, v)| v.window_start.unwrap_or(now))
                .map(|(k, _)| *k)
            {
                map.remove(&oldest);
            }
        }
        let e = map.entry(ip).or_default();
        if e.window_start.is_none() {
            e.window_start = Some(now);
        }
        e.attempts = e.attempts.saturating_add(1);
    }

    /// Drop the per-IP rate-limit counter for a client (called after a
    /// successful login so a legitimate user who mistyped once starts clean).
    pub fn clear_login_rate(&self, ip: IpAddr) {
        self.login_ips
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&ip);
    }

    /// Verify credentials and create a session on success. Locks the account
    /// for `lockout_duration` after `max_failed_attempts` failures inside
    /// `lockout_window`. The same error is returned for unknown users and
    /// wrong passwords.
    pub fn login(&self, username: &str, password: &str) -> Result<(String, Session), LoginError> {
        let key = username.to_lowercase();
        {
            let lockouts = self.lockouts.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(l) = lockouts.get(&key) {
                if let Some(until) = l.locked_until {
                    if until > Instant::now() {
                        return Err(LoginError::Locked {
                            retry_after_secs: until
                                .saturating_duration_since(Instant::now())
                                .as_secs()
                                .max(1),
                        });
                    }
                }
            }
        }

        let role = self.verify(username, password);
        match role {
            None => {
                self.record_failure(&key);
                Err(LoginError::InvalidCredentials)
            }
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
                    expires: now + self.session_ttl(),
                };
                let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
                sessions.prune_expired();
                sessions.insert(token.clone(), session.clone());
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

    fn record_failure(&self, key: &str) {
        let now = Instant::now();
        let mut lockouts = self.lockouts.lock().unwrap_or_else(|e| e.into_inner());
        // Bound the table: evict the entry whose window started earliest.
        if lockouts.len() >= MAX_LOCKOUTS && !lockouts.contains_key(key) {
            if let Some(oldest) = lockouts
                .iter()
                .min_by_key(|(_, v)| v.window_start.unwrap_or(now))
                .map(|(k, _)| k.clone())
            {
                lockouts.remove(&oldest);
            }
        }
        let l = lockouts.entry(key.to_string()).or_default();
        // Start a fresh window when the previous one has expired.
        if let Some(start) = l.window_start {
            if now.saturating_duration_since(start) > self.cfg.lockout_window_ms_duration()
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
        l.failures += 1;
        if l.failures >= self.cfg.max_failed_attempts {
            l.locked_until = Some(now + self.cfg.lockout_duration_ms_duration());
            tracing::warn!(event = "auth_locked", user = %key);
        }
    }

    fn clear_failures(&self, key: &str) {
        self.lockouts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }

    /// Look up a live session by token; expired tokens are dropped.
    pub fn session(&self, token: &str) -> Option<Session> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let expired = sessions
            .map
            .get(token)
            .map(|s| s.expires <= Instant::now())
            .unwrap_or(false);
        if expired {
            sessions.map.remove(token);
            return None;
        }
        sessions.map.get(token).cloned()
    }

    /// Invalidate a session (logout). Idempotent.
    pub fn logout(&self, token: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .remove(token);
    }

    /// Drop every session (not used in normal operation; test helper).
    pub fn logout_all(&self) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .clear();
    }

    pub fn session_count(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .len()
    }

    pub fn config(&self) -> &AuthConfig {
        &self.cfg
    }

    /// Test-only: record a failed login without running argon2 (keeps the
    /// lockout-table bound test fast).
    #[cfg(test)]
    pub(crate) fn record_failure_for_test(&self, key: &str) {
        self.record_failure(key);
    }
}

impl SessionTable {
    fn insert(&mut self, token: String, session: Session) {
        if self.map.len() >= MAX_SESSIONS {
            // Evict the session that expires soonest (≈ oldest).
            if let Some(oldest) = self
                .map
                .iter()
                .min_by_key(|(_, s)| s.expires)
                .map(|(t, _)| t.clone())
            {
                self.map.remove(&oldest);
            }
        }
        self.map.insert(token, session);
    }

    fn prune_expired(&mut self) {
        let now = Instant::now();
        self.map.retain(|_, s| s.expires > now);
    }
}

/// Argon2id hash with an auto-generated random salt (PHC string output).
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

    fn cfg() -> AuthConfig {
        AuthConfig::default()
    }

    #[test]
    fn disabled_without_passwords() {
        let auth = AuthState::from_passwords(cfg(), None, None);
        assert!(!auth.enabled());
        assert!(auth.login("admin", "x").is_err());
    }

    #[test]
    fn login_roundtrip_and_roles() {
        let auth = AuthState::from_passwords(
            cfg(),
            Some("correct horse".into()),
            Some("battery staple".into()),
        );
        assert!(auth.enabled());
        let (token, session) = auth.login("admin", "correct horse").expect("login");
        assert_eq!(session.role, Role::Admin);
        assert_eq!(session.username, "admin");
        assert!(!session.csrf.is_empty());
        let got = auth.session(&token).expect("session");
        assert_eq!(got.role, Role::Admin);

        let (_, viewer) = auth
            .login("viewer", "battery staple")
            .expect("viewer login");
        assert_eq!(viewer.role, Role::Viewer);

        assert!(auth.login("admin", "wrong").is_err());
        assert!(auth.login("nobody", "correct horse").is_err());
        // Unknown user and wrong password share the error variant.
        assert!(matches!(
            auth.login("nobody", "x"),
            Err(LoginError::InvalidCredentials)
        ));
    }

    #[test]
    fn logout_invalidates_session() {
        let auth = AuthState::from_passwords(cfg(), Some("pw".into()), None);
        let (token, _) = auth.login("admin", "pw").unwrap();
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
                auth.login("admin", "bad"),
                Err(LoginError::InvalidCredentials)
            ));
        }
        // Locked even with the correct password.
        assert!(matches!(
            auth.login("admin", "pw"),
            Err(LoginError::Locked { .. })
        ));
    }

    #[test]
    fn case_insensitive_usernames() {
        let auth = AuthState::from_passwords(cfg(), Some("pw".into()), None);
        let (_, s) = auth.login("ADMIN", "pw").unwrap();
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
        let (_, s) = loaded.login("admin", "s3cret").unwrap();
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
            auth.check_login_rate(ip).expect("within limit");
            auth.record_login_attempt(ip);
        }
        // 4th attempt is rate-limited.
        assert!(auth.check_login_rate(ip).is_err());
        // A different IP is unaffected.
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(auth.check_login_rate(other).is_ok());
        // Successful login clears the counter for that IP.
        auth.clear_login_rate(ip);
        assert!(auth.check_login_rate(ip).is_ok());
    }

    #[test]
    fn login_rate_limit_zero_disables() {
        let mut c = cfg();
        c.login_rate_limit_per_minute = 0;
        let auth = AuthState::from_passwords(c, Some("pw".into()), None);
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        for _ in 0..100 {
            auth.check_login_rate(ip).expect("disabled");
            auth.record_login_attempt(ip);
        }
    }

    #[test]
    fn rotate_admin_password_invalidates_old() {
        let auth = AuthState::from_passwords(cfg(), Some("old".into()), None);
        assert!(auth.login("admin", "old").is_ok());
        assert!(auth.rotate_admin_password("new-secret"));
        // Old password no longer works.
        assert!(matches!(
            auth.login("admin", "old"),
            Err(LoginError::InvalidCredentials)
        ));
        // New password works.
        let (_, s) = auth.login("admin", "new-secret").unwrap();
        assert_eq!(s.role, Role::Admin);
    }

    #[test]
    fn rotate_viewer_password_invalidates_old() {
        let auth =
            AuthState::from_passwords(cfg(), Some("admin-pw".into()), Some("view-old".into()));
        assert!(auth.login("viewer", "view-old").is_ok());
        assert!(auth.rotate_viewer_password("view-new"));
        assert!(matches!(
            auth.login("viewer", "view-old"),
            Err(LoginError::InvalidCredentials)
        ));
        let (_, s) = auth.login("viewer", "view-new").unwrap();
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
            auth.record_failure_for_test(&format!("user{i}"));
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
}
