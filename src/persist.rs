//! Atomic, file-based configuration persistence.
//!
//! The configuration is a single TOML file. Writes are crash-safe:
//!
//! 1. serialize + re-validate the candidate (never write what would not load),
//! 2. if the current file on disk parses, copy it aside as
//!    `<file>.backup` (the last-known-good configuration),
//! 3. write the new content to a temp file in the **same directory**,
//!    `fsync` it, `rename()` it over the primary path (atomic on POSIX),
//! 4. `fsync` the directory (best effort) so the rename itself is durable.
//!
//! A reader therefore always sees either the complete previous file or the
//! complete new file, and a crash at any point leaves a loadable
//! configuration (primary or backup).

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::config::{backup_path, AppConfig};

/// In-process serialization for the read-backup-write sequence. The control
/// plane already serializes mutations, but the persistence helper must remain
/// safe for direct callers and tests. Cross-process writers are not supported.
static SAVE_LOCK: Mutex<()> = Mutex::new(());

/// Unique suffix for temp files (combined with the PID, so two processes
/// sharing a directory cannot collide either).
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Persist `cfg` to `path` atomically. See module docs for the protocol.
pub fn save_atomic(path: &Path, cfg: &AppConfig) -> Result<(), String> {
    let _guard = SAVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let text = cfg.to_toml()?;
    // Round-trip check: refuse to write anything that would not load.
    AppConfig::parse(&text)?;

    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
    }

    // Preserve the current file as backup only when it is itself valid
    // (otherwise we would clobber the last-known-good copy with garbage).
    if let Ok(current) = fs::read_to_string(path) {
        if AppConfig::parse(&current).is_ok() {
            write_atomic(&backup_path(path), current.as_bytes())?;
        }
    }

    write_atomic(path, text.as_bytes())
}

/// Write `bytes` to `path` via temp file + fsync + rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("invalid path {}", path.display()))?;
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    // The random component prevents a stale temp file from a previous
    // container/process (notably PID 1 after a restart) from blocking writes.
    let tmp = dir.join(format!(
        ".{}.{}.{seq}.{:016x}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        fastrand::u64(..),
    ));

    let mut created = false;
    let result = (|| -> Result<(), String> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        // Owner-only: `res.toml` may embed `api_token`/session secrets and
        // the credentials file holds password hashes; world-readable config
        // would leak them to any local user (umask could otherwise leave
        // the 0666-create default in place).
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .map_err(|e| format!("create {}: {e}", tmp.display()))?;
        created = true;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
        }
        f.write_all(bytes)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
        drop(f);
        fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))?;
        Ok(())
    })();

    if result.is_err() {
        // Only remove a temp file this call actually created: a collision
        // with another process must never delete its in-flight file.
        if created {
            let _ = fs::remove_file(&tmp);
        }
        return result;
    }

    // The rename is already visible. A directory-fsync failure only affects
    // crash durability, not the current contents, so it must not turn a
    // successfully replaced file into a reported failure (the API would then
    // leave memory and disk inconsistent). Record it and report success.
    if let Err(e) = sync_dir(dir) {
        tracing::warn!(
            event = "config_dir_sync_failed",
            dir = %dir.display(),
            error = %e
        );
    }
    Ok(())
}

/// Best-effort directory fsync so the rename survives a power loss.
fn sync_dir(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let d = fs::File::open(dir).map_err(|e| format!("open dir {}: {e}", dir.display()))?;
        d.sync_all()
            .map_err(|e| format!("fsync dir {}: {e}", dir.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Protocol, UpstreamConfig};

    fn tmp_file(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("res-persist-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn cfg_with(port: u16) -> AppConfig {
        AppConfig {
            upstreams: vec![UpstreamConfig {
                id: 1,
                name: "cf".into(),
                address: "1.1.1.1".parse().unwrap(),
                port,
                protocol: Protocol::Udp,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn save_writes_loadable_file_and_keeps_backup() {
        let path = tmp_file("save.toml");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));

        save_atomic(&path, &cfg_with(53)).unwrap();
        let loaded = AppConfig::load(&path).unwrap();
        assert_eq!(loaded.upstreams[0].port, 53);
        // No backup yet: there was nothing valid to preserve.
        assert!(!backup_path(&path).exists());

        save_atomic(&path, &cfg_with(5353)).unwrap();
        let loaded = AppConfig::load(&path).unwrap();
        assert_eq!(loaded.upstreams[0].port, 5353);
        // Backup holds the previous (valid) configuration.
        let backup = AppConfig::load(&backup_path(&path)).unwrap();
        assert_eq!(backup.upstreams[0].port, 53);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
    }

    #[test]
    fn save_never_clobbers_backup_with_invalid_primary() {
        let path = tmp_file("garbage.toml");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));

        // First establish a good primary + backup pair.
        save_atomic(&path, &cfg_with(53)).unwrap();
        save_atomic(&path, &cfg_with(54)).unwrap();
        // Someone corrupts the primary on disk.
        fs::write(&path, "not toml {{{").unwrap();

        save_atomic(&path, &cfg_with(55)).unwrap();
        let backup = AppConfig::load(&backup_path(&path)).unwrap();
        assert_eq!(
            backup.upstreams[0].port, 53,
            "backup must still hold the last known good config (not the corrupted file)"
        );
        assert_eq!(AppConfig::load(&path).unwrap().upstreams[0].port, 55);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
    }

    #[test]
    fn save_creates_missing_parent_dirs() {
        let path = std::env::temp_dir().join(format!(
            "res-persist-{}-nested/nested.toml",
            std::process::id()
        ));
        save_atomic(&path, &cfg_with(53)).unwrap();
        assert!(path.exists());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rejects_saving_invalid_config() {
        let path = tmp_file("invalid.toml");
        let _ = fs::remove_file(&path);
        let mut bad = cfg_with(53);
        bad.upstreams[0].priority = 0;
        assert!(save_atomic(&path, &bad).is_err());
        assert!(!path.exists());
    }

    /// Config may embed `api_token` and password material: neither the
    /// primary nor the backup copy may be readable by other local users.
    #[cfg(unix)]
    #[test]
    fn saved_files_are_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_file("perm.toml");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));

        save_atomic(&path, &cfg_with(53)).unwrap();
        save_atomic(&path, &cfg_with(54)).unwrap(); // second save creates the backup

        for p in [path.clone(), backup_path(&path)] {
            let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} must be 0600, got {mode:o}", p.display());
        }

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
    }

    /// Permission denied must leave both files and the directory free of temp
    /// artifacts. Skipped when the test process is privileged (root can write
    /// to a 0555 directory, so the condition cannot be reproduced there).
    #[cfg(unix)]
    #[test]
    fn permission_denied_leaves_primary_backup_and_no_temp_files() {
        use std::os::unix::fs::PermissionsExt;

        struct RestoreMode {
            path: std::path::PathBuf,
            mode: u32,
        }
        impl Drop for RestoreMode {
            fn drop(&mut self) {
                let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(self.mode));
            }
        }

        let dir = std::env::temp_dir().join(format!(
            "res-persist-perm-{}-{:016x}",
            std::process::id(),
            fastrand::u64(..)
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("res.toml");
        save_atomic(&path, &cfg_with(53)).unwrap();
        save_atomic(&path, &cfg_with(54)).unwrap();
        let primary_before = fs::read(&path).unwrap();
        let backup_before = fs::read(backup_path(&path)).unwrap();

        let original = fs::metadata(&dir).unwrap().permissions().mode() & 0o7777;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
        let _restore = RestoreMode {
            path: dir.clone(),
            mode: original,
        };

        // A privileged test process (root) ignores the directory mode; skip
        // instead of asserting a condition the environment cannot create.
        if fs::write(dir.join(".privilege-probe"), b"x").is_ok() {
            let _ = fs::remove_file(dir.join(".privilege-probe"));
            drop(_restore);
            let _ = fs::remove_dir_all(&dir);
            return;
        }

        let err = save_atomic(&path, &cfg_with(55)).unwrap_err();
        assert!(
            err.contains("Permission denied") || err.contains("permission denied"),
            "unexpected error: {err}"
        );
        assert_eq!(fs::read(&path).unwrap(), primary_before);
        assert_eq!(fs::read(backup_path(&path)).unwrap(), backup_before);
        assert!(
            temp_files_for(&path).is_empty(),
            "failed permission check leaked a temp file"
        );

        drop(_restore);
        let _ = fs::remove_dir_all(&dir);
    }

    fn temp_files_for(path: &Path) -> Vec<std::path::PathBuf> {
        let name = path.file_name().unwrap().to_string_lossy();
        let prefix = format!(".{name}.{}.", std::process::id());
        fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".tmp"))
            })
            .collect()
    }

    #[test]
    fn backup_failure_leaves_primary_and_backup_untouched() {
        let path = tmp_file("backup-fail.toml");
        let backup = backup_path(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&backup);
        save_atomic(&path, &cfg_with(53)).unwrap();
        let primary_before = fs::read(&path).unwrap();

        // Force the backup write to fail at the final rename: a directory
        // cannot be replaced by a file. The primary must not be touched.
        fs::create_dir(&backup).unwrap();
        let err = save_atomic(&path, &cfg_with(54)).unwrap_err();
        assert!(err.contains("backup"), "unexpected error: {err}");
        assert_eq!(fs::read(&path).unwrap(), primary_before);
        assert!(temp_files_for(&path).is_empty(), "temp file leaked");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&backup);
    }

    #[test]
    fn rename_failure_cleans_temp_and_keeps_last_good_backup() {
        let path = tmp_file("rename-fail.toml");
        let backup = backup_path(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&path);
        let _ = fs::remove_file(&backup);
        let _ = fs::remove_dir_all(&backup);
        // Two successful saves establish primary=54 and backup=53.
        save_atomic(&path, &cfg_with(53)).unwrap();
        save_atomic(&path, &cfg_with(54)).unwrap();
        let backup_before = fs::read(&backup).unwrap();

        // Replace the primary with a directory so the final atomic rename
        // fails after the temp file has been written and fsynced.
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let err = save_atomic(&path, &cfg_with(55)).unwrap_err();
        assert!(err.contains("rename"), "unexpected error: {err}");
        assert!(
            path.is_dir(),
            "failed rename must not replace the directory"
        );
        assert!(temp_files_for(&path).is_empty(), "temp file leaked");
        assert_eq!(
            fs::read(&backup).unwrap(),
            backup_before,
            "failed primary rename must not clobber the last good backup"
        );

        let _ = fs::remove_dir(&path);
        let _ = fs::remove_file(&backup);
    }

    #[test]
    fn concurrent_saves_do_not_share_temp_files_or_corrupt_the_primary() {
        let path = tmp_file("concurrent.toml");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));

        let mut handles = Vec::new();
        for i in 0..8u16 {
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                save_atomic(&path, &cfg_with(5300 + i))
            }));
        }
        for h in handles {
            h.join().unwrap().expect("concurrent save failed");
        }

        let loaded = AppConfig::load(&path).expect("primary loads");
        assert!(
            (5300..5308).contains(&loaded.upstreams[0].port),
            "unexpected final writer: {}",
            loaded.upstreams[0].port
        );
        assert!(
            temp_files_for(&path).is_empty(),
            "concurrent writes leaked temp files"
        );
        if backup_path(&path).exists() {
            AppConfig::load(&backup_path(&path)).expect("backup loads");
        }

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path));
    }
}
