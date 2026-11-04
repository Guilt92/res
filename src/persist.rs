//! Atomic, file-based configuration persistence.
//!
//! The configuration is a single TOML file. Writes are crash-safe:
//!
//! 1. serialize + re-validate the candidate (never write what would not load),
//! 2. if the current file on disk parses, rotate the backup generations
//!    (oldest dropped, others shifted) and copy the current file aside as
//!    `<file>.backup` — the newest of up to [`MAX_BACKUP_GENERATIONS`]
//!    last-known-good configurations (older ones live at `<file>.backup.2`,
//!    `<file>.backup.3`).
//! 3. write the new content to a temp file in the **same directory**,
//!    `fsync` it, `rename()` it over the primary path (atomic on POSIX),
//! 4. `fsync` the directory (best effort) so the rename itself is durable.
//!
//! A reader therefore always sees either the complete previous file or the
//! complete new file, and a crash at any point leaves a loadable
//! configuration (primary or one of the backups). Temp files abandoned by a
//! crashed writer are removed on the next save. Restoring an older
//! generation is a validated operation: the file content must parse through
//! [`AppConfig::load`] before it is promoted (see the module tests and the
//! README's "Recovering from a bad config" section).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::config::{backup_path, AppConfig};

/// In-process serialization for the read-backup-write sequence. The control
/// plane already serializes mutations, but the persistence helper must remain
/// safe for direct callers and tests. Cross-process writers are not supported.
static SAVE_LOCK: Mutex<()> = Mutex::new(());

/// Backup generations kept per config file: `<file>.backup` (newest) plus
/// `<file>.backup.2` and `<file>.backup.3`.
pub const MAX_BACKUP_GENERATIONS: usize = 3;

/// Unique suffix for temp files (combined with the PID, so two processes
/// sharing a directory cannot collide either).
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Persist `cfg` to `path` atomically. See module docs for the protocol.
pub fn save_atomic(path: &Path, cfg: &AppConfig) -> Result<(), String> {
    let _guard = SAVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let text = cfg.to_toml()?;
    // Round-trip check: refuse to write anything that would not load.
    AppConfig::parse(&text)?;

    // Remove temp files abandoned by a crashed previous write before we
    // create our own (same-process saves are serialized; cross-process
    // writers are unsupported, so this cannot race a live writer).
    cleanup_stale_temp_files(path);

    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
    }

    // Preserve the current file as the newest backup generation only when it
    // is itself valid (otherwise we would clobber the last-known-good copy
    // with garbage).
    if let Ok(current) = fs::read_to_string(path) {
        if AppConfig::parse(&current).is_ok() {
            rotate_backups(path);
            write_atomic(&backup_path(path), current.as_bytes())?;
        }
    }

    if let Err(e) = write_atomic(path, text.as_bytes()) {
        // Persistence failures must be greppable in logs, not only visible
        // in the in-memory event ring and the single API response.
        tracing::error!(event = "config_persist_failed", path = %path.display(), error = %e);
        return Err(e);
    }
    Ok(())
}

/// Path of backup generation `gen` (1-based): 1 is `<file>.backup`, older
/// generations are `<file>.backup.2`, `<file>.backup.3`, ...
pub fn backup_generation_path(path: &Path, gen: usize) -> PathBuf {
    if gen <= 1 {
        backup_path(path)
    } else {
        let mut name = path.as_os_str().to_owned();
        name.push(format!(".backup.{gen}"));
        PathBuf::from(name)
    }
}

/// Shift backup generations down before a new one is written: drop the
/// oldest, move every other generation one slot older. Best-effort; a
/// rotation failure never aborts the main write.
fn rotate_backups(path: &Path) {
    let _ = fs::remove_file(backup_generation_path(path, MAX_BACKUP_GENERATIONS));
    for to in (2..=MAX_BACKUP_GENERATIONS).rev() {
        let from = backup_generation_path(path, to - 1);
        if from.exists() {
            let _ = fs::rename(&from, backup_generation_path(path, to));
        }
    }
}

/// Remove temp files matching this config file's temp pattern (crash debris).
/// Only files ending in `.tmp` with the `.name.` prefix are considered, so
/// unrelated files in the same directory are never touched.
fn cleanup_stale_temp_files(path: &Path) {
    let Some(dir) = path.parent() else {
        return;
    };
    let Some(file_name) = path.file_name() else {
        return;
    };
    let prefix = format!(".{}.", file_name.to_string_lossy());
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix) && name.ends_with(".tmp") {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Copy a backup generation to the primary path after validating that it
/// parses as a complete configuration. This is the only supported restore
/// path: raw file copies are not validated and may brick startup.
pub fn restore_backup(path: &Path, gen: usize) -> Result<(), String> {
    if gen == 0 || gen > MAX_BACKUP_GENERATIONS {
        return Err(format!(
            "backup generation must be 1..={MAX_BACKUP_GENERATIONS}"
        ));
    }
    let _guard = SAVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let source = backup_generation_path(path, gen);
    let text =
        fs::read_to_string(&source).map_err(|e| format!("read {}: {e}", source.display()))?;
    AppConfig::parse(&text)
        .map_err(|e| format!("backup {} is not a valid config: {e}", source.display()))?;
    if let Ok(current) = fs::read_to_string(path) {
        if AppConfig::parse(&current).is_ok() {
            rotate_backups(path);
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
        for gen in 1..=MAX_BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_generation_path(&path, gen));
        }

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
        for gen in 1..=MAX_BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_generation_path(&path, gen));
        }
    }

    #[test]
    fn backups_keep_multiple_generations() {
        let path = tmp_file("generations.toml");
        for gen in 1..=MAX_BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_generation_path(&path, gen));
        }
        let _ = fs::remove_file(&path);

        for (i, port) in [53u16, 54, 55, 56].iter().enumerate() {
            save_atomic(&path, &cfg_with(*port)).unwrap();
            if i == 0 {
                assert!(
                    !backup_path(&path).exists(),
                    "first save must not create a backup"
                );
                continue;
            }
            // Generation 1 always holds the config from the previous save.
            let g1 = AppConfig::load(&backup_generation_path(&path, 1)).unwrap();
            assert_eq!(g1.upstreams[0].port, port - 1, "after save {i}");
        }
        // After 4 saves the three generations hold 55, 54, 53.
        assert_eq!(
            AppConfig::load(&backup_generation_path(&path, 1))
                .unwrap()
                .upstreams[0]
                .port,
            55
        );
        assert_eq!(
            AppConfig::load(&backup_generation_path(&path, 2))
                .unwrap()
                .upstreams[0]
                .port,
            54
        );
        assert_eq!(
            AppConfig::load(&backup_generation_path(&path, 3))
                .unwrap()
                .upstreams[0]
                .port,
            53
        );

        let _ = fs::remove_file(&path);
        for gen in 1..=MAX_BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_generation_path(&path, gen));
        }
    }

    #[test]
    fn restore_backup_promotes_validated_generation() {
        let path = tmp_file("restore.toml");
        for gen in 1..=MAX_BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_generation_path(&path, gen));
        }
        let _ = fs::remove_file(&path);

        save_atomic(&path, &cfg_with(53)).unwrap();
        save_atomic(&path, &cfg_with(54)).unwrap();
        assert_eq!(AppConfig::load(&path).unwrap().upstreams[0].port, 54);

        // Restore generation 1 (holds port 53) and the primary swaps back.
        restore_backup(&path, 1).unwrap();
        assert_eq!(AppConfig::load(&path).unwrap().upstreams[0].port, 53);
        // The pre-restore primary became the newest backup generation.
        assert_eq!(
            AppConfig::load(&backup_generation_path(&path, 1))
                .unwrap()
                .upstreams[0]
                .port,
            54
        );

        // Out-of-range generations are rejected before touching anything.
        assert!(restore_backup(&path, 0).is_err());
        assert!(restore_backup(&path, MAX_BACKUP_GENERATIONS + 1).is_err());
        assert_eq!(AppConfig::load(&path).unwrap().upstreams[0].port, 53);

        let _ = fs::remove_file(&path);
        for gen in 1..=MAX_BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_generation_path(&path, gen));
        }
    }

    #[test]
    fn restore_backup_rejects_invalid_content() {
        let path = tmp_file("restore-invalid.toml");
        for gen in 1..=MAX_BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_generation_path(&path, gen));
        }
        let _ = fs::remove_file(&path);
        save_atomic(&path, &cfg_with(53)).unwrap();
        save_atomic(&path, &cfg_with(54)).unwrap();
        // Corrupt the newest backup generation.
        fs::write(backup_path(&path), "not toml {{{").unwrap();
        assert!(
            restore_backup(&path, 1).is_err(),
            "corrupted backup must never be promoted"
        );
        // Primary is untouched by the failed restore.
        assert_eq!(AppConfig::load(&path).unwrap().upstreams[0].port, 54);

        let _ = fs::remove_file(&path);
        for gen in 1..=MAX_BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_generation_path(&path, gen));
        }
    }

    #[test]
    fn stale_temp_files_are_removed_on_next_save() {
        let path = tmp_file("stale.toml");
        let _ = fs::remove_file(&path);
        for gen in 1..=MAX_BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_generation_path(&path, gen));
        }
        save_atomic(&path, &cfg_with(53)).unwrap();
        assert!(temp_files_for(&path).is_empty());

        // Simulate crash debris: temp files from a dead writer (different
        // pid and random sequence), matching the real naming pattern.
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let debris = path
            .parent()
            .unwrap()
            .join(format!(".{name}.9999.3.deadbeefdeadbeef.tmp"));
        fs::write(&debris, b"partial write").unwrap();
        // An unrelated file in the same directory must survive.
        let unrelated = path.parent().unwrap().join(".res.toml.notes");
        fs::write(&unrelated, b"keep me").unwrap();

        save_atomic(&path, &cfg_with(54)).unwrap();
        assert!(
            !debris.exists(),
            "stale temp file from a crashed writer must be removed"
        );
        assert!(unrelated.exists(), "unrelated files must be kept");
        assert!(temp_files_for(&path).is_empty());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&unrelated);
        for gen in 1..=MAX_BACKUP_GENERATIONS {
            let _ = fs::remove_file(backup_generation_path(&path, gen));
        }
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
    fn backup_path_obstacle_is_rotated_away_instead_of_blocking_saves() {
        let path = tmp_file("backup-fail.toml");
        let backup = backup_path(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&backup);
        save_atomic(&path, &cfg_with(53)).unwrap();

        // Block the newest backup slot with a directory (crash debris or an
        // operator mistake). Rotation must move the obstacle aside rather
        // than leaving every future save unable to write a backup.
        fs::create_dir(&backup).unwrap();
        save_atomic(&path, &cfg_with(54)).unwrap();
        assert_eq!(
            AppConfig::load(&path).unwrap().upstreams[0].port,
            54,
            "save must succeed past the obstacle"
        );
        // The newest backup generation now holds the pre-save primary, and
        // it is a regular loadable file.
        let newest = AppConfig::load(&backup).unwrap();
        assert_eq!(newest.upstreams[0].port, 53);

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
