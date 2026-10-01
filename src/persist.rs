//! Atomic, file-based configuration persistence.
//!
//! The configuration is a single TOML file. Writes are crash-safe:
//!
//! 1. serialize + re-validate the candidate (never write what would not load),
//! 2. if the current file on disk parses, copy it aside as
//!    `<file>.backup` (the last-known-good configuration),
//! 3. write the new content to a temp file in the **same directory**,
//!    `fsync` it, `rename()` it over the primary path (atomic on POSIX),
//! 4. `fsync` the directory so the rename itself is durable.
//!
//! A reader therefore always sees either the complete previous file or the
//! complete new file, and a crash at any point leaves a loadable
//! configuration (primary or backup).

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::config::{backup_path, AppConfig};

/// Persist `cfg` to `path` atomically. See module docs for the protocol.
pub fn save_atomic(path: &Path, cfg: &AppConfig) -> Result<(), String> {
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
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    let result = (|| -> Result<(), String> {
        let mut f = fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        f.write_all(bytes)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
        drop(f);
        fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))?;
        sync_dir(dir)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
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
}
