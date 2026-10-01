//! Best-effort system information for reproducible benchmark reports.
//!
//! Everything here is read from `/proc` and `/etc` on Linux and degrades to
//! `"unknown"` elsewhere — never panics, never shells out.

use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub cpu_model: String,
    pub cpus: u32,
    pub mem_total_bytes: u64,
    pub profile: &'static str,
    pub version: &'static str,
}

impl SystemInfo {
    pub fn collect() -> Self {
        Self {
            hostname: read_first_line("/proc/sys/kernel/hostname")
                .or_else(|| read_os_release("HOSTNAME"))
                .unwrap_or_else(|| "unknown".into()),
            os: read_os_release("PRETTY_NAME").unwrap_or_else(|| {
                read_first_line("/etc/os-release").unwrap_or_else(|| "unknown".into())
            }),
            kernel: read_first_line("/proc/sys/kernel/osrelease")
                .unwrap_or_else(|| "unknown".into()),
            cpu_model: cpu_model().unwrap_or_else(|| std::env::consts::ARCH.to_string()),
            cpus: std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(1),
            mem_total_bytes: read_mem_total().unwrap_or(0),
            profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    pub fn render(&self) -> String {
        format!(
            "hostname:    {}\nos:          {}\nkernel:      {}\ncpu:         {} ({} cpus)\nmemory:      {}\nprofile:     {} {}\n",
            self.hostname,
            self.os,
            self.kernel,
            self.cpu_model,
            self.cpus,
            if self.mem_total_bytes > 0 {
                format!(
                    "{:.1} GiB",
                    self.mem_total_bytes as f64 / 1024.0 / 1024.0 / 1024.0
                )
            } else {
                "unknown".into()
            },
            self.profile,
            self.version,
        )
    }

    pub fn json(&self) -> Value {
        json!({
            "hostname": self.hostname,
            "os": self.os,
            "kernel": self.kernel,
            "cpu_model": self.cpu_model,
            "cpus": self.cpus,
            "mem_total_bytes": self.mem_total_bytes,
            "profile": self.profile,
            "version": self.version,
        })
    }
}

fn read_first_line(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_os_release(key: &str) -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix(&format!("{key}=")) {
            return Some(v.trim_matches('"').to_string());
        }
    }
    None
}

fn cpu_model() -> Option<String> {
    let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("model name") {
            return Some(v.trim().trim_start_matches(':').trim().to_string())
                .filter(|s| !s.is_empty());
        }
        if let Some(v) = line.strip_prefix("Hardware") {
            return Some(v.trim().trim_start_matches(':').trim().to_string())
                .filter(|s| !s.is_empty());
        }
    }
    None
}

fn read_mem_total() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Resident set size of this process in bytes (0 when unavailable).
pub fn resident_memory_bytes() -> u64 {
    let text = match std::fs::read_to_string("/proc/self/status") {
        Ok(t) => t,
        Err(_) => return 0,
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

/// Open file descriptors of this process (0 when unavailable).
pub fn open_fd_count() -> u64 {
    std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count() as u64)
        .unwrap_or(0)
}

/// Cumulative user+system CPU time of this process in clock ticks
/// (`USER_HZ`, 100 on every mainstream Linux), from `/proc/self/stat`.
pub fn cpu_ticks() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/stat").ok()?;
    // Fields 14 (utime) and 15 (stime); the comm field (2) may contain
    // spaces/parens, so parse after the closing paren.
    let rest = text.rsplit(')').next()?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After `)` the first field is state (field 3); utime/stime are fields
    // 14/15 => indices 11/12 in this slice.
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_never_panics_and_reports_cpus() {
        let info = SystemInfo::collect();
        assert!(info.cpus >= 1);
        assert!(!info.render().is_empty());
        assert!(info.json()["cpus"].as_u64().is_some());
    }

    #[test]
    fn runtime_gauges_are_readable_on_linux() {
        #[cfg(target_os = "linux")]
        {
            assert!(cpu_ticks().is_some(), "expected /proc/self/stat");
            assert!(open_fd_count() > 0, "expected open fds");
            assert!(resident_memory_bytes() > 0, "expected VmRSS");
        }
    }
}
