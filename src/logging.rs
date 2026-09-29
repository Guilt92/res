//! Structured logging setup.

use crate::config::{LogFormat, LoggingConfig};

/// Initialise global tracing. Safe to call once per process; tests use
/// [`try_init`] semantics so repeated calls are non-fatal.
pub fn init(cfg: &LoggingConfig) {
    let filter = tracing_subscriber::EnvFilter::try_new(&cfg.filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true);

    let _ = match cfg.format {
        LogFormat::Json => builder.json().try_init(),
        LogFormat::Pretty => builder.try_init(),
    };
}
