//! OutisDNS binary: `serve` (default) and `probe` subcommands.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

use outisdns::config::{AppConfig, Protocol, UpstreamConfig};
use outisdns::dns::forward::Forwarder;
use outisdns::dns::msg::{self, Rcode};
use outisdns::runtime;

#[derive(Parser, Debug)]
#[command(
    name = "outisdns",
    version,
    about = "OutisDNS - health-aware DNS gateway/proxy",
    long_about = "OutisDNS is a from-scratch DNS gateway: it listens for DNS over UDP/TCP, \
validates requests, applies ACLs and rate limits, selects a healthy upstream, forwards the \
query with bounded failover, and exposes metrics/API. It is not a recursive resolver and does \
not use any external DNS server as its gateway."
)]
struct Cli {
    /// Path to the TOML configuration file
    #[arg(long, global = true, default_value = "config/outisdns.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the DNS gateway, health checker and control-plane API (default).
    Serve,
    /// Send a single DNS query to a server and report the result.
    ///
    /// Useful as a container health check: exit code 0 means a DNS response
    /// was received (add --require-ok to demand NOERROR/NXDOMAIN).
    Probe {
        /// Target server address (ip:port).
        #[arg(long, default_value = "127.0.0.1:53")]
        server: SocketAddr,
        /// Use TCP instead of UDP.
        #[arg(long)]
        tcp: bool,
        /// Timeout in milliseconds.
        #[arg(long, default_value_t = 2000)]
        timeout_ms: u64,
        /// Query name.
        #[arg(long, default_value = "example.com")]
        name: String,
        /// Query type (A, AAAA, NS, ...).
        #[arg(long, default_value = "A")]
        qtype: String,
        /// Require a successful rcode (NOERROR/NXDOMAIN) instead of any response.
        #[arg(long)]
        require_ok: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::Serve) {
        Commands::Serve => serve(cli.config).await,
        Commands::Probe {
            server,
            tcp,
            timeout_ms,
            name,
            qtype,
            require_ok,
        } => probe(server, tcp, timeout_ms, name, qtype, require_ok).await,
    }
}

async fn serve(path: PathBuf) -> anyhow::Result<()> {
    // A broken configuration file must never keep the gateway from starting:
    // fall back to `<file>.backup`, then to built-in defaults, and surface the
    // problem via /api/status, /api/diagnostics and a startup log line.
    let loaded = AppConfig::load_with_fallback(&path);
    if let Some(err) = &loaded.error {
        eprintln!(
            "outisdns: config {} rejected ({}), using {}",
            path.display(),
            err,
            loaded.source
        );
    }

    outisdns::logging::init(&loaded.config.logging);
    tracing::info!(
        event = "starting",
        version = env!("CARGO_PKG_VERSION"),
        config = %path.display(),
        config_source = loaded.source,
        config_error = ?loaded.error,
    );
    for w in loaded.config.warnings() {
        tracing::warn!(event = "config_warning", warning = %w);
    }

    let gateway = runtime::start(loaded.config, Some(path.clone())).await?;

    if loaded.source != "file" || loaded.error.is_some() {
        gateway.shared.metrics.config_errors_total.inc();
        gateway.shared.record_config_event(
            "startup_fallback",
            serde_json::json!({
                "source": loaded.source,
                "path": path.display().to_string(),
                "error": loaded.error,
            }),
        );
    }
    gateway.shared.set_config_state(loaded.source, loaded.error);
    gateway.shared.record_config_event(
        "startup",
        serde_json::json!({ "path": path.display().to_string() }),
    );

    // Graceful shutdown on SIGINT/SIGTERM (unix targets; ctrl_c elsewhere).
    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!(event = "signal_received", signal = "SIGINT");
            }
            _ = sigterm.recv() => {
                tracing::info!(event = "signal_received", signal = "SIGTERM");
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        tracing::info!(event = "signal_received", signal = "SIGINT");
    }

    gateway.shutdown().await;
    Ok(())
}

async fn probe(
    server: SocketAddr,
    tcp: bool,
    timeout_ms: u64,
    name: String,
    qtype: String,
    require_ok: bool,
) -> anyhow::Result<()> {
    let up = UpstreamConfig {
        id: 0,
        name: "probe".into(),
        address: server.ip(),
        port: server.port(),
        protocol: if tcp { Protocol::Tcp } else { Protocol::Udp },
        enabled: true,
        priority: 1,
        weight: 1,
        timeout_ms: None,
    };
    let raw = msg::build_query(&name, &qtype).map_err(|e| anyhow::anyhow!("{e}"))?;
    let parsed = msg::parse_query(&raw).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let forwarder = Forwarder::new(true);

    let started = Instant::now();
    match forwarder
        .exchange(&up, &parsed, &raw, Duration::from_millis(timeout_ms))
        .await
    {
        Ok(ok) => {
            let latency = started.elapsed().as_secs_f64() * 1000.0;
            let usable = matches!(ok.view.rcode, Rcode::NoError | Rcode::NXDomain);
            println!(
                "probe {} {} {} rcode={} latency={:.1}ms bytes={}",
                if usable { "OK" } else { "RESPONDED" },
                up.protocol,
                server,
                ok.view.rcode.as_str(),
                latency,
                ok.response.len(),
            );
            if require_ok && !usable {
                anyhow::bail!("rcode {} is not usable", ok.view.rcode.as_str());
            }
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "probe FAILED {} {} after {:.1}ms: {e}",
                up.protocol,
                server,
                started.elapsed().as_secs_f64() * 1000.0
            );
            Err(anyhow::anyhow!("probe failed: {e}"))
        }
    }
}
