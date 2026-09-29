//! Process orchestration: binds listeners, spawns background tasks, owns
//! graceful shutdown.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::api;
use crate::config::AppConfig;
use crate::dns::forward::Forwarder;
use crate::dns::listener;
use crate::dns::pipeline::Pipeline;
use crate::shared::Shared;
use crate::upstream::health;

pub struct Gateway {
    pub shared: Arc<Shared>,
    pub forwarder: Forwarder,
    shutdown: watch::Sender<bool>,
    tasks: Vec<(&'static str, JoinHandle<()>)>,
}

impl Gateway {
    /// Actual UDP listener address (useful when binding port 0 in tests).
    pub fn udp_addr(&self) -> Option<SocketAddr> {
        self.shared
            .bound
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .udp
    }

    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.shared
            .bound
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .tcp
    }

    pub fn api_addr(&self) -> Option<SocketAddr> {
        self.shared
            .bound
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .api
    }

    /// Signal shutdown and wait (bounded) for every task to finish.
    pub async fn shutdown(self) {
        tracing::info!(event = "shutdown_started");
        let grace = Duration::from_millis(self.shared.app.load().server.shutdown_grace_ms);
        let deadline = tokio::time::Instant::now() + grace + Duration::from_secs(2);
        let _ = self.shutdown.send(true);

        for (name, mut handle) in self.tasks {
            match tokio::time::timeout_at(deadline, &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!(event = "task_failed", task = name, error = %e);
                }
                Err(_) => {
                    tracing::warn!(event = "task_shutdown_timeout", task = name);
                    handle.abort();
                    let _ = handle.await;
                }
            }
        }

        tracing::info!(event = "shutdown_complete");
    }
}

/// Start the full gateway. Bind errors are fatal; nothing else is: the data
/// plane runs purely from the validated in-memory configuration.
pub async fn start(app: AppConfig, config_path: Option<PathBuf>) -> anyhow::Result<Gateway> {
    let shared = Shared::new(app)?;
    if let Some(p) = config_path {
        let _ = shared.config_path.set(p);
    }

    let forwarder = Forwarder::new(shared.app.load().server.upstream_tcp_fallback);
    let pipeline = Pipeline::new(Arc::clone(&shared), forwarder);

    // Bind listeners before spawning anything so startup failures are clean.
    let udp_addr = shared.rt.load().udp_addr;
    let udp_sock = UdpSocket::bind(udp_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind UDP {udp_addr}: {e}"))?;
    let tcp_addr = shared.rt.load().tcp_addr;
    let tcp_listener = TcpListener::bind(tcp_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind TCP {tcp_addr}: {e}"))?;
    let api_addr = shared.app.load().server.api_addr;
    let api_listener = TcpListener::bind(api_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind API {api_addr}: {e}"))?;

    {
        let mut bound = shared.bound.write().unwrap_or_else(|e| e.into_inner());
        bound.udp = Some(udp_sock.local_addr()?);
        bound.tcp = Some(tcp_listener.local_addr()?);
        bound.api = Some(api_listener.local_addr()?);
    }

    health::refresh_gauges(&shared, &shared.metrics);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks: Vec<(&'static str, JoinHandle<()>)> = Vec::with_capacity(8);

    tasks.push((
        "udp_listener",
        tokio::spawn(listener::run_udp(
            Arc::new(udp_sock),
            Arc::clone(&pipeline),
            Arc::clone(&shared.udp_inflight),
            shutdown_rx.clone(),
        )),
    ));
    tasks.push((
        "tcp_listener",
        tokio::spawn(listener::run_tcp(
            Arc::new(tcp_listener),
            Arc::clone(&pipeline),
            Arc::clone(&shared.tcp_connections),
            shutdown_rx.clone(),
        )),
    ));
    tasks.push((
        "health_checker",
        tokio::spawn(health::run_health_checker(
            Arc::clone(&shared),
            forwarder,
            shutdown_rx.clone(),
        )),
    ));
    tasks.push((
        "sampler",
        tokio::spawn(sampler(Arc::clone(&shared), shutdown_rx.clone())),
    ));

    let router = api::router(Arc::clone(&shared), forwarder);
    let api_shutdown = {
        let mut rx = shutdown_rx.clone();
        async move {
            let _ = rx.changed().await;
        }
    };
    tasks.push((
        "api_server",
        tokio::spawn(async move {
            if let Err(e) = axum::serve(api_listener, router)
                .with_graceful_shutdown(api_shutdown)
                .await
            {
                tracing::error!(event = "api_server_error", error = %e);
            }
        }),
    ));

    tracing::info!(
        event = "outisdns_started",
        version = env!("CARGO_PKG_VERSION"),
        udp = %shared.bound.read().unwrap_or_else(|e| e.into_inner()).udp.map(|a| a.to_string()).unwrap_or_default(),
        tcp = %shared.bound.read().unwrap_or_else(|e| e.into_inner()).tcp.map(|a| a.to_string()).unwrap_or_default(),
        api = %shared.bound.read().unwrap_or_else(|e| e.into_inner()).api.map(|a| a.to_string()).unwrap_or_default(),
        upstreams = shared.registry.len(),
    );

    Ok(Gateway {
        shared,
        forwarder,
        shutdown: shutdown_tx,
        tasks,
    })
}

/// Once-per-second sampler: QPS derivation plus operational gauges
/// (in-flight counts, RSS). Deliberately off the query hot path.
async fn sampler(shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tick.tick() => {
                let m = &shared.metrics;
                let total = m.queries_total.with_label_values(&["udp"]).get()
                    + m.queries_total.with_label_values(&["tcp"]).get();
                shared.qps.sample(total);
                m.udp_inflight.set(shared.udp_inflight.current() as i64);
                m.tcp_connections.set(shared.tcp_connections.current() as i64);
                m.resident_memory_bytes.set(resident_memory_bytes() as i64);
            }
        }
    }
}

/// Resident set size of this process in bytes (0 when unavailable).
fn resident_memory_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    let kb: u64 = rest
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    return kb * 1024;
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}
