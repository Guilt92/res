//! UDP and TCP DNS listeners with bounded concurrency and graceful drain.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::dns::pipeline::Pipeline;
use crate::dns::Transport;

/// Shared, dynamically bounded concurrency counter.
#[derive(Default)]
pub struct Counter {
    count: AtomicUsize,
}

impl Counter {
    pub fn current(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Strictly acquire one slot if `max` is not yet reached.
    pub fn try_acquire(self: &Arc<Self>, max: usize) -> Option<LimitGuard> {
        let acquired = self
            .count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                if v < max {
                    Some(v + 1)
                } else {
                    None
                }
            })
            .is_ok();
        acquired.then(|| LimitGuard {
            counter: Arc::clone(self),
        })
    }
}

/// RAII slot; released on drop (including task panic).
pub struct LimitGuard {
    counter: Arc<Counter>,
}

impl Drop for LimitGuard {
    fn drop(&mut self) {
        self.counter.count.fetch_sub(1, Ordering::AcqRel);
    }
}

/// UDP DNS listener: one socket, one receive loop, bounded spawned handlers.
pub async fn run_udp(
    sock: Arc<UdpSocket>,
    pipeline: Arc<Pipeline>,
    inflight: Arc<Counter>,
    mut shutdown: watch::Receiver<bool>,
) {
    let shared = Arc::clone(&pipeline.shared);
    let mut set: JoinSet<()> = JoinSet::new();
    let mut buf = vec![0u8; 65_535];

    tracing::info!(event = "udp_listener_started", addr = %sock.local_addr().map(|a| a.to_string()).unwrap_or_default());

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            joined = set.join_next(), if !set.is_empty() => {
                if let Some(Err(e)) = joined {
                    tracing::warn!(event = "udp_task_failed", error = %e);
                }
            }
            received = sock.recv_from(&mut buf) => {
                match received {
                    Ok((n, peer)) => {
                        let rt = shared.rt.load();
                        if n > rt.max_udp_packet_size {
                            shared.metrics.malformed_total.inc();
                            tracing::debug!(event = "oversized_packet", transport = "udp", len = n, max = rt.max_udp_packet_size);
                            continue;
                        }
                        let max_inflight = rt.max_inflight_udp;
                        drop(rt);

                        let Some(guard) = inflight.try_acquire(max_inflight) else {
                            shared.metrics.overload_dropped_total.inc();
                            tracing::debug!(event = "overload_dropped", transport = "udp");
                            continue;
                        };

                        let data = buf[..n].to_vec();
                        let pipeline = Arc::clone(&pipeline);
                        let sock = Arc::clone(&sock);
                        set.spawn(async move {
                            let _guard = guard;
                            if let Some(resp) = pipeline.handle(peer, Transport::Udp, data).await {
                                let _ = sock.send_to(&resp, peer).await;
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(event = "udp_recv_error", error = %e);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        }
    }

    drain(set, &shared).await;
    tracing::info!(event = "udp_listener_stopped");
}

/// TCP DNS listener: length-prefixed frames, connection limits, idle timeouts.
pub async fn run_tcp(
    listener: Arc<TcpListener>,
    pipeline: Arc<Pipeline>,
    connections: Arc<Counter>,
    mut shutdown: watch::Receiver<bool>,
) {
    let shared = Arc::clone(&pipeline.shared);
    let mut set: JoinSet<()> = JoinSet::new();

    tracing::info!(event = "tcp_listener_started", addr = %listener.local_addr().map(|a| a.to_string()).unwrap_or_default());

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            joined = set.join_next(), if !set.is_empty() => {
                if let Some(Err(e)) = joined {
                    tracing::warn!(event = "tcp_task_failed", error = %e);
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let max_conn = shared.rt.load().max_tcp_connections;
                        let Some(guard) = connections.try_acquire(max_conn) else {
                            shared.metrics.tcp_connections_rejected_total.inc();
                            tracing::warn!(event = "tcp_connection_rejected", client = %peer);
                            drop(stream);
                            continue;
                        };
                        shared.metrics.tcp_connections_total.inc();
                        let pipeline = Arc::clone(&pipeline);
                        let shutdown = shutdown.clone();
                        set.spawn(async move {
                            handle_conn(stream, peer, pipeline, guard, shutdown).await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!(event = "tcp_accept_error", error = %e);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        }
    }

    drain(set, &shared).await;
    tracing::info!(event = "tcp_listener_stopped");
}

async fn handle_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    pipeline: Arc<Pipeline>,
    _guard: LimitGuard,
    mut shutdown: watch::Receiver<bool>,
) {
    let _ = stream.set_nodelay(true);
    let shared = Arc::clone(&pipeline.shared);
    let mut served: u32 = 0;

    loop {
        let rt = shared.rt.load();
        let max_queries = rt.max_queries_per_tcp_conn;
        let idle = rt.tcp_idle_timeout;
        drop(rt);

        if served >= max_queries {
            break;
        }

        // --- length prefix ---
        let mut len_buf = [0u8; 2];
        match read_with_deadline(&mut stream, &mut len_buf, idle, &mut shutdown).await {
            ReadOutcome::Done => {}
            outcome => {
                log_conn_end(outcome, &shared, peer, served);
                break;
            }
        }
        let len = usize::from(u16::from_be_bytes(len_buf));
        if len < 12 {
            shared.metrics.malformed_total.inc();
            tracing::debug!(event = "tcp_malformed_frame", client = %peer, len);
            break;
        }

        // --- body ---
        let mut frame = vec![0u8; len];
        match read_with_deadline(&mut stream, &mut frame, idle, &mut shutdown).await {
            ReadOutcome::Done => {}
            outcome => {
                log_conn_end(outcome, &shared, peer, served);
                break;
            }
        }

        if let Some(resp) = pipeline.handle(peer, Transport::Tcp, frame).await {
            if resp.len() > u16::MAX as usize {
                tracing::warn!(event = "tcp_response_too_large", len = resp.len());
                break;
            }
            let mut out = Vec::with_capacity(2 + resp.len());
            out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            out.extend_from_slice(&resp);
            let write = tokio::select! {
                _ = shutdown.changed() => ReadOutcome::Shutdown,
                r = timeout(idle, stream.write_all(&out)) => match r {
                    Ok(Ok(_)) => ReadOutcome::Done,
                    Ok(Err(_)) => ReadOutcome::Io,
                    Err(_) => ReadOutcome::Timeout,
                },
            };
            if write != ReadOutcome::Done {
                log_conn_end(write, &shared, peer, served);
                break;
            }
        }
        served += 1;
    }

    tracing::debug!(event = "tcp_connection_closed", client = %peer, served);
}

#[derive(PartialEq, Eq)]
enum ReadOutcome {
    Done,
    Timeout,
    Io,
    Shutdown,
}

async fn read_with_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    idle: Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> ReadOutcome {
    tokio::select! {
        _ = shutdown.changed() => ReadOutcome::Shutdown,
        r = timeout(idle, stream.read_exact(buf)) => match r {
            Ok(Ok(_)) => ReadOutcome::Done,
            Ok(Err(_)) => ReadOutcome::Io,
            Err(_) => ReadOutcome::Timeout,
        },
    }
}

fn log_conn_end(
    outcome: ReadOutcome,
    shared: &Arc<crate::shared::Shared>,
    peer: SocketAddr,
    served: u32,
) {
    match outcome {
        ReadOutcome::Timeout => {
            tracing::debug!(event = "tcp_connection_idle_timeout", client = %peer, served);
        }
        ReadOutcome::Io => {
            tracing::debug!(event = "tcp_connection_closed_early", client = %peer, served);
        }
        ReadOutcome::Shutdown => {
            tracing::debug!(event = "tcp_connection_drained", client = %peer, served);
        }
        ReadOutcome::Done => {}
    }
    let _ = shared;
}

/// Wait for in-flight tasks up to the configured grace period, then abort.
async fn drain(mut set: JoinSet<()>, shared: &Arc<crate::shared::Shared>) {
    let grace = Duration::from_millis(shared.app.load().server.shutdown_grace_ms);
    let drained = timeout(grace, async { while set.join_next().await.is_some() {} }).await;
    if drained.is_err() {
        tracing::warn!(event = "drain_timeout_aborting_inflight");
        let mut set = set;
        set.shutdown().await;
    }
}
