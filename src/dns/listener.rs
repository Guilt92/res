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
                        shared.metrics.udp_packets_received_total.inc();
                        shared.metrics.observe_request_bytes(n);
                        let rt = shared.rt.load();
                        if n > rt.max_udp_packet_size {
                            shared.metrics.oversized_packets_total.inc();
                            tracing::debug!(event = "oversized_packet", transport = "udp", len = n, max = rt.max_udp_packet_size);
                            continue;
                        }
                        let max_inflight = rt.max_inflight_udp;
                        drop(rt);

                        let Some(guard) = inflight.try_acquire(max_inflight) else {
                            shared.metrics.overload_dropped_total.inc();
                            shared.note_system_event(
                                "overload_dropped",
                                serde_json::json!({ "transport": "udp", "max_inflight": max_inflight }),
                            );
                            tracing::debug!(event = "overload_dropped", transport = "udp");
                            continue;
                        };

                        let data = buf[..n].to_vec();
                        let pipeline = Arc::clone(&pipeline);
                        let sock = Arc::clone(&sock);
                        set.spawn(async move {
                            let _guard = guard;
                            if let Some(resp) = pipeline.handle(peer, Transport::Udp, data).await {
                                match sock.send_to(&resp, peer).await {
                                    Ok(_) => {
                                        pipeline.shared.metrics.udp_packets_sent_total.inc();
                                        pipeline
                                            .shared
                                            .metrics
                                            .observe_response_bytes(resp.len());
                                    }
                                    Err(e) => {
                                        // Never swallow a failed reply: without
                                        // this counter a broken client route is
                                        // invisible (queries look served).
                                        pipeline.shared.metrics.udp_send_errors_total.inc();
                                        tracing::debug!(
                                            event = "udp_send_failed",
                                            error = %e,
                                            client = %pipeline.shared.client_label(peer.ip()),
                                        );
                                    }
                                }
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
                            tracing::warn!(
                                event = "tcp_connection_rejected",
                                client = %shared.client_label(peer.ip()),
                            );
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
            tracing::debug!(
                event = "tcp_malformed_frame",
                client = %shared.client_label(peer.ip()),
                len
            );
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
        shared.metrics.observe_request_bytes(len);

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
            shared.metrics.observe_response_bytes(resp.len());
        }
        served += 1;
    }

    tracing::debug!(
        event = "tcp_connection_closed",
        client = %shared.client_label(peer.ip()),
        served
    );
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
    let client = shared.client_label(peer.ip());
    match outcome {
        ReadOutcome::Timeout => {
            tracing::debug!(event = "tcp_connection_idle_timeout", client = %client, served);
        }
        ReadOutcome::Io => {
            tracing::debug!(event = "tcp_connection_closed_early", client = %client, served);
        }
        ReadOutcome::Shutdown => {
            tracing::debug!(event = "tcp_connection_drained", client = %client, served);
        }
        ReadOutcome::Done => {}
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::AppConfig;
    use crate::dns::msg::{self, Rcode};

    /// Poll a condition for up to ~2s (metrics are written by sibling tasks).
    async fn wait_for(mut f: impl FnMut() -> bool) {
        for _ in 0..200 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not met within 2s");
    }

    async fn start_udp(
        app: AppConfig,
    ) -> (
        Arc<Pipeline>,
        SocketAddr,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let shared = crate::shared::Shared::new(app).expect("shared state");
        let inflight = Arc::clone(&shared.udp_inflight);
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind udp"));
        let addr = sock.local_addr().expect("udp addr");
        let pipeline = Pipeline::new(shared);
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(run_udp(sock, Arc::clone(&pipeline), inflight, rx));
        (pipeline, addr, tx, task)
    }

    async fn start_tcp(
        app: AppConfig,
    ) -> (
        Arc<Pipeline>,
        SocketAddr,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let shared = crate::shared::Shared::new(app).expect("shared state");
        let connections = Arc::clone(&shared.tcp_connections);
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.expect("bind tcp"));
        let addr = listener.local_addr().expect("tcp addr");
        let pipeline = Pipeline::new(shared);
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(run_tcp(listener, Arc::clone(&pipeline), connections, rx));
        (pipeline, addr, tx, task)
    }

    async fn stop(tx: watch::Sender<bool>, task: tokio::task::JoinHandle<()>) {
        let _ = tx.send(true);
        tokio::time::timeout(Duration::from_secs(6), task)
            .await
            .expect("listener must stop after shutdown")
            .expect("listener task must not panic");
    }

    async fn udp_ask(addr: SocketAddr, raw: &[u8], wait: Duration) -> Option<Vec<u8>> {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        sock.connect(addr).await.expect("connect");
        sock.send(raw).await.expect("send");
        let mut buf = vec![0u8; 65_535];
        match timeout(wait, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => Some(buf[..n].to_vec()),
            _ => None,
        }
    }

    async fn tcp_write(stream: &mut TcpStream, raw: &[u8]) {
        let mut frame = Vec::with_capacity(2 + raw.len());
        frame.extend_from_slice(&(raw.len() as u16).to_be_bytes());
        frame.extend_from_slice(raw);
        stream.write_all(&frame).await.expect("tcp write");
    }

    async fn tcp_read(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = usize::from(u16::from_be_bytes(len_buf));
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        Ok(body)
    }

    #[test]
    fn counter_acquires_up_to_max_then_rejects() {
        let c = Arc::new(Counter::default());
        let g1 = c.try_acquire(2).expect("first slot");
        let g2 = c.try_acquire(2).expect("second slot");
        assert!(c.try_acquire(2).is_none(), "max reached");
        assert_eq!(c.current(), 2);
        drop(g1);
        assert_eq!(c.current(), 1, "guard must release on drop");
        let g3 = c.try_acquire(2).expect("slot freed");
        assert_eq!(c.current(), 2);
        drop(g2);
        drop(g3);
        assert_eq!(c.current(), 0);
    }

    #[tokio::test]
    async fn udp_listener_replies_servfail_without_upstreams() {
        let (pipeline, addr, tx, task) = start_udp(AppConfig::default()).await;

        let raw = msg::build_query("example.com", "A").expect("query");
        let id = msg::parse_query(&raw).expect("parse query").id;
        let out = udp_ask(addr, &raw, Duration::from_secs(2))
            .await
            .expect("udp reply");
        let view = msg::parse_response(&out).expect("parse reply");
        assert_eq!(view.rcode, Rcode::ServFail);
        assert_eq!(view.id, id);

        assert_eq!(pipeline.shared.metrics.udp_packets_received_total.get(), 1);
        wait_for(|| pipeline.shared.metrics.udp_packets_sent_total.get() == 1).await;

        stop(tx, task).await;
    }

    #[tokio::test]
    async fn oversized_udp_packets_are_dropped_silently() {
        let mut app = AppConfig::default();
        app.server.max_udp_packet_size = 512;
        let (pipeline, addr, tx, task) = start_udp(app).await;

        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        sock.connect(addr).await.expect("connect");
        sock.send(&vec![0u8; 600]).await.expect("send junk");

        // The oversized datagram must produce no response at all.
        let mut buf = [0u8; 64];
        assert!(
            timeout(Duration::from_millis(300), sock.recv(&mut buf))
                .await
                .is_err(),
            "oversized packet must not be answered"
        );
        assert_eq!(pipeline.shared.metrics.oversized_packets_total.get(), 1);

        // The listener must still serve normal queries.
        let raw = msg::build_query("example.com", "A").expect("query");
        sock.send(&raw).await.expect("send query");
        let n = timeout(Duration::from_secs(2), sock.recv(&mut buf))
            .await
            .expect("valid query must be answered")
            .expect("valid query reply");
        let view = msg::parse_response(&buf[..n]).expect("parse reply");
        assert_eq!(view.rcode, Rcode::ServFail);
        assert_eq!(pipeline.shared.metrics.udp_packets_received_total.get(), 2);

        stop(tx, task).await;
    }

    #[tokio::test]
    async fn udp_overload_sheds_load_when_inflight_is_saturated() {
        let mut app = AppConfig::default();
        app.server.max_inflight_udp = 1;
        let (pipeline, addr, tx, task) = start_udp(app).await;

        // Occupy the single in-flight slot, as a slow query would.
        let held = pipeline
            .shared
            .udp_inflight
            .try_acquire(1)
            .expect("hold the slot");

        let raw = msg::build_query("example.com", "A").expect("query");
        assert!(
            udp_ask(addr, &raw, Duration::from_millis(300))
                .await
                .is_none(),
            "saturated listener must shed the query"
        );
        assert_eq!(pipeline.shared.metrics.overload_dropped_total.get(), 1);

        drop(held);
        let out = udp_ask(addr, &raw, Duration::from_secs(2))
            .await
            .expect("served after load shedding");
        let view = msg::parse_response(&out).expect("parse reply");
        assert_eq!(view.rcode, Rcode::ServFail);

        stop(tx, task).await;
    }

    #[tokio::test]
    async fn tcp_listener_serves_length_prefixed_frames() {
        let (pipeline, addr, tx, task) = start_tcp(AppConfig::default()).await;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let raw = msg::build_query("example.com", "A").expect("query");
        let id = msg::parse_query(&raw).expect("parse query").id;
        tcp_write(&mut stream, &raw).await;
        let body = timeout(Duration::from_secs(2), tcp_read(&mut stream))
            .await
            .expect("tcp reply must arrive")
            .expect("tcp reply bytes");
        let view = msg::parse_response(&body).expect("parse reply");
        assert_eq!(view.rcode, Rcode::ServFail);
        assert_eq!(view.id, id);
        assert_eq!(pipeline.shared.metrics.tcp_connections_total.get(), 1);

        drop(stream);
        stop(tx, task).await;
    }

    #[tokio::test]
    async fn tcp_connection_limit_rejects_excess_connections() {
        let mut app = AppConfig::default();
        app.server.max_tcp_connections = 1;
        let (pipeline, addr, tx, task) = start_tcp(app).await;

        // First connection is accepted and served (its handler keeps the
        // only slot occupied while it waits for the next frame).
        let mut first = TcpStream::connect(addr).await.expect("connect first");
        let raw = msg::build_query("example.com", "A").expect("query");
        tcp_write(&mut first, &raw).await;
        let body = timeout(Duration::from_secs(2), tcp_read(&mut first))
            .await
            .expect("first reply")
            .expect("first reply bytes");
        assert_eq!(
            msg::parse_response(&body).expect("parse").rcode,
            Rcode::ServFail
        );
        assert_eq!(pipeline.shared.metrics.tcp_connections_total.get(), 1);

        // Second connection exceeds the limit: accepted but immediately
        // dropped, so the client sees EOF without a single byte.
        let mut second = TcpStream::connect(addr).await.expect("connect second");
        let mut len_buf = [0u8; 2];
        let read = timeout(Duration::from_secs(2), second.read_exact(&mut len_buf)).await;
        assert!(
            matches!(&read, Ok(Err(_))),
            "rejected connection must see immediate EOF, got {read:?}"
        );
        assert_eq!(
            pipeline.shared.metrics.tcp_connections_rejected_total.get(),
            1
        );
        assert_eq!(pipeline.shared.metrics.tcp_connections_total.get(), 1);

        drop(first);
        drop(second);
        stop(tx, task).await;
    }

    #[tokio::test]
    async fn tcp_connection_closes_after_max_queries() {
        let mut app = AppConfig::default();
        app.server.max_queries_per_tcp_conn = 1;
        let (pipeline, addr, tx, task) = start_tcp(app).await;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let raw = msg::build_query("example.com", "A").expect("query");
        tcp_write(&mut stream, &raw).await;
        let body = timeout(Duration::from_secs(2), tcp_read(&mut stream))
            .await
            .expect("first reply")
            .expect("first reply bytes");
        assert_eq!(
            msg::parse_response(&body).expect("parse").rcode,
            Rcode::ServFail
        );

        // The server must close the connection instead of serving a second
        // query: the next read observes EOF.
        let read = timeout(Duration::from_secs(2), tcp_read(&mut stream)).await;
        assert!(
            matches!(&read, Ok(Err(_))),
            "connection must close after max_queries_per_tcp_conn, got {read:?}"
        );
        assert_eq!(pipeline.shared.metrics.tcp_connections_total.get(), 1);

        drop(stream);
        stop(tx, task).await;
    }
}
