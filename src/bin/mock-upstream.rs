//! Minimal local DNS responder for reproducible end-to-end benchmarks.
//!
//! Answers every query immediately (NOERROR + A 127.0.0.1) with optional
//! injected latency and packet loss, so gateway performance can be measured
//! without depending on external resolvers.

use std::time::Duration;

use clap::Parser;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Parser, Debug)]
#[command(about = "Local mock DNS upstream for benchmarking")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:5300")]
    listen: String,
    /// Artificial response latency in milliseconds.
    #[arg(long, default_value_t = 0)]
    latency_ms: u64,
    /// Probability (0.0-1.0) of silently dropping a query.
    #[arg(long, default_value_t = 0.0)]
    loss: f64,
}

fn build_response(query: &Message) -> Vec<u8> {
    let mut resp = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NoError;
    for q in query.queries.clone() {
        if q.query_type() == RecordType::A || q.query_type() == RecordType::ANY {
            resp.answers.push(Record::from_rdata(
                q.name().clone(),
                60,
                RData::A(hickory_proto::rr::rdata::A::new(127, 0, 0, 1)),
            ));
        }
        resp.queries.push(q);
    }
    resp.to_vec().unwrap_or_default()
}

fn should_drop(loss: f64) -> bool {
    loss > 0.0 && fastrand::f64() < loss
}

async fn maybe_delay(ms: u64) {
    if ms > 0 {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let listen: std::net::SocketAddr = args.listen.parse()?;
    let udp = UdpSocket::bind(listen).await?;
    let tcp = TcpListener::bind(listen).await?;
    eprintln!(
        "mock-upstream listening on {} (latency_ms={}, loss={})",
        listen, args.latency_ms, args.loss
    );

    let latency = args.latency_ms;
    let loss = args.loss;

    let udp_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = udp.recv_from(&mut buf).await else {
                break;
            };
            let data = buf[..n].to_vec();
            let resp = match Message::from_vec(&data) {
                Ok(q) if !should_drop(loss) => {
                    maybe_delay(latency).await;
                    build_response(&q)
                }
                _ => continue,
            };
            let _ = udp.send_to(&resp, peer).await;
        }
    });

    {
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = tcp.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    loop {
                        let mut len_buf = [0u8; 2];
                        if sock.read_exact(&mut len_buf).await.is_err() {
                            break;
                        }
                        let len = u16::from_be_bytes(len_buf) as usize;
                        let mut body = vec![0u8; len];
                        if sock.read_exact(&mut body).await.is_err() {
                            break;
                        }
                        if should_drop(loss) {
                            continue;
                        }
                        maybe_delay(latency).await;
                        let resp = match Message::from_vec(&body) {
                            Ok(q) => build_response(&q),
                            Err(_) => continue,
                        };
                        let mut out = (resp.len() as u16).to_be_bytes().to_vec();
                        out.extend_from_slice(&resp);
                        if sock.write_all(&out).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }

    let _ = udp_task.await;
    Ok(())
}
