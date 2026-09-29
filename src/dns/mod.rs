//! DNS data plane: listeners, query pipeline, forwarding, message handling.

pub mod forward;
pub mod listener;
pub mod msg;
pub mod pipeline;

/// Transport a client query arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}
