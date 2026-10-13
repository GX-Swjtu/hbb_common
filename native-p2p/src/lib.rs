//! Opt-in wire extension; no dependency on desktop capture, Flutter or a running frpc.
pub mod coordinator;
pub mod hole;
pub mod protocol;
pub mod stun;
pub mod strategy;
pub mod transport;
pub mod candidates;
pub mod interfaces;
mod probe_packet;

#[path = "../../src/bytes_codec.rs"]
pub mod bytes_codec;
pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}

pub const VERSION: u32 = 1;
pub const CAPABILITY: &str = "native-udp-punch";
pub const MAX_PUBLIC_IPS: usize = 4;
pub const MAX_LOCAL: usize = 8;
pub const MAX_PACKETS: usize = 8192;
pub const RANDOM_TARGETS: usize = 1000;
pub const MAX_MESSAGE: usize = 16 * 1024;
pub const ATTEMPT_SECONDS: u64 = 45;
pub const STUN_SERVER: &str = "stun.easyvoip.com:3478";

pub fn init() -> anyhow::Result<()> {
    sodiumoxide::init().map_err(|_| anyhow::anyhow!("libsodium initialization failed"))
}
