//! Opt-in wire extension; no dependency on desktop capture, Flutter or a running frpc.
pub mod coordinator;
pub mod hole;
pub mod protocol;
pub mod stun;
pub mod transport;

#[path = "../../src/bytes_codec.rs"]
pub mod bytes_codec;
pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}

pub const VERSION: u32 = 1;
pub const MAX_MESSAGE: usize = 16 * 1024;
pub const ATTEMPT_SECONDS: u64 = 45;
pub const STUN_SERVER: &str = "stun.easyvoip.com:3478";

pub fn init() -> anyhow::Result<()> {
    sodiumoxide::init().map_err(|_| anyhow::anyhow!("libsodium initialization failed"))
}
