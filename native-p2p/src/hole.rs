use crate::{protocol::Plan, strategy::{self, Mode}};
use anyhow::{bail, ensure, Context, Result};
use sodiumoxide::{
    crypto::auth,
    randombytes::{randombytes, randombytes_uniform},
};
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::UdpSocket,
    task::JoinSet,
    time::{sleep, timeout_at, Instant},
};

const MAGIC: &[u8] = b"RDP2PV1\0";
const BODY: usize = 8 + 32 + 1 + 16;
pub const EXTRA_SOCKETS: usize = 256;
pub const RANDOM_PORTS: usize = 1000;

fn packet(session: &str, response: bool, nonce: &[u8], key: &auth::Key) -> Result<Vec<u8>> {
    ensure!(
        session.len() == 32 && nonce.len() == 16,
        "invalid probe context"
    );
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(session.as_bytes());
    out.push(u8::from(response));
    out.extend_from_slice(nonce);
    out.extend_from_slice(auth::authenticate(&out, key).as_ref());
    Ok(out)
}

fn verified<'a>(
    data: &'a [u8],
    session: &str,
    response: bool,
    key: &auth::Key,
) -> Option<&'a [u8]> {
    if data.len() != BODY + auth::TAGBYTES
        || &data[..8] != MAGIC
        || &data[8..40] != session.as_bytes()
        || data[40] != u8::from(response)
    {
        return None;
    }
    let tag = auth::Tag::from_slice(&data[BODY..])?;
    auth::verify(&tag, &data[..BODY], key).then_some(&data[41..BODY])
}

pub async fn punch(
    socket: Arc<UdpSocket>,
    plan: &Plan,
    secret: &[u8],
    deadline: Instant,
) -> Result<(Arc<UdpSocket>, SocketAddr)> {
    ensure!(
        plan.session.len() == 32 && (2..=4).contains(&plan.peer_addresses.len()),
        "invalid punch plan"
    );
    let key = auth::Key::from_slice(secret).context("invalid probe key")?;
    let peer_ip = plan.peer_addresses[0].ip();
    ensure!(
        plan.peer_addresses
            .iter()
            .all(|p| p.is_ipv4() && p.ip() == peer_ip && p.port() > 0),
        "invalid peer addresses"
    );
    let deadline = deadline.min(Instant::now() + Duration::from_secs(38));
    if let Some(strategy) = plan.strategy {
        strategy.validate()?;
        if strategy.mode == Mode::Predict {
            return predict(socket, plan, key, deadline.min(Instant::now() + Duration::from_secs(8))).await;
        }
    }
    if plan.sender {
        sender(socket, plan, key, deadline).await
    } else {
        receiver(socket, plan, key, deadline).await
    }
}

struct RestoreTtl<'a>(&'a UdpSocket, u32);

impl Drop for RestoreTtl<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.0.set_ttl(self.1) {
            log::trace!("native restore TTL: {error}");
        }
    }
}

async fn mapping_probe(socket: &UdpSocket, data: &[u8], targets: &[SocketAddr], ttl: u32) -> Result<()> {
    let restore = if ttl > 0 {
        let original = socket.ttl()?;
        socket.set_ttl(ttl)?;
        Some(RestoreTtl(socket, original))
    } else { None };
    for target in targets {
        if let Err(error) = socket.send_to(data, target).await {
            log::trace!("native mapping probe: {error}");
        }
    }
    drop(restore);
    Ok(())
}

async fn predict(
    socket: Arc<UdpSocket>,
    plan: &Plan,
    key: auth::Key,
    deadline: Instant,
) -> Result<(Arc<UdpSocket>, SocketAddr)> {
    let nonce = randombytes(16);
    let data = packet(&plan.session, false, &nonce, &key)?;
    let ttl = plan.strategy.context("prediction strategy absent")?.ttl;
    if plan.sender {
        // frp Mode 1 reverses Mode 2's roles: the HardNAT endpoint sends to EasyNAT.
        timeout_at(deadline, sleep(Duration::from_secs(2))).await?;
    } else {
        for port in strategy::predicted_ports(&plan.peer_addresses)? {
            let target = SocketAddr::new(plan.peer_addresses[0].ip(), port);
            timeout_at(deadline, mapping_probe(&socket, &data, &[target], ttl)).await??;
            timeout_at(deadline, sleep(Duration::from_millis(15))).await?;
        }
    }
    let mut interval = tokio::time::interval(Duration::from_millis(200));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut sent = 0;
    let mut buffer = [0u8; 1500];
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => bail!("Mode 1 timed out"),
            _ = interval.tick(), if plan.sender && sent < 20 => {
                mapping_probe(&socket, &data, &plan.peer_addresses, 0).await?;
                sent += 1;
            },
            received = socket.recv_from(&mut buffer) => {
                let (n, peer) = match received {
                    Ok(value) => value,
                    Err(error) => { log::trace!("native prediction receive: {error}"); sleep(Duration::from_millis(10)).await; continue; }
                };
                if peer.ip() != plan.peer_addresses[0].ip() { continue; }
                if plan.sender {
                    if verified(&buffer[..n], &plan.session, true, &key) != Some(nonce.as_slice()) { continue; }
                } else if let Some(peer_nonce) = verified(&buffer[..n], &plan.session, false, &key) {
                    // Port prediction can include our own mapping behind a shared
                    // public IP; an authenticated hairpin of our primer is not a peer.
                    if peer_nonce == nonce.as_slice() { continue; }
                    let answer = packet(&plan.session, true, peer_nonce, &key)?;
                    for _ in 0..3 {
                        socket.send_to(&answer, peer).await?;
                        timeout_at(deadline, sleep(Duration::from_millis(15))).await?;
                    }
                } else { continue; }
                socket.connect(peer).await?;
                return Ok((socket, peer));
            }
        }
    }
}

async fn sender(
    socket: Arc<UdpSocket>,
    plan: &Plan,
    key: auth::Key,
    deadline: Instant,
) -> Result<(Arc<UdpSocket>, SocketAddr)> {
    timeout_at(deadline, sleep(Duration::from_secs(3))).await?;
    let nonce = randombytes(16);
    let data = packet(&plan.session, false, &nonce, &key)?;
    for peer in &plan.peer_addresses {
        socket.send_to(&data, peer).await?;
    }
    let mut used = HashSet::new();
    let mut interval = tokio::time::interval(Duration::from_millis(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut buffer = [0u8; 1500];
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => bail!("Mode 2 sender timed out"),
            _ = interval.tick(), if used.len() < RANDOM_PORTS => {
                let port = loop {
                    let port = 1024 + randombytes_uniform(65535 - 1024) as u16;
                    if used.insert(port) { break port; }
                };
                let target = SocketAddr::new(plan.peer_addresses[0].ip(), port);
                if let Err(error) = socket.send_to(&data, target).await { log::trace!("native probe send: {error}"); }
            },
            received = socket.recv_from(&mut buffer) => {
                let (n, peer) = match received {
                    Ok(value) => value,
                    Err(error) => { log::trace!("native probe receive: {error}"); sleep(Duration::from_millis(10)).await; continue; }
                };
                if peer.ip() == plan.peer_addresses[0].ip()
                    && verified(&buffer[..n], &plan.session, true, &key) == Some(nonce.as_slice()) {
                    socket.connect(peer).await?;
                    return Ok((socket, peer));
                }
            }
        }
    }
}

async fn receiver(
    socket: Arc<UdpSocket>,
    plan: &Plan,
    key: auth::Key,
    deadline: Instant,
) -> Result<(Arc<UdpSocket>, SocketAddr)> {
    let mut sockets = vec![socket];
    for _ in 0..EXTRA_SOCKETS {
        sockets.push(Arc::new(UdpSocket::bind("0.0.0.0:0").await?));
    }
    let data = packet(&plan.session, false, &randombytes(16), &key)?;
    for socket in &sockets {
        mapping_probe(socket, &data, &plan.peer_addresses[..2], plan.strategy.map_or(7, |s| s.ttl)).await?;
    }
    let mut readers = JoinSet::new();
    for socket in sockets {
        let session = plan.session.clone();
        let key = key.clone();
        let peer_ip = plan.peer_addresses[0].ip();
        readers.spawn(async move {
            let mut buffer = [0u8; 1500];
            loop {
                let (n, peer) = match timeout_at(deadline, socket.recv_from(&mut buffer)).await {
                    Ok(Ok(value)) => value,
                    Ok(Err(_)) => {
                        sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                    Err(error) => return Err(anyhow::Error::from(error)),
                };
                if peer.ip() != peer_ip {
                    continue;
                }
                if let Some(nonce) = verified(&buffer[..n], &session, false, &key) {
                    let answer = packet(&session, true, nonce, &key)?;
                    // As in frp, the observed source replaces the STUN candidate. Repeat the
                    // answer before handing off; a single lost response must not lose the hole.
                    for _ in 0..3 {
                        socket.send_to(&answer, peer).await?;
                        sleep(Duration::from_millis(15)).await;
                    }
                    socket.connect(peer).await?;
                    return Ok((socket, peer));
                }
            }
        });
    }
    while let Some(result) = timeout_at(deadline, readers.join_next()).await? {
        if let Ok(Ok(winner)) = result {
            readers.abort_all();
            while readers.join_next().await.is_some() {}
            return Ok(winner);
        }
    }
    bail!("Mode 2 receiver timed out")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_authentication_binds_session_and_role() {
        crate::init().unwrap();
        let key = auth::gen_key();
        let session = crate::protocol::id();
        let nonce = randombytes(16);
        let mut bytes = packet(&session, false, &nonce, &key).unwrap();
        assert_eq!(
            verified(&bytes, &session, false, &key),
            Some(nonce.as_slice())
        );
        assert!(verified(&bytes, &session, true, &key).is_none());
        assert!(verified(&bytes, &crate::protocol::id(), false, &key).is_none());
        bytes[50] ^= 1;
        assert!(verified(&bytes, &session, false, &key).is_none());
    }

    #[tokio::test]
    async fn deadline_and_cancellation_release_receiver_sockets() {
        crate::init().unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let plan = Plan {
            session: crate::protocol::id(),
            sender: false,
            peer_addresses: vec![peer.local_addr().unwrap(); 2],
            strategy: None,
        };
        let secret = randombytes(32);
        let expired = punch(socket.clone(), &plan, &secret, Instant::now() + Duration::from_millis(150)).await;
        assert!(expired.is_err());
        // JoinSet aborts readers on drop; let their destructors run before checking ownership.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(Arc::strong_count(&socket), 1);
        let kept = socket.clone();
        let task = tokio::spawn(async move {
            punch(kept, &plan, &secret, Instant::now() + Duration::from_secs(30)).await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(Arc::strong_count(&socket), 1);
    }

    #[tokio::test]
    async fn both_modes_and_ttl_variants_keep_the_winning_socket_for_data() {
        crate::init().unwrap();
        for mode in [Mode::Predict, Mode::Birthday] {
            for ttl in [7, 4, 0] {
                let mut neighbors = None;
                for _ in 0..8 {
                    let easy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let port = easy.local_addr().unwrap().port();
                    if port == 65535 { continue; }
                    if let Ok(hard) = UdpSocket::bind(("127.0.0.1", port + 1)).await {
                        neighbors = Some((Arc::new(easy), Arc::new(hard)));
                        break;
                    }
                }
                let (easy, hard) = neighbors.expect("neighboring loopback ports available");
                let easy_ttl = easy.ttl().unwrap();
                let hard_ttl = hard.ttl().unwrap();
                let mut earlier = hard.local_addr().unwrap();
                earlier.set_port(earlier.port() - 1);
                let session = crate::protocol::id();
                let selected = Some(strategy::Strategy { mode, ttl });
                let easy_plan = Plan {
                    session: session.clone(), sender: mode == Mode::Birthday,
                    peer_addresses: vec![earlier, hard.local_addr().unwrap(), hard.local_addr().unwrap()],
                    strategy: selected,
                };
                let hard_plan = Plan {
                    session, sender: mode == Mode::Predict,
                    peer_addresses: vec![easy.local_addr().unwrap(); 3], strategy: selected,
                };
                let deadline = Instant::now() + Duration::from_secs(6);
                let secret = randombytes(32);
                let (a, b) = tokio::join!(punch(easy.clone(), &easy_plan, &secret, deadline), punch(hard.clone(), &hard_plan, &secret, deadline));
                let (a, _) = a.unwrap();
                let (b, _) = b.unwrap();
                // EasyNAT's own port is deliberately inside the prediction range.
                assert_ne!(a.local_addr().unwrap(), a.peer_addr().unwrap());
                assert_eq!(easy.ttl().unwrap(), easy_ttl);
                assert_eq!(hard.ttl().unwrap(), hard_ttl);
                a.send(b"application-data").await.unwrap();
                let mut buf = [0u8; 1500];
                loop {
                    let n = timeout_at(deadline, b.recv(&mut buf)).await.unwrap().unwrap();
                    if &buf[..n] == b"application-data" { break; }
                }
                drop((a, b));
                assert_eq!(Arc::strong_count(&easy), 1);
                assert_eq!(Arc::strong_count(&hard), 1);
            }
        }
    }
}
