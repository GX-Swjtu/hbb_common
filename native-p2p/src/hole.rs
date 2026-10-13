use crate::protocol::Plan;
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
        plan.session.len() == 32 && plan.peer_addresses.len() == 2,
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
    if plan.sender {
        sender(socket, plan, key, deadline).await
    } else {
        receiver(socket, plan, key, deadline).await
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
        let original = socket.ttl()?;
        socket.set_ttl(7)?;
        let mut error = None;
        for peer in &plan.peer_addresses {
            if let Err(e) = socket.send_to(&data, peer).await {
                error = Some(e);
            }
        }
        socket.set_ttl(original)?;
        if let Some(error) = error {
            log::trace!("native mapping probe: {error}");
        }
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
}
