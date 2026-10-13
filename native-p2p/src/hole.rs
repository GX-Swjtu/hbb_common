use crate::{candidates::{self, Interface}, probe_packet::{packet, verified}, strategy::{self, Behavior, Mode}, protocol::Plan, MAX_PACKETS, RANDOM_TARGETS};
use anyhow::{bail, ensure, Context, Result};
use sodiumoxide::{crypto::auth, randombytes::{randombytes, randombytes_uniform}};
use std::{collections::HashSet, net::{IpAddr, SocketAddr}, sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}}, time::Duration};
use tokio::{net::UdpSocket, task::JoinSet, time::{sleep, timeout_at, Instant}};

#[derive(Default)]
pub struct Budget(AtomicUsize);
impl Budget {
    pub fn sent(&self) -> usize { self.0.load(Ordering::Relaxed) }
    fn take(&self) -> Result<()> {
        self.0.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| (n < MAX_PACKETS).then_some(n + 1))
            .map(|_| ()).map_err(|_| anyhow::anyhow!("native UDP packet budget exhausted"))
    }
}

struct RestoreTtl<'a>(&'a UdpSocket, u32);
impl Drop for RestoreTtl<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.0.set_ttl(self.1) { log::trace!("native UDP restore TTL: {e}"); }
    }
}

async fn send(socket: &UdpSocket, bytes: &[u8], target: SocketAddr, ttl: u32, budget: &Budget) -> Result<()> {
    budget.take()?;
    let restore = if ttl > 0 { let old = socket.ttl()?; socket.set_ttl(ttl)?; Some(RestoreTtl(socket, old)) } else { None };
    if let Err(e) = socket.send_to(bytes, target).await { log::trace!("native UDP probe send: {e}"); }
    drop(restore);
    Ok(())
}

pub fn random_targets(ips: &[IpAddr]) -> Result<Vec<SocketAddr>> {
    ensure!(!ips.is_empty() && ips.len() <= crate::MAX_PUBLIC_IPS, "invalid random probe exits");
    let mut used = HashSet::new();
    let mut targets = Vec::with_capacity(RANDOM_TARGETS);
    for _ in 0..RANDOM_TARGETS * 16 {
        let port = 1024 + randombytes_uniform(65535 - 1024) as u16;
        let target = SocketAddr::new(ips[targets.len() % ips.len()], port);
        if used.insert(target) { targets.push(target); }
        if targets.len() == RANDOM_TARGETS { return Ok(targets); }
    }
    bail!("random target generation exhausted")
}

pub async fn punch(
    socket: Arc<UdpSocket>, session: &str, sender: bool, plan: &Plan, secret: &[u8],
    interfaces: &[Interface], deadline: Instant,
) -> Result<(Arc<UdpSocket>, SocketAddr)> {
    ensure!(session.len() == 32, "invalid native UDP session");
    plan.peer.validate()?;
    plan.behavior.validate()?;
    let key = auth::Key::from_slice(secret).context("invalid probe key")?;
    let nonce = randombytes(16);
    let data = packet(session, false, &nonce, &key)?;
    let budget = Arc::new(Budget::default());
    // LAN and WAN share the same probe window, while KCP keeps its reserved time.
    let deadline = deadline.checked_sub(Duration::from_secs(3)).context("KCP budget unavailable")?
        .min(Instant::now() + Duration::from_secs(38));
    ensure!(Instant::now() < deadline, "no native UDP probe budget");
    timeout_at(deadline, async {
        let lan = candidates::on_link(interfaces, &plan.peer.local);
        if !lan.is_empty() {
            let end = deadline.min(Instant::now() + Duration::from_millis(750));
            let direct = Behavior { mode: Mode::Direct, ttl: 0, delay_ms: 0, reversed: false };
            // Both peers use the negotiated direction; only exact on-link endpoints are eligible.
            let result = exchange(socket.clone(), session, sender, &lan, &lan, &key, &nonce, &data,
                direct, budget.clone(), Arc::new(AtomicBool::new(false)), end).await;
            match result {
                Ok(winner) => { log::info!("native-p2p UDP LAN confirmed, probes={}", budget.sent()); return Ok(winner); }
                Err(e) => log::trace!("native UDP LAN attempt: {e}"),
            }
        }
        ensure!(!plan.lan_only, "native UDP has no eligible WAN strategy after LAN probe");
        let end = deadline.min(Instant::now() + plan.behavior.window());
        let targets = match (plan.behavior.mode, sender) {
            (Mode::Predict, false) | (Mode::BothPredict, _) => strategy::predictions(&plan.peer.public, 10),
            (Mode::Mixed, false) => strategy::predictions(&plan.peer.public, 2),
            _ => plan.peer.public.clone(),
        };
        ensure!(!targets.is_empty(), "native UDP prediction lacks evidence");
        let mut sockets = vec![socket];
        if !sender && matches!(plan.behavior.mode, Mode::Birthday | Mode::Mixed) {
            for _ in 0..256 { sockets.push(Arc::new(UdpSocket::bind("0.0.0.0:0").await?)); }
        }
        let claim = Arc::new(AtomicBool::new(false));
        let mut readers = JoinSet::new();
        for socket in sockets {
            let session = session.to_owned();
            let targets = targets.clone();
            let allowed = plan.peer.public.clone();
            let (key, nonce, data, budget, claim) = (key.clone(), nonce.clone(), data.clone(), budget.clone(), claim.clone());
            let behavior = plan.behavior;
            readers.spawn(async move {
                exchange(socket, &session, sender, &targets, &allowed, &key, &nonce, &data, behavior, budget, claim, end).await
            });
        }
        while let Some(result) = timeout_at(end, readers.join_next()).await? {
            if let Ok(Ok(winner)) = result {
                readers.abort_all();
                while readers.join_next().await.is_some() {}
                log::info!("native-p2p UDP {:?} confirmed, probes={}", plan.behavior, budget.sent());
                return Ok(winner);
            }
        }
        bail!("native UDP probe window ended")
    }).await?
}

#[allow(clippy::too_many_arguments)]
async fn exchange(
    socket: Arc<UdpSocket>, session: &str, sender: bool, targets: &[SocketAddr], allowed: &[SocketAddr],
    key: &auth::Key, nonce: &[u8], data: &[u8], behavior: Behavior,
    budget: Arc<Budget>, claim: Arc<AtomicBool>, deadline: Instant,
) -> Result<(Arc<UdpSocket>, SocketAddr)> {
    if !sender {
        for target in targets {
            timeout_at(deadline, send(&socket, data, *target, behavior.ttl, &budget)).await??;
            if matches!(behavior.mode, Mode::Predict | Mode::BothPredict | Mode::Mixed) { sleep(Duration::from_millis(2)).await; }
        }
    }
    // Repeated observed IPs weight the shared budget toward the actual UDP exits.
    let ips: Vec<_> = allowed.iter().map(SocketAddr::ip).collect();
    let random = sender && matches!(behavior.mode, Mode::Birthday | Mode::Mixed);
    let random_targets = if random { random_targets(&ips)? } else { Vec::new() };
    let start = Instant::now() + Duration::from_millis(u64::from(behavior.delay_ms));
    let mut interval = tokio::time::interval_at(start, Duration::from_millis(if random { 15 } else { 200 }));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut sent = 0;
    let mut buffer = [0u8; 1500];
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => bail!("native UDP {:?} timed out", behavior.mode),
            _ = interval.tick(), if sender && sent < if random { RANDOM_TARGETS + 1 } else { 25 } => {
                if random && sent > 0 { send(&socket, data, random_targets[sent - 1], 0, &budget).await?; }
                else { for target in targets { send(&socket, data, *target, 0, &budget).await?; } }
                sent += 1;
            },
            received = socket.recv_from(&mut buffer) => {
                let (n, peer) = match received {
                    Ok(v) => v,
                    Err(e) => { log::trace!("native UDP receive: {e}"); sleep(Duration::from_millis(10)).await; continue; }
                };
                // Local addresses have exact-port checks; public NAT responses may rewrite ports.
                if !allowed.iter().any(|a| if candidates::public_ip(a.ip()) { a.ip() == peer.ip() } else { *a == peer }) { continue; }
                if sender {
                    if verified(&buffer[..n], session, true, key) != Some(nonce) { continue; }
                } else {
                    let Some(peer_nonce) = verified(&buffer[..n], session, false, key) else { continue; };
                    if peer_nonce == nonce || claim.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed).is_err() { continue; }
                    let answer = packet(session, true, peer_nonce, key)?;
                    for _ in 0..3 {
                        timeout_at(deadline, send(&socket, &answer, peer, 0, &budget)).await??;
                        sleep(Duration::from_millis(15)).await;
                    }
                }
                socket.connect(peer).await?;
                return Ok((socket, peer));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn exchanges_preserve_sockets_ttl_and_reject_our_own_authenticated_primer() {
        crate::init().unwrap();
        for mode in [Mode::Direct, Mode::Predict, Mode::Birthday, Mode::BothPredict, Mode::Mixed] {
            let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let session = crate::protocol::id();
            let key = auth::gen_key();
            let nonce_a = randombytes(16);
            let nonce_b = randombytes(16);
            let data_a = packet(&session, false, &nonce_a, &key).unwrap();
            let data_b = packet(&session, false, &nonce_b, &key).unwrap();
            b.send_to(&data_b, b.local_addr().unwrap()).await.unwrap();
            let ttl = b.ttl().unwrap();
            let behavior = Behavior { mode, ttl: 7, delay_ms: 0, reversed: false };
            let deadline = Instant::now() + Duration::from_secs(3);
            let addr_a = [a.local_addr().unwrap()];
            let addr_b = [b.local_addr().unwrap()];
            let allowed_b = [a.local_addr().unwrap(), b.local_addr().unwrap()];
            let (left, right) = tokio::join!(
                exchange(a.clone(), &session, true, &addr_b, &addr_b, &key, &nonce_a, &data_a, behavior, Arc::new(Budget::default()), Arc::new(AtomicBool::new(false)), deadline),
                exchange(b.clone(), &session, false, &addr_a, &allowed_b, &key, &nonce_b, &data_b, behavior, Arc::new(Budget::default()), Arc::new(AtomicBool::new(false)), deadline),
            );
            let (left, peer_a) = left.unwrap();
            let (right, peer_b) = right.unwrap();
            assert_eq!(peer_a, b.local_addr().unwrap());
            assert_eq!(peer_b, a.local_addr().unwrap());
            assert_eq!(b.ttl().unwrap(), ttl);
            left.send(b"retained-data").await.unwrap();
            let mut buffer = [0; 1500];
            loop {
                let n = timeout_at(deadline, right.recv(&mut buffer)).await.unwrap().unwrap();
                if &buffer[..n] == b"retained-data" { break; }
            }
            drop((left, right));
            assert_eq!(Arc::strong_count(&a), 1);
            assert_eq!(Arc::strong_count(&b), 1);
        }
    }
    #[test]
    fn multi_exit_random_targets_and_total_packets_share_fixed_budgets() {
        crate::init().unwrap();
        let ips = ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"].map(|a| a.parse().unwrap());
        let targets = random_targets(&ips).unwrap();
        assert_eq!(targets.iter().collect::<HashSet<_>>().len(), RANDOM_TARGETS);
        for ip in ips { assert_eq!(targets.iter().filter(|a| a.ip() == ip).count(), 250); }
        let weighted = random_targets(&[ips[0], ips[1], ips[1], ips[1]]).unwrap();
        assert_eq!(weighted.iter().filter(|a| a.ip() == ips[1]).count(), 750);
        assert_eq!(weighted.iter().collect::<HashSet<_>>().len(), RANDOM_TARGETS);
        assert!(targets.iter().all(|a| (1024..=65534).contains(&a.port())));
        let budget = Budget::default();
        for _ in 0..MAX_PACKETS { budget.take().unwrap(); }
        assert!(budget.take().is_err());
        assert_eq!(budget.sent(), MAX_PACKETS);
    }
}
