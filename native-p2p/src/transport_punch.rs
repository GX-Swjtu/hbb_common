use super::*;
use crate::candidates::{self, Candidates, Interface};
use std::net::{IpAddr, Ipv4Addr};

// Separate from the legacy RPC: only native UDP source observations bind physical addresses.
async fn observe(session: &Session, source: Option<Ipv4Addr>, limit: Duration) -> Result<()> {
    timeout(limit, async {
        let target = tokio::net::lookup_host(&session.endpoint).await?.find(SocketAddr::is_ipv4).context("no IPv4 coordinator")?;
        let socket = tokio::net::TcpSocket::new_v4()?;
        if let Some(ip) = source { socket.bind(SocketAddr::new(ip.into(), 0))?; }
        let request = request(&session.identity.id, Action::Observe { session: session.ticket.session.clone() })?;
        let message = envelope(encode(&request, &session.identity.key)?);
        let mut codec = BytesCodec::new();
        codec.set_max_packet_length(crate::MAX_MESSAGE);
        let mut stream = Framed::new(socket.connect(target).await?, codec);
        stream.send(message.write_to_bytes()?.into()).await?;
        let bytes = stream.next().await.context("native UDP coordinator closed")??;
        let message = RendezvousMessage::parse_from_bytes(&bytes)?;
        let Some(rendezvous::rendezvous_message::Union::NativeP2pV1(message)) = message.union else { bail!("native UDP observation unsupported"); };
        ensure!(message.version == crate::VERSION, "unknown native version");
        let response: Response = decode(&message.payload, &session.server)?;
        ensure!(response.nonce == request.nonce && now()?.abs_diff(response.time) <= 30, "native UDP response replay");
        ensure!(matches!(response.reply, Reply::Observed(ip) if candidates::public_ip(ip)), "native UDP observation declined");
        Ok(())
    }).await?
}

impl Session {
    async fn observe_exits(&self, interfaces: &[Interface]) {
        let mut sources = vec![None];
        for interface in interfaces.iter().take(3) { sources.push(Some(interface.address)); }
        while sources.len() < 4 { sources.push(None); }
        let deadline = self.deadline.min(Instant::now() + Duration::from_secs(2));
        let mut pending = futures_util::stream::FuturesUnordered::new();
        for source in sources { pending.push(observe(self, source, deadline.saturating_duration_since(Instant::now()))); }
        while let Some(result) = pending.next().await {
            if let Err(e) = result { log::trace!("native UDP optional exit observation: {e}"); }
        }
    }

    pub async fn punch(self, stun_server: &str) -> Result<Punched> {
        let interfaces = crate::interfaces::physical().unwrap_or_default();
        self.punch_on(stun_server, &interfaces).await
    }

    /// Compatibility entry point for finite diagnostics and existing callers.
    pub async fn punch_on(mut self, stun_server: &str, interfaces: &[Interface]) -> Result<Punched> {
        match self.probe(stun_server, interfaces, None).await {
            Ok((socket, peer, strategy)) => Ok(Punched { socket, peer, session: self, strategy }),
            Err(error) => { self.close().await; Err(error) }
        }
    }

    /// Borrows the lease so cancellation leaves its explicit cleanup with the owner.
    /// All probe futures are polled in this task; dropping this future drops their sockets.
    pub async fn probe(&self, stun_server: &str, interfaces: &[Interface], observer: crate::progress::Observer)
        -> Result<(Arc<UdpSocket>, SocketAddr, crate::strategy::Behavior)> {
        use crate::progress::{report, Progress};
        let deadline = self.deadline;
        timeout_at(deadline, async {
            report(&observer, Progress::Stage("network"));
            let (socket, addresses) = crate::stun::discover_profile(stun_server).await?;
            self.observe_exits(interfaces).await;
            let port = socket.local_addr()?.port();
            let direct = addresses.iter().find(|a| a.port() == port && interfaces.iter().any(|i| IpAddr::V4(i.address) == a.ip())).copied();
            let candidates = Candidates { public: addresses, local: candidates::local(interfaces, port), direct };
            log::info!("native-p2p UDP observations={:?}, profile={:?}, local_candidates={}", candidates.public, crate::strategy::classify(&candidates)?, candidates.local.len());
            report(&observer, Progress::Local(candidates.clone()));
            report(&observer, Progress::Stage("peer"));
            let mut action = Action::Prepare { session: self.ticket.session.clone(), candidates };
            let plan = loop {
                match rpc(&self.endpoint, &self.identity, &self.server, action, Duration::from_secs(2)).await? {
                    Reply::Plan(plan) => break plan,
                    Reply::Waiting => {}
                    Reply::Error(e) => bail!(e),
                    _ => bail!("native UDP session closed"),
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
                action = Action::Poll { session: self.ticket.session.clone() };
            };
            ensure!(plan.session == self.ticket.session, "invalid native plan");
            log::info!("native-p2p UDP selected strategy={:?}, sender={}", plan.behavior, plan.sender);
            report(&observer, Progress::Selected(plan.clone()));
            report(&observer, Progress::Stage("probe"));
            let (socket, peer) = tokio::select! {
                result = crate::hole::punch_observed(socket, &plan.session, plan.sender, &plan, &self.secret, interfaces, deadline, observer) => result?,
                result = self.wait_for_cancellation() => return Err(result),
            };
            Ok((socket, peer, plan.behavior))
        }).await?
    }
}
