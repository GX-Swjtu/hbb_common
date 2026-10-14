use crate::{
    bytes_codec::BytesCodec,
    protocol::*,
    wire::rendezvous::{self, NativeP2pV1, RendezvousMessage},
};
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::{SinkExt, StreamExt};
use protobuf::Message;
use sodiumoxide::crypto::{box_, sealedbox, sign};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::{timeout, timeout_at, Instant},
};
use tokio_util::codec::Framed;

#[path = "transport_punch.rs"]
mod punching;

#[derive(Clone)]
pub struct Identity {
    pub id: String,
    pub key: sign::SecretKey,
}

pub fn envelope(payload: Vec<u8>) -> RendezvousMessage {
    let mut message = RendezvousMessage::new();
    message.set_native_p2p_v1(NativeP2pV1 {
        version: crate::VERSION,
        payload: payload.into(),
        ..Default::default()
    });
    message
}

pub async fn rpc(
    endpoint: &str,
    identity: &Identity,
    server: &sign::PublicKey,
    action: Action,
    limit: Duration,
) -> Result<Reply> {
    timeout(limit, async {
        let request = request(&identity.id, action)?;
        let message = envelope(encode(&request, &identity.key)?);
        let mut codec = BytesCodec::new();
        codec.set_max_packet_length(crate::MAX_MESSAGE);
        let mut stream = Framed::new(TcpStream::connect(endpoint).await?, codec);
        stream.send(message.write_to_bytes()?.into()).await?;
        let bytes = stream.next().await.context("native coordinator closed")??;
        let message = RendezvousMessage::parse_from_bytes(&bytes)?;
        let Some(rendezvous::rendezvous_message::Union::NativeP2pV1(message)) = message.union
        else {
            bail!("native coordinator unsupported");
        };
        ensure!(
            message.version == crate::VERSION,
            "unsupported native version"
        );
        let response: Response = decode(&message.payload, server)?;
        ensure!(
            response.nonce == request.nonce && now()?.abs_diff(response.time) <= 30,
            "native response replay"
        );
        Ok(response.reply)
    })
    .await?
}

pub struct Session {
    pub ticket: Ticket,
    endpoint: String,
    identity: Identity,
    server: sign::PublicKey,
    secret: Vec<u8>,
    pub deadline: Instant,
    cancel_on_drop: bool,
}

pub struct Punched {
    pub socket: Arc<UdpSocket>,
    pub peer: SocketAddr,
    pub session: Session,
    pub strategy: crate::strategy::Behavior,
}

impl Session {
    pub async fn begin(
        endpoint: &str,
        identity: Identity,
        server: sign::PublicKey,
        target: &str,
    ) -> Result<Option<Self>> {
        Self::begin_with_timeout(endpoint, identity, server, target, Duration::from_secs(1)).await
    }

    /// A caller with authenticated evidence of server support may allow more preparation time.
    pub async fn begin_with_timeout(
        endpoint: &str,
        identity: Identity,
        server: sign::PublicKey,
        target: &str,
        limit: Duration,
    ) -> Result<Option<Self>> {
        let (pk, sk) = box_::gen_keypair();
        let deadline = Instant::now() + Duration::from_secs(crate::ATTEMPT_SECONDS);
        let reply = rpc(
            endpoint,
            &identity,
            &server,
            Action::Begin {
                target: target.into(),
                box_pk: pk.as_ref().to_vec(),
                licence_key: STANDARD.encode(server.as_ref()),
            },
            limit.min(Duration::from_secs(crate::ATTEMPT_SECONDS)),
        )
        .await?;
        match reply {
            Reply::Ticket(ticket) => Ok(Some(Self::new(
                endpoint, identity, server, ticket, &pk, &sk, deadline,
            )?)),
            Reply::Unsupported => Ok(None),
            _ => bail!("native begin declined"),
        }
    }

    pub async fn join(
        endpoint: &str,
        identity: Identity,
        server: sign::PublicKey,
        invite: Invite,
    ) -> Result<Self> {
        let now = now()?;
        ensure!(
            invite.target == identity.id && invite.expires > now,
            "invalid native invitation"
        );
        let (pk, sk) = box_::gen_keypair();
        let deadline = Instant::now()
            + Duration::from_secs(crate::ATTEMPT_SECONDS.min(invite.expires - now));
        let reply = rpc(
            endpoint,
            &identity,
            &server,
            Action::Join {
                session: invite.session,
                box_pk: pk.as_ref().to_vec(),
            },
            Duration::from_secs(2),
        )
        .await?;
        match reply {
            Reply::Ticket(ticket) => {
                Self::new(endpoint, identity, server, ticket, &pk, &sk, deadline)
            }
            _ => bail!("native join declined"),
        }
    }

    fn new(
        endpoint: &str,
        identity: Identity,
        server: sign::PublicKey,
        ticket: Ticket,
        pk: &box_::PublicKey,
        sk: &box_::SecretKey,
        deadline: Instant,
    ) -> Result<Self> {
        ensure!(
            ticket.expires > now()? && ticket.session.len() == 32,
            "invalid native ticket"
        );
        ensure!(ticket.capability == crate::CAPABILITY, "native UDP capability not negotiated");
        let secret = sealedbox::open(&ticket.secret_box, pk, sk)
            .map_err(|_| anyhow::anyhow!("invalid sealed probe key"))?;
        ensure!(secret.len() == 32, "invalid probe key length");
        Ok(Self {
            ticket,
            endpoint: endpoint.into(),
            identity,
            server,
            secret,
            deadline,
            cancel_on_drop: true,
        })
    }

    /// The KCP acceptor relinquishes cancellation ownership to the caller, which
    /// still has to authenticate the device before reporting success. Server expiry
    /// bounds this lease if the caller exits during that handshake.
    pub fn handoff_to_caller(&mut self) {
        if !self.ticket.initiator {
            self.cancel_on_drop = false;
        }
    }

    /// Call only after KCP and the existing RustDesk device-identity handshake.
    /// The UDP-only diagnostic deliberately never rewards a strategy.
    pub async fn confirm_authenticated(&self) -> Result<()> {
        ensure!(self.ticket.initiator, "only native caller confirms authentication");
        let reply = rpc(
            &self.endpoint, &self.identity, &self.server,
            Action::Confirm { session: self.ticket.session.clone() },
            Duration::from_secs(1).min(self.deadline.saturating_duration_since(Instant::now())),
        ).await?;
        ensure!(matches!(reply, Reply::Closed), "native success report declined");
        Ok(())
    }

    async fn wait_for_cancellation(&self) -> anyhow::Error {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            match rpc(
                &self.endpoint,
                &self.identity,
                &self.server,
                Action::Poll {
                    session: self.ticket.session.clone(),
                },
                Duration::from_secs(1),
            )
            .await
            {
                Ok(Reply::Plan(_)) => {}
                Ok(_) => return anyhow::anyhow!("native peer cancelled or session expired"),
                // A lost coordination packet does not mean the peer cancelled.
                // The enclosing absolute deadline still bounds this attempt.
                Err(error) => log::trace!("native cancellation check unavailable: {error}"),
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.cancel_on_drop { return; }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let endpoint = self.endpoint.clone();
            let identity = self.identity.clone();
            let server = self.server;
            let action = Action::Cancel {
                session: self.ticket.session.clone(),
            };
            runtime.spawn(async move {
                if let Err(error) = rpc(
                    &endpoint,
                    &identity,
                    &server,
                    action,
                    Duration::from_secs(1),
                )
                .await
                {
                    log::trace!("native cancel: {error}");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn temporary_rpc_loss_is_not_peer_cancellation() {
        crate::init().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let (server, server_secret) = sign::gen_keypair();
        let (device, key) = sign::gen_keypair();
        let coordinator = tokio::spawn(async move {
            for attempt in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = Framed::new(stream, BytesCodec::new());
                let message = RendezvousMessage::parse_from_bytes(&stream.next().await.unwrap().unwrap()).unwrap();
                let request: Request = decode(&message.native_p2p_v1().payload, &device).unwrap();
                if attempt == 0 { continue; } // A transient lost RPC response.
                let response = Response { nonce: request.nonce, time: now().unwrap(), reply: Reply::Closed };
                stream.send(envelope(encode(&response, &server_secret).unwrap()).write_to_bytes().unwrap().into()).await.unwrap();
            }
        });
        let (pk, sk) = box_::gen_keypair();
        let ticket = Ticket { session: id(), expires: now().unwrap() + 45, secret_box: seal(&[1; 32], pk.as_ref()).unwrap(),
            peer_id: "peer".into(), signed_peer: vec![], initiator: true, capability: crate::CAPABILITY.into() };
        let mut session = Session::new(&endpoint, Identity { id: "device".into(), key }, server, ticket, &pk, &sk, Instant::now() + Duration::from_secs(45)).unwrap();
        session.cancel_on_drop = false;
        let error = timeout(Duration::from_secs(4), session.wait_for_cancellation()).await.unwrap();
        assert!(error.to_string().contains("peer cancelled"));
        coordinator.await.unwrap();
    }

    #[tokio::test]
    async fn old_server_is_abandoned_within_one_second() {
        crate::init().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let old_server = tokio::spawn(async move {
            let (_connection, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(3)).await;
        });
        let (server, key) = sign::gen_keypair();
        let started = Instant::now();
        let result = Session::begin(
            &endpoint,
            Identity { id: "caller".into(), key },
            server,
            "old-client",
        ).await;
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(1400));
        old_server.abort();
        let _ = old_server.await;
    }
}
