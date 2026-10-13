use crate::{
    bytes_codec::BytesCodec,
    protocol::*,
    wire::rendezvous::{self, NativeP2pV1, RendezvousMessage},
};
use anyhow::{bail, ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
use protobuf::Message;
use sodiumoxide::crypto::{box_, sealedbox, sign};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::{timeout, timeout_at, Instant},
};
use tokio_util::codec::Framed;

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
}

pub struct Punched {
    pub socket: Arc<UdpSocket>,
    pub peer: SocketAddr,
    pub session: Session,
}

impl Session {
    pub async fn begin(
        endpoint: &str,
        identity: Identity,
        server: sign::PublicKey,
        target: &str,
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
            },
            Duration::from_secs(1),
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
        ensure!(
            invite.target == identity.id && invite.expires > now()?,
            "invalid native invitation"
        );
        let (pk, sk) = box_::gen_keypair();
        let deadline = Instant::now()
            + Duration::from_secs(crate::ATTEMPT_SECONDS.min(invite.expires - now()?));
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
        })
    }

    pub async fn punch(self, stun_server: &str) -> Result<Punched> {
        let deadline = self.deadline;
        timeout_at(deadline, async move {
            let (socket, addresses) = crate::stun::discover(stun_server).await?;
            log::info!(
                "native-p2p UDP observations: {:?}, stable={}",
                addresses,
                mapping(&addresses)?
            );
            let mut action = Action::Prepare {
                session: self.ticket.session.clone(),
                addresses,
            };
            let plan = loop {
                let reply = rpc(
                    &self.endpoint,
                    &self.identity,
                    &self.server,
                    action,
                    Duration::from_secs(2),
                )
                .await?;
                match reply {
                    Reply::Plan(plan) => break plan,
                    Reply::Waiting => {}
                    Reply::Error(error) => bail!(error),
                    _ => bail!("native session closed"),
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
                action = Action::Poll {
                    session: self.ticket.session.clone(),
                };
            };
            ensure!(
                plan.session == self.ticket.session,
                "native plan session mismatch"
            );
            let (socket, peer) = crate::hole::punch(socket, &plan, &self.secret, deadline).await?;
            log::info!(
                "native-p2p Mode 2 confirmed, peer={peer}, sender={}",
                plan.sender
            );
            Ok(Punched {
                socket,
                peer,
                session: self,
            })
        })
        .await?
    }
}

impl Drop for Session {
    fn drop(&mut self) {
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
