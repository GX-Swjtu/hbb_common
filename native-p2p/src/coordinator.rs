//! Bounded, authenticated coordination; no legacy rendezvous state is changed.
use crate::protocol::{self, Action, Invite, Plan, Reply, Request, Response, Ticket};
use anyhow::{bail, ensure, Context, Result};
use sodiumoxide::{crypto::sign, randombytes::randombytes};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
};

const MAX_DEVICES: usize = 4096;
const MAX_SESSIONS: usize = 64;
const MAX_REQUESTS: usize = 512;

pub struct Device {
    pub id: String,
    pub key: sign::PublicKey,
    pub signed_key: Vec<u8>,
    pub address: SocketAddr,
}

struct Capability {
    device: Device,
    seen: u64,
    requests: VecDeque<(Vec<u8>, u64)>,
}

struct Attempt {
    from: String,
    target: String,
    expires: u64,
    secret: Vec<u8>,
    joined: bool,
    addresses: HashMap<String, Vec<SocketAddr>>,
}

#[derive(Default)]
pub struct Coordinator {
    devices: HashMap<String, Capability>,
    attempts: HashMap<String, Attempt>,
}

pub struct Outcome {
    pub response: Vec<u8>,
    pub invite: Option<(SocketAddr, Vec<u8>)>,
}

impl Coordinator {
    pub fn expire(&mut self, now: u64) {
        self.attempts.retain(|_, s| s.expires > now);
        self.devices.retain(|_, d| now.saturating_sub(d.seen) < 60);
    }

    pub fn remove(&mut self, id: &str) {
        self.devices.remove(id);
        self.attempts.retain(|_, s| s.from != id && s.target != id);
    }

    pub fn advertise(&mut self, device: Device, payload: &[u8]) -> Result<()> {
        let request: Request = protocol::decode(payload, &device.key)?;
        protocol::fresh(&request)?;
        ensure!(
            request.id == device.id
                && matches!(
                    request.action,
                    Action::Advertise {
                        version: crate::VERSION
                    }
                ),
            "invalid capability"
        );
        let now = protocol::now()?;
        self.expire(now);
        if let Some(cap) = self.devices.get_mut(&device.id) {
            Self::consume(cap, &request, now)?;
            cap.device = device;
            cap.seen = now;
        } else {
            ensure!(self.devices.len() < MAX_DEVICES, "native device limit");
            let mut cap = Capability {
                device,
                seen: now,
                requests: VecDeque::new(),
            };
            Self::consume(&mut cap, &request, now)?;
            self.devices.insert(cap.device.id.clone(), cap);
        }
        Ok(())
    }

    fn consume(cap: &mut Capability, request: &Request, now: u64) -> Result<()> {
        cap.requests
            .retain(|(_, time)| now.saturating_sub(*time) <= 60);
        ensure!(
            !cap.requests
                .iter()
                .any(|(nonce, _)| *nonce == request.nonce),
            "native request replay"
        );
        ensure!(cap.requests.len() < MAX_REQUESTS, "native request quota");
        cap.requests.push_back((request.nonce.clone(), now));
        Ok(())
    }

    pub fn handle(
        &mut self,
        payload: &[u8],
        source: SocketAddr,
        key: &sign::SecretKey,
    ) -> Result<Outcome> {
        let now = protocol::now()?;
        self.expire(now);
        let id = protocol::request_id(payload)?;
        let cap = self
            .devices
            .get_mut(&id)
            .context("native capability not registered")?;
        ensure!(
            cap.device.address.ip() == source.ip(),
            "native signaling exit changed"
        );
        let request: Request = protocol::decode(payload, &cap.device.key)?;
        protocol::fresh(&request)?;
        Self::consume(cap, &request, now)?;
        let (reply, invite) = match self.apply(&request, now, key) {
            Ok(value) => value,
            Err(error) => (Reply::Error(error.to_string()), None),
        };
        Ok(Outcome {
            response: protocol::encode(
                &Response {
                    nonce: request.nonce,
                    time: now,
                    reply,
                },
                key,
            )?,
            invite,
        })
    }

    fn apply(
        &mut self,
        request: &Request,
        now: u64,
        key: &sign::SecretKey,
    ) -> Result<(Reply, Option<(SocketAddr, Vec<u8>)>)> {
        match &request.action {
            Action::Begin { target, box_pk } => {
                let Some(peer) = self.devices.get(target) else {
                    return Ok((Reply::Unsupported, None));
                };
                if now.saturating_sub(peer.seen) > 30 || *target == request.id {
                    return Ok((Reply::Unsupported, None));
                }
                ensure!(self.attempts.len() < MAX_SESSIONS, "native session limit");
                ensure!(
                    !self.attempts.values().any(|s| [&s.from, &s.target]
                        .iter()
                        .any(|id| **id == request.id || **id == *target)),
                    "native device busy"
                );
                let session = protocol::id();
                let secret = randombytes(32);
                let expires = now + crate::ATTEMPT_SECONDS;
                let ticket = Ticket {
                    session: session.clone(),
                    expires,
                    secret_box: protocol::seal(&secret, box_pk)?,
                    peer_id: target.clone(),
                    signed_peer: peer.device.signed_key.clone(),
                    initiator: true,
                };
                let invite = protocol::encode(
                    &Invite {
                        session: session.clone(),
                        from: request.id.clone(),
                        target: target.clone(),
                        expires,
                    },
                    key,
                )?;
                let address = peer.device.address;
                self.attempts.insert(
                    session,
                    Attempt {
                        from: request.id.clone(),
                        target: target.clone(),
                        expires,
                        secret,
                        joined: false,
                        addresses: HashMap::new(),
                    },
                );
                Ok((Reply::Ticket(ticket), Some((address, invite))))
            }
            Action::Join { session, box_pk } => {
                let s = self
                    .attempts
                    .get_mut(session)
                    .context("native session expired")?;
                ensure!(request.id == s.target && !s.joined, "invalid native join");
                let peer = self.devices.get(&s.from).context("native peer offline")?;
                let ticket = Ticket {
                    session: session.clone(),
                    expires: s.expires,
                    secret_box: protocol::seal(&s.secret, box_pk)?,
                    peer_id: s.from.clone(),
                    signed_peer: peer.device.signed_key.clone(),
                    initiator: false,
                };
                s.joined = true;
                Ok((Reply::Ticket(ticket), None))
            }
            Action::Prepare { session, addresses } => {
                protocol::mapping(addresses)?;
                let cap = self
                    .devices
                    .get(&request.id)
                    .context("native peer offline")?;
                ensure!(
                    addresses[0].ip() == cap.device.address.ip(),
                    "UDP and signaling exits differ"
                );
                let s = self
                    .attempts
                    .get_mut(session)
                    .context("native session expired")?;
                ensure!(
                    request.id == s.from || (request.id == s.target && s.joined),
                    "invalid native participant"
                );
                ensure!(
                    !s.addresses.contains_key(&request.id),
                    "native candidates already submitted"
                );
                s.addresses.insert(request.id.clone(), addresses.clone());
                Ok((self.plan(session, &request.id)?, None))
            }
            Action::Poll { session } => Ok((self.plan(session, &request.id)?, None)),
            Action::Cancel { session } => {
                if let Some(s) = self.attempts.get(session) {
                    ensure!(
                        request.id == s.from || request.id == s.target,
                        "invalid native participant"
                    );
                    self.attempts.remove(session);
                }
                Ok((Reply::Closed, None))
            }
            Action::Advertise { .. } => bail!("capabilities require UDP registration"),
        }
    }

    fn plan(&self, session: &str, id: &str) -> Result<Reply> {
        let s = self
            .attempts
            .get(session)
            .context("native session expired")?;
        ensure!(id == s.from || id == s.target, "invalid native participant");
        if s.addresses.len() != 2 {
            return Ok(Reply::Waiting);
        }
        let own = s.addresses.get(id).context("native candidates absent")?;
        let peer_id = if id == s.from { &s.target } else { &s.from };
        let peer = s
            .addresses
            .get(peer_id)
            .context("native peer candidates absent")?;
        let sender = protocol::mapping(own)?;
        ensure!(
            sender != protocol::mapping(peer)?,
            "Mode 2 requires one EasyNAT and one HardNAT"
        );
        Ok(Reply::Plan(Plan {
            session: session.into(),
            sender,
            peer_addresses: peer.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::box_;

    fn register(c: &mut Coordinator, id: &str, address: &str) -> sign::SecretKey {
        let (pk, sk) = sign::gen_keypair();
        let r = protocol::request(
            id,
            Action::Advertise {
                version: crate::VERSION,
            },
        )
        .unwrap();
        c.advertise(
            Device {
                id: id.into(),
                key: pk,
                signed_key: vec![],
                address: address.parse().unwrap(),
            },
            &protocol::encode(&r, &sk).unwrap(),
        )
        .unwrap();
        sk
    }

    #[test]
    fn unsupported_peers_never_allocate_sessions_and_requests_cannot_replay() {
        crate::init().unwrap();
        let mut c = Coordinator::default();
        let (server, sk) = sign::gen_keypair();
        let caller = register(&mut c, "caller", "192.0.2.1:1000");
        let request = protocol::request(
            "caller",
            Action::Begin {
                target: "android-or-old".into(),
                box_pk: box_::gen_keypair().0.as_ref().into(),
            },
        )
        .unwrap();
        let payload = protocol::encode(&request, &caller).unwrap();
        let result = c
            .handle(&payload, "192.0.2.1:2000".parse().unwrap(), &sk)
            .unwrap();
        assert!(matches!(
            protocol::decode::<Response>(&result.response, &server)
                .unwrap()
                .reply,
            Reply::Unsupported
        ));
        assert!(c.attempts.is_empty());
        assert!(c
            .handle(&payload, "192.0.2.1:2000".parse().unwrap(), &sk)
            .is_err());
    }

    #[test]
    fn authenticated_mode_two_roles_exit_validation_and_expiry() {
        crate::init().unwrap();
        let mut c = Coordinator::default();
        let (_, sk) = sign::gen_keypair();
        let _easy = register(&mut c, "easy", "192.0.2.1:1000");
        let _hard = register(&mut c, "hard", "192.0.2.2:1000");
        let req = protocol::request(
            "hard",
            Action::Begin {
                target: "easy".into(),
                box_pk: box_::gen_keypair().0.as_ref().into(),
            },
        )
        .unwrap();
        let (Reply::Ticket(ticket), Some(_)) =
            c.apply(&req, protocol::now().unwrap(), &sk).unwrap()
        else {
            panic!()
        };
        let session = ticket.session;
        let join = protocol::request(
            "easy",
            Action::Join {
                session: session.clone(),
                box_pk: box_::gen_keypair().0.as_ref().into(),
            },
        )
        .unwrap();
        c.apply(&join, protocol::now().unwrap(), &sk).unwrap();
        for (id, values) in [
            ("easy", ["192.0.2.1:5000", "192.0.2.1:5000"]),
            ("hard", ["192.0.2.2:6000", "192.0.2.2:6001"]),
        ] {
            let prepare = protocol::request(
                id,
                Action::Prepare {
                    session: session.clone(),
                    addresses: values.iter().map(|v| v.parse().unwrap()).collect(),
                },
            )
            .unwrap();
            c.apply(&prepare, protocol::now().unwrap(), &sk).unwrap();
        }
        assert!(matches!(
            c.plan(&session, "easy").unwrap(),
            Reply::Plan(Plan { sender: true, .. })
        ));
        assert!(matches!(
            c.plan(&session, "hard").unwrap(),
            Reply::Plan(Plan { sender: false, .. })
        ));
        assert!(c.plan(&session, "unrelated").is_err());
        let forged = protocol::request(
            "easy",
            Action::Prepare {
                session: session.clone(),
                addresses: vec!["192.0.2.99:1000".parse().unwrap(); 2],
            },
        )
        .unwrap();
        assert!(c.apply(&forged, protocol::now().unwrap(), &sk).is_err());
        c.expire(protocol::now().unwrap() + crate::ATTEMPT_SECONDS);
        assert!(c.plan(&session, "easy").is_err());
    }
}
