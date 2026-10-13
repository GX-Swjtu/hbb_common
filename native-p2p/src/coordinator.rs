//! Bounded, authenticated coordination; no legacy rendezvous state is changed.
use crate::{
    protocol::{self, Action, Invite, Plan, Reply, Request, Response, Ticket},
    strategy::{self, History, Mode, Network, Strategy},
};
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
    enabled: bool,
    strategies: u32,
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
    strategies: u32,
    selection: Option<(Network, Strategy)>,
}

#[derive(Default)]
pub struct Coordinator {
    devices: HashMap<String, Capability>,
    attempts: HashMap<String, Attempt>,
    history: History,
}

pub struct Outcome {
    pub response: Vec<u8>,
    pub invite: Option<(SocketAddr, Vec<u8>)>,
}

impl Coordinator {
    pub fn expire(&mut self, now: u64) {
        self.attempts.retain(|_, s| s.expires > now);
        self.devices.retain(|_, d| now.saturating_sub(d.seen) < 60);
        self.history.expire(now);
    }

    pub fn advertise(&mut self, device: Device, payload: &[u8]) -> Result<()> {
        let request: Request = protocol::decode(payload, &device.key)?;
        protocol::fresh(&request)?;
        ensure!(
            request.id == device.id
                && matches!(
                    request.action,
                    Action::Advertise {
                        version: 0 | crate::VERSION, ..
                    }
                ),
            "invalid capability"
        );
        let enabled = matches!(request.action, Action::Advertise { version: crate::VERSION, .. });
        let strategies = match request.action {
            Action::Advertise { strategies: strategy::VERSION, .. } if enabled => strategy::VERSION,
            _ => 0,
        };
        let now = protocol::now()?;
        self.expire(now);
        if let Some(cap) = self.devices.get_mut(&device.id) {
            Self::consume(cap, &request, now)?;
            cap.device = device;
            cap.enabled = enabled;
            cap.strategies = strategies;
            cap.seen = now;
        } else {
            ensure!(self.devices.len() < MAX_DEVICES, "native device limit");
            let mut cap = Capability {
                device,
                enabled,
                strategies,
                seen: now,
                requests: VecDeque::new(),
            };
            Self::consume(&mut cap, &request, now)?;
            self.devices.insert(cap.device.id.clone(), cap);
        }
        if !enabled {
            // Retain the capability's replay history so a captured withdrawal cannot
            // cancel another attempt after this device enables the feature again.
            self.attempts.retain(|_, s| s.from != request.id && s.target != request.id);
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
        licence_key: &str,
    ) -> Result<Outcome> {
        let now = protocol::now()?;
        self.expire(now);
        let id = protocol::request_id(payload)?;
        let cap = self
            .devices
            .get_mut(&id)
            .context("native capability not registered")?;
        ensure!(cap.enabled, "native capability disabled");
        ensure!(
            cap.device.address.ip() == source.ip(),
            "native signaling exit changed"
        );
        let request: Request = protocol::decode(payload, &cap.device.key)?;
        protocol::fresh(&request)?;
        Self::consume(cap, &request, now)?;
        let (reply, invite) = match self.apply(&request, now, key, licence_key) {
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
        licence_key: &str,
    ) -> Result<(Reply, Option<(SocketAddr, Vec<u8>)>)> {
        match &request.action {
            Action::Begin { target, box_pk, licence_key: supplied_key } => {
                ensure!(licence_key.is_empty() || supplied_key == licence_key, "native server key mismatch");
                let Some(peer) = self.devices.get(target) else {
                    return Ok((Reply::Unsupported, None));
                };
                if !peer.enabled || now.saturating_sub(peer.seen) > 30 || *target == request.id {
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
                let strategies = if peer.strategies == strategy::VERSION
                    && self.devices.get(&request.id).is_some_and(|d| d.strategies == strategy::VERSION) {
                    strategy::VERSION
                } else { 0 };
                let ticket = Ticket {
                    session: session.clone(),
                    expires,
                    secret_box: protocol::seal(&secret, box_pk)?,
                    peer_id: target.clone(),
                    signed_peer: peer.device.signed_key.clone(),
                    initiator: true,
                    strategies,
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
                        strategies,
                        selection: None,
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
                    strategies: s.strategies,
                };
                s.joined = true;
                Ok((Reply::Ticket(ticket), None))
            }
            Action::Prepare { session, addresses } => {
                strategy::classify(addresses)?;
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
                ensure!(s.strategies == strategy::VERSION || addresses.len() == 2, "legacy native candidates require two observations");
                ensure!(
                    !s.addresses.contains_key(&request.id),
                    "native candidates already submitted"
                );
                s.addresses.insert(request.id.clone(), addresses.clone());
                Ok((self.plan(session, &request.id, now)?, None))
            }
            Action::Poll { session } => Ok((self.plan(session, &request.id, now)?, None)),
            Action::Confirm { session } => {
                let s = self.attempts.get(session).context("native session expired")?;
                ensure!(request.id == s.from, "only the authenticated KCP caller reports success");
                let (network, strategy) = s.selection.as_ref().context("no negotiated native strategy")?;
                self.history.confirmed(network, *strategy, now);
                // Removing the attempt also makes a second signed report ineffective.
                self.attempts.remove(session);
                Ok((Reply::Closed, None))
            }
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

    fn plan(&mut self, session: &str, id: &str, now: u64) -> Result<Reply> {
        let s = self
            .attempts
            .get_mut(session)
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
        let easy = strategy::classify(own)?.easy;
        ensure!(
            easy != strategy::classify(peer)?.easy,
            "native strategies require one EasyNAT and one HardNAT"
        );
        if s.strategies == strategy::VERSION && s.selection.is_none() {
            let network = Network::new(own, peer)?;
            let selected = self.history.select(&network, now);
            s.selection = Some((network, selected));
        }
        let strategy = s.selection.as_ref().map(|(_, strategy)| *strategy);
        let sender = if strategy.is_some_and(|s| s.mode == Mode::Predict) { !easy } else { easy };
        Ok(Reply::Plan(Plan {
            session: session.into(),
            sender,
            peer_addresses: peer.clone(),
            strategy,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::box_;

    fn register(c: &mut Coordinator, id: &str, address: &str) -> sign::SecretKey {
        register_with_strategies(c, id, address, 0)
    }

    fn register_with_strategies(c: &mut Coordinator, id: &str, address: &str, strategies: u32) -> sign::SecretKey {
        let (pk, sk) = sign::gen_keypair();
        let r = protocol::request(
            id,
            Action::Advertise {
                version: crate::VERSION,
                strategies,
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
    fn keyed_server_rejects_missing_or_wrong_key_before_inviting() {
        crate::init().unwrap();
        let mut c = Coordinator::default();
        let (server, sk) = sign::gen_keypair();
        let caller = register(&mut c, "caller", "192.0.2.1:1000");
        let _target = register(&mut c, "target", "192.0.2.2:1000");
        for supplied in [None, Some("wrong"), Some("required-key")] {
            let mut action = serde_json::json!({"Begin": {
                "target": "target", "box_pk": box_::gen_keypair().0.as_ref()
            }});
            if let Some(key) = supplied {
                action["Begin"]["licence_key"] = key.into();
            }
            let request = protocol::request("caller", serde_json::from_value(action).unwrap()).unwrap();
            let outcome = c.handle(
                &protocol::encode(&request, &caller).unwrap(),
                "192.0.2.1:2000".parse().unwrap(), &sk, "required-key",
            ).unwrap();
            let reply = protocol::decode::<Response>(&outcome.response, &server).unwrap().reply;
            if supplied == Some("required-key") {
                assert!(matches!(reply, Reply::Ticket(_)));
                assert!(outcome.invite.is_some());
            } else {
                assert!(matches!(reply, Reply::Error(e) if e == "native server key mismatch"));
                assert!(outcome.invite.is_none());
            }
        }
    }

    #[test]
    fn capability_withdrawal_requires_signature_and_cannot_replay_after_reenable() {
        crate::init().unwrap();
        let mut c = Coordinator::default();
        let (_, server) = sign::gen_keypair();
        let caller = register(&mut c, "caller", "192.0.2.1:1000");
        let target = register(&mut c, "target", "192.0.2.2:1000");
        let device = || Device {
            id: "target".into(), key: target.public_key(), signed_key: vec![],
            address: "192.0.2.2:1000".parse().unwrap(),
        };
        let begin = protocol::request("caller", Action::Begin {
            target: "target".into(), box_pk: box_::gen_keypair().0.as_ref().into(),
            licence_key: String::new(),
        }).unwrap();
        let (Reply::Ticket(ticket), _) = c.apply(&begin, protocol::now().unwrap(), &server, "").unwrap()
        else { panic!("expected ticket"); };
        let off = protocol::request("target", Action::Advertise { version: 0, strategies: 0 }).unwrap();
        assert!(c.advertise(device(), &protocol::encode(&off, &caller).unwrap()).is_err());
        assert!(matches!(c.plan(&ticket.session, "caller", protocol::now().unwrap()).unwrap(), Reply::Waiting));
        let withdrawal = protocol::encode(&off, &target).unwrap();
        c.advertise(device(), &withdrawal).unwrap();
        assert!(c.plan(&ticket.session, "caller", protocol::now().unwrap()).is_err());
        assert!(matches!(c.apply(&begin, protocol::now().unwrap(), &server, "").unwrap().0, Reply::Unsupported));
        let on = protocol::request("target", Action::Advertise { version: crate::VERSION, strategies: 0 }).unwrap();
        c.advertise(device(), &protocol::encode(&on, &target).unwrap()).unwrap();
        assert!(c.advertise(device(), &withdrawal).is_err());
        assert!(matches!(c.apply(&begin, protocol::now().unwrap(), &server, "").unwrap().0, Reply::Ticket(_)));
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
                licence_key: String::new(),
            },
        )
        .unwrap();
        let payload = protocol::encode(&request, &caller).unwrap();
        let result = c
            .handle(&payload, "192.0.2.1:2000".parse().unwrap(), &sk, "")
            .unwrap();
        assert!(matches!(
            protocol::decode::<Response>(&result.response, &server)
                .unwrap()
                .reply,
            Reply::Unsupported
        ));
        assert!(c.attempts.is_empty());
        assert!(c
            .handle(&payload, "192.0.2.1:2000".parse().unwrap(), &sk, "")
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
                licence_key: String::new(),
            },
        )
        .unwrap();
        let (Reply::Ticket(ticket), Some(_)) =
            c.apply(&req, protocol::now().unwrap(), &sk, "").unwrap()
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
        c.apply(&join, protocol::now().unwrap(), &sk, "").unwrap();
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
            c.apply(&prepare, protocol::now().unwrap(), &sk, "").unwrap();
        }
        assert!(matches!(
            c.plan(&session, "easy", protocol::now().unwrap()).unwrap(),
            Reply::Plan(Plan { sender: true, .. })
        ));
        assert!(matches!(
            c.plan(&session, "hard", protocol::now().unwrap()).unwrap(),
            Reply::Plan(Plan { sender: false, .. })
        ));
        assert!(c.plan(&session, "unrelated", protocol::now().unwrap()).is_err());
        let forged = protocol::request(
            "easy",
            Action::Prepare {
                session: session.clone(),
                addresses: vec!["192.0.2.99:1000".parse().unwrap(); 2],
            },
        )
        .unwrap();
        assert!(c.apply(&forged, protocol::now().unwrap(), &sk, "").is_err());
        c.expire(protocol::now().unwrap() + crate::ATTEMPT_SECONDS);
        assert!(c.plan(&session, "easy", protocol::now().unwrap()).is_err());
    }

    #[test]
    fn strategies_require_both_capabilities_and_confirmation_is_caller_only_once() {
        crate::init().unwrap();
        let (_, server) = sign::gen_keypair();
        let now = protocol::now().unwrap();
        for (a, b) in [(0, 1), (1, 0), (1, 1)] {
            let mut c = Coordinator::default();
            let _easy = register_with_strategies(&mut c, "easy", "192.0.2.1:1000", a);
            let _hard = register_with_strategies(&mut c, "hard", "192.0.2.2:1000", b);
            let begin = protocol::request("easy", Action::Begin {
                target: "hard".into(), box_pk: box_::gen_keypair().0.as_ref().into(), licence_key: String::new(),
            }).unwrap();
            let (Reply::Ticket(ticket), _) = c.apply(&begin, now, &server, "").unwrap() else { panic!() };
            let enhanced = a == 1 && b == 1;
            assert_eq!(ticket.strategies == 1, enhanced);
            if !enhanced { assert!(serde_json::to_value(&ticket).unwrap().get("strategies").is_none()); }
            let join = protocol::request("hard", Action::Join {
                session: ticket.session.clone(), box_pk: box_::gen_keypair().0.as_ref().into(),
            }).unwrap();
            c.apply(&join, now, &server, "").unwrap();
            let confirm = protocol::request("easy", Action::Confirm { session: ticket.session.clone() }).unwrap();
            assert!(c.apply(&confirm, now, &server, "").is_err());
            for (id, candidates) in [
                ("easy", ["192.0.2.1:5000", "192.0.2.1:5000", "192.0.2.1:5000"]),
                ("hard", ["192.0.2.2:6000", "192.0.2.2:6001", "192.0.2.2:6002"]),
            ] {
                let prepare = protocol::request(id, Action::Prepare {
                    session: ticket.session.clone(),
                    addresses: candidates[..if enhanced { 3 } else { 2 }].iter().map(|s| s.parse().unwrap()).collect(),
                }).unwrap();
                c.apply(&prepare, now, &server, "").unwrap();
            }
            let Reply::Plan(first) = c.plan(&ticket.session, "easy", now).unwrap() else { panic!() };
            assert_eq!(first.sender, !enhanced);
            assert_eq!(first.strategy.is_some(), enhanced);
            if !enhanced {
                assert!(serde_json::to_value(&first).unwrap().get("strategy").is_none());
                assert!(c.apply(&confirm, now, &server, "").is_err());
                continue;
            }
            for _ in 0..5 {
                let Reply::Plan(other) = c.plan(&ticket.session, "hard", now).unwrap() else { panic!() };
                assert_eq!(other.strategy, first.strategy);
                assert_ne!(other.sender, first.sender);
            }
            let wrong = protocol::request("hard", Action::Confirm { session: ticket.session.clone() }).unwrap();
            assert!(c.apply(&wrong, now, &server, "").is_err());
            assert!(matches!(c.apply(&confirm, now, &server, "").unwrap().0, Reply::Closed));
            assert!(c.apply(&confirm, now, &server, "").is_err());
        }
    }
}
