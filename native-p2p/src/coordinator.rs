//! Bounded authenticated coordination for the single native-udp-punch capability.
use crate::{
    candidates::{public_ip, Candidates},
    protocol::{self, Action, Invite, Plan, Reply, Request, Response, Ticket},
    strategy::{classify, Behavior, History, Mode, Network, Profile},
};
use anyhow::{bail, ensure, Context, Result};
use sodiumoxide::{crypto::sign, randombytes::randombytes};
use std::{collections::{BTreeSet, HashMap, VecDeque}, net::{IpAddr, SocketAddr}};

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
    seen: u64,
    requests: VecDeque<(Vec<u8>, u64)>,
}

struct Attempt {
    from: String,
    target: String,
    expires: u64,
    secret: Vec<u8>,
    joined: bool,
    exits: HashMap<String, BTreeSet<IpAddr>>,
    observations: HashMap<String, u8>,
    prepared: HashMap<String, (Candidates, Profile)>,
    selected: Option<(Network, Behavior)>,
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
        let Action::Advertise { capability, enabled } = &request.action else { bail!("invalid capability"); };
        ensure!(request.id == device.id && capability == crate::CAPABILITY, "unsupported capability");
        let now = protocol::now()?;
        self.expire(now);
        if let Some(cap) = self.devices.get_mut(&device.id) {
            Self::consume(cap, &request, now)?;
            cap.device = device;
            cap.enabled = *enabled;
            cap.seen = now;
        } else {
            ensure!(self.devices.len() < MAX_DEVICES, "native device limit");
            let mut cap = Capability { device, enabled: *enabled, seen: now, requests: VecDeque::new() };
            Self::consume(&mut cap, &request, now)?;
            self.devices.insert(cap.device.id.clone(), cap);
        }
        if !enabled {
            // Keep replay history when withdrawing support, but release the active lease.
            self.attempts.retain(|_, s| s.from != request.id && s.target != request.id);
        }
        Ok(())
    }

    fn consume(cap: &mut Capability, request: &Request, now: u64) -> Result<()> {
        cap.requests.retain(|(_, time)| now.saturating_sub(*time) <= 60);
        ensure!(!cap.requests.iter().any(|(nonce, _)| *nonce == request.nonce), "native request replay");
        ensure!(cap.requests.len() < MAX_REQUESTS, "native request quota");
        cap.requests.push_back((request.nonce.clone(), now));
        Ok(())
    }

    pub fn handle(&mut self, payload: &[u8], source: SocketAddr, key: &sign::SecretKey, licence_key: &str) -> Result<Outcome> {
        let now = protocol::now()?;
        self.expire(now);
        let id = protocol::request_id(payload)?;
        let cap = self.devices.get_mut(&id).context("native capability not registered")?;
        ensure!(cap.enabled, "native capability disabled");
        let request: Request = protocol::decode(payload, &cap.device.key)?;
        protocol::fresh(&request)?;
        Self::consume(cap, &request, now)?;
        // Only authenticated TCP observations admitted below enter an attempt's exit whitelist.
        ensure!(public_ip(source.ip()), "native UDP requires a public IPv4 signaling exit");
        let (reply, invite) = match self.apply(&request, source, now, key, licence_key) {
            Ok(value) => value,
            Err(error) => (Reply::Error(error.to_string()), None),
        };
        Ok(Outcome { response: protocol::encode(&Response { nonce: request.nonce, time: now, reply }, key)?, invite })
    }

    fn apply(&mut self, request: &Request, source: SocketAddr, now: u64, key: &sign::SecretKey, licence_key: &str) -> Result<(Reply, Option<(SocketAddr, Vec<u8>)>)> {
        match &request.action {
            Action::Begin { target, box_pk, licence_key: supplied } => {
                ensure!(licence_key.is_empty() || supplied == licence_key, "native server key mismatch");
                let Some(peer) = self.devices.get(target) else { return Ok((Reply::Unsupported, None)); };
                if !peer.enabled || now.saturating_sub(peer.seen) > 30 || *target == request.id { return Ok((Reply::Unsupported, None)); }
                ensure!(self.attempts.len() < MAX_SESSIONS, "native session limit");
                ensure!(!self.attempts.values().any(|s| [&s.from, &s.target].iter().any(|id| **id == request.id || **id == *target)), "native device busy");
                let session = protocol::id();
                let secret = randombytes(32);
                let expires = now + crate::ATTEMPT_SECONDS;
                let ticket = Ticket { session: session.clone(), expires, secret_box: protocol::seal(&secret, box_pk)?,
                    peer_id: target.clone(), signed_peer: peer.device.signed_key.clone(), initiator: true, capability: crate::CAPABILITY.into() };
                let invite = protocol::encode(&Invite { session: session.clone(), from: request.id.clone(), target: target.clone(), expires }, key)?;
                let address = peer.device.address;
                self.attempts.insert(session, Attempt { from: request.id.clone(), target: target.clone(), expires, secret, joined: false,
                    exits: [(request.id.clone(), [source.ip()].into())].into(), observations: HashMap::new(), prepared: HashMap::new(), selected: None });
                Ok((Reply::Ticket(ticket), Some((address, invite))))
            }
            Action::Join { session, box_pk } => {
                let s = self.attempts.get_mut(session).context("native session expired")?;
                ensure!(request.id == s.target && !s.joined, "invalid native join");
                let peer = self.devices.get(&s.from).context("native peer offline")?;
                let ticket = Ticket { session: session.clone(), expires: s.expires, secret_box: protocol::seal(&s.secret, box_pk)?,
                    peer_id: s.from.clone(), signed_peer: peer.device.signed_key.clone(), initiator: false, capability: crate::CAPABILITY.into() };
                s.joined = true;
                s.exits.insert(request.id.clone(), [source.ip()].into());
                Ok((Reply::Ticket(ticket), None))
            }
            Action::Observe { session } | Action::Prepare { session, .. } => {
                let s = self.attempts.get_mut(session).context("native session expired")?;
                ensure!(s.from == request.id || (s.target == request.id && s.joined), "invalid native participant");
                ensure!(!s.prepared.contains_key(&request.id), "native candidates already submitted");
                let exits = s.exits.get_mut(&request.id).context("native TCP source absent")?;
                if let Action::Prepare { candidates, .. } = &request.action {
                    ensure!((2..=4).contains(&candidates.public.len()), "two to four observations required");
                    let mut profile = classify(candidates)?;
                    let candidates = candidates.clone().verified(exits)?;
                    let verified = classify(&candidates)?;
                    profile.easy &= verified.easy;
                    profile.predictable = verified.predictable;
                    profile.public = verified.public;
                    profile.ips = verified.ips;
                    s.prepared.insert(request.id.clone(), (candidates, profile));
                    Ok((self.plan(session, &request.id, now)?, None))
                } else {
                    let count = s.observations.entry(request.id.clone()).or_default();
                    ensure!(*count < 4, "native observation quota");
                    *count += 1;
                    ensure!(exits.contains(&source.ip()) || exits.len() < crate::MAX_PUBLIC_IPS, "native exit limit");
                    exits.insert(source.ip());
                    Ok((Reply::Observed(source.ip()), None))
                }
            }
            Action::Poll { session } => Ok((self.plan(session, &request.id, now)?, None)),
            Action::Confirm { session } => {
                let s = self.attempts.get(session).context("native session expired")?;
                ensure!(request.id == s.from, "only the authenticated KCP caller reports success");
                let (network, behavior) = s.selected.as_ref().context("native strategy absent")?;
                self.history.confirmed(network, *behavior, now);
                self.attempts.remove(session);
                Ok((Reply::Closed, None))
            }
            Action::Cancel { session } => {
                if let Some(s) = self.attempts.get(session) {
                    ensure!(s.from == request.id || s.target == request.id, "invalid native participant");
                    self.attempts.remove(session);
                }
                Ok((Reply::Closed, None))
            }
            Action::Advertise { .. } => bail!("capabilities require UDP registration"),
        }
    }

    fn plan(&mut self, session: &str, id: &str, now: u64) -> Result<Reply> {
        let s = self.attempts.get_mut(session).context("native session expired")?;
        ensure!(id == s.from || (id == s.target && s.joined), "invalid native participant");
        if s.prepared.len() != 2 { return Ok(Reply::Waiting); }
        if s.selected.is_none() {
            let network = Network(s.prepared.get(&s.from).context("caller candidates absent")?.1.clone(),
                s.prepared.get(&s.target).context("target candidates absent")?.1.clone());
            let behavior = match self.history.select(&network, now) {
                Ok(b) => b,
                Err(_) if s.prepared.values().all(|(c, _)| !c.local.is_empty()) => Behavior { mode: Mode::Direct, ttl: 0, delay_ms: 0, reversed: false },
                Err(e) => return Ok(Reply::Error(crate::progress::Reason {
                    code: "no_strategy".into(), message: e.to_string(),
                    local: s.prepared.get(id).map(|v| v.0.clone()),
                    peer: s.prepared.iter().find(|(other, _)| other.as_str() != id).map(|(_, v)| v.0.clone()),
                }.encode())),
            };
            s.selected = Some((network, behavior));
        }
        let (network, behavior) = s.selected.as_ref().context("native strategy absent")?;
        let peer = if id == s.from { &s.target } else { &s.from };
        Ok(Reply::Plan(Plan { session: session.into(), sender: network.from_is_sender(*behavior) == (id == s.from),
            peer: s.prepared.get(peer).context("peer candidates absent")?.0.clone(), behavior: *behavior, lan_only: !network.eligible(*behavior) }))
    }
}

#[cfg(test)]
#[path = "coordinator_tests.rs"]
mod tests;
