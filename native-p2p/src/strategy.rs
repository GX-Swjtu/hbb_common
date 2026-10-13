//! Role/TTL/delay families from frp v0.71.0 pkg/nathole/analysis.go.
use super::candidates::Candidates;
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::{BTreeMap, HashMap}, net::{IpAddr, SocketAddr}};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode { Direct, Predict, Birthday, BothPredict, Mixed }

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Behavior {
    pub mode: Mode,
    pub ttl: u32,
    pub delay_ms: u32,
    pub reversed: bool,
}

impl Behavior {
    pub fn validate(self) -> Result<()> {
        ensure!(choices().contains(&self), "unsupported native UDP behavior");
        Ok(())
    }
    pub fn window(self) -> std::time::Duration {
        std::time::Duration::from_millis(match self.mode {
            Mode::Direct => u64::from(self.delay_ms) + 5000,
            Mode::Predict | Mode::BothPredict => 8000,
            Mode::Birthday | Mode::Mixed => 38000,
        })
    }
}

pub fn choices() -> Vec<Behavior> {
    let mut out = Vec::with_capacity(28);
    for reversed in [false, true] {
        for ttl in [7, 4, 0] { out.push(Behavior { mode: Mode::Direct, ttl, delay_ms: 0, reversed }); }
        for delay_ms in [5000, 10000] { out.push(Behavior { mode: Mode::Direct, ttl: 0, delay_ms, reversed }); }
    }
    for ttl in [7, 4, 0] {
        for delay_ms in [0, 2000] { out.push(Behavior { mode: Mode::Predict, ttl, delay_ms, reversed: false }); }
    }
    for ttl in [7, 4, 0] { out.push(Behavior { mode: Mode::Birthday, ttl, delay_ms: 3000, reversed: false }); }
    for reversed in [false, true] {
        for ttl in [7, 4, 0] { out.push(Behavior { mode: Mode::BothPredict, ttl, delay_ms: 0, reversed }); }
    }
    for ttl in [7, 4, 0] { out.push(Behavior { mode: Mode::Mixed, ttl, delay_ms: 3000, reversed: false }); }
    out
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize)]
pub struct Profile {
    pub easy: bool,
    pub predictable: bool,
    pub public: bool,
    pub ips: Vec<IpAddr>,
}

pub fn predictions(addresses: &[SocketAddr], max_width: u16) -> Vec<SocketAddr> {
    let mut groups = BTreeMap::<IpAddr, Vec<u16>>::new();
    for a in addresses { groups.entry(a.ip()).or_default().push(a.port()); }
    let mut out = Vec::new();
    for (ip, ports) in groups {
        let (Some(low), Some(high), Some(last)) = (ports.iter().min(), ports.iter().max(), ports.last()) else { continue; };
        let span = high - low;
        if ports.len() < 3 || !(1..=5).contains(&span) { continue; }
        // Per-destination allocators can alternate two small port pools. A small
        // span alone is not evidence that the next destination follows that pool.
        if !ports.windows(2).all(|p| p[1] > p[0]) && !ports.windows(2).all(|p| p[1] < p[0]) { continue; }
        let width = (span + 5).min(max_width);
        for port in last.saturating_sub(width).max(1024)..=last.saturating_add(width).min(65534) {
            out.push(SocketAddr::new(ip, port));
        }
    }
    out
}

pub fn classify(candidates: &Candidates) -> Result<Profile> {
    candidates.validate()?;
    let first = candidates.public.first().context("no observations")?;
    Ok(Profile {
        easy: candidates.public.len() >= 2 && candidates.public.iter().all(|a| a == first),
        predictable: !predictions(&candidates.public, 10).is_empty(),
        public: candidates.direct.is_some(),
        ips: candidates.ips(),
    })
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Network(pub Profile, pub Profile);

impl Network {
    pub fn eligible(&self, b: Behavior) -> bool {
        let (a, p) = (&self.0, &self.1);
        match b.mode {
            Mode::Direct => (a.easy && p.easy) || a.public || p.public,
            Mode::Predict => a.easy != p.easy && if a.easy { p.predictable } else { a.predictable },
            Mode::Birthday => a.easy != p.easy,
            Mode::BothPredict => !a.easy && !p.easy && a.predictable && p.predictable,
            Mode::Mixed => !a.easy && !p.easy && (a.predictable || p.predictable),
        }
    }
    pub fn from_is_sender(&self, b: Behavior) -> bool {
        match b.mode {
            Mode::Direct if self.0.public != self.1.public => self.1.public,
            Mode::Direct | Mode::BothPredict => !b.reversed,
            Mode::Predict => !self.0.easy,
            Mode::Birthday => self.0.easy,
            Mode::Mixed => self.0.predictable,
        }
    }
}

struct Record { scores: [i8; 28], seen: u64 }
#[derive(Default)]
pub struct History { records: HashMap<Network, Record> }

impl History {
    pub fn expire(&mut self, now: u64) {
        self.records.retain(|_, r| now.saturating_sub(r.seen) < 3600);
    }
    pub fn select(&mut self, network: &Network, now: u64) -> Result<Behavior> {
        self.expire(now);
        let choices = choices();
        let eligible: Vec<usize> = choices.iter().enumerate().filter(|(_, b)| network.eligible(**b)).map(|(i, _)| i).collect();
        ensure!(!eligible.is_empty(), "no supported native UDP NAT combination");
        if self.records.len() >= 1024 && !self.records.contains_key(network) {
            if let Some(oldest) = self.records.iter().min_by_key(|(_, r)| r.seen).map(|(k, _)| k.clone()) { self.records.remove(&oldest); }
        }
        let r = self.records.entry(network.clone()).or_insert(Record { scores: [0; 28], seen: now });
        let best = *eligible.iter().max_by_key(|i| (r.scores[**i], std::cmp::Reverse(**i))).context("no strategy")?;
        if r.scores[best] == -10 { r.scores = [0; 28]; }
        r.scores[best] = (r.scores[best] - 1).max(-10);
        r.seen = now;
        Ok(choices[best])
    }
    pub fn confirmed(&mut self, network: &Network, behavior: Behavior, now: u64) {
        if let (Some(r), Some(i)) = (self.records.get_mut(network), choices().iter().position(|b| *b == behavior)) {
            r.scores[i] = (r.scores[i] + 2).min(10);
            r.seen = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn c(ip: &str, ports: &[u16]) -> Candidates {
        Candidates { public: ports.iter().map(|p| SocketAddr::new(ip.parse().unwrap(), *p)).collect(), local: vec![], direct: None }
    }
    #[test]
    fn all_modes_require_evidence_and_history_rewards_only_confirmed_results() {
        assert_eq!(choices().len(), 28);
        let easy = classify(&c("192.0.2.1", &[5000, 5000, 5000])).unwrap();
        let predict = classify(&c("192.0.2.2", &[6000, 6001, 6002])).unwrap();
        let random = classify(&c("192.0.2.3", &[2000, 6000, 10000])).unwrap();
        for (a, b, mode) in [(easy.clone(), easy.clone(), Mode::Direct), (easy.clone(), predict.clone(), Mode::Predict),
            (easy, random.clone(), Mode::Birthday), (predict.clone(), predict.clone(), Mode::BothPredict), (predict, random.clone(), Mode::Mixed)] {
            let network = Network(a, b);
            let mut history = History::default();
            let first = history.select(&network, 100).unwrap();
            assert_eq!(first.mode, mode);
            let second = history.select(&network, 101).unwrap();
            assert_ne!(first, second);
            history.confirmed(&network, second, 102);
            assert_eq!(history.select(&network, 103).unwrap(), second);
            assert_eq!(history.select(&network, 4000).unwrap(), first);
        }
        assert!(History::default().select(&Network(random.clone(), random), 100).is_err());
        let mut multi = c("192.0.2.1", &[5000, 5001]);
        multi.public.push("192.0.2.2:5002".parse().unwrap());
        assert!(!classify(&multi).unwrap().predictable);
        assert!(!classify(&multi).unwrap().easy);
        assert!(!classify(&c("192.0.2.2", &[3457, 3454, 3458, 3455])).unwrap().predictable);
    }
}
