//! Bounded subset of frp v0.71.0 analysis/classify: Mode 1 prediction and Mode 2.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::{IpAddr, SocketAddr}, ops::RangeInclusive};

pub const VERSION: u32 = 1;
const MAX_NETWORKS: usize = 1024;
const HISTORY_SECONDS: u64 = 3600;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Predict,
    Birthday,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Strategy {
    pub mode: Mode,
    /// Zero leaves the OS TTL unchanged. It must never be passed to set_ttl().
    pub ttl: u32,
}

impl Strategy {
    pub fn validate(self) -> Result<()> {
        ensure!(matches!(self.ttl, 0 | 4 | 7), "unsupported native TTL");
        Ok(())
    }
}

const CHOICES: [Strategy; 6] = [
    Strategy { mode: Mode::Predict, ttl: 7 },
    Strategy { mode: Mode::Birthday, ttl: 7 },
    Strategy { mode: Mode::Predict, ttl: 4 },
    Strategy { mode: Mode::Birthday, ttl: 4 },
    Strategy { mode: Mode::Predict, ttl: 0 },
    Strategy { mode: Mode::Birthday, ttl: 0 },
];

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Profile {
    pub easy: bool,
    pub port_span: u16,
    pub predictable: bool,
}

pub fn classify(addresses: &[SocketAddr]) -> Result<Profile> {
    ensure!((2..=4).contains(&addresses.len()), "two to four UDP observations required");
    for pair in addresses.windows(2) {
        crate::protocol::mapping(pair)?;
    }
    let low = addresses.iter().map(SocketAddr::port).min().context("no UDP port")?;
    let high = addresses.iter().map(SocketAddr::port).max().context("no UDP port")?;
    let port_span = high - low;
    Ok(Profile {
        easy: port_span == 0,
        port_span,
        // Two destinations can coincide by chance. Require an additional observation
        // before using frp's small-span heuristic; this is not a NAT guarantee.
        predictable: addresses.len() >= 3 && (1..=5).contains(&port_span),
    })
}

pub fn predicted_ports(addresses: &[SocketAddr]) -> Result<RangeInclusive<u16>> {
    let profile = classify(addresses)?;
    ensure!(profile.predictable, "UDP port prediction lacks evidence");
    let last = addresses.last().context("no UDP candidate")?.port();
    let width = (profile.port_span + 5).min(10);
    let start = last.saturating_sub(width).max(1024);
    let end = last.saturating_add(width).min(65534);
    ensure!(start <= end, "UDP prediction outside allowed ports");
    Ok(start..=end)
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Network {
    easy_ip: IpAddr,
    hard_ip: IpAddr,
    predictable: bool,
}

impl Network {
    pub fn new(a: &[SocketAddr], b: &[SocketAddr]) -> Result<Self> {
        let a_profile = classify(a)?;
        let b_profile = classify(b)?;
        ensure!(a_profile.easy != b_profile.easy, "native strategies require one EasyNAT and one HardNAT");
        let (easy, hard, profile) = if a_profile.easy { (a, b, b_profile) } else { (b, a, a_profile) };
        Ok(Self {
            easy_ip: easy[0].ip(),
            hard_ip: hard[0].ip(),
            predictable: profile.predictable && predicted_ports(hard).is_ok(),
        })
    }
}

struct Record {
    scores: [i8; 6],
    seen: u64,
}

#[derive(Default)]
pub struct History {
    records: HashMap<Network, Record>,
}

impl History {
    pub fn expire(&mut self, now: u64) {
        self.records.retain(|_, r| now.saturating_sub(r.seen) < HISTORY_SECONDS);
    }

    pub fn select(&mut self, network: &Network, now: u64) -> Strategy {
        self.expire(now);
        if self.records.len() >= MAX_NETWORKS && !self.records.contains_key(network) {
            if let Some(oldest) = self.records.iter().min_by_key(|(_, r)| r.seen).map(|(k, _)| k.clone()) {
                self.records.remove(&oldest);
            }
        }
        let record = self.records.entry(network.clone()).or_insert(Record { scores: [0; 6], seen: now });
        let mut best = 1; // The proven Mode 2 / TTL 7 remains the default without prediction evidence.
        for i in 0..CHOICES.len() {
            if CHOICES[i].mode == Mode::Predict && !network.predictable { continue; }
            if record.scores[i] > record.scores[best]
                || (record.scores[i] == record.scores[best] && i < best) { best = i; }
        }
        if record.scores[best] == -10 { record.scores = [0; 6]; }
        record.scores[best] = record.scores[best].saturating_sub(1).max(-10);
        record.seen = now;
        CHOICES[best]
    }

    pub fn confirmed(&mut self, network: &Network, strategy: Strategy, now: u64) {
        if let (Some(record), Some(index)) = (self.records.get_mut(network), CHOICES.iter().position(|s| *s == strategy)) {
            record.scores[index] = record.scores[index].saturating_add(2).min(10);
            record.seen = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prediction_needs_three_consistent_observations_and_bounds_ports() {
        let values: Vec<SocketAddr> = ["192.0.2.2:65530", "192.0.2.2:65531", "192.0.2.2:65532"].iter().map(|s| s.parse().unwrap()).collect();
        assert!(!classify(&values[..2]).unwrap().predictable);
        assert_eq!(predicted_ports(&values).unwrap(), 65525..=65534);
        let mut random = values.clone();
        random[2].set_port(2000);
        assert!(!classify(&random).unwrap().predictable);
        random[2] = "192.0.2.3:65532".parse().unwrap();
        assert!(classify(&random).is_err());
    }

    #[test]
    fn unconfirmed_predictions_yield_to_mode_two_and_success_is_preferred() {
        let easy = ["192.0.2.1:5000".parse().unwrap(); 3];
        let hard = ["192.0.2.2:6000".parse().unwrap(), "192.0.2.2:6001".parse().unwrap(), "192.0.2.2:6002".parse().unwrap()];
        let network = Network::new(&easy, &hard).unwrap();
        let mut history = History::default();
        assert_eq!(history.select(&network, 100), CHOICES[0]);
        let working = history.select(&network, 101);
        assert_eq!(working, CHOICES[1]);
        history.confirmed(&network, working, 102);
        assert_eq!(history.select(&network, 103), working);
        assert_eq!(history.select(&network, 4000), CHOICES[0]);
        let random = [hard[0], "192.0.2.2:30000".parse().unwrap()];
        let network = Network::new(&easy, &random).unwrap();
        for ttl in [7, 4, 0] {
            assert_eq!(history.select(&network, 5000), Strategy { mode: Mode::Birthday, ttl });
        }
    }
}
