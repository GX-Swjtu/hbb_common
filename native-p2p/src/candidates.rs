use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::{IpAddr, Ipv4Addr, SocketAddr}};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidates {
    pub public: Vec<SocketAddr>,
    pub local: Vec<SocketAddr>,
    pub direct: Option<SocketAddr>,
}

pub fn public_ip(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v) if !v.is_unspecified() && !v.is_loopback()
        && !v.is_private() && !v.is_link_local() && !v.is_multicast()
        && !v.is_broadcast() && v.octets()[0] != 0 && v.octets()[0] < 240
        && !(v.octets()[0] == 100 && (64..=127).contains(&v.octets()[1])))
}

impl Candidates {
    pub fn validate(&self) -> Result<()> {
        ensure!((1..=4).contains(&self.public.len()), "invalid public observation count");
        ensure!(self.public.iter().all(|a| public_ip(a.ip()) && a.port() > 0), "invalid public candidate");
        ensure!(self.direct.map_or(true, |a| self.public.contains(&a)), "direct address must match an observation");
        ensure!(self.local.len() <= crate::MAX_LOCAL, "too many local candidates");
        ensure!(self.local.iter().all(|a| matches!(a.ip(), IpAddr::V4(ip) if ip.is_private()) && a.port() > 0), "invalid local candidate");
        ensure!(self.local.iter().collect::<BTreeSet<_>>().len() == self.local.len(), "duplicate local candidate");
        Ok(())
    }

    pub fn ips(&self) -> Vec<IpAddr> {
        self.public.iter().map(SocketAddr::ip).collect::<BTreeSet<_>>().into_iter().collect()
    }

    pub fn verified(mut self, exits: &BTreeSet<IpAddr>) -> Result<Self> {
        self.validate()?;
        self.public.retain(|a| exits.contains(&a.ip()));
        self.direct = self.direct.filter(|a| exits.contains(&a.ip()));
        ensure!(!self.public.is_empty(), "no TCP-verified UDP exit");
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Interface {
    pub address: Ipv4Addr,
    pub prefix: u8,
}

impl Interface {
    pub fn on_link(self, candidate: SocketAddr) -> bool {
        let IpAddr::V4(ip) = candidate.ip() else { return false; };
        if !ip.is_private() || self.prefix == 0 || self.prefix > 30 || ip == self.address { return false; }
        let mask = u32::MAX << (32 - self.prefix);
        let network = u32::from(self.address) & mask;
        let value = u32::from(ip);
        value & mask == network && value != network && value != (network | !mask)
    }
}

pub fn local(interfaces: &[Interface], port: u16) -> Vec<SocketAddr> {
    interfaces.iter().filter(|i| i.address.is_private() && (1..=30).contains(&i.prefix))
        .map(|i| SocketAddr::new(i.address.into(), port)).collect::<BTreeSet<_>>()
        .into_iter().take(crate::MAX_LOCAL).collect()
}

pub fn on_link(interfaces: &[Interface], candidates: &[SocketAddr]) -> Vec<SocketAddr> {
    candidates.iter().copied().filter(|a| !interfaces.iter().any(|i| IpAddr::V4(i.address) == a.ip())
        && interfaces.iter().any(|i| i.on_link(*a))).take(crate::MAX_LOCAL).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_require_verified_exits_and_physical_on_link_unicast() {
        let candidates = Candidates { public: vec!["192.0.2.1:5000".parse().unwrap(), "192.0.2.2:5001".parse().unwrap()], local: vec![], direct: None };
        assert!(candidates.clone().verified(&BTreeSet::new()).is_err());
        let filtered = candidates.verified(&["192.0.2.2".parse().unwrap()].into()).unwrap();
        assert_eq!(filtered.public.len(), 1);
        let interfaces = [Interface { address: "192.168.2.10".parse().unwrap(), prefix: 24 }];
        let peers = ["192.168.2.11:10", "192.168.2.10:10", "192.168.3.11:10", "192.168.2.255:10", "192.168.2.0:10", "127.0.0.1:10"];
        assert_eq!(on_link(&interfaces, &peers.map(|a| a.parse().unwrap())), vec!["192.168.2.11:10".parse::<SocketAddr>().unwrap()]);
        for ip in ["127.0.0.1", "0.1.2.3", "169.254.0.1", "10.0.0.1", "100.64.0.1", "224.0.0.1", "255.255.255.255", "::1"] {
            assert!(!public_ip(ip.parse().unwrap()));
        }
    }
}
