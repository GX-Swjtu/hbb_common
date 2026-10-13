use anyhow::{bail, ensure, Context, Result};
use sodiumoxide::randombytes::randombytes;
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    time::{timeout_at, Instant},
};

const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

pub async fn discover(server: &str) -> Result<(Arc<UdpSocket>, Vec<SocketAddr>)> {
    discover_inner(server, false).await
}

pub async fn discover_profile(server: &str) -> Result<(Arc<UdpSocket>, Vec<SocketAddr>)> {
    discover_inner(server, true).await
}

async fn discover_inner(server: &str, characterize: bool) -> Result<(Arc<UdpSocket>, Vec<SocketAddr>)> {
    let endpoint = tokio::time::timeout(Duration::from_secs(1), tokio::net::lookup_host(server))
        .await??
        .find(SocketAddr::is_ipv4)
        .context("STUN has no IPv4 address")?;
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let deadline = Instant::now() + Duration::from_secs(6);
    let (first, other) = binding(&socket, endpoint, deadline).await?;
    let other = other.context("STUN must supply OTHER-ADDRESS or CHANGED-ADDRESS")?;
    ensure!(other != endpoint, "STUN alternate endpoint must differ");
    let (second, _) = binding(&socket, other, deadline).await?;
    let mut addresses = vec![first, second];
    if characterize && endpoint.ip() != other.ip() && endpoint.port() != other.port() {
        // RFC 5780's two alternate IP/port combinations provide fresh destinations.
        // Repeating a binding to the same destination would not sample NAT allocation.
        // Optional samples never turn a working two-observation discovery into failure.
        for target in [SocketAddr::new(endpoint.ip(), other.port()), SocketAddr::new(other.ip(), endpoint.port())] {
            let extra_deadline = deadline.min(Instant::now() + Duration::from_millis(500));
            if Instant::now() >= extra_deadline { break; }
            match binding(&socket, target, extra_deadline).await {
                Ok((mapped, _)) => addresses.push(mapped),
                Err(error) => log::trace!("optional UDP characterization: {error}"),
            }
        }
    }
    Ok((socket, addresses))
}

async fn binding(
    socket: &UdpSocket,
    target: SocketAddr,
    deadline: Instant,
) -> Result<(SocketAddr, Option<SocketAddr>)> {
    let mut request = vec![0, 1, 0, 0];
    request.extend_from_slice(&COOKIE);
    request.extend_from_slice(&randombytes(12));
    let mut buffer = [0u8; 1500];
    for _ in 0..3 {
        socket.send_to(&request, target).await?;
        let retry = deadline.min(Instant::now() + Duration::from_millis(850));
        loop {
            let result = timeout_at(retry, socket.recv_from(&mut buffer)).await;
            let (n, source) = match result {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            };
            if source != target || n < 20 || buffer[8..20] != request[8..20] {
                continue;
            }
            return parse(&buffer[..n]);
        }
        ensure!(Instant::now() < deadline, "STUN deadline exceeded");
    }
    bail!("STUN binding timed out")
}

fn parse(data: &[u8]) -> Result<(SocketAddr, Option<SocketAddr>)> {
    ensure!(
        data.len() >= 20 && data[0..2] == [1, 1] && data[4..8] == COOKIE,
        "invalid STUN response"
    );
    let end = 20 + u16::from_be_bytes([data[2], data[3]]) as usize;
    ensure!(end <= data.len(), "truncated STUN response");
    let mut offset = 20;
    let mut mapped = None;
    let mut alternate = None;
    while offset + 4 <= end {
        let kind = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let size = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        ensure!(offset + size <= end, "truncated STUN attribute");
        if matches!(kind, 1 | 5 | 0x20 | 0x802c) && size >= 8 && data[offset + 1] == 1 {
            let mut port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let mut ip = [0; 4];
            ip.copy_from_slice(&data[offset + 4..offset + 8]);
            if kind == 0x20 {
                port ^= 0x2112;
                for (part, mask) in ip.iter_mut().zip(COOKIE) {
                    *part ^= mask;
                }
            }
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port));
            if kind == 1 && mapped.is_none() || kind == 0x20 {
                mapped = Some(addr);
            }
            if kind == 5 || kind == 0x802c {
                alternate = Some(addr);
            }
        }
        offset += (size + 3) & !3;
    }
    Ok((
        mapped.context("STUN response has no IPv4 mapping")?,
        alternate,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn silent_stun_has_a_bounded_failure() {
        crate::init().unwrap();
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let started = Instant::now();
        let result = discover(&silent.local_addr().unwrap().to_string()).await;
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn xor_mapping_and_alternate_address_are_parsed_without_rebinding() {
        let mut data = vec![1, 1, 0, 24];
        data.extend_from_slice(&COOKIE);
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&[0, 0x20, 0, 8, 0, 1]);
        data.extend_from_slice(&(5000u16 ^ 0x2112).to_be_bytes());
        data.extend([192, 0, 2, 1].iter().zip(COOKIE).map(|(a, b)| a ^ b));
        data.extend_from_slice(&[0x80, 0x2c, 0, 8, 0, 1]);
        data.extend_from_slice(&3479u16.to_be_bytes());
        data.extend_from_slice(&[192, 0, 2, 2]);
        assert_eq!(parse(&data).unwrap(), ("192.0.2.1:5000".parse().unwrap(), Some("192.0.2.2:3479".parse().unwrap())));
        data.pop();
        assert!(parse(&data).is_err());
    }

    #[tokio::test]
    async fn characterization_uses_distinct_destinations_without_rebinding() {
        crate::init().unwrap();
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let other = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let a = first.local_addr().unwrap();
        let b = other.local_addr().unwrap();
        let cross_a = UdpSocket::bind(SocketAddr::new(a.ip(), b.port())).await.unwrap();
        let cross_b = UdpSocket::bind(SocketAddr::new(b.ip(), a.port())).await.unwrap();
        let mut servers = tokio::task::JoinSet::new();
        for (index, socket) in [first, other, cross_a, cross_b].into_iter().enumerate() {
            servers.spawn(async move {
                let mut buf = [0u8; 1500];
                let (_, source) = socket.recv_from(&mut buf).await.unwrap();
                let mut response = vec![1, 1, 0, 24];
                response.extend_from_slice(&buf[4..20]);
                response.extend_from_slice(&[0, 1, 0, 8, 0, 1]);
                response.extend_from_slice(&(5000 + index as u16).to_be_bytes());
                response.extend_from_slice(&[192, 0, 2, 1]);
                response.extend_from_slice(&[0x80, 0x2c, 0, 8, 0, 1]);
                response.extend_from_slice(&b.port().to_be_bytes());
                response.extend_from_slice(&[127, 0, 0, 2]);
                socket.send_to(&response, source).await.unwrap();
                source.port()
            });
        }
        let (socket, observed) = discover_profile(&a.to_string()).await.unwrap();
        assert_eq!(observed.iter().map(SocketAddr::port).collect::<Vec<_>>(), vec![5000, 5001, 5002, 5003]);
        while let Some(source) = servers.join_next().await {
            assert_eq!(source.unwrap(), socket.local_addr().unwrap().port());
        }
    }
}
