use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use protobuf::Message;
use rustdesk_native_p2p::{
    self as p2p,
    protocol::{self, Action, Invite},
    transport::{Identity, Session},
    wire::rendezvous::*,
};
use sodiumoxide::{crypto::sign, randombytes::randombytes};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::UdpSocket,
    task::JoinSet,
    time::{timeout, timeout_at, Instant},
};

fn report(event: &str, value: serde_json::Value) {
    println!("{}", serde_json::json!({"event": event, "data": value}));
}

async fn register(socket: &UdpSocket, identity: &Identity) -> Result<()> {
    let pk = identity.key.public_key();
    let mut message = RendezvousMessage::new();
    message.set_register_pk(RegisterPk {
        id: identity.id.clone(),
        uuid: randombytes(16).into(),
        pk: pk.as_ref().to_vec().into(),
        ..Default::default()
    });
    socket.send(&message.write_to_bytes()?).await?;
    let mut data = [0u8; 4096];
    let n = timeout(Duration::from_secs(3), socket.recv(&mut data)).await??;
    let response = RendezvousMessage::parse_from_bytes(&data[..n])?;
    ensure!(
        matches!(response.union, Some(rendezvous_message::Union::RegisterPkResponse(r)) if r.result.enum_value_or_default() == register_pk_response::Result::OK),
        "key registration failed"
    );
    advertise(socket, identity).await
}

async fn advertise(socket: &UdpSocket, identity: &Identity) -> Result<()> {
    let capability = protocol::encode(
        &protocol::request(
            &identity.id,
            Action::Advertise {
                version: p2p::VERSION,
            },
        )?,
        &identity.key,
    )?;
    let mut message = RendezvousMessage::new();
    message.set_register_peer(RegisterPeer {
        id: identity.id.clone(),
        native_p2p_version: p2p::VERSION,
        native_p2p_capability: capability.into(),
        ..Default::default()
    });
    socket.send(&message.write_to_bytes()?).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    p2p::init()?;
    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).map(String::as_str).unwrap_or("help");
    if role == "discover" {
        let (socket, addresses) =
            p2p::stun::discover(args.get(2).map(String::as_str).unwrap_or(p2p::STUN_SERVER))
                .await?;
        report(
            "mapping",
            serde_json::json!({"local":socket.local_addr()?, "observations":addresses, "stable":protocol::mapping(&addresses)?}),
        );
        return Ok(());
    }
    ensure!(matches!(role, "listen" | "connect"), "usage: native-p2p-probe discover [stun] | listen SERVER PUBLIC_KEY | connect SERVER PUBLIC_KEY TARGET_ID");
    let endpoint = args.get(2).context("missing server")?;
    let key = STANDARD.decode(args.get(3).context("missing server public key")?.trim())?;
    let server = sign::PublicKey::from_slice(&key).context("invalid server public key")?;
    let (_, key) = sign::gen_keypair();
    let identity = Identity {
        id: format!("p2p{}", protocol::id()),
        key,
    };
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    socket.connect(endpoint).await?;
    register(&socket, &identity).await?;
    // Give the UDP capability one RTT to reach hbbs before opening the TCP request.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let mut tasks = JoinSet::new();
    let heartbeat = socket.clone();
    let heartbeat_id = identity.clone();
    tasks.spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(8)).await;
            advertise(&heartbeat, &heartbeat_id).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });
    report("ready", serde_json::json!({"id":identity.id, "role":role}));
    let result = timeout(Duration::from_secs(120), async {
        let session = if role == "listen" {
            let mut buffer = [0u8; p2p::MAX_MESSAGE];
            loop {
                let n = socket.recv(&mut buffer).await?;
                let message = RendezvousMessage::parse_from_bytes(&buffer[..n])?;
                if let Some(rendezvous_message::Union::NativeP2pV1(message)) = message.union {
                    ensure!(message.version == p2p::VERSION, "unknown invitation version");
                    let invite: Invite = protocol::decode(&message.payload, &server)?;
                    break Session::join(endpoint, identity.clone(), server, invite).await?;
                }
            }
        } else {
            Session::begin(endpoint, identity.clone(), server, args.get(4).context("missing target id")?).await?.context("peer does not support native P2P")?
        };
        let started = Instant::now();
        report("ticket", serde_json::json!({"session":session.ticket.session, "initiator":session.ticket.initiator}));
        let punched = session.punch(p2p::STUN_SERVER).await?;
        let deadline = punched.session.deadline;
        let peer = punched.peer;
        let local = punched.socket.local_addr()?;
        timeout_at(deadline, async {
            let mut buffer = [0u8; 1500];
            if role == "listen" {
                loop {
                    let n = punched.socket.recv(&mut buffer).await?;
                    if n == 256 { punched.socket.send(&buffer[..n]).await?; break; }
                }
            } else {
                let challenge = randombytes(256);
                let mut interval = tokio::time::interval(Duration::from_millis(200));
                loop {
                    tokio::select! {
                        _ = interval.tick() => { punched.socket.send(&challenge).await?; },
                        n = punched.socket.recv(&mut buffer) => {
                            let n = n?;
                            if buffer[..n] == challenge { break; }
                        }
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        }).await??;
        report("verified", serde_json::json!({"peer":peer,"local":local,"elapsed_ms":started.elapsed().as_millis(),"transport":"authenticated-udp-direct"}));
        Ok::<(), anyhow::Error>(())
    }).await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    drop(socket);
    // Let the bounded session-cancellation RPC finish before the runtime exits.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    report("closed", serde_json::json!({"sockets_closed":true}));
    match result {
        Ok(value) => value,
        Err(error) => bail!(error),
    }
}
