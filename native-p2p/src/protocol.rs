use anyhow::{bail, ensure, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sodiumoxide::{
    crypto::{box_, sealedbox, sign},
    randombytes::randombytes,
};
use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

const DOMAIN: &[u8] = b"rustdesk-native-udp-punch\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub nonce: Vec<u8>,
    pub time: u64,
    pub action: Action,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Action {
    Advertise {
        capability: String,
        enabled: bool,
    },
    Begin {
        target: String,
        box_pk: Vec<u8>,
        #[serde(default)]
        licence_key: String,
    },
    Join {
        session: String,
        box_pk: Vec<u8>,
    },
    Prepare {
        session: String,
        candidates: crate::candidates::Candidates,
    },
    Poll {
        session: String,
    },
    Cancel {
        session: String,
    },
    Confirm {
        session: String,
    },
    Observe {
        session: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub nonce: Vec<u8>,
    pub time: u64,
    pub reply: Reply,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Reply {
    Unsupported,
    Ticket(Ticket),
    Waiting,
    Plan(Plan),
    Closed,
    Error(String),
    Observed(std::net::IpAddr),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    pub session: String,
    pub expires: u64,
    pub secret_box: Vec<u8>,
    pub peer_id: String,
    pub signed_peer: Vec<u8>,
    pub initiator: bool,
    pub capability: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invite {
    pub session: String,
    pub from: String,
    pub target: String,
    pub expires: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub session: String,
    pub sender: bool,
    pub peer: crate::candidates::Candidates,
    pub behavior: crate::strategy::Behavior,
    pub lan_only: bool,
}

pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub fn id() -> String {
    randombytes(16).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn encode<T: Serialize>(value: &T, key: &sign::SecretKey) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(value)?;
    ensure!(
        body.len() < crate::MAX_MESSAGE / 4,
        "native payload too large"
    );
    let mut signed = DOMAIN.to_vec();
    signed.extend_from_slice(&body);
    Ok(serde_json::to_vec(&Signed {
        body,
        signature: sign::sign_detached(&signed, key).as_ref().to_vec(),
    })?)
}

pub fn decode<T: DeserializeOwned>(data: &[u8], key: &sign::PublicKey) -> Result<T> {
    ensure!(data.len() <= crate::MAX_MESSAGE, "native message too large");
    let value: Signed = serde_json::from_slice(data)?;
    let signature = sign::Signature::from_bytes(&value.signature)
        .map_err(|_| anyhow::anyhow!("invalid signature"))?;
    let mut signed = DOMAIN.to_vec();
    signed.extend_from_slice(&value.body);
    ensure!(
        sign::verify_detached(&signature, &signed, key),
        "native signature mismatch"
    );
    Ok(serde_json::from_slice(&value.body)?)
}

// Used only to locate a registered verification key; the result is not authorization.
pub fn request_id(data: &[u8]) -> Result<String> {
    ensure!(data.len() <= crate::MAX_MESSAGE, "native message too large");
    let signed: Signed = serde_json::from_slice(data)?;
    let request: Request = serde_json::from_slice(&signed.body)?;
    ensure!(
        !request.id.is_empty() && request.id.len() <= 253,
        "invalid device id"
    );
    Ok(request.id)
}

pub fn request(id: &str, action: Action) -> Result<Request> {
    Ok(Request {
        id: id.to_owned(),
        nonce: randombytes(24),
        time: now()?,
        action,
    })
}

pub fn fresh(request: &Request) -> Result<()> {
    ensure!(request.nonce.len() == 24, "invalid nonce");
    ensure!(
        now()?.abs_diff(request.time) <= 30,
        "expired native request"
    );
    Ok(())
}

pub fn seal(secret: &[u8], pk: &[u8]) -> Result<Vec<u8>> {
    let pk = box_::PublicKey::from_slice(pk).context("invalid ephemeral public key")?;
    Ok(sealedbox::seal(secret, &pk))
}

pub fn mapping(addresses: &[SocketAddr]) -> Result<bool> {
    ensure!(addresses.len() == 2, "two UDP observations required");
    for a in addresses {
        match a {
            SocketAddr::V4(v4)
                if !v4.ip().is_unspecified()
                    && !v4.ip().is_multicast()
                    && !v4.ip().is_broadcast()
                    && v4.port() > 0 => {}
            _ => bail!("unsupported UDP address"),
        }
    }
    ensure!(
        addresses[0].ip() == addresses[1].ip(),
        "changing public IP unsupported"
    );
    Ok(addresses[0] == addresses[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_requires_the_single_capability_and_no_test_generation_fields() {
        let old = serde_json::json!({"session": id(), "expires": now().unwrap() + 45,
            "secret_box": [], "peer_id": "old", "signed_peer": [], "initiator": true, "strategies": 1});
        assert!(serde_json::from_value::<Ticket>(old).is_err());
        let value = serde_json::to_value(Action::Advertise { capability: crate::CAPABILITY.into(), enabled: true }).unwrap();
        assert_eq!(value, serde_json::json!({"Advertise": {"capability": "native-udp-punch", "enabled": true}}));
    }

    #[test]
    fn signed_requests_reject_tampering_and_expiration() {
        crate::init().unwrap();
        let (pk, sk) = sign::gen_keypair();
        let request = request("device123", Action::Poll { session: id() }).unwrap();
        let bytes = encode(&request, &sk).unwrap();
        let verified: Request = decode(&bytes, &pk).unwrap();
        fresh(&verified).unwrap();
        let (other, _) = sign::gen_keypair();
        assert!(decode::<Request>(&bytes, &other).is_err());
        let mut expired = verified;
        expired.time = 0;
        assert!(fresh(&expired).is_err());
    }

    #[test]
    fn udp_mapping_is_independent_of_tcp_nat_type() {
        let stable = ["119.4.23.36:50000".parse().unwrap(); 2];
        let changed = [
            "182.150.22.214:3273".parse().unwrap(),
            "182.150.22.214:3277".parse().unwrap(),
        ];
        assert!(mapping(&stable).unwrap());
        assert!(!mapping(&changed).unwrap());
        assert!(mapping(&changed[..1]).is_err());
    }
}
