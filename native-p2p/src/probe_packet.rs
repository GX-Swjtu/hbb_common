use anyhow::{ensure, Result};
use sodiumoxide::crypto::auth;

const MAGIC: &[u8] = b"RDP2PV1\0";
const BODY: usize = 8 + 32 + 1 + 16;

pub(crate) fn packet(session: &str, response: bool, nonce: &[u8], key: &auth::Key) -> Result<Vec<u8>> {
    ensure!(
        session.len() == 32 && nonce.len() == 16,
        "invalid probe context"
    );
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(session.as_bytes());
    out.push(u8::from(response));
    out.extend_from_slice(nonce);
    out.extend_from_slice(auth::authenticate(&out, key).as_ref());
    Ok(out)
}

pub(crate) fn verified<'a>(
    data: &'a [u8],
    session: &str,
    response: bool,
    key: &auth::Key,
) -> Option<&'a [u8]> {
    if data.len() != BODY + auth::TAGBYTES
        || &data[..8] != MAGIC
        || &data[8..40] != session.as_bytes()
        || data[40] != u8::from(response)
    {
        return None;
    }
    let tag = auth::Tag::from_slice(&data[BODY..])?;
    auth::verify(&tag, &data[..BODY], key).then_some(&data[41..BODY])
}
