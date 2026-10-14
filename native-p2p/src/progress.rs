//! Optional, secret-free observations. These never alter the signed plan format.
use crate::{candidates::Candidates, protocol::Plan};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Progress {
    Stage(&'static str),
    Local(Candidates),
    Selected(Plan),
    Probes { sent: usize, authenticated: usize, sockets: usize },
}

pub type Observer = Option<Arc<dyn Fn(Progress) + Send + Sync>>;
pub fn report(observer: &Observer, progress: Progress) {
    if let Some(observer) = observer { observer(progress); }
}

const PREFIX: &str = "native-p2p-reason:";
const LIMIT: usize = 3072;

/// Carried in the existing signed Error string, never in a strict Plan or Ticket.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reason {
    pub code: String,
    pub message: String,
    pub local: Option<Candidates>,
    pub peer: Option<Candidates>,
}

impl Reason {
    pub fn encode(&self) -> String {
        match serde_json::to_string(self) {
            Ok(json) if json.len() <= LIMIT => format!("{PREFIX}{json}"),
            _ => "native UDP has no applicable strategy".into(),
        }
    }

    pub fn decode(text: &str) -> Option<Self> {
        let json = text.strip_prefix(PREFIX)?;
        if json.len() > LIMIT { return None; }
        let reason: Self = serde_json::from_str(json).ok()?;
        if reason.code.len() > 64 || reason.message.len() > 512 { return None; }
        for candidates in [&reason.local, &reason.peer].into_iter().flatten() {
            candidates.validate().ok()?;
        }
        Some(reason)
    }
}
