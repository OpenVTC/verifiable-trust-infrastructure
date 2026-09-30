//! Wire format between a `pnm` client and its control master.
//!
//! One newline-delimited JSON request, one newline-delimited JSON response,
//! with the client's stdio descriptors riding the request as `SCM_RIGHTS`.
//! Deliberately not a stable interface: both ends ship in the same binary and
//! [`Request::protocol`] refuses a mismatch rather than guessing.

use serde::{Deserialize, Serialize};

/// Bumped whenever the request or response shape changes. A master left running
/// across an upgrade is a real scenario — `ControlPersist` outlives a `cargo
/// install` — so the client checks this and falls back to a direct session
/// instead of talking to an older master.
pub(crate) const PROTOCOL: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Request {
    pub(crate) protocol: u32,
    /// Argv as the user typed it, minus `argv[0]`.
    pub(crate) args: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Response {
    /// Command ran. `code` is the exit status the client should adopt.
    Done { code: i32, elapsed_ms: u64 },
    /// Master refused the request; the client falls back to a direct session.
    Refused { reason: String },
    /// Answer to a status probe.
    Status {
        pid: u32,
        slug: String,
        persist: String,
        idle_secs: u64,
    },
    /// Master is shutting down.
    Exiting,
}

/// Control-plane verbs, the equivalent of `ssh -O check|exit`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum Control {
    Check,
    Exit,
}

/// A request is either a command to run or a control verb.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Envelope {
    Control(Control),
    Command(Request),
}
