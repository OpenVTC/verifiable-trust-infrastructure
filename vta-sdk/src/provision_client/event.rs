//! Channel protocol — events emitted by the runners and consumed by the
//! caller's UI / driver.
//!
//! Both [`VtaEvent`] and [`AttemptResultKind`] are part of the SDK's
//! versioned public surface. Variants are **stable** — adding a new
//! variant is the only permitted change. Renaming, removing, or
//! reshaping a variant is a breaking change. Consumers should match
//! exhaustively and treat unknown variants as forward-compat noise once
//! the channel grows past v1.
//!
//! See also [`super::diagnostics::DiagCheck`] / [`DiagStatus`], which
//! ride the `CheckStart` / `CheckDone` events.

use std::time::Instant;

use crate::webvh::WebvhServerRecord;

use super::diagnostics::{DiagCheck, DiagStatus, Protocol};
use super::intent::VtaReply;
use super::resolve::ResolvedVta;

/// Single event emitted by the runner. The consumer applies it to the
/// diagnostics list and/or transitions its UI state.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum VtaEvent {
    /// One of the diagnostic checks has started running. The consumer
    /// flips its row to `Running` (or whatever icon the UI uses).
    CheckStart(DiagCheck),
    /// One of the diagnostic checks has finished — successfully,
    /// skipped, or failed. The status carries operator-facing detail.
    CheckDone(DiagCheck, DiagStatus),
    /// The VTA's DID document has been resolved. The consumer stashes
    /// advertised-transport info on its state so downstream UI can dim
    /// options the VTA doesn't actually support.
    Resolved(ResolvedVta),
    /// A transport attempt has resolved — either to a terminal
    /// `Connected`, or to a pre-auth / post-auth failure. Drives the
    /// consumer's [`AttemptLog`] so retry prompts know which retries
    /// are still meaningful. Not emitted for `PreflightOk` — that is
    /// mid-attempt for the FullSetup DIDComm path.
    AttemptCompleted {
        protocol: Protocol,
        outcome: AttemptResultKind,
    },
    /// Emitted by the FullSetup DIDComm preflight when the auth check
    /// has succeeded and the webvh-server catalogue has been fetched.
    /// The consumer inspects `servers` to decide whether to auto-pick
    /// (0 or 1 entry) or prompt the operator (2+). After the choice is
    /// settled, a provision flight is spawned with the chosen
    /// `webvh_server_id` (or `None` for serverless).
    PreflightDone {
        rest_url: Option<String>,
        mediator_did: String,
        servers: Vec<WebvhServerRecord>,
    },
    /// The VTA round-trip succeeded.
    Connected {
        protocol: Protocol,
        /// REST URL advertised in the VTA DID doc, retained for the
        /// integration's runtime credential so it has a URL fallback
        /// at startup. Always `None` when the VTA advertises no
        /// `#vta-rest` service.
        rest_url: Option<String>,
        /// Mediator DID from the VTA DID doc that carried the round-trip:
        /// the `#DIDCommMessaging` mediator when `protocol == DidComm`,
        /// the `#tsp` mediator when `protocol == Tsp`. Always `Some` for
        /// both; `None` on the REST path.
        mediator_did: Option<String>,
        /// Unified reply — see [`VtaReply`] for the variants.
        reply: VtaReply,
    },
    /// Terminal failure. The string is operator-facing and ready to
    /// render verbatim.
    Failed(String),
}

/// Stable shape of an attempt outcome. Carries the operator-facing
/// failure reason for the failure variants — already wrapped with
/// retry-friendly prose by the runner.
#[derive(Clone, Debug)]
pub enum AttemptResultKind {
    Connected,
    PreAuthFailure(String),
    PostAuthFailure(String),
}

/// Recorded outcome of a single transport attempt. Lives in
/// [`AttemptLog`] so retry/recovery prompts can decide which retry
/// options to offer.
#[derive(Clone, Debug)]
pub struct AttemptResult {
    pub outcome: AttemptResultKind,
    pub at: Instant,
}

/// Per-transport history of attempts on this run. Every field is
/// `None` until the corresponding transport runs at least once.
#[derive(Clone, Debug, Default)]
pub struct AttemptLog {
    pub tsp: Option<AttemptResult>,
    pub didcomm: Option<AttemptResult>,
    pub rest: Option<AttemptResult>,
}

/// Outcome of a single transport's auth attempt — the runner-internal
/// shape that the orchestrator translates into [`VtaEvent`] variants.
///
/// Pre-auth / post-auth distinction matters for fallback. A pre-auth
/// failure (transport / handshake / ACL miss) is worth retrying over a
/// different transport; a post-auth failure (template error, etc.)
/// means the VTA accepted us and a different wire will reproduce the
/// rejection.
#[allow(clippy::large_enum_variant, dead_code)] // wired up by the transport runners landing in subsequent tasks.
#[derive(Debug)]
pub(crate) enum AttemptOutcome {
    /// Attempt produced a final reply with no further preflight needed.
    Connected(VtaReply),
    /// FullSetup preflight success. The orchestrator emits a
    /// [`VtaEvent::PreflightDone`]; the main loop then either
    /// auto-picks a webvh server (0/1 catalogue entries) or shows the
    /// picker (2+) before spawning the provision flight.
    PreflightOk {
        rest_url: Option<String>,
        mediator_did: String,
        servers: Vec<WebvhServerRecord>,
    },
    /// Failure before auth completed (transport / handshake / ACL miss).
    /// The string is the operator-facing failure message — the
    /// orchestrator emits it verbatim as [`VtaEvent::Failed`].
    PreAuthFailure(String),
    /// Failure after auth completed but before the protocol's natural
    /// endpoint. Produced by the REST FullSetup path when
    /// `provision_integration` returns an error after the auth
    /// handshake succeeded.
    PostAuthFailure(String),
}
