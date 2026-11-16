//! [`VtaAuditEvent`] — what a VTA writes into its hash-chained audit log.
//!
//! The envelope, the chain, the HMAC actor hashing and the writer are
//! `vti_common::audit`'s, generic over the event payload; this is the VTA's
//! payload. It moved here from `vti_common::audit::AuditEvent` (#2568), whose
//! other variants are the community's vocabulary and now live in `vtc-audit`.
//!
//! ## Wire contract
//!
//! Tagged `#[serde(tag = "type", content = "data")]`, exactly as the shared
//! enum was, so a VTA row reads `{"type":"VtaOperation","data":{…}}` before and
//! after the move. The chain commits to that encoding: renaming the variant or
//! a field breaks verification of every stored chain.

use serde::{Deserialize, Serialize};

/// A VTA audit-log event.
///
/// **Non-exhaustive**, as the shared enum it came from was: a reader that
/// cannot name an event still has to account for it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data")]
#[non_exhaustive]
pub enum VtaAuditEvent {
    /// An operation performed by a VTA, in the flat shape its call sites
    /// produce.
    ///
    /// A VTA audits every gated operation it serves, the set grows with the
    /// task catalogue, and the call sites already carry a dotted action name
    /// rather than a type. Modelling each as a variant would mean an enum that
    /// changes whenever an operation does, and a wire contract that breaks
    /// with it.
    ///
    /// So the action stays a string and this variant carries the four things
    /// a VTA call site supplies beside it. The actor and any DID-shaped
    /// target travel outside the data, in the envelope's hashed members,
    /// where an erasure can reach them.
    VtaOperation(VtaOperationData),
}

impl VtaAuditEvent {
    /// The serde tag for this variant — the `type` on the stored envelope.
    pub fn variant_name(&self) -> &'static str {
        match self {
            // The variant name, not the action inside it. A consumer
            // discriminating on `type` sees one kind for every VTA operation
            // and reads `data.action` for which one.
            Self::VtaOperation(..) => "VtaOperation",
        }
    }
}

/// Payload of [`VtaAuditEvent::VtaOperation`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VtaOperationData {
    /// Dotted action name as the call site reports it — `auth.challenge`,
    /// `acl.create`, `vault.sign-trust-task`. Part of the wire contract for
    /// consumers that filter on it.
    pub action: String,

    /// The object acted upon, where it is not a DID: a key id, a session id,
    /// a context path. A DID-shaped target is carried in the envelope's
    /// hashed `target_did_*` members instead, so that an erasure reaches it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,

    /// `success`, `failure`, or whatever the call site reports. Refusals are
    /// audited as well as successes, so this is load-bearing rather than
    /// decorative.
    pub outcome: String,

    /// The transport the request arrived over. A VTA-specific fact: the same
    /// operation under the same authority must reach the same decision on
    /// every transport, and this is how an auditor checks that it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,

    /// The trust context the action took place in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// Operator-supplied rationale, where the operation asks for one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A persisted VTA audit-log entry: the shared envelope carrying a
/// [`VtaAuditEvent`].
pub type VtaAuditEnvelope = vti_common::audit::AuditEnvelope<VtaAuditEvent>;

/// The VTA's hash-chained audit writer.
pub type VtaAuditWriter = vti_common::audit::AuditWriter<VtaAuditEvent>;
