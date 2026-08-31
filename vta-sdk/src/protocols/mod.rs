pub mod acl_management;
pub mod attestation_management;
pub mod audit_management;
pub mod auth;
pub mod backup_management;
/// Issued-credential lifecycle (`spec/vta/credentials/{issue,revoke}/0.1`) —
/// mint + revoke a VTA-signed W3C VC addressed to a holder DID.
pub mod consent_management;
pub mod context_management;
pub mod credential_exchange;
pub mod credentials_issuance;
pub mod device_management;
pub mod did_management;
pub mod did_template_management;
pub mod discovery;
#[cfg(feature = "didcomm")]
pub mod join_requests;
pub mod key_management;
/// Member-side membership-credential exchange (`members/*`) — the member → VTC
/// reciprocal VMC and the VTC's request for it.
pub mod members;
/// Per-context key/value store for AI-agent memory
/// (`spec/vta/memory/{put,list,delete}/0.1`).
pub mod memory;

/// Versioned, namespaced application state
/// (`spec/vta/app-state/{get,put,list,delete,get-many,put-many}/1.0`) — the
/// third store, beside the vault and agent memory, for JSON an application owns
/// and the VTA does not interpret.
pub mod app_state;
/// Passkey-based login flow (`vta/auth/passkey-login-{start,finish}/1.0`).
pub mod passkey_login;
/// Runtime Policy Decision Point management (`policy/*`) — where the
/// declarative approvals model is read and written.
pub mod policy_management;
pub mod protocol_management;
#[cfg(feature = "provision-integration")]
pub mod provision_integration_management;
pub mod seed_management;
pub mod vault_management;
pub mod vta_management;

// Standard DIDComm protocol types used across VTA/VTC services
pub const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";
pub const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
pub const MESSAGE_PICKUP_STATUS_TYPE: &str = "https://didcomm.org/messagepickup/3.0/status";

/// Problem-report `code` values emitted by VTA/VTC services. Kept in sync with
/// the `affinidi_messaging_didcomm_service::problem_report::codes` taxonomy so
/// the SDK can classify errors without depending on the server-side crate.
pub mod problem_report_codes {
    pub const UNAUTHORIZED: &str = "e.p.msg.unauthorized";
    pub const BAD_REQUEST: &str = "e.p.msg.bad-request";
    pub const NOT_FOUND: &str = "e.p.msg.not-found";
    pub const CONFLICT: &str = "e.p.msg.conflict";
    pub const INTERNAL: &str = "e.p.msg.internal-error";
    /// Workspace-specific extension to the affinidi taxonomy.
    /// Distinguishes "permission denied" (caller authenticated but
    /// lacks the role / context / sender-identity) from
    /// `unauthorized` (auth failed). Without this, the SDK
    /// collapses both into `VtaError::Auth` and the CLI prints
    /// "Token may be expired" — which is misleading when the real
    /// problem is a privilege-laundering rejection or an ACL miss.
    pub const FORBIDDEN: &str = "e.p.msg.forbidden";
    /// Per the canonical `provision/integration/0.1` spec: emitted
    /// when the caller omits `payload.context` AND the maintainer
    /// cannot infer a unique target context from the relayer's grant
    /// or its own contexts state. The problem-report body's `args`
    /// carries `candidates: Vec<String>` so the relayer can surface
    /// the list to the operator and retry with an explicit choice.
    pub const PROVISION_CONTEXT_REQUIRED: &str = "provision/integration:contextRequired";
}

/// Machine-readable `details.reason` values the VTA puts on a Trust-Task
/// rejection so the client can recover the outcome the server actually had.
///
/// # Why this exists
///
/// The Trust-Task framework defines no `notFound` / `conflict` / `gone`
/// standard code, so all three ride out under `taskFailed`
/// ([`RejectReason::TaskFailed`]). The code alone therefore cannot distinguish
/// "the row you asked for is absent" — routinely a *normal* state a caller
/// handles — from "this operation genuinely failed". Collapsing them loses
/// information that both the REST path (HTTP 404 / 409 / 410, see
/// [`VtaError::from_http`]) and the DIDComm protocol-message path
/// ([`problem_report_codes`], see [`VtaError::from_problem_report`]) preserve,
/// leaving the Trust-Task transport the only one that hands the caller an
/// opaque string.
///
/// The concrete failure this was written for: a VTA that has never had an
/// approval rule has no `approvals` policy row, which is the shipping default.
/// `pnm approvals list` reads that row through `policy/get/0.1` and is written
/// to treat a missing one as an empty model — but the `NotFound` never arrived
/// as `NotFound`, so *every* `pnm approvals` subcommand failed on a fresh VTA,
/// including the `require` that would have created the first rule.
///
/// The channel is the one the consent gate already established: `code` is
/// `taskFailed` for everything, so a consumer keys on a stable `details.reason`
/// instead.
///
/// [`RejectReason::TaskFailed`]: https://docs.rs/trust-tasks-rs
/// [`VtaError::from_http`]: crate::error::VtaError::from_http
/// [`VtaError::from_problem_report`]: crate::error::VtaError::from_problem_report
pub mod trust_task_reject_reasons {
    /// The requested resource does not exist. Recovers [`VtaError::NotFound`].
    ///
    /// [`VtaError::NotFound`]: crate::error::VtaError::NotFound
    pub const NOT_FOUND: &str = "not_found";
    /// The request conflicts with existing state (duplicate id, stale
    /// `expectedVersion`). Recovers [`VtaError::Conflict`].
    ///
    /// [`VtaError::Conflict`]: crate::error::VtaError::Conflict
    pub const CONFLICT: &str = "conflict";
    /// The resource existed but is permanently gone (a consumed single-use
    /// carve-out). Recovers [`VtaError::Gone`].
    ///
    /// [`VtaError::Gone`]: crate::error::VtaError::Gone
    pub const GONE: &str = "gone";
}

/// Machine-readable `details` members the VTA puts on an
/// `unsupportedType` / `unsupportedVersion` rejection.
///
/// # Why this exists
///
/// The framework carries the rejected Type URI only inside the human-readable
/// `message` (`unsupported type: <uri>`), and carries what the responder
/// *does* serve nowhere at all. So the one rejection whose fix is "upgrade
/// something" gave a client no way to say **which** thing without slicing a
/// sentence — and the version in that sentence is the whole diagnosis: an
/// older version named means the client is behind, a newer one means the
/// responder is.
///
/// Sibling of [`trust_task_reject_reasons`] and here for the same reason: the
/// service writes these keys and the SDK reads them, so a second spelling in
/// either place is a wire contract that drifts silently.
///
/// Absent from an older responder — a consumer must treat a missing
/// [`SERVED_VERSIONS`] as "unknown", never as "the family does not exist".
pub mod trust_task_reject_details {
    /// The Type URI the producer dispatched, as the consumer received it.
    /// Machine-readable counterpart to the URI in `message`.
    pub const REQUESTED_TYPE: &str = "requestedType";
    /// Type URIs of the **same family** the consumer does serve, sorted.
    /// Present only on `unsupportedVersion`.
    pub const SERVED_VERSIONS: &str = "servedVersions";
}

/// Extract code and comment from a problem-report message body.
pub fn extract_problem_report(body: &serde_json::Value) -> (String, String) {
    let code = body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let comment = body
        .get("comment")
        .and_then(|v| v.as_str())
        .unwrap_or("no details provided")
        .to_string();
    (code, comment)
}
