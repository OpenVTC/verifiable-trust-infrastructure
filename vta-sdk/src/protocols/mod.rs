pub mod acl_management;
pub mod attestation_management;
pub mod audit_management;
pub mod auth;
pub mod backup_management;
pub mod context_management;
pub mod credential_exchange;
pub mod did_management;
pub mod did_template_management;
pub mod discovery;
#[cfg(feature = "didcomm")]
pub mod join_requests;
pub mod key_management;
/// Passkey-based login flow (`vta/auth/passkey-login-{start,finish}/1.0`).
pub mod passkey_login;
pub mod protocol_management;
#[cfg(feature = "provision-integration")]
pub mod provision_integration_management;
pub mod seed_management;
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
    pub const PROVISION_CONTEXT_REQUIRED: &str = "provision/integration:context_required";
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
