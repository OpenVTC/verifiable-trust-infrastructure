//! Wire payloads for the issued-credential lifecycle Trust Tasks
//! (`spec/vta/credentials/{issue,revoke}/0.1`).
//!
//! These mint / revoke a VTA-signed W3C Verifiable Credential addressed to a
//! holder DID, distinct from the credential-vault slice (`vault/credentials/*`)
//! which stores credentials the holder already holds. Both request bodies carry
//! `deny_unknown_fields` as a forward-compat guard; all fields are camelCase on
//! the wire.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `spec/vta/credentials/issue/0.1` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssueCredentialBody {
    /// The holder DID the credential is issued to (`credentialSubject.id`).
    pub holder: String,
    /// The credential claims merged into `credentialSubject` (must be a
    /// non-empty JSON object).
    pub claims: Value,
    /// Optional extra credential type appended to
    /// `["VerifiableCredential", …]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    /// Validity window length in seconds from issuance (`validUntil =
    /// validFrom + validitySeconds`).
    pub validity_seconds: u64,
    /// Optional human-readable purpose (audit trail only; not signed into the
    /// VC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Optional structured authorization context surfaced to the operator's
    /// step-up device (e.g. a Cierge share/spend/tool ask). Request-only: the
    /// step-up gate reads it to render *what* is being authorized; it is never
    /// signed into the issued VC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_context: Option<Value>,
}

/// `spec/vta/credentials/issue/0.1` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCredentialResponse {
    /// The issued credential's id (also the store key).
    pub credential_id: String,
    /// The full signed W3C Verifiable Credential (with its Data-Integrity
    /// proof).
    pub credential: Value,
    /// RFC 3339 expiry (`validUntil`).
    pub expires_at: String,
}

/// `spec/vta/credentials/revoke/0.1` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeCredentialBody {
    /// The id of the credential to revoke (from the issue response).
    pub credential_id: String,
    /// Optional reason (recorded in the audit trail + revocation tombstone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `spec/vta/credentials/revoke/0.1` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeCredentialResponse {
    /// The revoked credential's id.
    pub credential_id: String,
    /// RFC 3339 timestamp at which the credential was revoked.
    pub revoked_at: String,
}
