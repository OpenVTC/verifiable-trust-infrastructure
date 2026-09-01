//! Wire payloads for the issued-credential lifecycle Trust Tasks
//! (`spec/vta/credentials/{issue/0.2, revoke/0.1, list/0.1}`).
//!
//! These mint / revoke a VTA-signed W3C Verifiable Credential addressed to a
//! holder DID, distinct from the credential-vault slice (`vault/credentials/*`)
//! which stores credentials the holder already holds. Both request bodies carry
//! `deny_unknown_fields` as a forward-compat guard; all fields are camelCase on
//! the wire.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `spec/vta/credentials/issue/0.2` request body.
///
/// Unchanged from 0.1 — the version moved for the response only.
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
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/vta/credentials/issue/0.2` response body.
///
/// 0.2 composes this from `credentials/_shared/0.2`'s `IssuedCredentialBase`
/// rather than restating the members inline, which is what the two versions
/// differ by. The composition adds one member, `issuedAt`.
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
    /// RFC 3339 mint time (`validFrom`).
    ///
    /// `Option` because the shared definition declares it optional, so a
    /// response without it is schema-valid and must still deserialize. The VTA
    /// always sends it: the stored record has carried `issued_at` since the
    /// family existed, and 0.1 simply had nowhere to put it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
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
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
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

/// The state of an issued credential, as reported by `list`.
///
/// **Derived when the list is answered, never stored.** A stored status is a
/// copy of a fact about the clock and is wrong from the first second after it
/// is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IssuedCredentialStatus {
    /// Neither revoked nor past its expiry.
    Active,
    /// Not revoked, and `expiresAt` has passed.
    Expired,
    /// A revocation was recorded.
    ///
    /// **Takes precedence over expiry.** A credential revoked before its
    /// window closed is revoked; reporting it as merely expired would hide
    /// that somebody acted.
    Revoked,
}

/// `spec/vta/credentials/list/0.1` request body.
///
/// Every member is an optional filter, AND-combined. An unfiltered request is
/// answered — unlike `vault/credentials/query`, which refuses one. The two look
/// alike and are not: there the caller reads a *holder's* private store, here
/// the issuer reads a record of its own past actions, and refusing to enumerate
/// would withhold from a party what it did itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListCredentialsBody {
    /// Only credentials issued to this DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    /// Only credentials carrying this type tag beyond `VerifiableCredential`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    /// Only credentials in this state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<IssuedCredentialStatus>,
    /// Maximum records to return. The agent caps this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    /// Continue a previous page. Opaque to the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// One row of a `list` response — a **body-free** projection of an issuance
/// record.
///
/// The credential itself is deliberately absent. `vault/list/0.1` states the
/// rule this follows — *list exists to enumerate; release exists to use* — and
/// a response carrying every claim body would turn reading a roster into a bulk
/// disclosure of everything the issuer ever asserted about anyone.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuedCredentialSummary {
    /// The id `vta/credentials/revoke` is keyed on.
    pub credential_id: String,
    /// Who the credential was issued to.
    pub holder: String,
    /// The type tag beyond `VerifiableCredential`, when the credential has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    pub issued_at: String,
    pub expires_at: String,
    pub status: IssuedCredentialStatus,
    /// Set iff `status` is `revoked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    /// Free text recorded at revocation, disclosed to every caller entitled to
    /// this list. An issuer must not write anything here it would not show that
    /// audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
}

/// `spec/vta/credentials/list/0.1` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListCredentialsResponse {
    /// One summary per matching credential. Empty when nothing matched — a
    /// successful answer, not an error.
    pub credentials: Vec<IssuedCredentialSummary>,
    /// The agent stopped early. A consumer must not read a truncated page as a
    /// complete account of what was issued.
    pub truncated: bool,
    /// Pass to the next request to continue. Absent on the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}
