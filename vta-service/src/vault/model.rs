//! `StoredCredential` — the format-agnostic credential envelope held by the
//! VTA `vault` (credential store, distinct from the password-manager
//! `VaultEntry` in `vti_common::vault`).
//!
//! Task 1.1 of the VTI credential architecture
//! (`docs/05-design-notes/vti-credential-architecture.md` §5). This module
//! is **format-agnostic**: the credential body is stored as opaque bytes
//! plus an indexed metadata envelope. **No cryptographic verification,
//! signing, presentation, or disclosure happens here** — those land in
//! later tasks (1.2 receive, 1.4 present, 1.5 mint, 1.6 status). This
//! module only models + indexes what the holder already holds.
//!
//! Security/privacy invariants this module upholds
//! (`vti-credential-architecture.md` §14):
//! - The credential body (`body`) is opaque to the store and encrypted at
//!   rest via the keyspace's AES-256-GCM wrapper. This module never parses
//!   it, never logs it, and never re-emits it.
//! - There is **no "list all" surface** in this module. Reads are by `id`
//!   ([`super::storage::get`]) or by an explicit, single-field index
//!   prefix scan ([`super::index`]). The no-wallet-enumeration invariant is
//!   enforced at the route/operation layer (no endpoint returns the whole
//!   set), and this module deliberately gives that layer only targeted
//!   primitives to build on.

use serde::{Deserialize, Serialize};

/// Proof / serialization format of the stored credential body. Stored as a
/// tag so the (later) receive/present/status code can dispatch to the right
/// format verifier without this format-agnostic layer needing to understand
/// any of them. Open-ended via [`CredentialFormat::Other`] so a new format
/// never requires a storage-schema change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialFormat {
    /// BBS+ Data-Integrity proof (`bbs-2023`) — selective disclosure.
    Bbs2023,
    /// Ed25519 JCS Data-Integrity proof (`eddsa-jcs-2022`).
    EddsaJcs2022,
    /// IETF SD-JWT-VC.
    SdJwtVc,
    /// Forward-compatibility escape hatch — carries the raw tag verbatim so
    /// an unknown format round-trips losslessly.
    #[serde(untagged)]
    Other(String),
}

/// Lifecycle / validity status of a stored credential. Set to
/// [`CredentialStatus::Unknown`] at store time (this task does no status
/// resolution); task 1.6 refreshes it from the status list so search and
/// present can exclude revoked/expired credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialStatus {
    /// Believed valid (signature/not-expired checks are the caller's job in
    /// later tasks; this layer treats the tag as opaque metadata).
    Valid,
    /// Past its `valid_until` or otherwise time-expired.
    Expired,
    /// Status-list bit set / explicitly revoked.
    Revoked,
    /// Not yet resolved against a status list. The default at store time.
    Unknown,
}

impl CredentialStatus {
    /// Stable wire/index token for this status. Used to build the `status`
    /// secondary-index key; kept in sync with the serde `rename_all`.
    pub fn as_index_token(&self) -> &'static str {
        match self {
            CredentialStatus::Valid => "valid",
            CredentialStatus::Expired => "expired",
            CredentialStatus::Revoked => "revoked",
            CredentialStatus::Unknown => "unknown",
        }
    }
}

/// Purpose of the credential — the semantic role it plays in the trust
/// fabric. Indexed so a (later) DCQL match can target "an invite for
/// community X" without parsing every body. Open-ended via
/// [`CredentialPurpose::Other`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialPurpose {
    Invite,
    Membership,
    Role,
    Endorsement,
    Personhood,
    #[serde(untagged)]
    Other(String),
}

impl CredentialPurpose {
    /// Stable token used in the `purpose` secondary-index key.
    pub fn as_index_token(&self) -> String {
        match self {
            CredentialPurpose::Invite => "invite".to_string(),
            CredentialPurpose::Membership => "membership".to_string(),
            CredentialPurpose::Role => "role".to_string(),
            CredentialPurpose::Endorsement => "endorsement".to_string(),
            CredentialPurpose::Personhood => "personhood".to_string(),
            CredentialPurpose::Other(s) => s.clone(),
        }
    }
}

/// A credential the holder has stored on this VTA, plus the indexed
/// metadata envelope that lets the holder's agent search **by criteria**
/// without parsing every body. Field-for-field per
/// `vti-credential-architecture.md` §5.
///
/// `body` is the credential itself, treated as **opaque bytes** by this
/// layer. It is encrypted at rest by the keyspace AES-256-GCM wrapper
/// (the whole record is serialized then encrypted before it hits fjall).
/// The metadata fields are co-encrypted in the record value; the *index
/// keys* (built by [`super::index`]) carry only the indexed field values,
/// which are routing metadata, never the credential body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredCredential {
    /// Local handle — the holder-agent-assigned id (ULID recommended).
    /// Unique within this vault. Used as the primary key.
    pub id: String,
    /// Proof / serialization format of `body`.
    pub format: CredentialFormat,
    /// VC `type` tags (e.g. `InvitationCredential`). Multiple tags are
    /// each indexed independently so a match on any one tag finds the
    /// credential.
    #[serde(default)]
    pub types: Vec<String>,
    /// Reference into the VTC schema store / catalog entry, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
    /// Which community / context this credential is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community_did: Option<String>,
    /// The holder DID this VC is about (credential subject).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    /// Issuer DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,
    /// Semantic purpose (invite / membership / role / …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<CredentialPurpose>,
    /// Lifecycle status. Defaults to `Unknown` at store time; refreshed by
    /// the status task (1.6).
    pub status: CredentialStatus,
    /// RFC 3339 validity window start, when the body declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    /// RFC 3339 validity window end, when the body declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    /// RFC 3339 timestamp the credential was received/stored.
    pub received_at: String,
    /// Free-form provenance string (e.g. the exchange thread / source DID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Holder-applied labels. Not indexed in this task (search by tag is a
    /// later DCQL concern); carried so the round-trip is lossless.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub tags: std::collections::BTreeMap<String, String>,
    /// The credential itself — **opaque bytes**, encrypted at rest. This
    /// layer never parses, verifies, signs, or discloses it. Stored as a
    /// byte vector; the format-agnostic store makes no assumption about
    /// whether it is a UTF-8 JWT, CBOR, or anything else.
    pub body: Vec<u8>,
}

impl StoredCredential {
    /// The set of `(field, value)` pairs this credential is indexed under.
    /// Drives both index insertion and removal so the two can never drift.
    /// Only **present** (`Some`) fields are emitted — a credential with no
    /// issuer DID simply isn't reachable via an issuer-DID scan.
    ///
    /// Each `types` tag is emitted as its own `type` entry (a credential
    /// with two type tags is reachable by either).
    pub(crate) fn index_terms(&self) -> Vec<(IndexField, String)> {
        let mut terms = Vec::new();
        for t in &self.types {
            terms.push((IndexField::Type, t.clone()));
        }
        if let Some(c) = &self.community_did {
            terms.push((IndexField::CommunityDid, c.clone()));
        }
        if let Some(i) = &self.issuer_did {
            terms.push((IndexField::IssuerDid, i.clone()));
        }
        if let Some(p) = &self.purpose {
            terms.push((IndexField::Purpose, p.as_index_token()));
        }
        terms.push((IndexField::Status, self.status.as_index_token().to_string()));
        terms
    }
}

/// The fields the vault maintains a secondary index over, per task 1.1:
/// `{type, community_did, issuer_did, purpose, status}`. Each variant maps
/// to a stable token used in the index key namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexField {
    Type,
    CommunityDid,
    IssuerDid,
    Purpose,
    Status,
}

impl IndexField {
    /// Stable token used as the field segment of an index key. Changing one
    /// of these is a storage-format break (it orphans existing index rows),
    /// so they are deliberately terse and fixed.
    pub fn token(&self) -> &'static str {
        match self {
            IndexField::Type => "type",
            IndexField::CommunityDid => "community",
            IndexField::IssuerDid => "issuer",
            IndexField::Purpose => "purpose",
            IndexField::Status => "status",
        }
    }
}
