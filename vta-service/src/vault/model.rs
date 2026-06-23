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
use vti_common::vault::{LifecycleError, VaultStatus, default_active};

/// Reserved [`StoredCredential::tags`] key holding the BBS pseudonym holder
/// link secret (`prover_nym`), base64url-no-pad. See [`StoredCredential::tags`].
pub const BBS_PROVER_NYM_TAG: &str = "bbs:prover_nym";
/// Reserved [`StoredCredential::tags`] key holding the BBS pseudonym
/// `secret_prover_blind`, base64url-no-pad. See [`StoredCredential::tags`].
pub const BBS_SECRET_PROVER_BLIND_TAG: &str = "bbs:secret_prover_blind";

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
    /// Circom-ecosystem ZKP credential — BabyJubJub-EdDSA over a Poseidon
    /// commitment (`affinidi-zkp-crypto`), the second ZKP option alongside
    /// [`Self::Bbs2023`]. **Phase-0-gated:** the format identity + storage
    /// seam exist, but the commitment primitives and the Circom/Groth16
    /// prover+verifier are not yet wired (server-side proving, deferred).
    Zkp,
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
    /// **Provenance** axis: which community this credential is about / from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community_did: Option<String>,
    /// **Custody** axis: which context in *this* VTA owns the credential —
    /// distinct from [`community_did`](Self::community_did) (provenance). The
    /// owning context's `ContextPolicy` governs disclosure of this credential
    /// (which verifiers, which types). `None` = unscoped (super-admin root) → no
    /// policy → unrestricted, which is how records stored before this field
    /// deserialize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
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
    ///
    /// Two **reserved** keys carry the BBS pseudonym holder secrets for a
    /// `bbs-2023` credential issued in **holder-binding** mode (see
    /// [`crate::vault::bbs`]): [`BBS_PROVER_NYM_TAG`] (the holder's link secret
    /// `prover_nym`) and [`BBS_SECRET_PROVER_BLIND_TAG`] (`secret_prover_blind`),
    /// both base64url-no-pad. They are present only for pseudonym credentials and
    /// are co-encrypted at rest with the rest of the record. Storing them here —
    /// rather than as format-specific columns — keeps this layer format-agnostic
    /// (§5: "a new format never requires a storage-schema change").
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub tags: std::collections::BTreeMap<String, String>,
    /// The credential itself — **opaque bytes**, encrypted at rest. This
    /// layer never parses, verifies, signs, or discloses it. Stored as a
    /// byte vector; the format-agnostic store makes no assumption about
    /// whether it is a UTF-8 JWT, CBOR, or anything else.
    pub body: Vec<u8>,
    /// **Archival** lifecycle state — orthogonal to `status` (which is
    /// *validity*, status-list driven and overwritten by
    /// [`crate::vault::status::refresh_status`]). Reuses the password-vault
    /// [`VaultStatus`]. `Active` by default (and for records stored before
    /// the lifecycle existed). `Archived`/`Deleted` credentials are excluded
    /// from query/present; a `Deleted` credential is a recoverable tombstone
    /// the sweeper hard-purges (index rows and all) at `grace_until`.
    #[serde(
        default = "default_active",
        skip_serializing_if = "VaultStatus::is_active"
    )]
    pub lifecycle: VaultStatus,
    /// RFC 3339 — set iff `lifecycle == Archived`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<String>,
    /// RFC 3339 — set iff `lifecycle == Deleted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    /// RFC 3339 purge deadline — recoverable via restore while `now <
    /// grace_until`. Set iff `lifecycle == Deleted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_until: Option<String>,
}

impl StoredCredential {
    /// `true` when the credential is in normal use (not archived/deleted) —
    /// the only state from which it may be presented.
    pub fn is_active(&self) -> bool {
        self.lifecycle.is_active()
    }

    /// `Active → Archived`. Refused (`NotActive`) otherwise.
    pub fn archive(&mut self, now: &str) -> Result<(), LifecycleError> {
        if self.lifecycle != VaultStatus::Active {
            return Err(LifecycleError::NotActive);
        }
        self.lifecycle = VaultStatus::Archived;
        self.archived_at = Some(now.to_string());
        Ok(())
    }

    /// `Archived → Active`. Refused (`NotArchived`) otherwise.
    pub fn unarchive(&mut self) -> Result<(), LifecycleError> {
        if self.lifecycle != VaultStatus::Archived {
            return Err(LifecycleError::NotArchived);
        }
        self.lifecycle = VaultStatus::Active;
        self.archived_at = None;
        Ok(())
    }

    /// `Active|Archived → Deleted` (recoverable tombstone). Refused
    /// (`AlreadyDeleted`) if already a tombstone — restore or purge instead.
    pub fn soft_delete(&mut self, now: &str, grace_until: &str) -> Result<(), LifecycleError> {
        if self.lifecycle == VaultStatus::Deleted {
            return Err(LifecycleError::AlreadyDeleted);
        }
        self.lifecycle = VaultStatus::Deleted;
        self.archived_at = None;
        self.deleted_at = Some(now.to_string());
        self.grace_until = Some(grace_until.to_string());
        Ok(())
    }

    /// `Deleted → Active`, only while still inside the grace window. Refused
    /// `NotDeleted` if not a tombstone, or `GraceExpired` if `now >=
    /// grace_until`. Lexical RFC 3339 comparison (house style).
    pub fn restore(&mut self, now: &str) -> Result<(), LifecycleError> {
        if self.lifecycle != VaultStatus::Deleted {
            return Err(LifecycleError::NotDeleted);
        }
        if let Some(grace) = self.grace_until.as_deref()
            && now >= grace
        {
            return Err(LifecycleError::GraceExpired);
        }
        self.lifecycle = VaultStatus::Active;
        self.deleted_at = None;
        self.grace_until = None;
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StoredCredential {
        StoredCredential {
            id: "cred-1".into(),
            format: CredentialFormat::SdJwtVc,
            types: vec!["MembershipCredential".into()],
            schema_id: None,
            community_did: Some("did:web:acme".into()),
            context_id: None,
            subject_did: None,
            issuer_did: Some("did:web:issuer".into()),
            purpose: Some(CredentialPurpose::Membership),
            status: CredentialStatus::Valid,
            valid_from: None,
            valid_until: None,
            received_at: "2026-06-03T00:00:00Z".into(),
            source: None,
            tags: std::collections::BTreeMap::new(),
            body: b"opaque".to_vec(),
            lifecycle: VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        }
    }

    #[test]
    fn legacy_credential_without_lifecycle_defaults_active() {
        // A record persisted before the lifecycle existed lacks the new keys.
        let legacy = r#"{
            "id":"c","format":"sd-jwt-vc","types":[],"status":"valid",
            "receivedAt":"2026-01-01T00:00:00Z","body":[1,2,3]
        }"#;
        let cred: StoredCredential = serde_json::from_str(legacy).expect("parse legacy");
        assert_eq!(cred.lifecycle, VaultStatus::Active);
        assert!(cred.is_active());
        // Active credentials re-emit without the lifecycle key (wire stays clean).
        let re = serde_json::to_string(&cred).unwrap();
        assert!(
            !re.contains("lifecycle"),
            "active cred omits lifecycle: {re}"
        );
    }

    #[test]
    fn credential_lifecycle_transitions() {
        let t0 = "2026-06-18T10:00:00+00:00";
        let grace = "2026-07-18T10:00:00+00:00";

        // archive / unarchive.
        let mut c = sample();
        c.archive(t0).unwrap();
        assert_eq!(c.lifecycle, VaultStatus::Archived);
        assert_eq!(c.archived_at.as_deref(), Some(t0));
        assert!(!c.is_active());
        assert_eq!(c.archive(t0), Err(LifecycleError::NotActive));
        c.unarchive().unwrap();
        assert!(c.is_active() && c.archived_at.is_none());
        assert_eq!(c.unarchive(), Err(LifecycleError::NotArchived));

        // soft delete / restore inside the window.
        let mut c = sample();
        c.soft_delete(t0, grace).unwrap();
        assert_eq!(c.lifecycle, VaultStatus::Deleted);
        assert_eq!(c.grace_until.as_deref(), Some(grace));
        assert_eq!(
            c.soft_delete(t0, grace),
            Err(LifecycleError::AlreadyDeleted)
        );
        c.restore(t0).unwrap();
        assert!(c.is_active());
        assert_eq!(c.restore(t0), Err(LifecycleError::NotDeleted));

        // restore after grace is refused (sweeper owns it).
        let mut c = sample();
        c.soft_delete(t0, grace).unwrap();
        assert_eq!(
            c.restore("2026-08-01T00:00:00+00:00"),
            Err(LifecycleError::GraceExpired)
        );
        assert_eq!(
            c.lifecycle,
            VaultStatus::Deleted,
            "failed restore is a no-op"
        );
    }
}
