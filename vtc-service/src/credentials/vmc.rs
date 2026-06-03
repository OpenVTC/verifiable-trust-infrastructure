//! Verifiable Membership Credential builder — spec §6.1's VMC
//! row, M2.9 entry point.
//!
//! Shape:
//!
//! ```json
//! {
//!   "@context": [
//!     "https://www.w3.org/ns/credentials/v2",
//!     "https://openvtc.org/contexts/dtg-membership-v1.jsonld"
//!   ],
//!   "type": ["VerifiableCredential", "VerifiableMembershipCredential"],
//!   "issuer": "did:webvh:vtc.example.com:abc",
//!   "validFrom": "2026-05-12T00:00:00Z",
//!   "validUntil": "2026-06-11T00:00:00Z",
//!   "credentialSubject": {
//!     "id": "did:key:zMember",
//!     "personhood": false
//!   },
//!   "credentialStatus": {
//!     "id": "https://vtc.example.com/v1/status-lists/revocation#42",
//!     "type": "BitstringStatusListEntry",
//!     "statusPurpose": "revocation",
//!     "statusListIndex": "42",
//!     "statusListCredential": "https://vtc.example.com/v1/status-lists/revocation"
//!   },
//!   "proof": { … data-integrity proof attached by `LocalSigner` … }
//! }
//! ```
//!
//! The `credentialStatus` block is optional at this milestone —
//! M2.10 + M2.11 wire it in with live status-list URLs. M2.9
//! tests can construct a VMC with `status_ref = None` to exercise
//! the proof + validity-window paths in isolation.

use affinidi_vc::VerifiableCredential;
use chrono::Duration;
use serde::{Deserialize, Serialize};
use vti_common::error::AppError;

use super::LocalSigner;

/// The membership type the catalog stamps in the VC's `type` array (alongside
/// the universal `VerifiableCredential`). Sourced from the DTG catalog
/// (`DTGCredentialType::Membership`).
pub const VMC_TYPE: &str = "MembershipCredential";

/// `credentialStatus` reference for a VMC. Mirrors the
/// `BitstringStatusListEntry` shape per spec §6.2. M2.10 + M2.11
/// will compute the index and URL; M2.9's signer wraps it in the
/// VC verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatusRef {
    /// Per-VC unique entry id (typically
    /// `{status_list_url}#{index}`).
    pub id: String,
    /// Always `"BitstringStatusListEntry"` per the W3C status-list
    /// spec.
    #[serde(rename = "type")]
    pub r#type: String,
    /// `"revocation"` or `"suspension"` per spec §6.2.
    pub status_purpose: String,
    /// Index into the BitstringStatusList. Wire shape is a string
    /// per the W3C spec.
    pub status_list_index: String,
    /// URL of the BitstringStatusList credential itself.
    pub status_list_credential: String,
}

impl CredentialStatusRef {
    /// Build a `revocation`-purpose entry from a list URL + index.
    /// Mirrors what M2.11 will produce.
    pub fn revocation(status_list_url: impl Into<String>, index: u32) -> Self {
        let url = status_list_url.into();
        Self {
            id: format!("{url}#{index}"),
            r#type: "BitstringStatusListEntry".into(),
            status_purpose: "revocation".into(),
            status_list_index: index.to_string(),
            status_list_credential: url,
        }
    }
}

/// Parameters for [`build_vmc`].
#[derive(Debug, Clone)]
pub struct VmcParams {
    /// Subject DID — the member receiving the VMC.
    pub member_did: String,
    /// Optional top-level `id` URI for the VC. When `Some`, the
    /// builder splices it into the credential after construction
    /// (the upstream typed VC doesn't expose `id` as a builder
    /// method). M2.12's issuance flow uses
    /// `urn:uuid:<server-allocated>` so the audit trail + the
    /// `Member.current_vmc_id` pointer can reference the same
    /// stable id.
    pub id: Option<String>,
    /// Status-list reference, or `None` to omit `credentialStatus`
    /// entirely (used by tests + the M2.9-only path before
    /// M2.10/M2.11 wire in live status lists).
    pub status_ref: Option<CredentialStatusRef>,
    /// `validUntil = now + validity`. Spec §3-F requires this
    /// window be bounded; the workspace default is 30 days
    /// ([`super::DEFAULT_VMC_VALIDITY`]).
    pub validity: Duration,
    /// `personhood: bool` carried on the credentialSubject.
    /// Phase 2's renewal flow re-evaluates this via
    /// `personhood.rego` per spec §6.3 step 3.
    pub personhood: bool,
}

impl VmcParams {
    pub fn new(member_did: impl Into<String>) -> Self {
        Self {
            member_did: member_did.into(),
            id: None,
            status_ref: None,
            validity: super::DEFAULT_VMC_VALIDITY,
            personhood: false,
        }
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn with_status_ref(mut self, status_ref: CredentialStatusRef) -> Self {
        self.status_ref = Some(status_ref);
        self
    }

    pub fn with_validity(mut self, validity: Duration) -> Self {
        self.validity = validity;
        self
    }

    pub fn with_personhood(mut self, personhood: bool) -> Self {
        self.personhood = personhood;
        self
    }
}

/// Build + sign a VMC. `issuer = signer.issuer_did()`,
/// `validFrom = now()`, `validUntil = now() + params.validity`.
/// Returns the signed VC with `proof` attached.
///
/// The credential's canonical shape comes from the DTG catalog
/// ([`super::dtg::issue_membership`]); the signed JSON is carried as a
/// (lossless, JSON-backed) [`VerifiableCredential`] so every consumer is
/// unchanged.
pub async fn build_vmc(
    signer: &LocalSigner,
    params: VmcParams,
) -> Result<VerifiableCredential, AppError> {
    let doc = super::dtg::issue_membership(
        signer,
        &params.member_did,
        params.id.as_deref(),
        params.status_ref.as_ref(),
        params.validity,
        params.personhood,
    )
    .await?;
    serde_json::from_value(doc)
        .map_err(|e| AppError::Internal(format!("DTG VMC -> VerifiableCredential: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as JsonValue;

    const TEST_VTC_DID: &str = "did:webvh:vtc.example.com:abc";
    const MEMBER_DID: &str = "did:key:zMember1";

    fn signer() -> LocalSigner {
        LocalSigner::from_ed25519_seed(TEST_VTC_DID.into(), &[0xAA; 32])
    }

    /// Happy path: VMC carries the expected types, issuer, and
    /// subject id; the proof verifies against the signer's public
    /// key.
    #[tokio::test]
    async fn vmc_happy_path_verifies() {
        let signer = signer();
        let vc = build_vmc(&signer, VmcParams::new(MEMBER_DID))
            .await
            .expect("build VMC");

        // Type array contains both `VerifiableCredential` (the
        // builder adds it implicitly) and `VerifiableMembershipCredential`.
        assert!(vc.types.iter().any(|t| t == "VerifiableCredential"));
        assert!(vc.types.iter().any(|t| t == VMC_TYPE));

        // Issuer matches the signer's DID.
        let issuer_value = serde_json::to_value(&vc.issuer).unwrap();
        assert_eq!(issuer_value, JsonValue::String(TEST_VTC_DID.into()));

        // Subject id == member DID.
        let subject_id = match &vc.credential_subject {
            affinidi_vc::SubjectValue::Single(m) => m.get("id").cloned(),
            affinidi_vc::SubjectValue::Multiple(v) => v[0].get("id").cloned(),
        };
        assert_eq!(subject_id, Some(JsonValue::String(MEMBER_DID.into())));

        // Proof verifies.
        signer.verify(&vc).expect("VMC proof must verify");
    }

    /// `validUntil = validFrom + params.validity` to the second.
    #[tokio::test]
    async fn vmc_valid_until_pinned_to_validity_window() {
        let signer = signer();
        let validity = Duration::days(7);
        let vc = build_vmc(&signer, VmcParams::new(MEMBER_DID).with_validity(validity))
            .await
            .unwrap();
        let vf = chrono::DateTime::parse_from_rfc3339(vc.valid_from.as_deref().unwrap()).unwrap();
        let vu = chrono::DateTime::parse_from_rfc3339(vc.valid_until.as_deref().unwrap()).unwrap();
        // Build clamps the seconds — diff matches exactly.
        assert_eq!((vu - vf).num_seconds(), validity.num_seconds());
    }

    /// Personhood adds a `PersonhoodCredential` to the `type` array (the DTG
    /// catalog convention) rather than a `credentialSubject` field.
    #[tokio::test]
    async fn vmc_personhood_adds_personhood_type() {
        let signer = signer();
        let vc = build_vmc(&signer, VmcParams::new(MEMBER_DID).with_personhood(true))
            .await
            .unwrap();
        assert!(
            vc.types.iter().any(|t| t == "PersonhoodCredential"),
            "personhood=true must add the PersonhoodCredential type, got {:?}",
            vc.types
        );
    }

    /// A status_ref produces a `credentialStatus` block in the
    /// serialised VC.
    #[tokio::test]
    async fn vmc_status_ref_serialises_into_credential_status() {
        let signer = signer();
        let status = CredentialStatusRef::revocation(
            "https://vtc.example.com/v1/status-lists/revocation",
            7,
        );
        let vc = build_vmc(
            &signer,
            VmcParams::new(MEMBER_DID).with_status_ref(status.clone()),
        )
        .await
        .unwrap();
        let v = serde_json::to_value(&vc).unwrap();
        let cs = &v["credentialStatus"];
        assert_eq!(cs["statusPurpose"], "revocation");
        assert_eq!(cs["statusListIndex"], "7");
        assert_eq!(cs["statusListCredential"], status.status_list_credential);
        // And the proof still verifies after splicing.
        signer.verify(&vc).expect("VMC proof must still verify");
    }

    /// Mutating the VMC after signing invalidates the proof.
    #[tokio::test]
    async fn vmc_tampered_subject_invalidates_proof() {
        let signer = signer();
        let mut vc = build_vmc(&signer, VmcParams::new(MEMBER_DID))
            .await
            .unwrap();

        // Tamper with the subject — flip personhood.
        let mut as_value = serde_json::to_value(&vc).unwrap();
        as_value["credentialSubject"]["personhood"] = JsonValue::Bool(true);
        vc = serde_json::from_value(as_value).unwrap();

        let err = signer.verify(&vc).expect_err("tampered VMC must fail");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "expected Forbidden, got {err:?}"
        );
    }
}
