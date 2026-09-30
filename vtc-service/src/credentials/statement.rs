//! Custom endorsement VC builder — Phase 4 M4.7.2. Spec §6.1.
//!
//! ## Wire shape
//!
//! The VC carries the same catalog `EndorsementCredential`
//! type as role VECs — wire-compatible. The discriminator
//! lives on `endorsement.type`:
//!
//! ```json
//! {
//!   "type": ["VerifiableCredential", "EndorsementCredential"],
//!   "issuer": "did:webvh:vtc.example.com:abc",
//!   "credentialSubject": {
//!     "id": "<subject-did>",
//!     "endorsement": {
//!       "type": "<operator-defined-uri>",
//!       "claim": { "level": "expert", ... },
//!       "communityDid": "did:webvh:vtc.example.com:abc"
//!     }
//!   }
//! }
//! ```
//!
//! ## Validation surface
//!
//! Type validation is the route layer's concern (consults the
//! `endorsement_types:` registry per D4 review). The builder
//! is a pure transformer; it enforces:
//!
//! - `claim` is a JSON object (non-object → error).
//! - `claim` body fits the 8 KiB cap.
//! - `type` is a non-empty string.

use affinidi_vc::VerifiableCredential;
use chrono::Duration;
use serde_json::Value as JsonValue;
use vti_common::error::AppError;

use super::LocalSigner;
use super::vmc::CredentialStatusRef;

/// 8 KiB cap on the `endorsement.claim` body. Mirrors the
/// route layer's M4.8.2 enforcement; the builder rejects
/// over-sized claims too so unit tests catch the boundary.
pub const CLAIM_MAX_BYTES: usize = 8 * 1024;

/// Default validity for a custom endorsement. Mirrors the
/// role VEC default (30d). Operators tighten via the route
/// body's `validity_seconds`.
pub const DEFAULT_CUSTOM_ENDORSEMENT_VALIDITY: Duration = Duration::days(30);

/// Parameters for [`build_custom_endorsement`].
#[derive(Debug, Clone)]
pub struct CustomEndorsementParams {
    /// Subject DID — the member receiving the endorsement.
    pub subject_did: String,
    /// Operator-registered endorsement type URI. The route
    /// layer enforces "type is in the registry" before
    /// calling the builder; the builder only checks
    /// non-empty.
    pub endorsement_type: String,
    /// Free-form per-type claim body. Must be a JSON object;
    /// must fit `CLAIM_MAX_BYTES`.
    pub claim: JsonValue,
    /// Optional VC `id` URI. The route layer supplies
    /// `urn:uuid:<row-id>` so the credential id matches the
    /// `Endorsement` row's id.
    pub id: Option<String>,
    /// `validUntil = now + validity`.
    pub validity: Duration,
    /// Status-list reference. Custom endorsements reuse the
    /// shared `Revocation` status list (D8 review).
    pub status_ref: CredentialStatusRef,
}

impl CustomEndorsementParams {
    pub fn new(
        subject_did: impl Into<String>,
        endorsement_type: impl Into<String>,
        claim: JsonValue,
        status_ref: CredentialStatusRef,
    ) -> Self {
        Self {
            subject_did: subject_did.into(),
            endorsement_type: endorsement_type.into(),
            claim,
            id: None,
            validity: DEFAULT_CUSTOM_ENDORSEMENT_VALIDITY,
            status_ref,
        }
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn with_validity(mut self, validity: Duration) -> Self {
        self.validity = validity;
        self
    }
}

/// Build + sign a custom endorsement VEC. `issuer =
/// signer.issuer_did()` (always the community DID).
pub async fn build_custom_endorsement(
    signer: &LocalSigner,
    params: CustomEndorsementParams,
) -> Result<VerifiableCredential, AppError> {
    // Builder-side validation. Route layer enforces type
    // registry membership separately; the builder only
    // checks shape.
    if params.endorsement_type.trim().is_empty() {
        return Err(AppError::Validation(
            "endorsement.type cannot be empty".into(),
        ));
    }
    if !params.claim.is_object() {
        return Err(AppError::Validation(
            "endorsement.claim must be a JSON object".into(),
        ));
    }
    let claim_bytes = serde_json::to_vec(&params.claim)
        .map_err(|e| AppError::Internal(format!("serialise claim: {e}")))?;
    if claim_bytes.len() > CLAIM_MAX_BYTES {
        return Err(AppError::Validation(format!(
            "endorsement.claim exceeds {CLAIM_MAX_BYTES} bytes (got {})",
            claim_bytes.len()
        )));
    }

    // Custom-endorsement shape: `credentialSubject.endorsement = { type, claim,
    // communityDid }`, sourced through the DTG catalog (`issue_endorsement`),
    // with the operator's required `credentialStatus`.
    let endorsement = serde_json::json!({
        "type": params.endorsement_type,
        "claim": params.claim,
        "communityDid": signer.issuer_did(),
    });

    let doc = super::dtg::issue_endorsement(
        signer,
        &params.subject_did,
        endorsement,
        params.id.as_deref(),
        Some(&params.status_ref),
        params.validity,
    )
    .await?;
    super::dtg::into_typed(doc, "custom endorsement")
}

#[cfg(test)]
mod tests {
    use super::super::vec::VEC_TYPE;
    use super::*;
    use affinidi_vc::SubjectValue;
    use serde_json::json;

    const TEST_VTC_DID: &str = "did:webvh:vtc.example.com:abc";

    fn signer() -> LocalSigner {
        LocalSigner::from_ed25519_seed(TEST_VTC_DID.into(), &[0xBB; 32])
    }

    fn status_ref(idx: u32) -> CredentialStatusRef {
        CredentialStatusRef::revocation(format!("{TEST_VTC_DID}#revocation"), idx)
    }

    #[tokio::test]
    async fn builds_signs_and_verifies() {
        let signer = signer();
        let params = CustomEndorsementParams::new(
            "did:key:zSubject",
            "https://example.com/v1/skills/rust",
            json!({ "level": "expert", "since": "2020" }),
            status_ref(42),
        )
        .with_id("urn:uuid:11111111-1111-1111-1111-111111111111");
        let vc = build_custom_endorsement(&signer, params).await.unwrap();

        // Type array contains both VerifiableCredential + VEC.
        assert!(vc.types.iter().any(|t| t == "VerifiableCredential"));
        assert!(vc.types.iter().any(|t| t == VEC_TYPE));

        // Subject carries `endorsement.type` matching the param.
        let subj = match &vc.credential_subject {
            SubjectValue::Single(m) => m.clone(),
            SubjectValue::Multiple(v) => v[0].clone(),
        };
        let endorsement = subj.get("endorsement").unwrap();
        assert_eq!(endorsement["type"], "https://example.com/v1/skills/rust");
        assert_eq!(endorsement["claim"]["level"], "expert");
        assert_eq!(endorsement["communityDid"], TEST_VTC_DID);

        // Verifies against the signer.
        signer.verify(&vc).unwrap();
    }

    #[tokio::test]
    async fn rejects_empty_type() {
        let signer = signer();
        let params = CustomEndorsementParams::new("did:key:zS", "", json!({}), status_ref(0));
        assert!(build_custom_endorsement(&signer, params).await.is_err());
    }

    #[tokio::test]
    async fn rejects_non_object_claim() {
        let signer = signer();
        let params = CustomEndorsementParams::new(
            "did:key:zS",
            "https://x/t",
            json!("not an object"),
            status_ref(0),
        );
        assert!(build_custom_endorsement(&signer, params).await.is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_claim() {
        let signer = signer();
        let big_value = "x".repeat(10 * 1024); // > 8 KiB
        let params = CustomEndorsementParams::new(
            "did:key:zS",
            "https://x/t",
            json!({ "blob": big_value }),
            status_ref(0),
        );
        let err = build_custom_endorsement(&signer, params).await;
        assert!(err.is_err(), "oversized claim must reject");
    }
}
