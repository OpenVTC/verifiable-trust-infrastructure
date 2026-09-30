//! Community statement (VSC) builder — what `vtc/endorsements/issue/0.1`
//! mints. Spec §6.1.
//!
//! ## Wire shape
//!
//! A DTG **Verifiable Statement Credential**: the community, issuing as itself
//! (`issuerScope` `public`), states `claim` about the subject under a predicate
//! the community registered (`vtc/endorsement-types/register/0.1`). The
//! predicate carries the meaning; the claim rides verbatim as
//! `credentialSubject.object.value`:
//!
//! ```json
//! {
//!   "type": ["VerifiableCredential", "DTGCredential", "StatementCredential"],
//!   "issuer": "did:webvh:vtc.example.com:abc",
//!   "issuerScope": "public",
//!   "credentialSubject": {
//!     "id": "<subject-did>",
//!     "predicate": "https://registry.trustoverip.org/dtg/vsc/endorses/1",
//!     "object": { "value": { "level": "expert", … } }
//!   },
//!   "credentialStatus": { … }
//! }
//! ```
//!
//! Under `endorses/1` it is a Verifiable Endorsement Credential (VEC).
//!
//! ## Validation surface
//!
//! Predicate registration and the claim schema are the route layer's concern
//! (the `endorsement_types:` registry). The builder is a pure transformer; it
//! enforces:
//!
//! - `predicate` is an absolute predicate IRI (`dtg_credentials`' own check).
//! - `claim` is a JSON object (non-object → error).
//! - `claim` body fits the 8 KiB cap.

use affinidi_vc::VerifiableCredential;
use chrono::Duration;
use serde_json::Value as JsonValue;
use vti_common::error::AppError;

use super::LocalSigner;
use super::vmc::CredentialStatusRef;

/// The DTG catalog type a statement carries in `type`.
pub const VSC_TYPE: &str = vta_sdk::protocols::members::STATEMENT_CREDENTIAL_TYPE;

/// 8 KiB cap on the claim body. Mirrors the route layer's M4.8.2
/// enforcement; the builder rejects over-sized claims too so unit tests catch
/// the boundary.
pub const CLAIM_MAX_BYTES: usize = 8 * 1024;

/// Default validity for a community statement. Mirrors the role VAC default
/// (30d). Operators tighten via the route body's `validity_seconds`.
pub const DEFAULT_STATEMENT_VALIDITY: Duration = Duration::days(30);

/// Parameters for [`build_statement`].
#[derive(Debug, Clone)]
pub struct StatementParams {
    /// Subject DID — the party the statement is about.
    pub subject_did: String,
    /// The registered predicate IRI (`credentialSubject.predicate`). The route
    /// layer enforces "predicate is registered" before calling the builder.
    pub predicate: String,
    /// Free-form claim body (`credentialSubject.object.value`). Must be a JSON
    /// object; must fit `CLAIM_MAX_BYTES`.
    pub claim: JsonValue,
    /// Optional VC `id` URI. The route layer supplies `urn:uuid:<row-id>` so
    /// the credential id matches the `Endorsement` row's id.
    pub id: Option<String>,
    /// `validUntil = now + validity`.
    pub validity: Duration,
    /// Status-list reference. Statements reuse the shared `Revocation` status
    /// list (D8 review).
    pub status_ref: CredentialStatusRef,
}

impl StatementParams {
    pub fn new(
        subject_did: impl Into<String>,
        predicate: impl Into<String>,
        claim: JsonValue,
        status_ref: CredentialStatusRef,
    ) -> Self {
        Self {
            subject_did: subject_did.into(),
            predicate: predicate.into(),
            claim,
            id: None,
            validity: DEFAULT_STATEMENT_VALIDITY,
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

/// Check a claim body against the builder's shape rules: a JSON object within
/// [`CLAIM_MAX_BYTES`]. Shared with the identity-verification path, which
/// takes the same `claim` member.
pub fn check_claim(claim: &JsonValue) -> Result<(), AppError> {
    if !claim.is_object() {
        return Err(AppError::Validation("claim must be a JSON object".into()));
    }
    let claim_bytes = serde_json::to_vec(claim)
        .map_err(|e| AppError::Internal(format!("serialise claim: {e}")))?;
    if claim_bytes.len() > CLAIM_MAX_BYTES {
        return Err(AppError::Validation(format!(
            "claim exceeds {CLAIM_MAX_BYTES} bytes (got {})",
            claim_bytes.len()
        )));
    }
    Ok(())
}

/// Build + sign a community statement. `issuer = signer.issuer_did()` (always
/// the community DID).
pub async fn build_statement(
    signer: &LocalSigner,
    params: StatementParams,
) -> Result<VerifiableCredential, AppError> {
    dtg_credentials::check_predicate_iri(&params.predicate)
        .map_err(|e| AppError::Validation(e.to_string()))?;
    check_claim(&params.claim)?;

    let doc = super::dtg::issue_statement(
        signer,
        &params.subject_did,
        &params.predicate,
        params.claim,
        params.id.as_deref(),
        Some(&params.status_ref),
        params.validity,
    )
    .await?;
    super::dtg::into_typed(doc, "community statement")
}

#[cfg(test)]
mod tests {
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
        let params = StatementParams::new(
            "did:key:zSubject",
            dtg_credentials::ENDORSES_V1,
            json!({ "level": "expert", "since": "2020" }),
            status_ref(42),
        )
        .with_id("urn:uuid:11111111-1111-1111-1111-111111111111");
        let vc = build_statement(&signer, params).await.unwrap();

        assert!(vc.types.iter().any(|t| t == "VerifiableCredential"));
        assert!(vc.types.iter().any(|t| t == VSC_TYPE));

        let subj = match &vc.credential_subject {
            SubjectValue::Single(m) => m.clone(),
            SubjectValue::Multiple(v) => v[0].clone(),
        };
        assert_eq!(subj["predicate"], dtg_credentials::ENDORSES_V1);
        assert_eq!(subj["object"]["value"]["level"], "expert");

        signer.verify(&vc).unwrap();
    }

    #[tokio::test]
    async fn rejects_a_predicate_that_is_not_an_iri() {
        let signer = signer();
        for bad in ["", "dtg:endorses", "IdentityVetting"] {
            let params = StatementParams::new("did:key:zS", bad, json!({}), status_ref(0));
            assert!(build_statement(&signer, params).await.is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn rejects_non_object_claim() {
        let signer = signer();
        let params = StatementParams::new(
            "did:key:zS",
            "https://x.example/t",
            json!("not an object"),
            status_ref(0),
        );
        assert!(build_statement(&signer, params).await.is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_claim() {
        let signer = signer();
        let big_value = "x".repeat(10 * 1024); // > 8 KiB
        let params = StatementParams::new(
            "did:key:zS",
            "https://x.example/t",
            json!({ "blob": big_value }),
            status_ref(0),
        );
        let err = build_statement(&signer, params).await;
        assert!(err.is_err(), "oversized claim must reject");
    }
}
