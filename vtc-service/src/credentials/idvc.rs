//! Identity Verification Credential (IDVC) issued by the community.
//!
//! DTG Credentials §Identity Verification Credentials defines an IDVC as *any
//! W3C VC satisfying a community's identity-proofing requirements* and says
//! explicitly that IDVCs are **not** `DTGCredential` subtypes. So this is the
//! one credential the VTC mints outside the DTG catalog: a plain W3C VC under
//! the credentials v2 context alone.
//!
//! ```json
//! {
//!   "@context": ["https://www.w3.org/ns/credentials/v2"],
//!   "id": "urn:uuid:…",
//!   "type": ["VerifiableCredential", "IdentityVerificationCredential"],
//!   "issuer": "<community DID>",
//!   "validFrom": "…", "validUntil": "…",
//!   "credentialSubject": { "id": "<member DID>", "method": "inPerson", … },
//!   "credentialStatus": { "type": "BitstringStatusListEntry", … }
//! }
//! ```
//!
//! It records the in-person vetting ceremony: an administrator met the person,
//! satisfied themselves the DID in front of them is theirs, and the community
//! issued this to that DID. The default `personhood.rego` accepts it when the
//! community itself is the issuer and the member is the subject.
//!
//! ## How it is issued
//!
//! Through `vtc/endorsements/issue/0.1` with `typeUri`
//! [`IDENTITY_VERIFICATION_CREDENTIAL_TYPE`]. That keeps one administrator
//! operation for "the community attests something about a member" and — more
//! to the point — keeps the community's revocation machinery: the credential
//! takes a slot on the shared Revocation status list, is recorded as an
//! endorsement row, and is withdrawn with `vtc/endorsements/revoke/0.1` like
//! any other. The type is reserved, so it is never registered through
//! `vtc/endorsement-types/register` (which accepts predicate IRIs only), and a
//! caller cannot mint one through the statement path by accident: the
//! handler dispatches on the reserved value before it looks for a registered
//! predicate. The specification describes `endorsements/issue` as minting a
//! statement credential; issuing an IDVC through it is a recorded divergence
//! (`docs/03-vtc/personhood-and-graph.md`), pending a dedicated task.

use chrono::{Duration, Utc};
use serde_json::{Map, Value};
use vti_common::error::AppError;

use super::LocalSigner;
use super::vmc::CredentialStatusRef;

/// The `type` an IDVC carries beside `VerifiableCredential`, and the reserved
/// `typeUri` that asks `vtc/endorsements/issue/0.1` for one.
pub const IDENTITY_VERIFICATION_CREDENTIAL_TYPE: &str = "IdentityVerificationCredential";

/// Build and sign an IDVC for `subject_did`.
///
/// `claim` is a JSON object whose members are carried in `credentialSubject`
/// beside `id` — how the identity was verified, by whom. It may not carry `id`
/// itself: the subject is `subject_did`, never a value the caller smuggles in.
/// The credential is always revocable, so `status_ref` is required.
///
/// # Errors
///
/// [`AppError::Validation`] for a claim that is not an object or that names
/// `id`; the signer's error otherwise.
pub async fn issue_identity_verification(
    signer: &LocalSigner,
    subject_did: &str,
    claim: &Value,
    id: &str,
    status_ref: &CredentialStatusRef,
    validity: Duration,
) -> Result<Value, AppError> {
    let claim = claim.as_object().ok_or_else(|| {
        AppError::Validation("an identity-verification claim must be a JSON object".into())
    })?;
    if claim.contains_key("id") {
        return Err(AppError::Validation(
            "an identity-verification claim cannot name `id`: the subject is `subjectDid`".into(),
        ));
    }
    let mut subject = Map::new();
    subject.insert("id".into(), Value::String(subject_did.to_string()));
    subject.extend(claim.iter().map(|(k, v)| (k.clone(), v.clone())));

    let now = Utc::now();
    let status = serde_json::to_value(status_ref)
        .map_err(|e| AppError::Internal(format!("credentialStatus -> value: {e}")))?;
    let mut doc = serde_json::json!({
        "@context": [dtg_credentials::W3C_VC_V2_CONTEXT],
        "id": id,
        "type": ["VerifiableCredential", IDENTITY_VERIFICATION_CREDENTIAL_TYPE],
        "issuer": signer.issuer_did(),
        "validFrom": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "validUntil": (now + validity).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "credentialSubject": Value::Object(subject),
        "credentialStatus": status,
    });
    signer.sign_doc(&mut doc).await?;
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
    use serde_json::json;

    const COMMUNITY: &str = "did:web:acme.example";

    fn signer() -> LocalSigner {
        LocalSigner::from_ed25519_seed(COMMUNITY.into(), &[9u8; 32])
    }

    fn status() -> CredentialStatusRef {
        CredentialStatusRef::revocation("https://acme.example/v1/status-lists/revocation", 7)
    }

    #[tokio::test]
    async fn an_idvc_is_a_plain_w3c_vc_not_a_dtg_credential() {
        let s = signer();
        let doc = issue_identity_verification(
            &s,
            "did:key:zMember",
            &json!({ "method": "inPerson", "verifiedBy": "did:key:zAdmin" }),
            "urn:uuid:idvc-1",
            &status(),
            Duration::days(365),
        )
        .await
        .unwrap();
        assert_eq!(doc["@context"], json!([dtg_credentials::W3C_VC_V2_CONTEXT]));
        assert_eq!(
            doc["type"],
            json!([
                "VerifiableCredential",
                IDENTITY_VERIFICATION_CREDENTIAL_TYPE
            ])
        );
        assert!(doc.get("issuerScope").is_none(), "not a DTG credential");
        assert_eq!(doc["issuer"], COMMUNITY);
        assert_eq!(doc["credentialSubject"]["id"], "did:key:zMember");
        assert_eq!(doc["credentialSubject"]["method"], "inPerson");
        assert_eq!(doc["credentialStatus"]["statusListIndex"], "7");
        // The DTG parser refuses it: it is not, and must not pass for, a DTG
        // credential.
        assert!(serde_json::from_value::<dtg_credentials::DTGCredential>(doc.clone()).is_err());

        let proof: DataIntegrityProof = serde_json::from_value(doc["proof"].clone()).unwrap();
        let mut unsigned = doc.clone();
        unsigned.as_object_mut().unwrap().remove("proof");
        proof
            .verify_with_public_key(&unsigned, s.public_bytes(), VerifyOptions::new())
            .expect("the community's signature covers the status entry");
    }

    #[tokio::test]
    async fn a_claim_cannot_rename_the_subject() {
        let err = issue_identity_verification(
            &signer(),
            "did:key:zMember",
            &json!({ "id": "did:key:zSomeoneElse" }),
            "urn:uuid:idvc-2",
            &status(),
            Duration::days(1),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }
}
