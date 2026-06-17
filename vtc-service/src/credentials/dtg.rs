//! Issue catalog credentials from the **DTG (Decentralized Trust Graph)**
//! credentials catalog (`dtg-credentials`) — task 2.0.
//!
//! Every credential the VTC mints (Membership, role/custom Endorsement,
//! Invitation, …) gets its **canonical shape** here from the `dtg-credentials`
//! catalog constructors (`new_vmc`, `new_vec`, `new_vic`, …) rather than being
//! hand-rolled. The catalog fixes the `@context`, the `type` array, and the
//! `credentialSubject` shape for each kind, so every issuer in the ecosystem
//! mints the same wire form.
//!
//! ## Signing covers `id` + `credentialStatus`
//!
//! The catalog's `DTGCredential` models the VC body (`@context`, `type`,
//! `issuer`, `validFrom`/`validUntil`, `credentialSubject`, `proof`) but **not**
//! a top-level `id` or a `credentialStatus` block. Those are spliced onto the
//! serialized body **before** signing, and the whole document is signed via
//! [`LocalSigner::sign_doc`] — so the proof covers the status reference (a
//! revoked credential can't have its `credentialStatus` stripped without
//! breaking the signature). The result is the signed VC as a
//! [`serde_json::Value`], the shape every downstream consumer (seal, store,
//! `recognition`) already speaks.
//!
//! ## Keys stay in `LocalSigner`
//!
//! Issuance signs through the VTC's local issuer key ([`LocalSigner`]); the key
//! is never exported. `issuer = signer.issuer_did()` for every credential.

use affinidi_vc::VerifiableCredential;
use chrono::{DateTime, Duration, Utc};
use dtg_credentials::DTGCredential;
use serde_json::Value;
use vti_common::error::AppError;

use crate::acl::VtcRole;

use super::signer::LocalSigner;
use super::vec::COMMUNITY_ROLE_ENDORSEMENT_TYPE;
use super::vmc::CredentialStatusRef;

/// Parse a signed catalog credential (the JSON any `issue_*` returns) into the
/// typed [`VerifiableCredential`] the credential builders hand back. Centralises
/// the `serde_json::from_value` + `AppError::Internal` mapping the `build_vmc` /
/// `build_role_vec` / `build_custom_endorsement` builders each repeated (P2.8);
/// `kind` (e.g. `"VMC"`, `"role VEC"`) is woven into the error for diagnosis.
pub fn into_typed(doc: Value, kind: &str) -> Result<VerifiableCredential, AppError> {
    serde_json::from_value(doc)
        .map_err(|e| AppError::Internal(format!("DTG {kind} -> VerifiableCredential: {e}")))
}

/// `[validFrom, validUntil]` for a credential minted `now` with `validity`.
fn window(validity: Duration) -> (DateTime<Utc>, DateTime<Utc>) {
    let now = Utc::now();
    (now, now + validity)
}

/// Serialize a catalog credential's body, splice the optional `id` +
/// `credentialStatus`, and sign the whole document. Returns the signed VC JSON.
async fn finalize(
    signer: &LocalSigner,
    dtg: DTGCredential,
    id: Option<&str>,
    status_ref: Option<&CredentialStatusRef>,
    subject_scopes: &[String],
) -> Result<Value, AppError> {
    // The wire VC is the catalog's `DTGCommon` body; the `DTGCredential`
    // wrapper's `type_`/`version` helpers are not part of the credential.
    let mut doc = serde_json::to_value(dtg.credential())
        .map_err(|e| AppError::Internal(format!("DTG credential -> value: {e}")))?;
    let obj = doc
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("DTG credential is not a JSON object".into()))?;

    if let Some(id) = id {
        obj.insert("id".into(), Value::String(id.to_string()));
    }
    if let Some(status_ref) = status_ref {
        let status = serde_json::to_value(status_ref)
            .map_err(|e| AppError::Internal(format!("credentialStatus -> value: {e}")))?;
        obj.insert("credentialStatus".into(), status);
    }
    // Splice `scopes` into credentialSubject (covered by the signature). The
    // catalog subject is `{ id }`; this is additive — used by invitations to
    // carry an authorized role (`role:<name>`).
    if !subject_scopes.is_empty()
        && let Some(subject) = obj
            .get_mut("credentialSubject")
            .and_then(Value::as_object_mut)
    {
        subject.insert(
            "scopes".into(),
            Value::Array(subject_scopes.iter().cloned().map(Value::String).collect()),
        );
    }

    // Sign the full document (covers id + credentialStatus + subject scopes).
    signer.sign_doc(&mut doc).await?;
    Ok(doc)
}

/// Issue a signed **Membership** credential (VMC) as JSON.
///
/// `personhood = true` adds `PersonhoodCredential` to the `type` array (the
/// catalog's convention) rather than a subject field.
pub async fn issue_membership(
    signer: &LocalSigner,
    member_did: &str,
    id: Option<&str>,
    status_ref: Option<&CredentialStatusRef>,
    validity: Duration,
    personhood: bool,
) -> Result<Value, AppError> {
    let (valid_from, valid_until) = window(validity);
    let dtg = DTGCredential::new_vmc(
        signer.issuer_did().to_string(),
        member_did.to_string(),
        valid_from,
        Some(valid_until),
        personhood,
    );
    finalize(signer, dtg, id, status_ref, &[]).await
}

/// Issue a signed **role-grant** Endorsement credential (VEC) as JSON.
///
/// The endorsement carries `{ type: "CommunityRole", role, communityDid }` at
/// `credentialSubject.endorsement` — the shape `recognition` parses for
/// cross-community role verification.
pub async fn issue_role(
    signer: &LocalSigner,
    member_did: &str,
    role: &VtcRole,
    id: Option<&str>,
    status_ref: Option<&CredentialStatusRef>,
    validity: Duration,
) -> Result<Value, AppError> {
    let endorsement = serde_json::json!({
        "type": COMMUNITY_ROLE_ENDORSEMENT_TYPE,
        "role": role.to_string(),
        "communityDid": signer.issuer_did(),
    });
    issue_endorsement(signer, member_did, endorsement, id, status_ref, validity).await
}

/// Issue a signed **Endorsement** credential (VEC) as JSON with a
/// caller-supplied `endorsement` value at `credentialSubject.endorsement`.
/// Used for both role grants ([`issue_role`]) and operator-defined custom
/// endorsements.
pub async fn issue_endorsement(
    signer: &LocalSigner,
    member_did: &str,
    endorsement: Value,
    id: Option<&str>,
    status_ref: Option<&CredentialStatusRef>,
    validity: Duration,
) -> Result<Value, AppError> {
    let (valid_from, valid_until) = window(validity);
    let dtg = DTGCredential::new_vec(
        signer.issuer_did().to_string(),
        member_did.to_string(),
        valid_from,
        Some(valid_until),
        endorsement,
    );
    finalize(signer, dtg, id, status_ref, &[]).await
}

/// Issue a signed **Invitation** credential (VIC) as JSON to a `subject_did`
/// that is **not** (yet) a member. The issue-to-unknown-holder transport
/// (sealed + delivered out-of-band) is Phase 3; this is the issuance op. Pass a
/// `status_ref` to make the invite revocable.
pub async fn issue_invitation(
    signer: &LocalSigner,
    subject_did: &str,
    id: Option<&str>,
    status_ref: Option<&CredentialStatusRef>,
    validity: Duration,
    subject_scopes: &[String],
) -> Result<Value, AppError> {
    let (valid_from, valid_until) = window(validity);
    let dtg = DTGCredential::new_vic(
        signer.issuer_did().to_string(),
        subject_did.to_string(),
        valid_from,
        Some(valid_until),
    );
    finalize(signer, dtg, id, status_ref, subject_scopes).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};

    const TEST_DID: &str = "did:web:acme.example";

    fn signer() -> LocalSigner {
        LocalSigner::from_ed25519_seed(TEST_DID.into(), &[7u8; 32])
    }

    /// Verify the issuer proof over the document (proof stripped), as every
    /// downstream verifier does.
    fn verify(doc: &Value, signer: &LocalSigner) -> Result<(), String> {
        let proof: DataIntegrityProof =
            serde_json::from_value(doc.get("proof").cloned().ok_or("no proof")?)
                .map_err(|e| e.to_string())?;
        let mut unsigned = doc.clone();
        unsigned.as_object_mut().unwrap().remove("proof");
        proof
            .verify_with_public_key(&unsigned, signer.public_bytes(), VerifyOptions::new())
            .map_err(|e| e.to_string())
    }

    #[test]
    fn into_typed_maps_malformed_json_to_kind_tagged_internal() {
        // A non-VC JSON shape fails the typed parse with an Internal error
        // that names the credential kind for diagnosis. (The success path is
        // covered by the build_vmc / build_role_vec / build_custom_endorsement
        // suites, which all route through `into_typed`.)
        let err = into_typed(serde_json::json!({ "not": "a credential" }), "VMC")
            .expect_err("a non-VC object must not parse as a VerifiableCredential");
        match err {
            AppError::Internal(msg) => {
                assert!(msg.contains("VMC"), "error must name the kind: {msg}");
                assert!(msg.contains("VerifiableCredential"), "{msg}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn membership_issues_with_catalog_shape_and_verifies() {
        let s = signer();
        let doc = issue_membership(
            &s,
            "did:key:zMember",
            Some("urn:uuid:vmc-1"),
            None,
            Duration::days(30),
            false,
        )
        .await
        .expect("issue VMC");

        verify(&doc, &s).expect("VMC proof verifies");
        assert_eq!(doc["issuer"], TEST_DID);
        assert_eq!(doc["id"], "urn:uuid:vmc-1");
        assert_eq!(doc["credentialSubject"]["id"], "did:key:zMember");
        let types: Vec<String> = serde_json::from_value(doc["type"].clone()).unwrap();
        assert!(
            types.iter().any(|t| t == "MembershipCredential"),
            "{types:?}"
        );
        assert!(
            !types.iter().any(|t| t == "PersonhoodCredential"),
            "personhood was false"
        );
        assert!(
            doc.get("credentialStatus").is_none(),
            "no status_ref → no block"
        );
    }

    #[tokio::test]
    async fn personhood_membership_adds_type() {
        let s = signer();
        let doc = issue_membership(&s, "did:key:zM", None, None, Duration::days(30), true)
            .await
            .unwrap();
        let types: Vec<String> = serde_json::from_value(doc["type"].clone()).unwrap();
        assert!(
            types.iter().any(|t| t == "PersonhoodCredential"),
            "{types:?}"
        );
    }

    #[tokio::test]
    async fn role_vec_preserves_recognition_endorsement_shape() {
        let s = signer();
        let doc = issue_role(
            &s,
            "did:key:zMember",
            &VtcRole::Admin,
            Some("urn:uuid:vec-1"),
            None,
            Duration::days(30),
        )
        .await
        .expect("issue role VEC");

        verify(&doc, &s).expect("VEC proof verifies");
        // The shape recognition/verify.rs parses: endorsement.{role,communityDid}.
        let endorsement = &doc["credentialSubject"]["endorsement"];
        assert_eq!(endorsement["type"], "CommunityRole");
        assert_eq!(endorsement["role"], VtcRole::Admin.to_string());
        assert_eq!(endorsement["communityDid"], TEST_DID);
    }

    #[tokio::test]
    async fn invitation_issues_to_a_non_member_and_verifies() {
        // A VIC is issued to a DID with no membership record (an invite); it
        // verifies, carries the Invitation type, and is revocable.
        let s = signer();
        let status = CredentialStatusRef::revocation("urn:uuid:invite-list", 3);
        let doc = issue_invitation(
            &s,
            "did:key:zInvitee",
            Some("urn:uuid:vic-1"),
            Some(&status),
            Duration::days(7),
            &[],
        )
        .await
        .expect("issue VIC");

        verify(&doc, &s).expect("VIC proof verifies");
        assert_eq!(doc["credentialSubject"]["id"], "did:key:zInvitee");
        let types: Vec<String> = serde_json::from_value(doc["type"].clone()).unwrap();
        assert!(
            types.iter().any(|t| t == "InvitationCredential"),
            "{types:?}"
        );
        assert!(
            doc.get("credentialStatus").is_some(),
            "VIC must be revocable"
        );
    }

    #[tokio::test]
    async fn credential_status_is_inside_the_signed_bytes() {
        let s = signer();
        let status = CredentialStatusRef::revocation("urn:uuid:list-1", 42);
        let doc = issue_endorsement(
            &s,
            "did:key:zMember",
            serde_json::json!({ "type": "CommunityRole", "role": "member" }),
            None,
            Some(&status),
            Duration::days(30),
        )
        .await
        .expect("issue VEC with status");

        verify(&doc, &s).expect("VEC-with-status verifies");
        assert!(doc.get("credentialStatus").is_some());

        // Tampering with the status (e.g. removing it) breaks the proof —
        // proving the status is covered by the signature.
        let mut tampered = doc.clone();
        tampered.as_object_mut().unwrap().remove("credentialStatus");
        assert!(
            verify(&tampered, &s).is_err(),
            "stripping a signed credentialStatus must invalidate the proof"
        );
    }
}
