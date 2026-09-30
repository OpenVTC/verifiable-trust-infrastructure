//! Issue catalog credentials from the **DTG (Decentralized Trust Graph)**
//! credentials catalog (`dtg-credentials`) — task 2.0.
//!
//! Every DTG credential the VTC mints (Membership, role Authority, Statement,
//! Invitation) gets its **canonical shape** here from the `dtg-credentials`
//! catalog constructors (`new_vmc`, `new_community_role_vac`, `new_vsc`,
//! `new_vic`) rather than being hand-rolled. The catalog fixes the `@context`
//! (`[credentials/v2, DTG_CONTEXT_V1]`), the `type` array (exactly one concrete
//! subtype), `issuerScope` and the `credentialSubject` shape for each kind, so
//! every issuer in the ecosystem mints the same wire form.
//!
//! ## `issuerScope`
//!
//! Every credential here is issued by the community under its own DID, which
//! every verifier — members, applicants, foreign communities — must be able to
//! recognise. That is `public` in the DTG Credentials Core Specification, and
//! it is the only scope the VTC declares.
//!
//! The one credential the VTC issues that is *not* a DTG credential is the
//! identity-verification credential ([`super::idvc`]), a plain
//! W3C VC.
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
use dtg_credentials::{DTGCredential, IssuerScope, StatementObject};
use serde_json::Value;
use vti_common::error::AppError;

use crate::acl::VtcRole;

use super::signer::LocalSigner;
use super::vmc::CredentialStatusRef;

/// `maxAttenuation` on every community role VAC: `0`, so a role cannot be
/// attenuated onward. Who holds a community role is the community's decision
/// to make personally — vtc/vetting/vetters/grant/0.1 fixes `0` for
/// `role:vetter` for exactly that reason, and vtc/join-requests/decide/0.1
/// issues "the same shape" for every other role.
pub const ROLE_VAC_MAX_ATTENUATION: u32 = 0;

/// Parse a signed catalog credential (the JSON any `issue_*` returns) into the
/// typed [`VerifiableCredential`] the credential builders hand back. Centralises
/// the `serde_json::from_value` + `AppError::Internal` mapping the `build_vmc` /
/// `build_role_vac` / `build_custom_endorsement` builders each repeated (P2.8);
/// `kind` (e.g. `"VMC"`, `"role VAC"`) is woven into the error for diagnosis.
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
    // Hold the model to the catalog's own rules — context, type, issuerScope,
    // a statement's predicate profile — before anything is signed. Signing
    // goes through `LocalSigner` rather than `DTGCredential::sign`, so this is
    // the one place those checks run.
    dtg.validate()
        .map_err(|e| AppError::Validation(format!("DTG credential is not conformant: {e}")))?;
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

/// Issue a signed community **role** credential as JSON: a VAC conferring
/// `role:<role>` at the community's DID, `issuerScope` `public`,
/// `maxAttenuation` [`ROLE_VAC_MAX_ATTENUATION`].
///
/// The action is [`role_action_for`]`(role)` — `role:admin`, `role:moderator`,
/// `role:custom:<name>` — so `recognition` can map it back to a [`VtcRole`].
pub async fn issue_role(
    signer: &LocalSigner,
    member_did: &str,
    role: &VtcRole,
    id: Option<&str>,
    status_ref: Option<&CredentialStatusRef>,
    validity: Duration,
) -> Result<Value, AppError> {
    issue_role_action(
        signer,
        member_did,
        &role.to_string(),
        id,
        status_ref,
        validity,
    )
    .await
}

/// [`issue_role`] for a role that is not a [`VtcRole`] — `vetter`, which
/// vtc/vetting/vetters/grant/0.1 names bare.
pub async fn issue_role_action(
    signer: &LocalSigner,
    member_did: &str,
    role: &str,
    id: Option<&str>,
    status_ref: Option<&CredentialStatusRef>,
    validity: Duration,
) -> Result<Value, AppError> {
    let (valid_from, valid_until) = window(validity);
    let dtg = DTGCredential::new_community_role_vac(
        signer.issuer_did().to_string(),
        member_did.to_string(),
        role,
        valid_from,
        valid_until,
    )
    .and_then(|vac| vac.with_max_attenuation(ROLE_VAC_MAX_ATTENUATION))
    .map_err(|e| AppError::Validation(format!("role credential: {e}")))?;
    finalize(signer, dtg, id, status_ref, &[]).await
}

/// The VAC action a community role credential carries for `role`.
pub fn role_action_for(role: &VtcRole) -> String {
    dtg_credentials::create::role_action(&role.to_string())
}

/// Issue a signed community **statement** (VSC) as JSON: the community, as
/// itself (`issuerScope` `public`), asserts `value` about `subject_did` under
/// `predicate`, carried as `credentialSubject.object.value`.
///
/// What `vtc/endorsements/issue/0.1` mints. Under
/// [`dtg_credentials::ENDORSES_V1`] it is a Verifiable Endorsement Credential.
/// A predicate whose profile requires `taskContext` is refused by
/// [`finalize`]'s conformance check, since nothing here cites a task.
pub async fn issue_statement(
    signer: &LocalSigner,
    subject_did: &str,
    predicate: &str,
    value: Value,
    id: Option<&str>,
    status_ref: Option<&CredentialStatusRef>,
    validity: Duration,
) -> Result<Value, AppError> {
    let (valid_from, valid_until) = window(validity);
    let dtg = DTGCredential::new_vsc(
        signer.issuer_did().to_string(),
        IssuerScope::Public,
        subject_did.to_string(),
        predicate,
        StatementObject::Value(value),
        valid_from,
        Some(valid_until),
    )
    .map_err(|e| AppError::Validation(format!("statement credential: {e}")))?;
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
    // A community inviting as itself: `public`, like every credential here.
    let dtg = DTGCredential::new_vic(
        signer.issuer_did().to_string(),
        IssuerScope::Public,
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
        // covered by the build_vmc / build_role_vac / build_custom_endorsement
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
    async fn role_vac_carries_the_recognition_authority_shape() {
        let s = signer();
        let doc = issue_role(
            &s,
            "did:key:zMember",
            &VtcRole::Admin,
            Some("urn:uuid:vac-1"),
            None,
            Duration::days(30),
        )
        .await
        .expect("issue role VAC");

        verify(&doc, &s).expect("VAC proof verifies");
        // The shape recognition/verify.rs parses: authority.{scope,actions}.
        assert_eq!(doc["issuerScope"], "public");
        let authority = &doc["credentialSubject"]["authority"];
        assert_eq!(authority["scope"], TEST_DID);
        assert_eq!(
            authority["actions"],
            serde_json::json!([role_action_for(&VtcRole::Admin)])
        );
        assert_eq!(authority["maxAttenuation"], ROLE_VAC_MAX_ATTENUATION);
        assert!(authority.get("parent").is_none());
    }

    #[tokio::test]
    async fn a_statement_under_a_task_bound_predicate_is_refused() {
        // `vetted/1` requires `taskContext`, which a community statement never
        // carries — the conformance check refuses it before signing.
        let err = issue_statement(
            &signer(),
            "did:key:zMember",
            dtg_credentials::VETTED_V1,
            serde_json::json!({ "community": TEST_DID }),
            None,
            None,
            Duration::days(30),
        )
        .await
        .expect_err("vetted/1 cannot be issued without a task citation");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
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
        let doc = issue_statement(
            &s,
            "did:key:zMember",
            dtg_credentials::ENDORSES_V1,
            serde_json::json!({ "skill": "rust" }),
            None,
            Some(&status),
            Duration::days(30),
        )
        .await
        .expect("issue VSC with status");

        verify(&doc, &s).expect("VSC-with-status verifies");
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

/// The catalog's wire shape, pinned.
///
/// The point of minting through `dtg-credentials` is that every issuer in the
/// ecosystem emits the same document, so what this crate decides — the
/// `@context` URIs, their order, and the `type` array — *is* the interop
/// contract. It is also the part a dependency bump can change without changing
/// a single line here: the constructors keep their signatures, the code keeps
/// compiling, and every credential the VTC mints quietly becomes a different
/// document.
///
/// The tests above assert `type` and were the whole of the coverage; nothing
/// asserted `@context`. That gap is why this exists. Verified byte-identical
/// across the 0.1.3 → 0.2.0 bump by emitting under both and diffing — this test
/// is what makes the *next* bump answerable without repeating that.
///
/// A failure here is not necessarily a defect: the catalog is allowed to move.
/// It means the wire form changed, so the change is deliberate, coordinated with
/// the other issuers, and reflected in the values below.
#[cfg(test)]
mod catalog_wire_shape {
    use super::*;

    const TEST_DID: &str = "did:web:acme.example";
    const CONTEXT: [&str; 2] = [
        dtg_credentials::W3C_VC_V2_CONTEXT,
        dtg_credentials::DTG_CONTEXT_V1,
    ];

    fn signer() -> LocalSigner {
        LocalSigner::from_ed25519_seed(TEST_DID.into(), &[7u8; 32])
    }

    /// `@context`, `type` and `issuerScope`, exactly, in order. Order matters in
    /// JSON-LD: the later context overlays the earlier, so a swap changes what
    /// the terms mean.
    fn assert_shape(doc: &Value, expected_types: &[&str], kind: &str) {
        assert_scoped_shape(doc, expected_types, "public", kind);
    }

    fn assert_scoped_shape(doc: &Value, expected_types: &[&str], scope: &str, kind: &str) {
        assert_eq!(doc["issuerScope"], scope, "{kind}: issuerScope drifted");
        let ctx: Vec<String> = serde_json::from_value(doc["@context"].clone())
            .unwrap_or_else(|e| panic!("{kind}: @context is not a string array: {e}"));
        assert_eq!(ctx, CONTEXT, "{kind}: @context drifted");

        let types: Vec<String> = serde_json::from_value(doc["type"].clone())
            .unwrap_or_else(|e| panic!("{kind}: type is not a string array: {e}"));
        assert_eq!(types, expected_types, "{kind}: type array drifted");
    }

    #[tokio::test]
    async fn membership_credential_wire_shape() {
        let doc = issue_membership(
            &signer(),
            "did:key:zM",
            None,
            None,
            Duration::days(30),
            true,
        )
        .await
        .expect("issue VMC");
        assert_shape(
            &doc,
            &[
                "VerifiableCredential",
                "DTGCredential",
                "MembershipCredential",
                // Personhood rides as an extra type, not a separate credential.
                "PersonhoodCredential",
            ],
            "VMC",
        );
    }

    #[tokio::test]
    async fn membership_without_personhood_drops_only_that_type() {
        let doc = issue_membership(
            &signer(),
            "did:key:zM",
            None,
            None,
            Duration::days(30),
            false,
        )
        .await
        .expect("issue VMC");
        assert_shape(
            &doc,
            &[
                "VerifiableCredential",
                "DTGCredential",
                "MembershipCredential",
            ],
            "VMC (no personhood)",
        );
    }

    #[tokio::test]
    async fn authority_credential_wire_shape() {
        let doc = issue_role(
            &signer(),
            "did:key:zM",
            &VtcRole::Member,
            None,
            None,
            Duration::days(30),
        )
        .await
        .expect("issue role VAC");
        assert_shape(
            &doc,
            &[
                "VerifiableCredential",
                "DTGCredential",
                "AuthorityCredential",
            ],
            "role VAC",
        );
        assert_eq!(
            doc["credentialSubject"]["authority"],
            serde_json::json!({
                "scope": TEST_DID,
                "actions": ["role:member"],
                "maxAttenuation": 0,
            })
        );
    }

    #[tokio::test]
    async fn statement_credential_wire_shape() {
        let doc = issue_statement(
            &signer(),
            "did:key:zM",
            dtg_credentials::ENDORSES_V1,
            serde_json::json!({ "skill": "rust" }),
            None,
            None,
            Duration::days(30),
        )
        .await
        .expect("issue VSC");
        assert_shape(
            &doc,
            &[
                "VerifiableCredential",
                "DTGCredential",
                "StatementCredential",
            ],
            "VSC",
        );
        // The claim rides verbatim as `object.value` under the predicate.
        assert_eq!(
            doc["credentialSubject"]["predicate"],
            dtg_credentials::ENDORSES_V1
        );
        assert_eq!(
            doc["credentialSubject"]["object"],
            serde_json::json!({ "value": { "skill": "rust" } })
        );
    }

    /// The VPC is the one DTG credential in this file the VTC **verifies but
    /// never mints** — it is self-issued by a person under a persona DID, and
    /// the community signer has no business asserting someone's persona. So
    /// there is no `issue_persona`, and this test mints one only to pin the
    /// shape `routes::relationships::check_vpc_shape` validates against.
    ///
    /// That makes the pin more load-bearing here than for the credentials
    /// above, not less: for a VMC a catalog drift changes what we emit and we
    /// find out from a consumer, but for a VPC it changes what we *accept*,
    /// and the failure is every conformant VPC in the ecosystem being
    /// rejected by a VTC that still compiles and still passes its own tests.
    #[test]
    fn persona_credential_wire_shape() {
        let (valid_from, valid_until) = super::window(Duration::days(30));
        let dtg = dtg_credentials::DTGCredential::new_vpc(
            "did:key:zPersona".into(),
            IssuerScope::Directed,
            "did:key:zCounterparty".into(),
            valid_from,
            Some(valid_until),
        );
        // Not signed: the VTC has no key that may legitimately sign a VPC, so
        // the body alone is what is pinned. Every other test here goes through
        // `finalize` because the VTC does mint those.
        let doc = serde_json::to_value(dtg.credential()).expect("VPC body -> value");
        // A persona is recognised by the set of counterparties it is shown to.
        assert_scoped_shape(
            &doc,
            &["VerifiableCredential", "DTGCredential", "PersonaCredential"],
            "directed",
            "VPC",
        );
        // DTG Credentials §VPC: issuer is the P-DID, subject is the
        // counterparty. The VTC reads both — the first to verify the proof,
        // the second to check the annotation names the edge's counterparty.
        assert_eq!(doc["issuer"], "did:key:zPersona");
        assert_eq!(doc["credentialSubject"]["id"], "did:key:zCounterparty");
    }

    #[tokio::test]
    async fn invitation_credential_wire_shape() {
        let doc = issue_invitation(&signer(), "did:key:zM", None, None, Duration::days(30), &[])
            .await
            .expect("issue VIC");
        assert_shape(
            &doc,
            &[
                "VerifiableCredential",
                "DTGCredential",
                "InvitationCredential",
            ],
            "VIC",
        );
    }
}
