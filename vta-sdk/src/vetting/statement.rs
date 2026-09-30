//! The Vetting Statement: what a vetter signs after checking an applicant.
//!
//! A DTG **Verifiable Statement Credential** (`StatementCredential`) under the
//! registry predicate [`VETTED_PREDICATE`]
//! (`https://registry.trustoverip.org/dtg/vsc/vetted/1`), whose
//! `credentialSubject.object.value` is a [`VettedObjectValue`]
//! (vetting/session/0.1, "The statement"). It is not an endorsement: the vetter
//! records a check it carried out, and the predicate — not a type string —
//! carries that meaning.
//!
//! Issued from the **vetter's member DID** (accountable within the community),
//! declaring `issuerScope` `directed` or `public` — the profile's minimum is
//! `directed` — to the applicant's join DID, with a bounded `validUntil`, and
//! citing the `vetting/session` document by both `taskContext` (its `id`) and
//! `taskDigestMultibase` (its task digest), which the profile REQUIRES. Building
//! and parsing go through `dtg-credentials`, the workspace's DTG SDK, so the
//! v1 context, the `type` rule and the profile are checked by the same code
//! that issues them.

use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use dtg_credentials::{DTGCredential, VETTED_V1};
use serde_json::Value;

pub use dtg_credentials::IssuerScope;

use super::card::{CLOCK_SKEW, VerifiedVettingCard};
use super::{VettingError, did_of, digest, verify_attached_proof};
#[cfg(doc)]
use crate::protocols::vetting::VETTED_PREDICATE;
use crate::protocols::vetting::{CheckShape, VettedObjectValue};
use crate::trust_task_proof::TrustTaskVmResolver;

const WHAT: &str = "vetting statement";

/// Everything needed to issue a statement.
#[derive(Debug, Clone)]
pub struct StatementDraft {
    /// `urn:uuid:…` — what a revocation notice names.
    pub id: String,
    /// The vetter's member DID.
    pub issuer: String,
    /// The correlation scope the vetter declares for `issuer`: `directed`
    /// (the community and its applicants recognise the member DID) or
    /// `public`. `pairwise` is refused — the `vetted/1` profile's minimum is
    /// `directed`.
    pub issuer_scope: IssuerScope,
    /// The applicant's join DID (the verified card's publisher).
    pub subject: String,
    /// The attestation: `credentialSubject.object.value`.
    pub value: VettedObjectValue,
    /// Normally now.
    pub valid_from: DateTime<Utc>,
    /// `validFrom` + the community's `maxStatementAge`.
    pub valid_until: DateTime<Utc>,
    /// The `vetting/session` document that opened the session, exactly as the
    /// vetter sent it. Its `id` becomes `taskContext` and its task digest
    /// `taskDigestMultibase`, so the two cannot disagree.
    pub session: Value,
}

/// Build and sign a statement. `signer` must be a key of `draft.issuer`.
///
/// # Errors
///
/// [`VettingError::WrongSigner`], [`VettingError::Malformed`] (a value that
/// breaks its shared definition, a `pairwise` scope, or a session document
/// without an `id`), [`VettingError::Expired`] (empty window) or
/// [`VettingError::Sign`].
pub async fn sign_statement(draft: StatementDraft, signer: &Secret) -> Result<Value, VettingError> {
    let malformed = |detail: String| VettingError::Malformed { what: WHAT, detail };
    if did_of(&signer.id) != draft.issuer {
        return Err(VettingError::WrongSigner {
            what: WHAT,
            role: "issuer",
        });
    }
    draft
        .value
        .check_shape()
        .map_err(|e| malformed(e.to_string()))?;
    if draft.valid_until <= draft.valid_from {
        return Err(VettingError::Expired(WHAT));
    }
    let value =
        serde_json::to_value(&draft.value).map_err(|e| VettingError::Sign(e.to_string()))?;
    let mut credential = DTGCredential::new_vetted_vsc(
        draft.issuer,
        draft.issuer_scope,
        draft.subject,
        value,
        &draft.session,
        draft.valid_from,
        Some(draft.valid_until),
    )
    .map_err(|e| malformed(e.to_string()))?
    .with_id(draft.id);
    credential
        .sign(signer, None)
        .await
        .map_err(|e| VettingError::Sign(e.to_string()))?;
    serde_json::to_value(&credential).map_err(|e| VettingError::Sign(e.to_string()))
}

/// A statement whose proof, type, profile, window and shape all check.
///
/// What this does **not** establish: that the issuer is an eligible vetter of
/// the community, or that the statement has not been withdrawn. Those are facts
/// only the community holds.
#[derive(Debug, Clone)]
pub struct VerifiedVettingStatement {
    id: String,
    issuer: String,
    issuer_scope: IssuerScope,
    subject: String,
    value: VettedObjectValue,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    task_context: String,
    task_digest_multibase: String,
    has_status: bool,
    digest_multibase: String,
}

impl VerifiedVettingStatement {
    /// The statement `id`.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// The vetter's DID (proven: it signed).
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    /// The `issuerScope` the vetter declared: `directed` or `public`.
    #[must_use]
    pub fn issuer_scope(&self) -> IssuerScope {
        self.issuer_scope
    }
    /// The applicant's join DID.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// The attestation: `credentialSubject.object.value`.
    #[must_use]
    pub fn value(&self) -> &VettedObjectValue {
        &self.value
    }
    /// Start of validity.
    #[must_use]
    pub fn valid_from(&self) -> DateTime<Utc> {
        self.valid_from
    }
    /// End of validity.
    #[must_use]
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }
    /// The `vetting/session` document id.
    #[must_use]
    pub fn task_context(&self) -> &str {
        &self.task_context
    }
    /// The `vetting/session` document's task digest.
    #[must_use]
    pub fn task_digest_multibase(&self) -> &str {
        &self.task_digest_multibase
    }
    /// Whether the statement names a `credentialStatus` entry to check.
    #[must_use]
    pub fn has_status(&self) -> bool {
        self.has_status
    }
    /// `digestMultibase` of the statement — what a revocation notice names.
    #[must_use]
    pub fn digest_multibase(&self) -> &str {
        &self.digest_multibase
    }

    /// Check this statement was issued over `card`: same subject, community,
    /// commitment and card digest. The applicant's client runs this before
    /// filing a statement, so a vetter that attested to a different card is
    /// caught immediately rather than at the community.
    ///
    /// # Errors
    ///
    /// [`VettingError::Binding`] naming the member that differs.
    pub fn check_against_card(&self, card: &VerifiedVettingCard) -> Result<(), VettingError> {
        let c = card.card();
        if self.subject != c.publisher.as_str() {
            return Err(VettingError::Binding("subject"));
        }
        if self.value.community != c.community.as_str() {
            return Err(VettingError::Binding("community"));
        }
        if self.value.identity_commitment != c.identity_commitment.as_str() {
            return Err(VettingError::Binding("identityCommitment"));
        }
        if self.value.card_digest_multibase != card.digest_multibase() {
            return Err(VettingError::Binding("cardDigestMultibase"));
        }
        Ok(())
    }

    /// Check this statement cites `session` — the `vetting/session` document
    /// the vetter sent — by both `taskContext` and `taskDigestMultibase`.
    ///
    /// # Errors
    ///
    /// [`VettingError::Binding`] naming `taskContext` or `taskDigestMultibase`.
    pub fn check_against_session(&self, session: &Value) -> Result<(), VettingError> {
        if session.get("id").and_then(Value::as_str) != Some(self.task_context.as_str()) {
            return Err(VettingError::Binding("taskContext"));
        }
        let expected = dtg_credentials::task_digest_multibase_json(session)
            .map_err(|e| VettingError::Digest(e.to_string()))?;
        let same = dtg_credentials::digests_match(&self.task_digest_multibase, &expected)
            .map_err(|e| VettingError::Digest(e.to_string()))?;
        if !same {
            return Err(VettingError::Binding("taskDigestMultibase"));
        }
        Ok(())
    }
}

/// Verify a statement as received — by the applicant on delivery, or by the
/// community inside a join presentation.
///
/// The credential must parse as a DTG credential under the v1 context — which
/// holds it to the `vetted/1` profile: `taskContext` and `taskDigestMultibase`
/// present, `issuerScope` at least `directed` — carry the predicate
/// [`VETTED_PREDICATE`], and have an `object.value` that is a
/// [`VettedObjectValue`].
///
/// # Errors
///
/// The first failed check: [`VettingError::Malformed`], [`VettingError::Expired`],
/// [`VettingError::Proof`] or [`VettingError::WrongSigner`].
pub async fn verify_statement(
    value: &Value,
    now: DateTime<Utc>,
    resolver: &TrustTaskVmResolver,
) -> Result<VerifiedVettingStatement, VettingError> {
    let malformed = |detail: String| VettingError::Malformed { what: WHAT, detail };
    let credential: DTGCredential =
        serde_json::from_value(value.clone()).map_err(|e| malformed(e.to_string()))?;
    let statement = credential
        .statement()
        .ok_or_else(|| malformed("not a StatementCredential".into()))?;
    if statement.predicate != VETTED_V1 {
        return Err(malformed(format!(
            "predicate `{}` is not {VETTED_V1}",
            statement.predicate
        )));
    }
    let object = statement
        .object
        .value()
        .ok_or_else(|| malformed("no object.value".into()))?;
    let vetted: VettedObjectValue = serde_json::from_value(object.clone())
        .map_err(|e| malformed(format!("object.value: {e}")))?;
    vetted
        .check_shape()
        .map_err(|e| malformed(format!("object.value: {e}")))?;
    let id = credential
        .id()
        .ok_or_else(|| malformed("no id — a statement must be revocable by name".into()))?
        .to_string();
    // Both are guaranteed by the profile check the parse ran; read defensively.
    let task_context = credential
        .task_context()
        .ok_or_else(|| malformed("no taskContext naming the session".into()))?
        .to_string();
    let task_digest_multibase = credential
        .task_digest_multibase()
        .ok_or_else(|| malformed("no taskDigestMultibase binding the session".into()))?
        .to_string();
    let valid_until = credential
        .valid_until()
        .ok_or_else(|| malformed("no validUntil — statements are bounded evidence".into()))?;
    if credential.valid_from() > now + CLOCK_SKEW || now > valid_until {
        return Err(VettingError::Expired(WHAT));
    }
    let issuer = credential.issuer().to_string();

    let signer = verify_attached_proof(WHAT, value, "assertionMethod", resolver).await?;
    if signer != issuer {
        return Err(VettingError::WrongSigner {
            what: WHAT,
            role: "issuer",
        });
    }

    Ok(VerifiedVettingStatement {
        id,
        issuer,
        issuer_scope: credential.issuer_scope(),
        subject: statement.id.clone(),
        value: vetted,
        valid_from: credential.valid_from(),
        valid_until,
        task_context,
        task_digest_multibase,
        has_status: credential.credential().credential_status.is_some(),
        digest_multibase: digest(value)?,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::protocols::vetting::{VETTED_PREDICATE, VettingMethod, VettingRelationship};
    use crate::vetting::card::{
        CardExpectations, sign_card,
        tests::{CHALLENGE, COMMUNITY, draft},
        verify_card,
    };
    use crate::vetting::test_support::{did, secret};
    use chrono::Duration;
    use serde_json::json;

    pub(crate) fn vetted_value(commitment: &str, card_digest: &str) -> VettedObjectValue {
        VettedObjectValue {
            community: COMMUNITY.into(),
            method: VettingMethod::Video,
            document_classes: vec!["passport".try_into().unwrap()],
            claims_verified: vec!["name.legal".try_into().unwrap()],
            liveness_confirmed: true,
            identity_commitment: commitment.into(),
            card_digest_multibase: card_digest.into(),
            declared_relationship: VettingRelationship::CommunityColleague,
            attestation_text_digest: None,
        }
    }

    /// A `vetting/session` document, as the vetter sent it.
    pub(crate) fn session_document(vetter: &str, applicant: &str) -> Value {
        json!({
            "id": "urn:uuid:session-1",
            "type": "https://trusttasks.org/spec/vetting/session/0.1",
            "threadId": "urn:uuid:session-1",
            "parentThreadId": "urn:uuid:request-1",
            "issuer": vetter,
            "recipient": applicant,
            "issuedAt": "2026-09-17T15:00:00Z",
            "payload": { "method": "video" }
        })
    }

    async fn verified_card(applicant: &Secret, vetter: &Secret) -> VerifiedVettingCard {
        let now = Utc::now();
        let signed = sign_card(draft(applicant, vetter, now), applicant)
            .await
            .unwrap();
        let required = vec!["name.legal".to_string()];
        let (a, v) = (did(applicant), did(vetter));
        verify_card(
            &signed,
            &CardExpectations {
                audience: &v,
                publisher: &a,
                community: COMMUNITY,
                challenge: CHALLENGE,
                domain: COMMUNITY,
                required_claims: &required,
                now,
            },
            &TrustTaskVmResolver::did_key_only(),
        )
        .await
        .unwrap()
    }

    pub(crate) fn statement_draft(
        vetter: &Secret,
        subject: &str,
        value: VettedObjectValue,
    ) -> StatementDraft {
        let now = Utc::now();
        StatementDraft {
            id: "urn:uuid:statement-1".into(),
            issuer: did(vetter),
            issuer_scope: IssuerScope::Directed,
            subject: subject.into(),
            value,
            valid_from: now,
            valid_until: now + Duration::days(120),
            session: session_document(&did(vetter), subject),
        }
    }

    #[tokio::test]
    async fn a_statement_verifies_and_binds_to_its_card_and_session() {
        let (applicant, vetter) = (secret(1), secret(2));
        let card = verified_card(&applicant, &vetter).await;
        let e = vetted_value(&card.card().identity_commitment, card.digest_multibase());
        let draft = statement_draft(&vetter, &did(&applicant), e);
        let session = draft.session.clone();
        let signed = sign_statement(draft, &vetter).await.unwrap();
        assert_eq!(
            signed["@context"],
            json!([
                dtg_credentials::W3C_VC_V2_CONTEXT,
                dtg_credentials::DTG_CONTEXT_V1
            ])
        );
        assert_eq!(
            signed["type"],
            json!([
                "VerifiableCredential",
                "DTGCredential",
                "StatementCredential"
            ])
        );
        assert_eq!(signed["issuerScope"], "directed");
        assert_eq!(signed["taskContext"], "urn:uuid:session-1");
        assert!(signed["taskDigestMultibase"].is_string());
        assert_eq!(signed["credentialSubject"]["predicate"], VETTED_PREDICATE);
        assert!(
            signed["credentialSubject"]["object"]["value"]
                .get("type")
                .is_none()
        );

        let verified = verify_statement(&signed, Utc::now(), &TrustTaskVmResolver::did_key_only())
            .await
            .unwrap();
        assert_eq!(verified.issuer(), did(&vetter));
        assert_eq!(verified.issuer_scope(), IssuerScope::Directed);
        assert_eq!(verified.value().method, VettingMethod::Video);
        verified.check_against_card(&card).unwrap();
        verified.check_against_session(&session).unwrap();

        let mut other = session;
        other["issuedAt"] = json!("2026-09-17T15:01:00Z");
        assert!(matches!(
            verified.check_against_session(&other),
            Err(VettingError::Binding("taskDigestMultibase"))
        ));
    }

    #[tokio::test]
    async fn an_altered_value_breaks_the_proof() {
        let (applicant, vetter) = (secret(1), secret(2));
        let e = vetted_value("zCommitment", "zCard");
        let mut signed = sign_statement(statement_draft(&vetter, &did(&applicant), e), &vetter)
            .await
            .unwrap();
        signed["credentialSubject"]["object"]["value"]["method"] = json!("inPerson");
        let err = verify_statement(&signed, Utc::now(), &TrustTaskVmResolver::did_key_only())
            .await
            .unwrap_err();
        assert!(matches!(err, VettingError::Proof { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn a_statement_over_a_different_card_is_caught() {
        let (applicant, vetter) = (secret(1), secret(2));
        let card = verified_card(&applicant, &vetter).await;
        let e = vetted_value("zDifferentCommitment", card.digest_multibase());
        let signed = sign_statement(statement_draft(&vetter, &did(&applicant), e), &vetter)
            .await
            .unwrap();
        let verified = verify_statement(&signed, Utc::now(), &TrustTaskVmResolver::did_key_only())
            .await
            .unwrap();
        assert!(matches!(
            verified.check_against_card(&card),
            Err(VettingError::Binding("identityCommitment"))
        ));
    }

    #[tokio::test]
    async fn only_the_named_issuer_may_sign() {
        let (applicant, vetter, other) = (secret(1), secret(2), secret(3));
        let e = vetted_value("zC", "zD");
        let err = sign_statement(statement_draft(&vetter, &did(&applicant), e), &other)
            .await
            .unwrap_err();
        assert!(matches!(err, VettingError::WrongSigner { .. }));
    }

    #[tokio::test]
    async fn an_expired_statement_is_refused() {
        let (applicant, vetter) = (secret(1), secret(2));
        let e = vetted_value("zC", "zD");
        let signed = sign_statement(statement_draft(&vetter, &did(&applicant), e), &vetter)
            .await
            .unwrap();
        let later = Utc::now() + Duration::days(200);
        let err = verify_statement(&signed, later, &TrustTaskVmResolver::did_key_only())
            .await
            .unwrap_err();
        assert!(matches!(err, VettingError::Expired(_)));
    }

    /// vetting/session/0.1: a `pairwise` declaration cannot describe a vetter
    /// truthfully, so it is refused at issue.
    #[tokio::test]
    async fn a_pairwise_vetter_cannot_issue() {
        let (applicant, vetter) = (secret(1), secret(2));
        let mut draft = statement_draft(&vetter, &did(&applicant), vetted_value("zC", "zD"));
        draft.issuer_scope = IssuerScope::Pairwise;
        assert!(matches!(
            sign_statement(draft, &vetter).await.unwrap_err(),
            VettingError::Malformed { .. }
        ));
    }

    #[tokio::test]
    async fn a_statement_under_another_predicate_is_not_a_vetting_statement() {
        let (applicant, vetter) = (secret(1), secret(2));
        let now = Utc::now();
        let mut vsc = DTGCredential::new_endorses_vsc(
            did(&vetter),
            IssuerScope::Directed,
            did(&applicant),
            serde_json::to_value(vetted_value("zC", "zD")).unwrap(),
            now,
            Some(now + Duration::days(30)),
        )
        .unwrap()
        .with_id("urn:uuid:not-a-vetting".to_string());
        vsc.sign(&vetter, None).await.unwrap();
        let signed = serde_json::to_value(&vsc).unwrap();
        assert!(matches!(
            verify_statement(&signed, now, &TrustTaskVmResolver::did_key_only())
                .await
                .unwrap_err(),
            VettingError::Malformed { .. }
        ));
    }

    /// The retired shape: an `EndorsementCredential` under the old context.
    #[tokio::test]
    async fn a_pre_v1_statement_is_refused() {
        let legacy = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:uuid:legacy",
            "type": ["VerifiableCredential", "DTGCredential", "EndorsementCredential"],
            "issuer": "did:key:z6MkVetter",
            "validFrom": "2026-09-01T00:00:00Z",
            "validUntil": "2027-01-01T00:00:00Z",
            "taskContext": "urn:uuid:session-1",
            "credentialSubject": { "id": "did:key:z6MkApplicant", "endorsement": {} }
        });
        assert!(matches!(
            verify_statement(&legacy, Utc::now(), &TrustTaskVmResolver::did_key_only())
                .await
                .unwrap_err(),
            VettingError::Malformed { .. }
        ));
    }
}
