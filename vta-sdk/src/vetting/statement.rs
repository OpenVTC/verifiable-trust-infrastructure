//! The Vetting Statement: what a vetter signs after checking an applicant.
//!
//! A DTG `EndorsementCredential` whose `endorsement` is an
//! [`IdentityVettingEndorsement`]. Why a VEC and not a new credential type: the
//! VEC is DTG's credential for "one party asserting something about its
//! counterparty", with a community-defined `endorsement` body — exactly this.
//!
//! Issued from the **vetter's member DID** (accountable within the community),
//! to the applicant's join DID, with a bounded `validUntil` and the session
//! document's `id` as `taskContext`. Building goes through `dtg-credentials`,
//! the workspace's DTG SDK; verification parses strictly here so it does not
//! depend on that crate's internal representation.

use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use dtg_credentials::DTGCredential;
use serde::Deserialize;
use serde_json::Value;

use super::card::{CLOCK_SKEW, VerifiedVettingCard};
use super::{VettingError, did_of, digest, verify_attached_proof};
use crate::protocols::vetting::{
    CheckShape, IDENTITY_VETTING_ENDORSEMENT_TYPE, IdentityVettingEndorsement,
};
use crate::trust_task_proof::TrustTaskVmResolver;

const WHAT: &str = "vetting statement";

/// The DTG credentials context every DTG credential carries.
const DTG_CONTEXT: &str = "https://firstperson.network/credentials/dtg/v1";

/// Everything needed to issue a statement.
#[derive(Debug, Clone)]
pub struct StatementDraft {
    /// `urn:uuid:…` — what a revocation notice names.
    pub id: String,
    /// The vetter's member DID.
    pub issuer: String,
    /// The applicant's join DID (the verified card's publisher).
    pub subject: String,
    /// The attestation.
    pub endorsement: IdentityVettingEndorsement,
    /// Normally now.
    pub valid_from: DateTime<Utc>,
    /// `validFrom` + the community's `maxStatementAge`.
    pub valid_until: DateTime<Utc>,
    /// The `vetting/session` document's `id`.
    pub task_context: String,
}

/// Build and sign a statement. `signer` must be a key of `draft.issuer`.
///
/// # Errors
///
/// [`VettingError::WrongSigner`], [`VettingError::Malformed`] (wrong endorsement
/// type), [`VettingError::Expired`] (empty window) or [`VettingError::Sign`].
pub async fn sign_statement(draft: StatementDraft, signer: &Secret) -> Result<Value, VettingError> {
    if did_of(&signer.id) != draft.issuer {
        return Err(VettingError::WrongSigner {
            what: WHAT,
            role: "issuer",
        });
    }
    if draft.endorsement.endorsement_type != IDENTITY_VETTING_ENDORSEMENT_TYPE {
        return Err(VettingError::Malformed {
            what: WHAT,
            detail: format!(
                "endorsement type `{}` is not identity-vetting",
                draft.endorsement.endorsement_type
            ),
        });
    }
    draft
        .endorsement
        .check_shape()
        .map_err(|e| VettingError::Malformed {
            what: WHAT,
            detail: e.to_string(),
        })?;
    if draft.valid_until <= draft.valid_from {
        return Err(VettingError::Expired(WHAT));
    }
    let endorsement =
        serde_json::to_value(&draft.endorsement).map_err(|e| VettingError::Sign(e.to_string()))?;
    let mut credential = DTGCredential::new_vec(
        draft.issuer,
        draft.subject,
        draft.valid_from,
        Some(draft.valid_until),
        endorsement,
    )
    .with_id(draft.id);
    credential.credential_mut().task_context = Some(draft.task_context);
    credential
        .sign(signer, None)
        .await
        .map_err(|e| VettingError::Sign(e.to_string()))?;
    serde_json::to_value(&credential).map_err(|e| VettingError::Sign(e.to_string()))
}

/// The members of a statement verification reads. Not `deny_unknown_fields`:
/// a VC may carry members this profile does not use. The endorsement body,
/// which is what is being attested, is parsed strictly.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireStatement {
    #[serde(rename = "@context")]
    context: Vec<String>,
    #[serde(rename = "type")]
    types: Vec<String>,
    id: Option<String>,
    issuer: WireIssuer,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
    task_context: Option<String>,
    credential_subject: WireSubject,
    credential_status: Option<Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WireIssuer {
    Id(String),
    Object { id: String },
}

#[derive(Deserialize)]
struct WireSubject {
    id: String,
    endorsement: Value,
}

/// A statement whose proof, type, window and shape all check.
///
/// What this does **not** establish: that the issuer is an eligible vetter of
/// the community, or that the statement has not been withdrawn. Those are facts
/// only the community holds.
#[derive(Debug, Clone)]
pub struct VerifiedVettingStatement {
    id: String,
    issuer: String,
    subject: String,
    endorsement: IdentityVettingEndorsement,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    task_context: String,
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
    /// The applicant's join DID.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// The attestation.
    #[must_use]
    pub fn endorsement(&self) -> &IdentityVettingEndorsement {
        &self.endorsement
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
        if self.endorsement.community != c.community.as_str() {
            return Err(VettingError::Binding("community"));
        }
        if self.endorsement.identity_commitment != c.identity_commitment.as_str() {
            return Err(VettingError::Binding("identityCommitment"));
        }
        if self.endorsement.card_digest_multibase != card.digest_multibase() {
            return Err(VettingError::Binding("cardDigestMultibase"));
        }
        Ok(())
    }
}

/// Verify a statement as received — by the applicant on delivery, or by the
/// community inside a join presentation.
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
    let wire: WireStatement =
        serde_json::from_value(value.clone()).map_err(|e| malformed(e.to_string()))?;
    for required in [
        "VerifiableCredential",
        "DTGCredential",
        "EndorsementCredential",
    ] {
        if !wire.types.iter().any(|t| t == required) {
            return Err(malformed(format!("type does not include {required}")));
        }
    }
    if !wire.context.iter().any(|c| c == DTG_CONTEXT) {
        return Err(malformed("missing the DTG credentials context".into()));
    }
    let endorsement: IdentityVettingEndorsement =
        serde_json::from_value(wire.credential_subject.endorsement)
            .map_err(|e| malformed(format!("endorsement: {e}")))?;
    if endorsement.endorsement_type != IDENTITY_VETTING_ENDORSEMENT_TYPE {
        return Err(malformed("endorsement is not identity-vetting".into()));
    }
    endorsement
        .check_shape()
        .map_err(|e| malformed(format!("endorsement: {e}")))?;
    let id = wire
        .id
        .ok_or_else(|| malformed("no id — a statement must be revocable by name".into()))?;
    let task_context = wire
        .task_context
        .ok_or_else(|| malformed("no taskContext naming the session".into()))?;
    let valid_until = wire
        .valid_until
        .ok_or_else(|| malformed("no validUntil — statements are bounded evidence".into()))?;
    if wire.valid_from > now + CLOCK_SKEW || now > valid_until {
        return Err(VettingError::Expired(WHAT));
    }
    let issuer = match wire.issuer {
        WireIssuer::Id(id) | WireIssuer::Object { id } => id,
    };

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
        subject: wire.credential_subject.id,
        endorsement,
        valid_from: wire.valid_from,
        valid_until,
        task_context,
        has_status: wire.credential_status.is_some(),
        digest_multibase: digest(value)?,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::protocols::vetting::{VettingMethod, VettingRelationship};
    use crate::vetting::card::{
        CardExpectations, sign_card,
        tests::{CHALLENGE, COMMUNITY, draft},
        verify_card,
    };
    use crate::vetting::test_support::{did, secret};
    use chrono::Duration;
    use serde_json::json;

    pub(crate) fn endorsement(commitment: &str, card_digest: &str) -> IdentityVettingEndorsement {
        IdentityVettingEndorsement {
            endorsement_type: IDENTITY_VETTING_ENDORSEMENT_TYPE.into(),
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
        endorsement: IdentityVettingEndorsement,
    ) -> StatementDraft {
        let now = Utc::now();
        StatementDraft {
            id: "urn:uuid:statement-1".into(),
            issuer: did(vetter),
            subject: subject.into(),
            endorsement,
            valid_from: now,
            valid_until: now + Duration::days(120),
            task_context: "urn:uuid:session-1".into(),
        }
    }

    #[tokio::test]
    async fn a_statement_verifies_and_binds_to_its_card() {
        let (applicant, vetter) = (secret(1), secret(2));
        let card = verified_card(&applicant, &vetter).await;
        let e = endorsement(&card.card().identity_commitment, card.digest_multibase());
        let signed = sign_statement(statement_draft(&vetter, &did(&applicant), e), &vetter)
            .await
            .unwrap();
        assert_eq!(signed["type"][2], "EndorsementCredential");
        assert_eq!(signed["taskContext"], "urn:uuid:session-1");

        let verified = verify_statement(&signed, Utc::now(), &TrustTaskVmResolver::did_key_only())
            .await
            .unwrap();
        assert_eq!(verified.issuer(), did(&vetter));
        assert_eq!(verified.endorsement().method, VettingMethod::Video);
        verified.check_against_card(&card).unwrap();
    }

    #[tokio::test]
    async fn an_altered_endorsement_breaks_the_proof() {
        let (applicant, vetter) = (secret(1), secret(2));
        let e = endorsement("zCommitment", "zCard");
        let mut signed = sign_statement(statement_draft(&vetter, &did(&applicant), e), &vetter)
            .await
            .unwrap();
        signed["credentialSubject"]["endorsement"]["method"] = json!("inPerson");
        let err = verify_statement(&signed, Utc::now(), &TrustTaskVmResolver::did_key_only())
            .await
            .unwrap_err();
        assert!(matches!(err, VettingError::Proof { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn a_statement_over_a_different_card_is_caught() {
        let (applicant, vetter) = (secret(1), secret(2));
        let card = verified_card(&applicant, &vetter).await;
        let e = endorsement("zSomeOtherCommitment", card.digest_multibase());
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
        let e = endorsement("zC", "zD");
        let err = sign_statement(statement_draft(&vetter, &did(&applicant), e), &other)
            .await
            .unwrap_err();
        assert!(matches!(err, VettingError::WrongSigner { .. }));
    }

    #[tokio::test]
    async fn an_expired_statement_is_refused() {
        let (applicant, vetter) = (secret(1), secret(2));
        let e = endorsement("zC", "zD");
        let signed = sign_statement(statement_draft(&vetter, &did(&applicant), e), &vetter)
            .await
            .unwrap();
        let later = Utc::now() + Duration::days(200);
        let err = verify_statement(&signed, later, &TrustTaskVmResolver::did_key_only())
            .await
            .unwrap_err();
        assert!(matches!(err, VettingError::Expired(_)));
    }

    #[tokio::test]
    async fn an_unrelated_endorsement_is_not_a_vetting_statement() {
        let (applicant, vetter) = (secret(1), secret(2));
        let mut e = endorsement("zC", "zD");
        e.endorsement_type = "SkillEndorsement".into();
        assert!(matches!(
            sign_statement(statement_draft(&vetter, &did(&applicant), e), &vetter)
                .await
                .unwrap_err(),
            VettingError::Malformed { .. }
        ));
    }
}
