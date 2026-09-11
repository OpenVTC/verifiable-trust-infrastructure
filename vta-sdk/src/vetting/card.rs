//! The Vetting Card: what an applicant shows one vetter.
//!
//! A profile of the r-card (a Verifiable Data Structure). The applicant's
//! client fills the claims from a persona disclosure, then signs the card with
//! the join DID's key — the same key the final join presentation is signed
//! with, which is what ties every card, every statement and the join together.
//!
//! The card's shape is the published one: [`VettingCard`], generated from
//! `vetting/session/0.1`, whose `#response` carries it.
//!
//! A card is **bound**: to one vetter (`audience`), one session (`challenge`,
//! `domain`) and a validity window of at most [`MAX_CARD_VALIDITY`]. It cannot
//! be replayed to another vetter or into another session.
//!
//! ## The identity commitment
//!
//! `identityCommitment` = `digestMultibase` over `{salt, claims}` where
//! `claims` are the card's identity claims (the community's `requiredClaims`)
//! sorted by type. The applicant uses **one salt per application**, so every
//! vetter sees the same commitment; the salt goes to vetters inside the card
//! and never to the community. Each statement repeats the commitment, so the
//! community can check that all its vetters verified the *same* claimed
//! identity without learning it — and the salt keeps a low-entropy name from
//! being recovered by enumeration (dtgwg-cred-spec #38).

use std::num::NonZeroU64;

use affinidi_data_integrity::{SignOptions, crypto_suites::CryptoSuite};
use affinidi_secrets_resolver::secrets::Secret;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};

use super::{VettingError, did_of, digest, verify_attached_proof};
use crate::protocols::vetting::session::v0_1::{
    DataIntegrityProof, Response as SessionResponse, VettingCard, VettingCardClaim,
};
use crate::protocols::vetting::{CheckShape, VETTING_CARD_TYPES, against_definition};
use crate::trust_task_proof::TrustTaskVmResolver;

/// Longest a card may be presentable for.
pub const MAX_CARD_VALIDITY: Duration = Duration::minutes(15);

/// Clock skew tolerated between applicant and vetter.
pub const CLOCK_SKEW: Duration = Duration::seconds(60);

/// The card's proof purpose: the publisher asserts what the card says.
pub const CARD_PROOF_PURPOSE: &str = "assertionMethod";

const WHAT: &str = "vetting card";

fn malformed(detail: impl ToString) -> VettingError {
    VettingError::Malformed {
        what: WHAT,
        detail: detail.to_string(),
    }
}

/// A fresh per-application commitment salt: 32 random bytes, base64url.
///
/// # Errors
///
/// [`VettingError::Random`] if the platform has no randomness source.
pub fn new_commitment_salt() -> Result<String, VettingError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| VettingError::Random(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Compute the identity commitment over `claims` for the claim types in
/// `identity_types`.
///
/// # Errors
///
/// [`VettingError::MissingClaim`] if an identity claim is absent;
/// [`VettingError::Digest`] if canonicalisation fails.
pub fn identity_commitment(
    salt: &str,
    claims: &[VettingCardClaim],
    identity_types: &[String],
) -> Result<String, VettingError> {
    let mut types: Vec<&String> = identity_types.iter().collect();
    types.sort();
    types.dedup();
    let mut selected = Vec::with_capacity(types.len());
    for claim_type in types {
        let claim = claims
            .iter()
            .find(|c| c.type_.as_str() == claim_type.as_str())
            .ok_or_else(|| VettingError::MissingClaim(claim_type.clone()))?;
        selected.push(json!({ "type": claim.type_, "value": claim.value }));
    }
    digest(&json!({ "salt": salt, "claims": selected }))
}

/// Everything needed to make a card.
#[derive(Debug, Clone)]
pub struct CardDraft {
    /// `urn:uuid:` and a UUID — fresh per card.
    pub id: String,
    /// The applicant's join DID.
    pub publisher: String,
    /// The vetter's DID.
    pub audience: String,
    /// The community DID.
    pub community: String,
    /// From the `vetting/session` payload.
    pub challenge: String,
    /// From the `vetting/session` payload.
    pub domain: String,
    /// Normally now.
    pub issued_at: DateTime<Utc>,
    /// At most [`MAX_CARD_VALIDITY`].
    pub validity: Duration,
    /// The disclosed claims.
    pub claims: Vec<VettingCardClaim>,
    /// The claim types the commitment covers — the session's `requiredClaims`.
    pub identity_types: Vec<String>,
    /// The application's salt ([`new_commitment_salt`]).
    pub salt: String,
}

/// Build and sign a card. `signer` must be a key of `draft.publisher`.
///
/// # Errors
///
/// [`VettingError::WrongSigner`] if `signer` is not the publisher's key,
/// [`VettingError::Expired`] if the validity exceeds [`MAX_CARD_VALIDITY`],
/// [`VettingError::MissingClaim`] if an identity claim is absent,
/// [`VettingError::Malformed`] if the card breaks its published shape, or
/// [`VettingError::Sign`].
pub async fn sign_card(draft: CardDraft, signer: &Secret) -> Result<Value, VettingError> {
    if did_of(&signer.id) != draft.publisher {
        return Err(VettingError::WrongSigner {
            what: WHAT,
            role: "publisher",
        });
    }
    if draft.validity <= Duration::zero() || draft.validity > MAX_CARD_VALIDITY {
        return Err(VettingError::Expired(WHAT));
    }
    let identity_commitment =
        identity_commitment(&draft.salt, &draft.claims, &draft.identity_types)?;

    // The published card requires its proof. It is built with a well-formed
    // stand-in, checked, and signed as it serialises without one; the signature
    // then takes the stand-in's place.
    let card = VettingCard::try_from(
        VettingCard::builder()
            .type_(VETTING_CARD_TYPES.to_vec())
            .id(draft.id)
            .publisher(draft.publisher.clone())
            .card_version(NonZeroU64::MIN)
            .audience(draft.audience)
            .community(draft.community)
            .challenge(draft.challenge)
            .domain(draft.domain)
            .issued_at(draft.issued_at)
            .expires_at(draft.issued_at + draft.validity)
            .claims(draft.claims)
            .identity_commitment(identity_commitment)
            .commitment_salt(draft.salt)
            .proof(proof_stand_in(&draft.publisher)?),
    )
    .map_err(malformed)?;
    card.check_shape().map_err(malformed)?;

    let mut value = serde_json::to_value(&card).map_err(|e| VettingError::Sign(e.to_string()))?;
    let fields = value.as_object_mut().expect("a card is an object");
    fields.remove("proof");
    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &value,
        signer,
        SignOptions::new()
            .with_proof_purpose(CARD_PROOF_PURPOSE)
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .map_err(|e| VettingError::Sign(e.to_string()))?;
    value.as_object_mut().expect("a card is an object").insert(
        "proof".into(),
        serde_json::to_value(proof).map_err(|e| VettingError::Sign(e.to_string()))?,
    );
    parse_card(&value)?;
    Ok(value)
}

/// A proof member of the published shape, for a card that is not signed yet.
fn proof_stand_in(publisher: &str) -> Result<DataIntegrityProof, VettingError> {
    DataIntegrityProof::try_from(
        DataIntegrityProof::builder()
            .type_("DataIntegrityProof")
            .cryptosuite("eddsa-jcs-2022")
            .verification_method(publisher)
            .proof_purpose(CARD_PROOF_PURPOSE)
            .proof_value("z1"),
    )
    .map_err(malformed)
}

/// Read a card as received: the generated type, and the card definition of the
/// schema `vetting/session/0.1#response` carries it under.
fn parse_card(value: &Value) -> Result<VettingCard, VettingError> {
    let card: VettingCard = serde_json::from_value(value.clone()).map_err(malformed)?;
    against_definition::<SessionResponse>("VettingCard", value).map_err(malformed)?;
    Ok(card)
}

/// What a vetter's client expects of the card it receives.
#[derive(Debug, Clone, Copy)]
pub struct CardExpectations<'a> {
    /// The vetter's own DID.
    pub audience: &'a str,
    /// The applicant's `joinDid` from the accepted request.
    pub publisher: &'a str,
    /// The community named in the request.
    pub community: &'a str,
    /// The challenge the vetter sent.
    pub challenge: &'a str,
    /// The domain the vetter sent.
    pub domain: &'a str,
    /// The session's `requiredClaims`.
    pub required_claims: &'a [String],
    /// The verifier's clock.
    pub now: DateTime<Utc>,
}

/// A card whose shape, signature, bindings, window and commitment all check.
#[derive(Debug, Clone)]
pub struct VerifiedVettingCard {
    card: VettingCard,
    digest_multibase: String,
}

impl VerifiedVettingCard {
    /// The card's contents.
    #[must_use]
    pub fn card(&self) -> &VettingCard {
        &self.card
    }

    /// `digestMultibase` of the card, for the statement's
    /// `cardDigestMultibase`.
    #[must_use]
    pub fn digest_multibase(&self) -> &str {
        &self.digest_multibase
    }

    /// The claim of `claim_type`, if the card carries one.
    #[must_use]
    pub fn claim(&self, claim_type: &str) -> Option<&VettingCardClaim> {
        self.card
            .claims
            .iter()
            .find(|c| c.type_.as_str() == claim_type)
    }
}

/// Verify a card received in a `vetting/session#response`.
///
/// Verification reads `value` — the JSON as received — for the proof and the
/// digest, never the parsed card re-serialised.
///
/// # Errors
///
/// The first failed check: [`VettingError::Malformed`], [`VettingError::Binding`],
/// [`VettingError::Expired`], [`VettingError::WrongSigner`],
/// [`VettingError::Proof`], [`VettingError::MissingClaim`] or
/// [`VettingError::Commitment`].
pub async fn verify_card(
    value: &Value,
    expect: &CardExpectations<'_>,
    resolver: &TrustTaskVmResolver,
) -> Result<VerifiedVettingCard, VettingError> {
    let card = parse_card(value)?;
    if card.audience.as_str() != expect.audience {
        return Err(VettingError::Binding("audience"));
    }
    if card.publisher.as_str() != expect.publisher {
        return Err(VettingError::Binding("publisher"));
    }
    if card.community.as_str() != expect.community {
        return Err(VettingError::Binding("community"));
    }
    if card.challenge.as_str() != expect.challenge {
        return Err(VettingError::Binding("challenge"));
    }
    if card.domain.as_str() != expect.domain {
        return Err(VettingError::Binding("domain"));
    }
    if card.expires_at <= card.issued_at
        || card.expires_at - card.issued_at > MAX_CARD_VALIDITY
        || card.issued_at > expect.now + CLOCK_SKEW
        || expect.now > card.expires_at + CLOCK_SKEW
    {
        return Err(VettingError::Expired(WHAT));
    }

    let signer = verify_attached_proof(WHAT, value, CARD_PROOF_PURPOSE, resolver).await?;
    if signer != card.publisher.as_str() {
        return Err(VettingError::WrongSigner {
            what: WHAT,
            role: "publisher",
        });
    }

    for required in expect.required_claims {
        if !card
            .claims
            .iter()
            .any(|c| c.type_.as_str() == required.as_str())
        {
            return Err(VettingError::MissingClaim(required.clone()));
        }
    }
    let recomputed =
        identity_commitment(&card.commitment_salt, &card.claims, expect.required_claims)?;
    if recomputed != card.identity_commitment.as_str() {
        return Err(VettingError::Commitment);
    }

    let digest_multibase = digest(value)?;
    Ok(VerifiedVettingCard {
        card,
        digest_multibase,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::vetting::test_support::{did, secret};

    pub(crate) const COMMUNITY: &str = "did:web:vtc.example";
    /// 43 base64url characters, the shape of 32 bytes.
    pub(crate) const CHALLENGE: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";
    const SALT: &str = "saltsaltsaltsaltsaltsaltsaltsaltsaltsaltsal";

    pub(crate) fn claim(claim_type: &str, value: Value) -> VettingCardClaim {
        VettingCardClaim::try_from(
            VettingCardClaim::builder()
                .type_(claim_type)
                .value(value)
                .provenance("selfAsserted"),
        )
        .unwrap()
    }

    pub(crate) fn claims() -> Vec<VettingCardClaim> {
        vec![
            claim("name.legal", json!("Alice Example")),
            claim("account.handle", json!("alice@example.org")),
        ]
    }

    pub(crate) fn draft(applicant: &Secret, vetter: &Secret, now: DateTime<Utc>) -> CardDraft {
        CardDraft {
            id: "urn:uuid:d2c4e6f8-1a3b-4c5d-8e7f-9a0b1c2d3e01".into(),
            publisher: did(applicant),
            audience: did(vetter),
            community: COMMUNITY.into(),
            challenge: CHALLENGE.into(),
            domain: COMMUNITY.into(),
            issued_at: now,
            validity: Duration::minutes(15),
            claims: claims(),
            identity_types: vec!["name.legal".into()],
            salt: SALT.into(),
        }
    }

    fn expectations<'a>(
        applicant: &'a str,
        vetter: &'a str,
        required: &'a [String],
        now: DateTime<Utc>,
    ) -> CardExpectations<'a> {
        CardExpectations {
            audience: vetter,
            publisher: applicant,
            community: COMMUNITY,
            challenge: CHALLENGE,
            domain: COMMUNITY,
            required_claims: required,
            now,
        }
    }

    #[tokio::test]
    async fn a_signed_card_verifies_for_its_vetter() {
        let (applicant, vetter) = (secret(1), secret(2));
        let now = Utc::now();
        let signed = sign_card(draft(&applicant, &vetter, now), &applicant)
            .await
            .unwrap();
        let required = vec!["name.legal".to_string()];
        let (a, v) = (did(&applicant), did(&vetter));
        let verified = verify_card(
            &signed,
            &expectations(&a, &v, &required, now),
            &TrustTaskVmResolver::did_key_only(),
        )
        .await
        .unwrap();
        assert_eq!(verified.claim("name.legal").unwrap().value, "Alice Example");
        assert!(verified.digest_multibase().starts_with('z'));
        assert_eq!(
            verified.card().proof.proof_purpose,
            CARD_PROOF_PURPOSE,
            "the stand-in proof is replaced by the signature"
        );
    }

    #[tokio::test]
    async fn another_vetter_cannot_use_the_card() {
        let (applicant, vetter, other) = (secret(1), secret(2), secret(3));
        let now = Utc::now();
        let signed = sign_card(draft(&applicant, &vetter, now), &applicant)
            .await
            .unwrap();
        let required = vec!["name.legal".to_string()];
        let (a, o) = (did(&applicant), did(&other));
        let err = verify_card(
            &signed,
            &expectations(&a, &o, &required, now),
            &TrustTaskVmResolver::did_key_only(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VettingError::Binding("audience")));
    }

    #[tokio::test]
    async fn an_altered_claim_breaks_the_proof() {
        let (applicant, vetter) = (secret(1), secret(2));
        let now = Utc::now();
        let mut signed = sign_card(draft(&applicant, &vetter, now), &applicant)
            .await
            .unwrap();
        signed["claims"][0]["value"] = json!("Mallory Example");
        let required = vec!["name.legal".to_string()];
        let (a, v) = (did(&applicant), did(&vetter));
        let err = verify_card(
            &signed,
            &expectations(&a, &v, &required, now),
            &TrustTaskVmResolver::did_key_only(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VettingError::Proof { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn a_stale_card_is_refused() {
        let (applicant, vetter) = (secret(1), secret(2));
        let then = Utc::now() - Duration::hours(1);
        let signed = sign_card(draft(&applicant, &vetter, then), &applicant)
            .await
            .unwrap();
        let required = vec!["name.legal".to_string()];
        let (a, v) = (did(&applicant), did(&vetter));
        let err = verify_card(
            &signed,
            &expectations(&a, &v, &required, Utc::now()),
            &TrustTaskVmResolver::did_key_only(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VettingError::Expired(_)));
    }

    #[tokio::test]
    async fn only_the_publisher_may_sign() {
        let (applicant, vetter) = (secret(1), secret(2));
        let err = sign_card(draft(&applicant, &vetter, Utc::now()), &vetter)
            .await
            .unwrap_err();
        assert!(matches!(err, VettingError::WrongSigner { .. }));
    }

    #[tokio::test]
    async fn validity_is_capped() {
        let (applicant, vetter) = (secret(1), secret(2));
        let mut d = draft(&applicant, &vetter, Utc::now());
        d.validity = Duration::hours(2);
        assert!(matches!(
            sign_card(d, &applicant).await.unwrap_err(),
            VettingError::Expired(_)
        ));
    }

    #[tokio::test]
    async fn a_card_id_is_a_urn_uuid() {
        let (applicant, vetter) = (secret(1), secret(2));
        let mut d = draft(&applicant, &vetter, Utc::now());
        d.id = "urn:uuid:card-1".into();
        assert!(matches!(
            sign_card(d, &applicant).await.unwrap_err(),
            VettingError::Malformed { .. }
        ));
    }

    #[test]
    fn commitment_is_stable_across_vetters_and_blind_to_optional_claims() {
        let identity = vec!["name.legal".to_string()];
        let a = identity_commitment("salt", &claims(), &identity).unwrap();
        let only_name = &claims()[..1];
        assert_eq!(
            a,
            identity_commitment("salt", only_name, &identity).unwrap()
        );
        assert_ne!(
            a,
            identity_commitment("other-salt", &claims(), &identity).unwrap(),
            "the salt is what stops enumeration"
        );
        assert!(matches!(
            identity_commitment("salt", &claims(), &["person.birthDate".to_string()]),
            Err(VettingError::MissingClaim(_))
        ));
    }

    #[tokio::test]
    async fn a_portrait_is_never_signed_onto_a_card() {
        let (applicant, vetter) = (secret(1), secret(2));
        let mut d = draft(&applicant, &vetter, Utc::now());
        d.claims.push(claim(
            crate::protocols::vetting::PORTRAIT_CLAIM_TYPE,
            json!("data:image/png;base64,AAAA"),
        ));
        assert!(matches!(
            sign_card(d, &applicant).await.unwrap_err(),
            VettingError::Malformed { .. }
        ));
    }

    #[tokio::test]
    async fn a_card_must_carry_exactly_the_card_types() {
        let (applicant, vetter) = (secret(1), secret(2));
        let now = Utc::now();
        let mut signed = sign_card(draft(&applicant, &vetter, now), &applicant)
            .await
            .unwrap();
        signed["type"] = json!(["VettingCard"]);
        let required = vec!["name.legal".to_string()];
        let (a, v) = (did(&applicant), did(&vetter));
        let err = verify_card(
            &signed,
            &expectations(&a, &v, &required, now),
            &TrustTaskVmResolver::did_key_only(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VettingError::Malformed { .. }), "{err:?}");
    }

    #[test]
    fn salts_are_32_random_bytes() {
        let a = new_commitment_salt().unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&a).unwrap().len(), 32);
        assert_ne!(a, new_commitment_salt().unwrap());
    }
}
