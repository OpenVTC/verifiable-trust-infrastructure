//! A vetter proving to an applicant that the community named them a vetter.
//!
//! A community names a vetter by issuing them a **vetter role credential**: a
//! DTG `EndorsementCredential` with endorsement
//! `{ type: "CommunityRole", role: "vetter", communityDid }`, signed by the
//! community and carrying a `credentialStatus`. The community counts
//! statements against its own record of the grant; an applicant, who holds no
//! such record, is shown the credential instead.
//!
//! The vetter answers an applicant's `vetting/request/0.1` with a Verifiable
//! Presentation of it, carried as `eligibilityVp` on the `#response` — before
//! any session exists (dtgwg-trust-tasks-tf `specs/vetting/request/0.1`,
//! rule 5). The presentation is bound to that request: `nonce` is the request
//! document's `id`, and `domain` is the request's `joinDid` — the applicant.
//! The vetter signs it with `authentication` ([`build_eligibility_vp`]). The
//! applicant checks that the presentation answers its own request, that its
//! holder is the vetter it asked, and that the community signed a role
//! credential for exactly that vetter, for exactly that community, in the role
//! the requirements name ([`verify_eligibility_vp`]).
//!
//! What this does **not** establish: that the grant has not been revoked.
//! Status-list resolution needs the network and a fetch profile, so it is left
//! to the caller, who gets the `credentialStatus` from
//! [`VerifiedEligibility::credential_status`]. A revoked grant also stops the
//! vetter's statements counting at the community, which is the check that
//! decides admission.

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use super::card::CLOCK_SKEW;
use super::{VettingError, did_of, verify_attached_proof};
use crate::protocols::vetting::{COMMUNITY_ROLE_ENDORSEMENT_TYPE, role_matches};
use crate::trust_task_proof::TrustTaskVmResolver;

const VP_WHAT: &str = "eligibility presentation";
const VEC_WHAT: &str = "vetter role credential";

/// The presentation's proof purpose: the holder authenticates to the applicant.
pub const ELIGIBILITY_PROOF_PURPOSE: &str = "authentication";

/// The role credential's proof purpose: the community asserts the grant.
const ROLE_CREDENTIAL_PROOF_PURPOSE: &str = "assertionMethod";

const VC_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";

/// `(communityDid, role)` of a community role credential, or `None` when
/// `credential` is not one.
///
/// Reads the shape only — nothing here is verified. Use it to pick candidates
/// out of a wallet before presenting them.
#[must_use]
pub fn community_role(credential: &Value) -> Option<(String, String)> {
    let is_endorsement = match credential.get("type")? {
        Value::String(t) => t == "EndorsementCredential",
        Value::Array(types) => types
            .iter()
            .any(|t| t.as_str() == Some("EndorsementCredential")),
        _ => false,
    };
    if !is_endorsement {
        return None;
    }
    let endorsement = credential.pointer("/credentialSubject/endorsement")?;
    if endorsement.get("type")?.as_str()? != COMMUNITY_ROLE_ENDORSEMENT_TYPE {
        return None;
    }
    Some((
        endorsement.get("communityDid")?.as_str()?.to_string(),
        endorsement.get("role")?.as_str()?.to_string(),
    ))
}

/// Present `credentials` to an applicant, bound to the request being answered.
///
/// `challenge` becomes the presentation's `nonce` and must be the `id` of the
/// applicant's `vetting/request` document; `domain` must be that request's
/// `joinDid`, the applicant. The holder is the DID of `holder`'s key.
///
/// # Errors
///
/// [`VettingError::WrongSigner`] if no DID can be read from `holder`'s id, or
/// [`VettingError::Sign`].
pub async fn build_eligibility_vp(
    holder: &Secret,
    credentials: Vec<Value>,
    challenge: &str,
    domain: &str,
) -> Result<Value, VettingError> {
    let holder_did = did_of(&holder.id);
    if holder_did.len() <= "did:".len() || !holder_did.starts_with("did:") {
        return Err(VettingError::WrongSigner {
            what: VP_WHAT,
            role: "holder",
        });
    }
    let mut vp = json!({
        "@context": [VC_CONTEXT_V2],
        "type": ["VerifiablePresentation"],
        "holder": holder_did,
        "verifiableCredential": credentials,
        "nonce": challenge,
        "domain": domain,
    });
    let proof = DataIntegrityProof::sign(
        &vp,
        holder,
        SignOptions::new()
            .with_proof_purpose(ELIGIBILITY_PROOF_PURPOSE)
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .map_err(|e| VettingError::Sign(e.to_string()))?;
    vp.as_object_mut()
        .expect("presentation is an object")
        .insert(
            "proof".into(),
            serde_json::to_value(proof).map_err(|e| VettingError::Sign(e.to_string()))?,
        );
    Ok(vp)
}

/// What the applicant expects an eligibility presentation to prove.
#[derive(Debug, Clone, Copy)]
pub struct EligibilityExpectations<'a> {
    /// The vetter the request was sent to.
    pub vetter: &'a str,
    /// The community the applicant is joining.
    pub community: &'a str,
    /// `eligibleVetters.role` from the community's requirements.
    pub role: &'a str,
    /// The `id` of the applicant's `vetting/request` document, which the
    /// presentation's `nonce` must carry.
    pub challenge: &'a str,
    /// The applicant's `joinDid` from that request, which the presentation's
    /// `domain` must carry.
    pub domain: &'a str,
    /// Verification time.
    pub now: DateTime<Utc>,
}

/// A role credential that makes the presenting vetter eligible.
///
/// Only [`verify_eligibility_vp`] builds one. Revocation is not checked: read
/// [`credential_status`](Self::credential_status) and resolve it.
#[derive(Debug, Clone)]
pub struct VerifiedEligibility {
    credential_id: Option<String>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    credential_status: Option<Value>,
}

impl VerifiedEligibility {
    /// The role credential's `id`.
    #[must_use]
    pub fn credential_id(&self) -> Option<&str> {
        self.credential_id.as_deref()
    }

    /// The role credential's `validFrom`.
    #[must_use]
    pub fn valid_from(&self) -> DateTime<Utc> {
        self.valid_from
    }

    /// The role credential's `validUntil`.
    #[must_use]
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    /// The role credential's `credentialStatus`, for the caller to resolve.
    #[must_use]
    pub fn credential_status(&self) -> Option<&Value> {
        self.credential_status.as_ref()
    }
}

#[derive(Deserialize)]
struct WirePresentation {
    #[serde(rename = "type")]
    types: OneOrMany,
    holder: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(rename = "verifiableCredential", default)]
    credentials: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn contains(&self, wanted: &str) -> bool {
        match self {
            Self::One(t) => t == wanted,
            Self::Many(ts) => ts.iter().any(|t| t == wanted),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireRoleCredential {
    id: Option<String>,
    issuer: WireIssuer,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
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
}

/// Verify a vetter's eligibility presentation.
///
/// Holds when the presentation is signed for `authentication` by its holder,
/// the holder is `expect.vetter`, `nonce` and `domain` are the request's `id`
/// and `joinDid`, and
/// it carries a role credential that `expect.community` signed for
/// `assertionMethod`, naming `expect.vetter`, for `expect.community`, in a role
/// that [`role_matches`] `expect.role`, and valid at `expect.now`.
///
/// # Errors
///
/// The first failed check: [`VettingError::Malformed`],
/// [`VettingError::WrongSigner`], [`VettingError::Binding`],
/// [`VettingError::Proof`], [`VettingError::Expired`], or
/// [`VettingError::NoRoleCredential`] when no credential names this vetter in
/// this role for this community. When several candidates fail, the first one's
/// error is returned.
pub async fn verify_eligibility_vp(
    vp: &Value,
    expect: &EligibilityExpectations<'_>,
    resolver: &TrustTaskVmResolver,
) -> Result<VerifiedEligibility, VettingError> {
    let wire: WirePresentation =
        serde_json::from_value(vp.clone()).map_err(|e| VettingError::Malformed {
            what: VP_WHAT,
            detail: e.to_string(),
        })?;
    if !wire.types.contains("VerifiablePresentation") {
        return Err(VettingError::Malformed {
            what: VP_WHAT,
            detail: "type does not include VerifiablePresentation".into(),
        });
    }
    if wire.holder != expect.vetter {
        return Err(VettingError::WrongSigner {
            what: VP_WHAT,
            role: "vetter",
        });
    }
    if wire.nonce.as_deref() != Some(expect.challenge) {
        return Err(VettingError::Binding("nonce"));
    }
    if wire.domain.as_deref() != Some(expect.domain) {
        return Err(VettingError::Binding("domain"));
    }
    let signer = verify_attached_proof(VP_WHAT, vp, ELIGIBILITY_PROOF_PURPOSE, resolver).await?;
    if signer != wire.holder {
        return Err(VettingError::WrongSigner {
            what: VP_WHAT,
            role: "holder",
        });
    }

    let mut first_error = None;
    for credential in &wire.credentials {
        let Some((community, role)) = community_role(credential) else {
            continue;
        };
        if community != expect.community || !role_matches(&role, expect.role) {
            continue;
        }
        match verify_role_credential(credential, expect, resolver).await {
            Ok(verified) => return Ok(verified),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    Err(first_error.unwrap_or(VettingError::NoRoleCredential))
}

async fn verify_role_credential(
    credential: &Value,
    expect: &EligibilityExpectations<'_>,
    resolver: &TrustTaskVmResolver,
) -> Result<VerifiedEligibility, VettingError> {
    let malformed = |detail: String| VettingError::Malformed {
        what: VEC_WHAT,
        detail,
    };
    let wire: WireRoleCredential =
        serde_json::from_value(credential.clone()).map_err(|e| malformed(e.to_string()))?;
    let issuer = match wire.issuer {
        WireIssuer::Id(id) | WireIssuer::Object { id } => id,
    };
    if issuer != expect.community {
        return Err(VettingError::WrongSigner {
            what: VEC_WHAT,
            role: "issuer",
        });
    }
    if wire.credential_subject.id != expect.vetter {
        return Err(VettingError::Binding("credentialSubject"));
    }
    let valid_until = wire
        .valid_until
        .ok_or_else(|| malformed("no validUntil — a role grant is bounded".into()))?;
    if wire.valid_from > expect.now + CLOCK_SKEW || expect.now > valid_until + CLOCK_SKEW {
        return Err(VettingError::Expired(VEC_WHAT));
    }
    let signer = verify_attached_proof(
        VEC_WHAT,
        credential,
        ROLE_CREDENTIAL_PROOF_PURPOSE,
        resolver,
    )
    .await?;
    if signer != issuer {
        return Err(VettingError::WrongSigner {
            what: VEC_WHAT,
            role: "issuer",
        });
    }
    Ok(VerifiedEligibility {
        credential_id: wire.id,
        valid_from: wire.valid_from,
        valid_until,
        credential_status: wire.credential_status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vetting::test_support::{did, secret};
    use chrono::Duration;
    use dtg_credentials::DTGCredential;

    /// The `id` of the `vetting/request` document being answered.
    const CHALLENGE: &str = "urn:uuid:3f1c9a52-8c1e-4f2b-9d7a-0b6e5c4d3a21";
    /// That request's `joinDid`: the applicant.
    const DOMAIN: &str = "did:key:z6MkApplicantJoinDid";

    async fn role_vec(
        community: &Secret,
        subject: &str,
        community_did: &str,
        role: &str,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Value {
        let mut credential = DTGCredential::new_vec(
            did(community),
            subject.to_string(),
            valid_from,
            Some(valid_until),
            json!({
                "type": COMMUNITY_ROLE_ENDORSEMENT_TYPE,
                "role": role,
                "communityDid": community_did,
            }),
        )
        .with_id("urn:uuid:vetter-grant".to_string());
        credential.sign(community, None).await.unwrap();
        serde_json::to_value(&credential).unwrap()
    }

    async fn live_vec(community: &Secret, vetter: &Secret, role: &str) -> Value {
        let now = Utc::now();
        let c = did(community);
        role_vec(
            community,
            &did(vetter),
            &c,
            role,
            now - Duration::days(1),
            now + Duration::days(364),
        )
        .await
    }

    async fn verify(
        vp: &Value,
        vetter: &str,
        community: &str,
        role: &str,
    ) -> Result<VerifiedEligibility, VettingError> {
        verify_eligibility_vp(
            vp,
            &EligibilityExpectations {
                vetter,
                community,
                role,
                challenge: CHALLENGE,
                domain: DOMAIN,
                now: Utc::now(),
            },
            &TrustTaskVmResolver::did_key_only(),
        )
        .await
    }

    #[tokio::test]
    async fn a_vetter_proves_the_community_named_them() {
        let (community, vetter) = (secret(0xC0), secret(0x11));
        let vec = live_vec(&community, &vetter, "vetter").await;
        assert_eq!(
            community_role(&vec),
            Some((did(&community), "vetter".to_string()))
        );
        let vp = build_eligibility_vp(&vetter, vec![vec], CHALLENGE, DOMAIN)
            .await
            .unwrap();
        assert_eq!(vp["holder"], did(&vetter));
        assert_eq!(vp["proof"]["proofPurpose"], ELIGIBILITY_PROOF_PURPOSE);

        let verified = verify(&vp, &did(&vetter), &did(&community), "vetter")
            .await
            .unwrap();
        assert_eq!(verified.credential_id(), Some("urn:uuid:vetter-grant"));
        assert!(verified.valid_until() > verified.valid_from());
        assert!(verified.credential_status().is_none());
        // The requirements may spell the role as the ACL does.
        verify(&vp, &did(&vetter), &did(&community), "custom:vetter")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_presentation_for_another_session_is_refused() {
        let (community, vetter) = (secret(0xC0), secret(0x11));
        let vec = live_vec(&community, &vetter, "vetter").await;

        let other_challenge = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
        let vp = build_eligibility_vp(&vetter, vec![vec.clone()], other_challenge, DOMAIN)
            .await
            .unwrap();
        assert!(matches!(
            verify(&vp, &did(&vetter), &did(&community), "vetter").await,
            Err(VettingError::Binding("nonce"))
        ));

        let vp = build_eligibility_vp(&vetter, vec![vec], CHALLENGE, "did:web:elsewhere")
            .await
            .unwrap();
        assert!(matches!(
            verify(&vp, &did(&vetter), &did(&community), "vetter").await,
            Err(VettingError::Binding("domain"))
        ));
    }

    #[tokio::test]
    async fn a_role_credential_from_another_community_does_not_count() {
        let (community, other, vetter) = (secret(0xC0), secret(0xC1), secret(0x11));
        let vec = live_vec(&other, &vetter, "vetter").await;
        let vp = build_eligibility_vp(&vetter, vec![vec], CHALLENGE, DOMAIN)
            .await
            .unwrap();
        assert!(matches!(
            verify(&vp, &did(&vetter), &did(&community), "vetter").await,
            Err(VettingError::NoRoleCredential)
        ));

        // A credential that *claims* this community but was signed by another.
        let now = Utc::now();
        let forged = role_vec(
            &other,
            &did(&vetter),
            &did(&community),
            "vetter",
            now - Duration::days(1),
            now + Duration::days(30),
        )
        .await;
        let vp = build_eligibility_vp(&vetter, vec![forged], CHALLENGE, DOMAIN)
            .await
            .unwrap();
        assert!(matches!(
            verify(&vp, &did(&vetter), &did(&community), "vetter").await,
            Err(VettingError::WrongSigner { role: "issuer", .. })
        ));
    }

    #[tokio::test]
    async fn a_different_role_does_not_count() {
        let (community, vetter) = (secret(0xC0), secret(0x11));
        let vec = live_vec(&community, &vetter, "moderator").await;
        let vp = build_eligibility_vp(&vetter, vec![vec], CHALLENGE, DOMAIN)
            .await
            .unwrap();
        assert!(matches!(
            verify(&vp, &did(&vetter), &did(&community), "vetter").await,
            Err(VettingError::NoRoleCredential)
        ));
    }

    #[tokio::test]
    async fn a_tampered_role_credential_is_refused() {
        let (community, vetter) = (secret(0xC0), secret(0x11));
        let mut vec = live_vec(&community, &vetter, "vetter").await;
        vec["validUntil"] = json!((Utc::now() + Duration::days(3650)).to_rfc3339());
        let vp = build_eligibility_vp(&vetter, vec![vec], CHALLENGE, DOMAIN)
            .await
            .unwrap();
        assert!(matches!(
            verify(&vp, &did(&vetter), &did(&community), "vetter").await,
            Err(VettingError::Proof { .. })
        ));
    }

    #[tokio::test]
    async fn an_expired_role_credential_is_refused() {
        let (community, vetter) = (secret(0xC0), secret(0x11));
        let now = Utc::now();
        let vec = role_vec(
            &community,
            &did(&vetter),
            &did(&community),
            "vetter",
            now - Duration::days(400),
            now - Duration::days(1),
        )
        .await;
        let vp = build_eligibility_vp(&vetter, vec![vec], CHALLENGE, DOMAIN)
            .await
            .unwrap();
        assert!(matches!(
            verify(&vp, &did(&vetter), &did(&community), "vetter").await,
            Err(VettingError::Expired(_))
        ));
    }

    #[tokio::test]
    async fn someone_else_presenting_a_vetters_credential_is_refused() {
        let (community, vetter, mallory) = (secret(0xC0), secret(0x11), secret(0x66));
        let vec = live_vec(&community, &vetter, "vetter").await;
        let vp = build_eligibility_vp(&mallory, vec![vec.clone()], CHALLENGE, DOMAIN)
            .await
            .unwrap();
        assert!(matches!(
            verify(&vp, &did(&vetter), &did(&community), "vetter").await,
            Err(VettingError::WrongSigner { role: "vetter", .. })
        ));

        // Mallory relabels the holder but cannot re-sign as the vetter.
        let mut relabelled = vp;
        relabelled["holder"] = json!(did(&vetter));
        assert!(
            verify(&relabelled, &did(&vetter), &did(&community), "vetter")
                .await
                .is_err()
        );

        // And a credential naming someone else, presented by its holder.
        let vp = build_eligibility_vp(&mallory, vec![vec], CHALLENGE, DOMAIN)
            .await
            .unwrap();
        assert!(matches!(
            verify(&vp, &did(&mallory), &did(&community), "vetter").await,
            Err(VettingError::Binding("credentialSubject"))
        ));
    }

    #[tokio::test]
    async fn a_holder_without_a_did_cannot_present() {
        let mut holder = secret(0x11);
        holder.id = "key-0".into();
        assert!(matches!(
            build_eligibility_vp(&holder, vec![], CHALLENGE, DOMAIN).await,
            Err(VettingError::WrongSigner { role: "holder", .. })
        ));
    }

    #[test]
    fn only_community_role_endorsements_are_role_credentials() {
        let vc = |endorsement: Value| {
            json!({
                "type": ["VerifiableCredential", "EndorsementCredential"],
                "credentialSubject": { "id": "did:key:z", "endorsement": endorsement }
            })
        };
        assert!(
            community_role(&vc(json!({
                "type": "CommunityRole", "role": "vetter", "communityDid": "did:web:c"
            })))
            .is_some()
        );
        assert!(community_role(&vc(json!({ "type": "IdentityVetting" }))).is_none());
        assert!(
            community_role(&vc(json!({ "type": "CommunityRole", "role": "vetter" }))).is_none()
        );
        assert!(community_role(&json!({ "type": ["VerifiableCredential"] })).is_none());
    }
}
