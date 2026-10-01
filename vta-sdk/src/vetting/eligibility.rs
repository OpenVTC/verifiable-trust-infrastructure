//! A vetter proving to an applicant that the community named them a vetter.
//!
//! A community names a vetter by issuing them a **vetter role credential**: a
//! DTG Verifiable Authority Credential (`AuthorityCredential`) issued by the
//! community with `issuerScope` `public`, whose `credentialSubject.authority` is
//! `{ scope: <community DID>, actions: ["role:vetter"], maxAttenuation: 0 }`,
//! carrying a `credentialStatus` (vtc/vetting/vetters/grant/0.1). The community counts
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
use dtg_credentials::{DTGCredentialType, IssuerScope};
use serde::Deserialize;
use serde_json::{Value, json};

use super::card::CLOCK_SKEW;
use super::{VettingError, did_of, verify_attached_proof};
use crate::protocols::vetting::{role_matches, role_of_action};
use crate::trust_task_proof::TrustTaskVmResolver;

const VP_WHAT: &str = "eligibility presentation";
const ROLE_WHAT: &str = "vetter role credential";

/// The presentation's proof purpose: the holder authenticates to the applicant.
pub const ELIGIBILITY_PROOF_PURPOSE: &str = "authentication";

/// The role credential's proof purpose: the community asserts the grant.
const ROLE_CREDENTIAL_PROOF_PURPOSE: &str = "assertionMethod";

const VC_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";

/// `(community DID, roles)` of a community role credential, or `None` when
/// `credential` is not one.
///
/// A community role credential is a DTG VAC — parsed strictly, as
/// [`verify_eligibility_vp`] parses it: the v1 context, exactly one subtype
/// (`AuthorityCredential`), a declared `issuerScope` — whose `issuer` is its own
/// `authority.scope` (the community conferring authority in itself), carrying
/// no `authority.parent`, with at least one `role:<name>` action. The roles are
/// the `<name>`s, in action order.
///
/// Checks the shape only — no proof, window or scope declaration is verified.
/// Use it to pick candidates out of a wallet before presenting them.
#[must_use]
pub fn community_roles(credential: &Value) -> Option<(String, Vec<String>)> {
    // Without its proof: a two-key community's grant carries a proof set
    // (VTI-57), and this checks the shape only.
    let vac = super::dtg_shape(credential).ok()?;
    if vac.type_() != DTGCredentialType::Authority {
        return None;
    }
    let authority = vac.credential().authority()?;
    if authority.scope != vac.issuer() || authority.parent.is_some() {
        return None;
    }
    let roles: Vec<String> = authority
        .actions
        .iter()
        .filter_map(|a| role_of_action(a))
        .map(str::to_string)
        .collect();
    if roles.is_empty() {
        return None;
    }
    Some((authority.scope.clone(), roles))
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

/// Verify a vetter's eligibility presentation.
///
/// Holds when the presentation is signed for `authentication` by its holder,
/// the holder is `expect.vetter`, `nonce` and `domain` are the request's `id`
/// and `joinDid`, and
/// it carries a role credential — a DTG VAC under the v1 context, declaring
/// `issuerScope` `public`, with no `authority.parent` — that `expect.community`
/// signed for `assertionMethod`, naming `expect.vetter`, whose `authority.scope`
/// is `expect.community` and whose `authority.actions` include `role:<role>`
/// for a role that [`role_matches`] `expect.role`, valid at `expect.now`.
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
        let Some((community, roles)) = community_roles(credential) else {
            continue;
        };
        if community != expect.community || !roles.iter().any(|r| role_matches(r, expect.role)) {
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
        what: ROLE_WHAT,
        detail,
    };
    // A strict DTG parse: the v1 context, exactly one concrete subtype, a
    // declared `issuerScope`.
    // The proof (one, or a set) is verified below over the credential as
    // received; the shape parse sets it aside (VTI-57).
    let vac = super::dtg_shape(credential).map_err(|e| malformed(e.to_string()))?;
    if vac.type_() != DTGCredentialType::Authority {
        return Err(malformed("not an AuthorityCredential".into()));
    }
    let issuer = vac.issuer().to_string();
    if issuer != expect.community {
        return Err(VettingError::WrongSigner {
            what: ROLE_WHAT,
            role: "issuer",
        });
    }
    // vetting/request/0.1: the community issued it directly — declaring
    // `public`, the only scope a community can truthfully declare — rather
    // than someone attenuating theirs.
    if vac.issuer_scope() != IssuerScope::Public {
        return Err(malformed(
            "a community role credential declares issuerScope public".into(),
        ));
    }
    let authority = vac
        .credential()
        .authority()
        .ok_or_else(|| malformed("no credentialSubject.authority".into()))?;
    if authority.parent.is_some() {
        return Err(malformed(
            "an attenuated VAC is not a community role grant".into(),
        ));
    }
    if authority.scope != expect.community {
        return Err(VettingError::Binding("authority.scope"));
    }
    if vac.subject() != expect.vetter {
        return Err(VettingError::Binding("credentialSubject"));
    }
    let valid_until = vac
        .valid_until()
        .ok_or_else(|| malformed("no validUntil — a role grant is bounded".into()))?;
    if vac.valid_from() > expect.now + CLOCK_SKEW || expect.now > valid_until + CLOCK_SKEW {
        return Err(VettingError::Expired(ROLE_WHAT));
    }
    let signer = verify_attached_proof(
        ROLE_WHAT,
        credential,
        ROLE_CREDENTIAL_PROOF_PURPOSE,
        resolver,
    )
    .await?;
    if signer != issuer {
        return Err(VettingError::WrongSigner {
            what: ROLE_WHAT,
            role: "issuer",
        });
    }
    Ok(VerifiedEligibility {
        credential_id: vac.id().map(str::to_string),
        valid_from: vac.valid_from(),
        valid_until,
        credential_status: vac.credential().credential_status.clone(),
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

    /// A role VAC signed by `community`, conferring `role:<role>` at
    /// `community_did` — which a forger may set to someone else's DID.
    async fn role_vac(
        community: &Secret,
        subject: &str,
        community_did: &str,
        role: &str,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Value {
        let mut credential = DTGCredential::new_vac(
            did(community),
            IssuerScope::Public,
            subject.to_string(),
            community_did.to_string(),
            vec![crate::protocols::vetting::role_action(role)],
            valid_from,
            valid_until,
        )
        .unwrap()
        .with_max_attenuation(0)
        .unwrap()
        .with_id("urn:uuid:vetter-grant".to_string());
        credential.sign(community, None).await.unwrap();
        serde_json::to_value(&credential).unwrap()
    }

    async fn live_vac(community: &Secret, vetter: &Secret, role: &str) -> Value {
        let now = Utc::now();
        let c = did(community);
        role_vac(
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

    /// `vac` re-signed so its `proof` is a set of two, as a community holding
    /// two signing keys writes it.
    async fn with_proof_set(community: &Secret, mut vac: Value) -> Value {
        let first = vac["proof"].clone();
        let mut proofless = vac.clone();
        proofless.as_object_mut().unwrap().remove("proof");
        let second = affinidi_data_integrity::DataIntegrityProof::sign(
            &proofless,
            community,
            affinidi_data_integrity::SignOptions::new().with_proof_purpose("assertionMethod"),
        )
        .await
        .unwrap();
        vac["proof"] = serde_json::json!([first, serde_json::to_value(second).unwrap()]);
        vac
    }

    /// VTI-57: a vetter grant from a two-key community carries a proof set.
    /// `community_roles` used to fail to parse it and answer `None`, so openvtc
    /// filed the grant as a plain role and never seated the vetter.
    #[tokio::test]
    async fn vti_57_a_grant_carrying_a_proof_set_names_its_roles() {
        let (community, vetter) = (secret(0xC7), secret(0x17));
        let vac = with_proof_set(&community, live_vac(&community, &vetter, "vetter").await).await;
        assert!(vac["proof"].is_array());
        assert_eq!(
            community_roles(&vac),
            Some((did(&community), vec!["vetter".to_string()]))
        );
    }

    /// VTI-57, presentation side: the same grant presented to an applicant
    /// verifies; the strict shape parse refused it as malformed.
    #[tokio::test]
    async fn vti_57_an_eligibility_vp_over_a_proof_set_grant_verifies() {
        let (community, vetter) = (secret(0xC8), secret(0x18));
        let vac = with_proof_set(&community, live_vac(&community, &vetter, "vetter").await).await;
        let vp = build_eligibility_vp(&vetter, vec![vac], CHALLENGE, DOMAIN)
            .await
            .unwrap();
        verify(&vp, &did(&vetter), &did(&community), "vetter")
            .await
            .expect("a proof-set grant verifies");
    }

    /// Setting the proof aside for the shape parse loosens nothing: a set with
    /// one tampered proof is still refused, by the proof check.
    #[tokio::test]
    async fn vti_57_a_tampered_proof_in_the_set_is_still_refused() {
        let (community, vetter) = (secret(0xC9), secret(0x19));
        let mut vac =
            with_proof_set(&community, live_vac(&community, &vetter, "vetter").await).await;
        vac["proof"][1]["proofValue"] = vac["proof"][0]["proofValue"].clone();
        vac["proof"][1]["created"] = serde_json::json!("2020-01-01T00:00:00Z");
        let vp = build_eligibility_vp(&vetter, vec![vac], CHALLENGE, DOMAIN)
            .await
            .unwrap();
        assert!(
            verify(&vp, &did(&vetter), &did(&community), "vetter")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_vetter_proves_the_community_named_them() {
        let (community, vetter) = (secret(0xC0), secret(0x11));
        let vac = live_vac(&community, &vetter, "vetter").await;
        assert_eq!(
            community_roles(&vac),
            Some((did(&community), vec!["vetter".to_string()]))
        );
        assert_eq!(vac["credentialSubject"]["authority"]["maxAttenuation"], 0);
        let vp = build_eligibility_vp(&vetter, vec![vac], CHALLENGE, DOMAIN)
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
        let vac = live_vac(&community, &vetter, "vetter").await;

        let other_challenge = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
        let vp = build_eligibility_vp(&vetter, vec![vac.clone()], other_challenge, DOMAIN)
            .await
            .unwrap();
        assert!(matches!(
            verify(&vp, &did(&vetter), &did(&community), "vetter").await,
            Err(VettingError::Binding("nonce"))
        ));

        let vp = build_eligibility_vp(&vetter, vec![vac], CHALLENGE, "did:web:elsewhere")
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
        let vac = live_vac(&other, &vetter, "vetter").await;
        let vp = build_eligibility_vp(&vetter, vec![vac], CHALLENGE, DOMAIN)
            .await
            .unwrap();
        assert!(matches!(
            verify(&vp, &did(&vetter), &did(&community), "vetter").await,
            Err(VettingError::NoRoleCredential)
        ));

        // A credential that *claims* this community's scope but was signed by
        // another is not a community role credential at all.
        let now = Utc::now();
        let forged = role_vac(
            &other,
            &did(&vetter),
            &did(&community),
            "vetter",
            now - Duration::days(1),
            now + Duration::days(30),
        )
        .await;
        assert_eq!(community_roles(&forged), None);
        let vp = build_eligibility_vp(&vetter, vec![forged.clone()], CHALLENGE, DOMAIN)
            .await
            .unwrap();
        assert!(matches!(
            verify(&vp, &did(&vetter), &did(&community), "vetter").await,
            Err(VettingError::NoRoleCredential)
        ));

        // Relabelling the issuer to match breaks the forger's own signature.
        let mut relabelled = forged;
        relabelled["issuer"] = json!(did(&community));
        let vp = build_eligibility_vp(&vetter, vec![relabelled], CHALLENGE, DOMAIN)
            .await
            .unwrap();
        assert!(matches!(
            verify(&vp, &did(&vetter), &did(&community), "vetter").await,
            Err(VettingError::Proof { .. })
        ));
    }

    #[tokio::test]
    async fn a_different_role_does_not_count() {
        let (community, vetter) = (secret(0xC0), secret(0x11));
        let vac = live_vac(&community, &vetter, "moderator").await;
        let vp = build_eligibility_vp(&vetter, vec![vac], CHALLENGE, DOMAIN)
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
        let mut vac = live_vac(&community, &vetter, "vetter").await;
        vac["validUntil"] = json!((Utc::now() + Duration::days(3650)).to_rfc3339());
        let vp = build_eligibility_vp(&vetter, vec![vac], CHALLENGE, DOMAIN)
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
        let vac = role_vac(
            &community,
            &did(&vetter),
            &did(&community),
            "vetter",
            now - Duration::days(400),
            now - Duration::days(1),
        )
        .await;
        let vp = build_eligibility_vp(&vetter, vec![vac], CHALLENGE, DOMAIN)
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
        let vac = live_vac(&community, &vetter, "vetter").await;
        let vp = build_eligibility_vp(&mallory, vec![vac.clone()], CHALLENGE, DOMAIN)
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
        let vp = build_eligibility_vp(&mallory, vec![vac], CHALLENGE, DOMAIN)
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

    #[tokio::test]
    async fn a_role_credential_declaring_a_narrower_scope_is_refused() {
        let (community, vetter) = (secret(0xC0), secret(0x11));
        let now = Utc::now();
        let mut vac = DTGCredential::new_vac(
            did(&community),
            IssuerScope::Directed,
            did(&vetter),
            did(&community),
            vec!["role:vetter".into()],
            now - Duration::days(1),
            now + Duration::days(30),
        )
        .unwrap();
        vac.sign(&community, None).await.unwrap();
        let vp = build_eligibility_vp(
            &vetter,
            vec![serde_json::to_value(&vac).unwrap()],
            CHALLENGE,
            DOMAIN,
        )
        .await
        .unwrap();
        assert!(matches!(
            verify(&vp, &did(&vetter), &did(&community), "vetter").await,
            Err(VettingError::Malformed { .. })
        ));
    }

    #[test]
    fn only_community_issued_role_vacs_are_role_credentials() {
        let now = Utc::now();
        let vac = |issuer: &str, scope: &str, actions: &[&str]| {
            let vac = DTGCredential::new_vac(
                issuer.into(),
                IssuerScope::Public,
                "did:key:z".into(),
                scope.into(),
                actions.iter().map(|a| a.to_string()).collect(),
                now,
                now + Duration::days(1),
            )
            .unwrap();
            crate::vetting::tests_support_json(&vac)
        };
        assert_eq!(
            community_roles(&vac(
                "did:web:c",
                "did:web:c",
                &["role:vetter", "read", "role:mod"]
            )),
            Some(("did:web:c".into(), vec!["vetter".into(), "mod".into()]))
        );
        // Not a role action.
        assert!(community_roles(&vac("did:web:c", "did:web:c", &["vetter"])).is_none());
        // Scope other than the issuer's own.
        assert!(community_roles(&vac("did:web:c", "did:web:d", &["role:vetter"])).is_none());
        // Not a DTG v1 credential: the parse is strict.
        let mut legacy = vac("did:web:c", "did:web:c", &["role:vetter"]);
        legacy["@context"] = json!(["https://www.w3.org/ns/credentials/v2"]);
        assert!(community_roles(&legacy).is_none());
        // The retired role-endorsement shape.
        assert!(
            community_roles(&json!({
                "type": ["VerifiableCredential", "EndorsementCredential"],
                "issuer": "did:web:c",
                "credentialSubject": { "id": "did:key:z", "endorsement": {
                    "type": "CommunityRole", "role": "vetter", "communityDid": "did:web:c"
                } }
            }))
            .is_none()
        );
    }
}
