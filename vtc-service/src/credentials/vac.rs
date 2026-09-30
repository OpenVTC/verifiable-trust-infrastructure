//! Community role credential builder — spec §6.1 / M2.9.
//!
//! A community role ("admin", "moderator", …) is conferred by a DTG
//! **Verifiable Authority Credential** (VAC): the community, issuing as itself
//! (`issuerScope` `public`), grants the member the action `role:<role>` at its
//! own DID, and nobody may attenuate it onward (`maxAttenuation` `0`):
//!
//! ```json
//! {
//!   "type": ["VerifiableCredential", "DTGCredential", "AuthorityCredential"],
//!   "issuer": "did:webvh:vtc.example.com:abc",
//!   "issuerScope": "public",
//!   "credentialSubject": {
//!     "id": "<member DID>",
//!     "authority": {
//!       "scope": "did:webvh:vtc.example.com:abc",
//!       "actions": ["role:admin"],
//!       "maxAttenuation": 0
//!     }
//!   }
//! }
//! ```
//!
//! A role is not an endorsement: an endorsement is a statement about a member a
//! verifier weighs for itself, while a role is a decision by the party that
//! governs the community, which the DTG Credentials Core Specification carries
//! only in a VAC (vtc/join-requests/decide/0.1, vtc/vetting/vetters/grant/0.1).
//!
//! The credential is re-issued on every role change (spec §6.1)
//! and on every renewal (spec §6.3 step 2) so the external chain
//! stays consistent.

use affinidi_vc::VerifiableCredential;
use chrono::Duration;
use vti_common::error::AppError;

use crate::acl::VtcRole;

use super::LocalSigner;

/// The DTG catalog type a role credential carries in `type` (alongside
/// `VerifiableCredential` and `DTGCredential`).
pub const VAC_TYPE: &str = vta_sdk::protocols::members::AUTHORITY_CREDENTIAL_TYPE;

/// Default validity for a freshly-minted role VAC. Mirrors the
/// VMC default (30d). Operators tighten via configuration.
pub const DEFAULT_ROLE_VAC_VALIDITY: Duration = Duration::days(30);

/// Parameters for [`build_role_vac`].
#[derive(Debug, Clone)]
pub struct RoleVacParams {
    /// Subject DID — the member receiving the role grant.
    pub member_did: String,
    /// Optional top-level `id` URI for the VC (typically
    /// `urn:uuid:<server-allocated>`). Mirrors
    /// [`super::vmc::VmcParams::id`].
    pub id: Option<String>,
    /// The role being granted. Spec §5.3 names four standard
    /// roles + `Custom(String)`; all five surface as the action
    /// `role:<`[`VtcRole::to_string`]`>`.
    pub role: VtcRole,
    /// `validUntil = now + validity`. Same default as VMC. A VAC always
    /// carries `validUntil`.
    pub validity: Duration,
}

impl RoleVacParams {
    pub fn new(member_did: impl Into<String>, role: VtcRole) -> Self {
        Self {
            member_did: member_did.into(),
            id: None,
            role,
            validity: DEFAULT_ROLE_VAC_VALIDITY,
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

/// Build + sign a role VAC. `issuer = signer.issuer_did()`.
pub async fn build_role_vac(
    signer: &LocalSigner,
    params: RoleVacParams,
) -> Result<VerifiableCredential, AppError> {
    // Role VACs carry no credentialStatus today (`status_ref = None`): a role
    // is withdrawn by re-issuing on role change, and the ACL row is what
    // authorises locally.
    let doc = super::dtg::issue_role(
        signer,
        &params.member_did,
        &params.role,
        params.id.as_deref(),
        None,
        params.validity,
    )
    .await?;
    super::dtg::into_typed(doc, "role VAC")
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_vc::SubjectValue;
    use serde_json::{Map, Value as JsonValue};

    const TEST_VTC_DID: &str = "did:webvh:vtc.example.com:abc";
    const MEMBER_DID: &str = "did:key:zMember1";

    fn signer() -> LocalSigner {
        LocalSigner::from_ed25519_seed(TEST_VTC_DID.into(), &[0xBB; 32])
    }

    fn subject_map(vc: &VerifiableCredential) -> Map<String, JsonValue> {
        match &vc.credential_subject {
            SubjectValue::Single(m) => m.clone(),
            SubjectValue::Multiple(v) => v[0].clone(),
        }
    }

    /// Build + verify a VAC for each standard role. Spec §5.3's
    /// matrix covers Admin/Moderator/Issuer/Member; Custom is
    /// the open-ended fifth variant.
    #[tokio::test]
    async fn role_vac_round_trips_for_each_standard_role() {
        let signer = signer();
        let cases = [
            (VtcRole::Admin, "role:admin"),
            (VtcRole::Moderator, "role:moderator"),
            (VtcRole::Issuer, "role:issuer"),
            (VtcRole::Member, "role:member"),
            (VtcRole::Custom("editor".into()), "role:custom:editor"),
        ];
        for (role, expected_action) in cases {
            let vc = build_role_vac(&signer, RoleVacParams::new(MEMBER_DID, role.clone()))
                .await
                .unwrap_or_else(|e| panic!("build VAC for {role:?}: {e:?}"));

            assert!(vc.types.iter().any(|t| t == VAC_TYPE));

            let subj = subject_map(&vc);
            let authority = &subj["authority"];
            assert_eq!(authority["scope"], TEST_VTC_DID);
            assert_eq!(authority["actions"], serde_json::json!([expected_action]));
            assert_eq!(authority["maxAttenuation"], 0);
            assert_eq!(subj["id"], MEMBER_DID);

            signer
                .verify(&vc)
                .unwrap_or_else(|e| panic!("VAC proof must verify for {role:?}: {e:?}"));
        }
    }

    /// Tampering with the granted action invalidates the proof.
    #[tokio::test]
    async fn role_vac_tampered_action_invalidates_proof() {
        let signer = signer();
        let mut vc = build_role_vac(&signer, RoleVacParams::new(MEMBER_DID, VtcRole::Member))
            .await
            .unwrap();
        let mut as_value = serde_json::to_value(&vc).unwrap();
        // Promote member to admin without re-signing.
        as_value["credentialSubject"]["authority"]["actions"] = serde_json::json!(["role:admin"]);
        vc = serde_json::from_value(as_value).unwrap();

        let err = signer.verify(&vc).expect_err("tampered VAC must fail");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "expected Forbidden, got {err:?}"
        );
    }
}
