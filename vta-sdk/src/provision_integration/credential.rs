//! `VtaAuthorizationCredential` — the VC the VTA issues to a holder at
//! integration bootstrap.
//!
//! See `docs/02-vta/provision-integration.md` §"VC" for the full
//! shape. Summary:
//!
//! - `credentialSubject.adminOf.{vta, context, role}` — always present.
//! - `credentialSubject.operatorOf.{did, template}` — present when the
//!   template minted a DID for the holder.
//! - `validUntil` — short (~1h). No `credentialStatus`; revocation is
//!   ACL removal on the VTA.

use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, VerifyOptions};
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_vc::{CredentialBuilder, SubjectValue, VerifiableCredential};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ProvisionIntegrationError, VTA_AUTHORIZATION_CONTEXT_URL};

/// Default validity window for a freshly-issued
/// `VtaAuthorizationCredential`. Operators may override via
/// `VtaAuthorizationParams::validity`. Chosen to cover a typical
/// operator-carries-bundle latency with margin; tightly bounded so a
/// leaked bundle has a short blast-radius window.
pub const DEFAULT_VALIDITY: Duration = Duration::hours(1);

/// Top-level `credentialSubject` for the VTA authorization VC.
///
/// Matches the shape declared in `contexts/vta-authorization-v1.jsonld`
/// — wire JSON uses camelCase (`adminOf`, `operatorOf`) to line up with
/// the context's term mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VtaAuthorizationClaim {
    /// Subject DID — the holder's `client_did`. Serialized as `id` to
    /// match the VC Data Model 2.0 `credentialSubject.id` convention.
    pub id: String,

    /// ACL claim: "this holder is `role` within `context` at `vta`".
    pub admin_of: AdminOfClaim,

    /// Optional: "this holder operates the given agent DID, rendered
    /// from `template`". Present when the template minted an
    /// integration DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_of: Option<OperatorOfClaim>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AdminOfClaim {
    /// The VTA's DID. Same as the VC's `issuer` — duplicated here for
    /// claim clarity ("admin of *this* VTA").
    pub vta: String,
    pub context: String,
    /// Role string matching the workspace's existing ACL vocabulary
    /// (`"admin"`, `"super_admin"`, etc.).
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OperatorOfClaim {
    /// The agent DID the template rendered (e.g. the mediator's own
    /// `did:webvh`).
    pub did: String,
    /// Name of the template that produced this DID.
    pub template: String,
}

/// Parameters for issuing a VC.
pub struct VtaAuthorizationParams {
    pub subject: VtaAuthorizationClaim,
    pub validity: Duration,
}

impl VtaAuthorizationParams {
    pub fn new(subject: VtaAuthorizationClaim) -> Self {
        Self {
            subject,
            validity: DEFAULT_VALIDITY,
        }
    }

    pub fn with_validity(mut self, validity: Duration) -> Self {
        self.validity = validity;
        self
    }
}

/// Issue a `VtaAuthorizationCredential`, signing with the VTA's
/// `assertionMethod` key.
///
/// The resulting VC has:
/// - `@context`: VC-DM 2.0 + `vta-authorization-v1`.
/// - `type`: `["VerifiableCredential", "VtaAuthorizationCredential"]`.
/// - `issuer`: `vta_did` (the `issuer_secret`'s DID is derived from
///   `issuer_secret.id`, which must be of the form `<vta_did>#<vm-id>`).
/// - `validFrom` / `validUntil`: signed over.
/// - `proof`: Data Integrity, `eddsa-jcs-2022`, `proofPurpose =
///   "assertionMethod"`.
///
/// # Errors
///
/// - [`ProvisionIntegrationError::Parse`] if the issuer secret id is
///   not a DID URL with a `#` fragment.
/// - [`ProvisionIntegrationError::DataIntegrity`] if signing fails
///   (wrong key type, canonicalization error, etc.).
pub async fn issue_vta_authorization_credential(
    issuer_secret: &Secret,
    params: VtaAuthorizationParams,
) -> Result<VerifiableCredential, ProvisionIntegrationError> {
    // issuer_secret.id is `did:...#vm-id`; peel the DID off for `issuer`.
    let issuer_did = issuer_secret
        .id
        .split_once('#')
        .map(|(did, _)| did.to_string())
        .ok_or_else(|| {
            ProvisionIntegrationError::Parse(format!(
                "issuer secret id must be a DID URL with a '#' fragment, got '{}'",
                issuer_secret.id
            ))
        })?;

    let now = Utc::now();
    let valid_until = now + params.validity;

    let subject_value = subject_to_map(&params.subject)?;

    let mut vc = CredentialBuilder::v2()
        .context(VTA_AUTHORIZATION_CONTEXT_URL)
        .issuer_uri(issuer_did)
        .add_type("VtaAuthorizationCredential")
        .valid_from(rfc3339(now))
        .valid_until(rfc3339(valid_until))
        .subject(subject_value)
        .build()
        .map_err(|e| ProvisionIntegrationError::DataIntegrity(format!("VC build: {e}")))?;

    // Sign the VC document (absent the `proof` field).
    let proof = DataIntegrityProof::sign(&vc, issuer_secret, SignOptions::new())
        .await
        .map_err(|e| ProvisionIntegrationError::DataIntegrity(format!("sign VC: {e}")))?;

    vc.proof =
        Some(serde_json::to_value(&proof).map_err(|e| {
            ProvisionIntegrationError::DataIntegrity(format!("serialize proof: {e}"))
        })?);

    Ok(vc)
}

/// A `VtaAuthorizationCredential` whose proof, validity window, type, and
/// `credentialSubject` shape have all been verified.
///
/// Constructable only via [`verify_vta_authorization_credential`]; this
/// makes it impossible to forget the proof check or the claim-shape parse
/// step. Downstream code that takes a `VerifiedAuthorizationCredential`
/// is statically guaranteed to be looking at a verified VC.
#[derive(Debug, Clone)]
pub struct VerifiedAuthorizationCredential {
    vc: VerifiableCredential,
    claim: VtaAuthorizationClaim,
}

impl VerifiedAuthorizationCredential {
    /// The verified VC.
    pub fn vc(&self) -> &VerifiableCredential {
        &self.vc
    }

    /// The parsed `credentialSubject` claim.
    pub fn claim(&self) -> &VtaAuthorizationClaim {
        &self.claim
    }

    /// Decompose into the underlying VC + parsed claim — useful for
    /// callers that need to archive the VC and act on the claim.
    pub fn into_parts(self) -> (VerifiableCredential, VtaAuthorizationClaim) {
        (self.vc, self.claim)
    }
}

/// Verify a `VtaAuthorizationCredential` using the caller's copy of the
/// issuer's public key bytes.
///
/// Checks (in order):
/// 1. `type` contains `VtaAuthorizationCredential`.
/// 2. Proof verifies against the supplied issuer pubkey.
/// 3. `validFrom` <= now + skew.
/// 4. `validUntil` > now - skew.
/// 5. `credentialSubject` parses into [`VtaAuthorizationClaim`].
///
/// Returns a [`VerifiedAuthorizationCredential`] carrying both the VC
/// and the parsed claim. There is no separate "parse claim" step; the
/// typestate guarantees verification and parsing both happened.
pub fn verify_vta_authorization_credential(
    vc: &VerifiableCredential,
    issuer_public_key_bytes: &[u8],
    clock_skew: Duration,
) -> Result<VerifiedAuthorizationCredential, ProvisionIntegrationError> {
    if !vc.types.iter().any(|t| t == "VtaAuthorizationCredential") {
        return Err(ProvisionIntegrationError::InvalidClaim(
            "type array must include 'VtaAuthorizationCredential'".into(),
        ));
    }

    let proof_value = vc
        .proof
        .as_ref()
        .ok_or_else(|| ProvisionIntegrationError::BadProof("VC has no proof".into()))?;
    let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone())
        .map_err(|e| ProvisionIntegrationError::BadProof(format!("parse proof: {e}")))?;

    // Reconstruct the VC without its `proof` field for verification.
    let mut vc_without_proof = vc.clone();
    vc_without_proof.proof = None;

    proof
        .verify_with_public_key(
            &vc_without_proof,
            issuer_public_key_bytes,
            VerifyOptions::new(),
        )
        .map_err(|e| ProvisionIntegrationError::BadProof(format!("verify VC: {e}")))?;

    // Freshness check.
    check_validity_window(
        vc.valid_from.as_deref(),
        vc.valid_until.as_deref(),
        clock_skew,
    )?;

    let claim = parse_claim(vc)?;

    Ok(VerifiedAuthorizationCredential {
        vc: vc.clone(),
        claim,
    })
}

/// Parse the VC's `credentialSubject` into a typed
/// [`VtaAuthorizationClaim`]. Internal helper invoked eagerly by
/// [`verify_vta_authorization_credential`] — external consumers should
/// always go through the verified path.
pub(crate) fn parse_claim(
    vc: &VerifiableCredential,
) -> Result<VtaAuthorizationClaim, ProvisionIntegrationError> {
    // `credential_subject` is a `SubjectValue` (Single or Multiple). Our
    // VC carries exactly one subject by construction; reject anything
    // else at the type-shape layer.
    let map = match &vc.credential_subject {
        SubjectValue::Single(map) => map.clone(),
        SubjectValue::Multiple(vec) if vec.len() == 1 => vec[0].clone(),
        SubjectValue::Multiple(vec) => {
            return Err(ProvisionIntegrationError::InvalidClaim(format!(
                "expected single credentialSubject, got {}",
                vec.len()
            )));
        }
    };

    serde_json::from_value(serde_json::Value::Object(map))
        .map_err(|e| ProvisionIntegrationError::InvalidClaim(format!("parse subject: {e}")))
}

// Helpers ---------------------------------------------------------------

fn subject_to_map(
    claim: &VtaAuthorizationClaim,
) -> Result<serde_json::Map<String, Value>, ProvisionIntegrationError> {
    let v = serde_json::to_value(claim)
        .map_err(|e| ProvisionIntegrationError::Parse(format!("serialize claim: {e}")))?;
    match v {
        Value::Object(map) => Ok(map),
        other => Err(ProvisionIntegrationError::Parse(format!(
            "expected object for credentialSubject, got {other:?}"
        ))),
    }
}

fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn check_validity_window(
    valid_from: Option<&str>,
    valid_until: Option<&str>,
    skew: Duration,
) -> Result<(), ProvisionIntegrationError> {
    let now = Utc::now();

    if let Some(vf) = valid_from {
        let parsed = vf
            .parse::<DateTime<Utc>>()
            .map_err(|e| ProvisionIntegrationError::Parse(format!("validFrom: {e}")))?;
        if parsed > now + skew {
            return Err(ProvisionIntegrationError::Expired(format!(
                "not yet valid (validFrom {vf} is in the future)"
            )));
        }
    }

    if let Some(vu) = valid_until {
        let parsed = vu
            .parse::<DateTime<Utc>>()
            .map_err(|e| ProvisionIntegrationError::Parse(format!("validUntil: {e}")))?;
        if parsed + skew < now {
            return Err(ProvisionIntegrationError::Expired(format!(
                "expired at {vu}"
            )));
        }
    }

    Ok(())
}

/// Integer seconds since the Unix epoch, for places that prefer epoch
/// time over ISO 8601 strings.
pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_crypto::did_key as did_key_helpers;
    use chrono::Duration;

    /// Derive a `did:key` (Ed25519) + matching `Secret` from a fixed seed.
    /// Returns (did, secret with `id` set to `<did>#<multibase>`, raw pubkey).
    fn test_issuer(seed_byte: u8) -> (String, Secret, Vec<u8>) {
        let seed = [seed_byte; 32];
        let mut secret = Secret::generate_ed25519(None, Some(&seed));
        let pub_mb = secret.get_public_keymultibase().unwrap();
        let did = format!("did:key:{pub_mb}");
        secret.id = format!("{did}#{pub_mb}");
        let pk = secret.get_public_bytes().to_vec();
        (did, secret, pk)
    }

    fn sample_claim(subject_did: &str, vta_did: &str) -> VtaAuthorizationClaim {
        VtaAuthorizationClaim {
            id: subject_did.to_string(),
            admin_of: AdminOfClaim {
                vta: vta_did.to_string(),
                context: "prod-mediator".to_string(),
                role: "admin".to_string(),
            },
            operator_of: Some(OperatorOfClaim {
                did: "did:webvh:mediator.example.com".to_string(),
                template: "didcomm-mediator".to_string(),
            }),
        }
    }

    #[tokio::test]
    async fn issue_and_verify_round_trip() {
        let (vta_did, issuer, pk) = test_issuer(1);
        let (subject_did, _subject_secret, _) = test_issuer(2);
        let claim = sample_claim(&subject_did, &vta_did);

        let vc = issue_vta_authorization_credential(&issuer, VtaAuthorizationParams::new(claim))
            .await
            .unwrap();

        // Roundtrip through JSON — verify should still succeed on the
        // deserialized form, not just the in-memory struct.
        let json = serde_json::to_string(&vc).unwrap();
        let parsed: VerifiableCredential = serde_json::from_str(&json).unwrap();

        let verified = verify_vta_authorization_credential(&parsed, &pk, Duration::minutes(5))
            .expect("verify round-trip VC");

        let claim = verified.claim();
        assert_eq!(claim.id, subject_did);
        assert_eq!(claim.admin_of.vta, vta_did);
        assert_eq!(claim.admin_of.role, "admin");
        assert_eq!(
            claim.operator_of.as_ref().unwrap().did,
            "did:webvh:mediator.example.com"
        );
    }

    #[tokio::test]
    async fn tampered_claim_fails_verification() {
        let (vta_did, issuer, pk) = test_issuer(3);
        let (subject_did, _, _) = test_issuer(4);
        let claim = sample_claim(&subject_did, &vta_did);

        let mut vc =
            issue_vta_authorization_credential(&issuer, VtaAuthorizationParams::new(claim))
                .await
                .unwrap();

        // Attacker edits the role from "admin" to "super_admin".
        if let SubjectValue::Single(ref mut map) = vc.credential_subject
            && let Some(serde_json::Value::Object(admin_of)) = map.get_mut("adminOf")
        {
            admin_of.insert(
                "role".to_string(),
                serde_json::Value::String("super_admin".into()),
            );
        }

        let err = verify_vta_authorization_credential(&vc, &pk, Duration::minutes(5)).unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "expected BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn expired_vc_rejected() {
        let (vta_did, issuer, pk) = test_issuer(5);
        let (subject_did, _, _) = test_issuer(6);
        let claim = sample_claim(&subject_did, &vta_did);

        // Issue with a negative validity — validUntil is already in the past.
        let vc = issue_vta_authorization_credential(
            &issuer,
            VtaAuthorizationParams::new(claim).with_validity(Duration::hours(-2)),
        )
        .await
        .unwrap();

        let err = verify_vta_authorization_credential(&vc, &pk, Duration::minutes(5)).unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::Expired(_)),
            "expected Expired, got {err:?}"
        );
    }

    #[tokio::test]
    async fn wrong_issuer_key_rejected() {
        let (vta_did, issuer, _correct_pk) = test_issuer(7);
        let (_, _, wrong_pk) = test_issuer(8);
        let (subject_did, _, _) = test_issuer(9);
        let claim = sample_claim(&subject_did, &vta_did);

        let vc = issue_vta_authorization_credential(&issuer, VtaAuthorizationParams::new(claim))
            .await
            .unwrap();

        let err =
            verify_vta_authorization_credential(&vc, &wrong_pk, Duration::minutes(5)).unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "expected BadProof on wrong key, got {err:?}"
        );
    }

    #[tokio::test]
    async fn missing_type_rejected() {
        let (vta_did, issuer, pk) = test_issuer(10);
        let (subject_did, _, _) = test_issuer(11);
        let claim = sample_claim(&subject_did, &vta_did);

        let mut vc =
            issue_vta_authorization_credential(&issuer, VtaAuthorizationParams::new(claim))
                .await
                .unwrap();

        vc.types.retain(|t| t != "VtaAuthorizationCredential");

        let err = verify_vta_authorization_credential(&vc, &pk, Duration::minutes(5)).unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::InvalidClaim(_)),
            "expected InvalidClaim, got {err:?}"
        );
    }

    // Cross-reference check against affinidi-crypto's did:key helper —
    // confirms the Secret's derived pubkey matches what `did_key_helpers`
    // would decode from the same did:key string. Catches key-shape drift
    // between the two libraries.
    #[test]
    fn test_issuer_pubkey_matches_did_key_decode() {
        let (did, _, pk) = test_issuer(42);
        let decoded = did_key_helpers::did_key_to_ed25519_pub(&did).unwrap();
        assert_eq!(decoded.as_slice(), pk.as_slice());
    }
}
