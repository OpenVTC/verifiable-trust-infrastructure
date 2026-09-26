//! The single DID verification-method → public-key resolver for the VTC, plus
//! the issuer-binding check every Data-Integrity / SD-JWT verify shares.
//!
//! Three call sites used to hand-roll "resolve a DID doc → find the VM → pull
//! the key → verify": the credential-exchange verifier, cross-community
//! recognition, and VRC relationships. The exchange path already did it the
//! right way — it delegates resolution to the `affinidi-data-integrity`
//! library's [`DataIntegrityProof::verify`](affinidi_data_integrity::DataIntegrityProof::verify),
//! handing it a [`VerificationMethodResolver`](affinidi_data_integrity::VerificationMethodResolver).
//! This module hoists that one resolver so recognition + relationships verify
//! through the same library path instead of re-implementing key resolution.
//!
//! Resolution delegates to [`TrustTaskVmResolver`], the workspace's one
//! verification-method resolver: `did:key` and `did:peer` resolve locally (no
//! I/O); other methods (`did:webvh` / `did:web`) resolve through the DID cache
//! (which must then be configured).
//!
//! **Every resolution names a purpose (VTI-KEY-022).** A key is returned only
//! when the DID that names it lists it under the verification relationship the
//! proof's `proofPurpose` names, and the method's controller is that DID. This
//! resolver deliberately does not implement the upstream
//! `VerificationMethodResolver`, which carries no purpose: a Data Integrity
//! proof is verified through [`super::proof_set::verify_one`], which binds the
//! resolver to that proof's own purpose.

use affinidi_data_integrity::{DataIntegrityError, ResolvedKey};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::secrets::KeyType;
use ed25519_dalek::VerifyingKey;
use vti_common::auth::{ProofPurpose, PurposeVmResolver, TrustTaskVmResolver};
use vti_common::error::AppError;

/// A [`PurposeVmResolver`] over the VTC's optional [`DIDCacheClient`].
///
/// Owns its [`DIDCacheClient`] (which is cheap to clone — Arc-backed) rather
/// than borrowing it, so the same resolver can be used both inline (`&resolver`)
/// and behind an `Arc<dyn PurposeVmResolver>` (the status-list fetcher holds one
/// for the credential-signature check).
pub struct DidVmResolver {
    #[cfg_attr(not(feature = "bbs"), allow(dead_code))]
    resolver: Option<DIDCacheClient>,
    keys: TrustTaskVmResolver,
}

impl DidVmResolver {
    pub fn new(resolver: Option<DIDCacheClient>) -> Self {
        Self {
            keys: TrustTaskVmResolver::from_optional(resolver.clone()),
            resolver,
        }
    }

    /// Resolve a verification-method URI to its Ed25519 public-key bytes,
    /// provided its DID authorised it for `purpose`.
    pub(crate) async fn resolve_ed25519(
        &self,
        vm: &str,
        purpose: ProofPurpose,
    ) -> Result<Vec<u8>, AppError> {
        let key = self
            .keys
            .resolve_vm_for_purpose(vm, purpose)
            .await
            .map_err(|e| AppError::Validation(format!("verification method refused: {e}")))?;
        if key.key_type != KeyType::Ed25519 {
            return Err(AppError::Validation(format!(
                "the verification method is a {:?} key; this path verifies Ed25519 signatures",
                key.key_type
            )));
        }
        Ok(key.public_key_bytes)
    }

    /// As [`Self::resolve_ed25519`] but returns a [`VerifyingKey`] for the
    /// SD-JWT issuer-signature path.
    pub(crate) async fn resolve_verifying_key(
        &self,
        vm: &str,
        purpose: ProofPurpose,
    ) -> Result<VerifyingKey, AppError> {
        let bytes = self.resolve_ed25519(vm, purpose).await?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            AppError::Validation(format!(
                "the verification method's Ed25519 key is {} bytes, not 32",
                bytes.len()
            ))
        })?;
        VerifyingKey::from_bytes(&arr).map_err(|e| {
            AppError::Validation(format!(
                "the verification method is not a valid Ed25519 key: {e}"
            ))
        })
    }

    /// Resolve a verification-method URI to its 96-byte compressed BLS12-381
    /// G2 public key — a BBS+ issuer key — provided its DID authorised it for
    /// `purpose`. The upstream Ed25519 extractor doesn't cover G2, so this
    /// keeps the explicit Multikey (`0xeb` multicodec) decode.
    #[cfg(feature = "bbs")]
    pub(crate) async fn resolve_bbs_g2(
        &self,
        vm: &str,
        purpose: ProofPurpose,
    ) -> Result<[u8; 96], AppError> {
        use serde_json::Value;
        use vta_sdk::trust_task_proof::purpose::{
            authorised_method, check_did_key_method, split_vm,
        };
        let refused = |e: DataIntegrityError| {
            AppError::Validation(format!("verification method refused: {e}"))
        };
        let (base_did, _) = split_vm(vm).map_err(refused)?;
        if base_did.starts_with("did:key:") {
            check_did_key_method(vm).map_err(refused)?;
            return affinidi_crypto::bls12381::did_key_to_g2_pub(base_did).map_err(|e| {
                AppError::Validation(format!("the verification method is not a BBS did:key: {e}"))
            });
        }
        let resolver = self.resolver.as_ref().ok_or_else(|| {
            AppError::Validation(
                "resolving this verification method needs a DID resolver to verify did:webvh / \
                 did:web BBS issuers"
                    .to_string(),
            )
        })?;
        // A cached document that does not list `vm` is re-resolved once,
        // fresh, before the method is refused: the signer may have rotated
        // since it was cached (VTI-KEY-134).
        let resolved = vta_sdk::trust_task_proof::resolve_for_vm(resolver, base_did, vm)
            .await
            .map_err(|e| {
                AppError::Validation(format!(
                    "the verification method's DID did not resolve: {e}"
                ))
            })?;
        let entry = authorised_method(&resolved.doc, base_did, vm, purpose).map_err(refused)?;
        let multibase = entry
            .property_set
            .get("publicKeyMultibase")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AppError::Validation(
                    "the verification method has no publicKeyMultibase (BLS12-381 G2 Multikey)"
                        .to_string(),
                )
            })?;
        affinidi_crypto::bls12381::did_key_to_g2_pub(&format!("did:key:{multibase}")).map_err(|e| {
            AppError::Validation(format!(
                "the verification method is not a BLS12-381 G2 Multikey: {e}"
            ))
        })
    }
}

#[async_trait::async_trait]
impl PurposeVmResolver for DidVmResolver {
    async fn resolve_vm_for_purpose(
        &self,
        vm: &str,
        purpose: ProofPurpose,
    ) -> Result<ResolvedKey, DataIntegrityError> {
        // The declared key type, not an assumed Ed25519: a hybrid credential's
        // ML-DSA proof must resolve as ML-DSA to verify as one.
        self.keys.resolve_vm_for_purpose(vm, purpose).await
    }
}

/// A credential proof's `verificationMethod` must sit under the credential's
/// declared `issuer` — a key controlled by some *other* DID must not sign a
/// credential claiming this issuer. Shared by every issuer-bound DI verify
/// (credential-exchange DI VPs, recognition foreign VECs, VRC relationships).
///
/// Exact string equality of the DID, and the method must be a DID URL with a
/// fragment: a bare DID names no verification method. The message names the
/// rule, not the identifiers.
pub(crate) fn check_issuer_binding(vm: &str, issuer_did: &str) -> Result<(), AppError> {
    match vm.split_once('#') {
        Some((base, fragment)) if !fragment.is_empty() && base == issuer_did => Ok(()),
        Some((_, fragment)) if !fragment.is_empty() => Err(AppError::Validation(
            "proof verificationMethod is not under the credential's issuer".to_string(),
        )),
        _ => Err(AppError::Validation(
            "proof verificationMethod is not a DID URL naming a verification method".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_binding_is_exact_and_needs_a_fragment() {
        check_issuer_binding("did:web:a.example#key-0", "did:web:a.example").expect("bound");
        assert!(check_issuer_binding("did:web:b.example#key-0", "did:web:a.example").is_err());
        assert!(check_issuer_binding("did:web:a.example", "did:web:a.example").is_err());
        assert!(check_issuer_binding("did:web:a.example#", "did:web:a.example").is_err());
        let err = check_issuer_binding("did:web:b.example#key-0", "did:web:a.example")
            .unwrap_err()
            .to_string();
        assert!(
            !err.contains("a.example"),
            "no identifiers in the refusal: {err}"
        );
    }
}
