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
//! Resolution: `did:key` verification methods resolve locally (no I/O); other
//! methods (`did:webvh` / `did:web`) resolve through the DID cache (which must
//! then be configured). Ed25519 keys are pulled with the upstream
//! [`VerificationMethod::get_public_key_bytes`] extractor, which handles
//! Multikey + `Ed25519VerificationKey2020` + `publicKeyJwk` uniformly.

use ed25519_dalek::VerifyingKey;
use vti_common::error::AppError;

/// A [`VerificationMethodResolver`](affinidi_data_integrity::VerificationMethodResolver)
/// over the VTC's optional [`DIDCacheClient`](affinidi_did_resolver_cache_sdk::DIDCacheClient).
pub(crate) struct DidVmResolver<'a> {
    resolver: Option<&'a affinidi_did_resolver_cache_sdk::DIDCacheClient>,
}

impl<'a> DidVmResolver<'a> {
    pub(crate) fn new(
        resolver: Option<&'a affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    ) -> Self {
        Self { resolver }
    }

    /// Resolve a verification-method URI (or a bare `did:key`) to its Ed25519
    /// public-key bytes. `did:key` is local; other methods use the cache and the
    /// upstream key extractor (Multikey / `Ed25519VerificationKey2020` / JWK).
    pub(crate) async fn resolve_ed25519(&self, vm: &str) -> Result<Vec<u8>, AppError> {
        let base_did = vm.split('#').next().unwrap_or(vm);
        if base_did.starts_with("did:key:") {
            return affinidi_crypto::did_key::did_key_to_ed25519_pub(base_did)
                .map(|k| k.to_vec())
                .map_err(|e| {
                    AppError::Validation(format!("`{base_did}` is not a resolvable did:key: {e}"))
                });
        }
        let resolver = self.resolver.ok_or_else(|| {
            AppError::Validation(format!(
                "resolving `{base_did}` needs a DID resolver, but none is configured — configure \
                 the DID cache to verify did:webvh / did:web issuers + holders"
            ))
        })?;
        let resolved = resolver
            .resolve(base_did)
            .await
            .map_err(|e| AppError::Validation(format!("DID `{base_did}` did not resolve: {e}")))?;
        let relative = vm
            .split_once('#')
            .map(|(_, f)| format!("#{f}"))
            .unwrap_or_default();
        let entry = resolved
            .doc
            .verification_method
            .iter()
            .find(|m| m.id.as_str() == vm || m.id.as_str() == relative)
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "verificationMethod `{vm}` not found in DID `{base_did}`"
                ))
            })?;
        entry.get_public_key_bytes().map_err(|e| {
            AppError::Validation(format!(
                "verificationMethod `{vm}` public key could not be extracted: {e}"
            ))
        })
    }

    /// As [`Self::resolve_ed25519`] but returns a [`VerifyingKey`] for the
    /// SD-JWT issuer-signature path.
    pub(crate) async fn resolve_verifying_key(&self, vm: &str) -> Result<VerifyingKey, AppError> {
        let bytes = self.resolve_ed25519(vm).await?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            AppError::Validation(format!("verificationMethod `{vm}` key is not 32 bytes"))
        })?;
        VerifyingKey::from_bytes(&arr).map_err(|e| {
            AppError::Validation(format!(
                "verificationMethod `{vm}` is not a valid Ed25519 key: {e}"
            ))
        })
    }

    /// Resolve a verification-method URI (or a bare `did:key`) to its 96-byte
    /// compressed BLS12-381 G2 public key — a BBS+ issuer key. The upstream
    /// Ed25519 extractor doesn't cover G2, so this keeps the explicit Multikey
    /// (`0xeb` multicodec) decode.
    #[cfg(feature = "bbs")]
    pub(crate) async fn resolve_bbs_g2(&self, vm: &str) -> Result<[u8; 96], AppError> {
        use serde_json::Value;
        let base_did = vm.split('#').next().unwrap_or(vm);
        if base_did.starts_with("did:key:") {
            return affinidi_crypto::bls12381::did_key_to_g2_pub(base_did).map_err(|e| {
                AppError::Validation(format!("`{base_did}` is not a BBS did:key: {e}"))
            });
        }
        let resolver = self.resolver.ok_or_else(|| {
            AppError::Validation(format!(
                "resolving `{base_did}` needs a DID resolver to verify did:webvh / did:web \
                 BBS issuers"
            ))
        })?;
        let resolved = resolver
            .resolve(base_did)
            .await
            .map_err(|e| AppError::Validation(format!("DID `{base_did}` did not resolve: {e}")))?;
        let doc: Value = serde_json::to_value(&resolved.doc)
            .map_err(|e| AppError::Internal(format!("DID document serialise failed: {e}")))?;
        let vms = doc
            .get("verificationMethod")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                AppError::Validation(format!("DID `{base_did}` has no verificationMethod array"))
            })?;
        let relative = vm
            .split_once('#')
            .map(|(_, f)| format!("#{f}"))
            .unwrap_or_default();
        let entry = vms
            .iter()
            .find(|e| {
                let id = e.get("id").and_then(Value::as_str).unwrap_or("");
                id == vm || id == relative
            })
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "verificationMethod `{vm}` not found in DID `{base_did}`"
                ))
            })?;
        let multibase = entry
            .get("publicKeyMultibase")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "verificationMethod `{vm}` has no publicKeyMultibase (BLS12-381 G2 Multikey)"
                ))
            })?;
        affinidi_crypto::bls12381::did_key_to_g2_pub(&format!("did:key:{multibase}")).map_err(|e| {
            AppError::Validation(format!(
                "verificationMethod `{vm}` is not a BLS12-381 G2 Multikey: {e}"
            ))
        })
    }
}

#[async_trait::async_trait]
impl affinidi_data_integrity::VerificationMethodResolver for DidVmResolver<'_> {
    async fn resolve_vm(
        &self,
        vm: &str,
    ) -> Result<affinidi_data_integrity::ResolvedKey, affinidi_data_integrity::DataIntegrityError>
    {
        let bytes = self
            .resolve_ed25519(vm)
            .await
            .map_err(|e| affinidi_data_integrity::DataIntegrityError::Resolver(e.to_string()))?;
        Ok(affinidi_data_integrity::ResolvedKey::new(
            affinidi_secrets_resolver::secrets::KeyType::Ed25519,
            bytes,
        ))
    }
}

/// A credential proof's `verificationMethod` must sit under the credential's
/// declared `issuer` — a key controlled by some *other* DID must not sign a
/// credential claiming this issuer. Shared by every issuer-bound DI verify
/// (credential-exchange DI VPs, recognition foreign VECs, VRC relationships).
pub(crate) fn check_issuer_binding(vm: &str, issuer_did: &str) -> Result<(), AppError> {
    let base = vm.split('#').next().unwrap_or(vm);
    if base != issuer_did {
        return Err(AppError::Validation(format!(
            "proof verificationMethod `{vm}` is not under the issuer `{issuer_did}`"
        )));
    }
    Ok(())
}
