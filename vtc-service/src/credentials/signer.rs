//! `LocalSigner` — plan §D1's cached-locally signing surface.
//!
//! Wraps the VTC's `#key-0` Ed25519 secret in the shape
//! [`affinidi_data_integrity::DataIntegrityProof::sign`] wants.
//! The secret already lives in the secret store (loaded at boot
//! from `VtcKeyBundle` per `tasks/vtc-mvp/vta-driven-keys.md`); the
//! signer is a thin handle that pairs it with the VTC's issuer
//! DID so callers don't have to plumb both through every builder.
//!
//! ## Why not just pass `&Secret` directly
//!
//! Three reasons we wrap:
//! 1. **Issuer-DID coupling.** Every VC the VTC signs has
//!    `issuer = vtc_did`. Pairing the DID with the secret in one
//!    handle means the VMC + VEC builders don't have to take both
//!    and the caller can't pass mismatched values.
//! 2. **Assertion-method id.** `secret.id` is the
//!    `verificationMethod` URI the proof carries. Building it
//!    once at construction (`{vtc_did}#key-0`) keeps the wire
//!    shape consistent.
//! 3. **Test fixtures.** Tests want a "from seed bytes" shortcut
//!    that doesn't go through the keyring / secrets-resolver
//!    plumbing. [`LocalSigner::from_ed25519_seed`] gives them
//!    that without exposing the wrapper internals.

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, VerifyOptions};
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_vc::VerifiableCredential;
use vti_common::error::AppError;

/// Verification-method fragment the VTC consistently uses for
/// its assertion-method key. Lines up with what
/// `server::init_auth` stamps onto the secret at boot
/// (`{vtc_did}#key-0`).
pub const ASSERTION_KEY_FRAGMENT: &str = "key-0";

/// A local signer wrapping the VTC's `#key-0` Ed25519 secret.
/// Constructed once at boot from the secret store and shared via
/// `AppState`; cloning is cheap (the inner secret is a small
/// owned struct).
#[derive(Debug, Clone)]
pub struct LocalSigner {
    issuer_did: String,
    secret: Secret,
}

impl LocalSigner {
    /// Construct from a fully-formed [`Secret`]. Caller is
    /// responsible for ensuring `secret.id` is
    /// `{issuer_did}#key-0` — the helpers below all enforce
    /// this; this constructor exists for callers that already
    /// did the work (e.g. the boot path that read the secret
    /// out of [`affinidi_secrets_resolver::ThreadedSecretsResolver`]).
    pub fn new(issuer_did: String, secret: Secret) -> Self {
        Self { issuer_did, secret }
    }

    /// Construct from 32 raw Ed25519 seed bytes. The resulting
    /// signer's `secret.id` is `{issuer_did}#key-0`. Used by
    /// tests + the boot path that decodes a `VtcKeyBundle`.
    pub fn from_ed25519_seed(issuer_did: String, seed: &[u8; 32]) -> Self {
        let assertion_id = assertion_method_id(&issuer_did);
        let secret = Secret::generate_ed25519(Some(&assertion_id), Some(seed));
        Self { issuer_did, secret }
    }

    /// VTC issuer DID — stamped on every credential's `issuer`
    /// field.
    pub fn issuer_did(&self) -> &str {
        &self.issuer_did
    }

    /// `verificationMethod` URI the proof carries.
    pub fn assertion_method_id(&self) -> &str {
        &self.secret.id
    }

    /// Bytes-on-the-wire public key, useful to tests that want
    /// to verify a freshly-signed VC without going through the
    /// did resolver.
    pub fn public_bytes(&self) -> &[u8] {
        self.secret.get_public_bytes()
    }

    /// Sign the supplied VC in place. Appends the
    /// `DataIntegrityProof` to `vc.proof`. Returns
    /// [`AppError::Internal`] on signing failure — every error
    /// the data-integrity layer surfaces is a workspace bug
    /// (wrong key type, canonicalisation crash, etc.) rather
    /// than operator input.
    pub async fn sign(&self, vc: &mut VerifiableCredential) -> Result<(), AppError> {
        let proof = DataIntegrityProof::sign(vc, &self.secret, SignOptions::new())
            .await
            .map_err(|e| AppError::Internal(format!("sign VC: {e}")))?;
        vc.proof = Some(
            serde_json::to_value(&proof)
                .map_err(|e| AppError::Internal(format!("serialize VC proof: {e}")))?,
        );
        Ok(())
    }

    /// Sign an arbitrary JSON credential document **in place**, splicing the
    /// resulting `DataIntegrityProof` into its `proof` field.
    ///
    /// Unlike [`sign`](Self::sign) (a typed [`VerifiableCredential`]), this signs
    /// a raw `serde_json::Value`. It's the signing surface for the DTG issuance
    /// layer ([`super::dtg`]): a credential's canonical shape is sourced from the
    /// `dtg-credentials` catalog, then fields the catalog struct doesn't model
    /// (a top-level `id`, a `credentialStatus` block) are spliced **before**
    /// signing so the proof covers them. Any pre-existing `proof` is removed
    /// first — a proof never covers itself.
    pub async fn sign_doc(&self, doc: &mut serde_json::Value) -> Result<(), AppError> {
        let obj = doc
            .as_object_mut()
            .ok_or_else(|| AppError::Internal("credential document is not a JSON object".into()))?;
        obj.remove("proof");
        let proof = DataIntegrityProof::sign(&*doc, &self.secret, SignOptions::new())
            .await
            .map_err(|e| AppError::Internal(format!("sign VC doc: {e}")))?;
        let proof_value = serde_json::to_value(&proof)
            .map_err(|e| AppError::Internal(format!("serialize VC doc proof: {e}")))?;
        doc.as_object_mut()
            .expect("doc was an object above")
            .insert("proof".into(), proof_value);
        Ok(())
    }

    /// Verify a previously-signed VC against this signer's public
    /// key. Used by tests + the M2.13 renewal path that hands
    /// freshly-issued VCs to verifiers. Returns `Ok(())` on
    /// success, [`AppError::Validation`] when the proof is
    /// missing or malformed, [`AppError::Forbidden`] when the
    /// signature does not verify.
    pub fn verify(&self, vc: &VerifiableCredential) -> Result<(), AppError> {
        let proof_value = vc
            .proof
            .as_ref()
            .ok_or_else(|| AppError::Validation("VC has no proof to verify".into()))?;
        let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone())
            .map_err(|e| AppError::Validation(format!("parse VC proof: {e}")))?;

        let mut vc_without_proof = vc.clone();
        vc_without_proof.proof = None;

        proof
            .verify_with_public_key(&vc_without_proof, self.public_bytes(), VerifyOptions::new())
            .map_err(|e| AppError::Forbidden(format!("verify VC: {e}")))?;
        Ok(())
    }
}

/// `{did}#key-0` — the conventional assertion-method id for the
/// VTC. Re-exposed here so the VMC + VEC builders compose the
/// same URI without re-deriving it from `LocalSigner` every
/// time.
pub fn assertion_method_id(issuer_did: &str) -> String {
    format!("{issuer_did}#{ASSERTION_KEY_FRAGMENT}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DID: &str = "did:webvh:vtc.example.com:abc";

    #[test]
    fn from_seed_constructs_with_canonical_kid() {
        let seed = [0xAB; 32];
        let signer = LocalSigner::from_ed25519_seed(TEST_DID.into(), &seed);
        assert_eq!(signer.issuer_did(), TEST_DID);
        assert_eq!(
            signer.assertion_method_id(),
            format!("{TEST_DID}#{ASSERTION_KEY_FRAGMENT}")
        );
        // Public key bytes deterministic for the seed.
        let other = LocalSigner::from_ed25519_seed(TEST_DID.into(), &seed);
        assert_eq!(signer.public_bytes(), other.public_bytes());
    }

    #[test]
    fn different_seeds_produce_different_public_keys() {
        let a = LocalSigner::from_ed25519_seed(TEST_DID.into(), &[0xAB; 32]);
        let b = LocalSigner::from_ed25519_seed(TEST_DID.into(), &[0xCD; 32]);
        assert_ne!(a.public_bytes(), b.public_bytes());
    }

    #[test]
    fn assertion_method_id_is_did_hash_fragment() {
        assert_eq!(
            assertion_method_id("did:key:zX"),
            "did:key:zX#key-0".to_string()
        );
    }
}
