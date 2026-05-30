//! Key-handle abstraction — the seam between this engine and *native* custody.
//!
//! Private key material **never** crosses the FFI boundary and is never held in
//! Rust. The native app implements [`Signer`] over a key in the Secure Enclave
//! (iOS) / StrongBox / Android Keystore, gated behind a biometric prompt, and
//! passes it in. The engine builds the exact bytes that need signing and calls
//! back out; the enclave operation and the biometric UI happen entirely
//! natively. This is the seam every later signing flow ([`crate::stepup`],
//! [`crate::session`]) is built on.

use crate::error::FfiError;

/// A signing capability backed by a platform-protected private key, implemented
/// on the **native** (Kotlin/Swift) side. Per the workspace "default to DIDs"
/// principle, the key is identified by its `did:key`, never a raw pubkey.
#[uniffi::export(callback_interface)]
pub trait Signer: Send + Sync {
    /// The `did:key` (Ed25519) whose key this signer controls. The engine uses
    /// it as the proof `verificationMethod` on documents it assembles.
    fn did(&self) -> String;

    /// Sign `payload` with the enclave-held key. The biometric prompt and the
    /// Secure Enclave / StrongBox operation are performed natively; a user
    /// cancellation or biometric failure returns [`FfiError`]. The signature is
    /// raw bytes (EdDSA over `payload`); the engine never sees key material.
    fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, FfiError>;
}

/// Exercises the custody seam end to end: decode a base64url step-up challenge
/// and have the native [`Signer`] sign those bytes, returning the signature.
///
/// This is the round-trip native → engine → native-callback → engine → native
/// that proves the boundary (and [`FfiError`] propagation *back through* the
/// callback) works. Later slices replace the raw-challenge input with the
/// canonicalised signing input of an `auth/step-up/approve-response` document,
/// but the signing seam — engine builds bytes, native enclave signs them — is
/// exactly this.
#[uniffi::export]
pub fn sign_challenge(
    signer: Box<dyn Signer>,
    challenge_b64url: String,
) -> Result<Vec<u8>, FfiError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(challenge_b64url.as_bytes())
        .map_err(|e| FfiError::Decode {
            reason: format!("challenge is not valid base64url: {e}"),
        })?;
    signer.sign(bytes)
}
