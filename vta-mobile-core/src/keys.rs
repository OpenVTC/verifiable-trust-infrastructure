//! Key-handle abstraction — the seam between this engine and *native* custody.
//!
//! **Slice 3.** Private key material never crosses the FFI boundary and is
//! never held in Rust. Instead the native app implements a signing callback
//! backed by the Secure Enclave / StrongBox (biometric-gated), and passes a
//! handle in; this engine calls back out to sign.
//!
//! Planned surface (UniFFI callback interface / trait):
//! - `trait Signer { fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, FfiError>; fn did(&self) -> String; }`
//!
//! So `stepup`/`session` request signatures over bytes they construct, and the
//! biometric prompt + enclave operation happen entirely on the native side.
