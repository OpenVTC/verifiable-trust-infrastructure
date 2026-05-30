//! The pure-function FFI façade.
//!
//! Everything callable from Kotlin/Swift is `#[uniffi::export]`ed here (or
//! re-exported from a sibling module). Slice 1 keeps the surface minimal and
//! synchronous to prove the build + bindgen pipeline end to end.

use base64::Engine as _;

use crate::error::FfiError;

/// Engine build/version metadata. A trivial record so the host app can confirm
/// the FFI bridge is live and log which engine build it loaded.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EngineInfo {
    /// The `vta-mobile-core` crate version.
    pub version: String,
    /// The UniFFI namespace (matches the generated Kotlin/Swift module).
    pub namespace: String,
}

/// Returns the engine version string. The simplest possible FFI round-trip —
/// the host app's first call to confirm linkage.
#[uniffi::export]
pub fn library_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Returns engine metadata as a structured record (exercises UniFFI record
/// codegen across the boundary).
#[uniffi::export]
pub fn engine_info() -> EngineInfo {
    EngineInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        namespace: "vta_mobile_core".to_string(),
    }
}

/// Decodes a base64url step-up challenge and returns its length in bytes,
/// enforcing the ≥128-bit (16-byte) minimum the `auth/step-up/approve-request`
/// spec requires. A first *real*, pure, synchronous check that exercises the
/// `Result`/[`FfiError`] surface across the FFI boundary.
#[uniffi::export]
pub fn challenge_len_bytes(challenge_b64url: String) -> Result<u32, FfiError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(challenge_b64url.as_bytes())
        .map_err(|e| FfiError::Decode {
            reason: format!("challenge is not valid base64url: {e}"),
        })?;
    if bytes.len() < 16 {
        return Err(FfiError::InvalidInput {
            reason: format!(
                "challenge is {} bytes; the step-up spec requires ≥16 (128 bits)",
                bytes.len()
            ),
        });
    }
    Ok(bytes.len() as u32)
}
