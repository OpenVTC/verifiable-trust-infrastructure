//! The error type that crosses the FFI boundary.
//!
//! Kept coarse and stable: the host app switches on the *variant* for control
//! flow; the `reason`/detail strings are for logs and diagnostics, not for
//! parsing. New variants are additive — never reshape an existing one, or you
//! break every generated binding.

/// Errors returned across the UniFFI boundary to Kotlin / Swift.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// Caller supplied a value that failed a precondition (shape, range, …).
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },

    /// A value that should have been a recognised encoding (base64url, JSON, …)
    /// could not be decoded.
    #[error("decode error: {reason}")]
    Decode { reason: String },

    /// The requested operation is part of a not-yet-wired build-out slice.
    #[error("not yet implemented: {what}")]
    Unimplemented { what: String },
}
