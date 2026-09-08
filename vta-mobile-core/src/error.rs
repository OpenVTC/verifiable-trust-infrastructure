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

    /// A DIDComm mediator transport operation failed (connect, authenticate,
    /// receive). Network/protocol failures from the live mediator surface here.
    #[error("transport error: {reason}")]
    Transport { reason: String },

    /// An inbound approval request could not be cryptographically attributed to
    /// an enrolled executor: its Data Integrity proof is missing or invalid, the
    /// proof's key is not the document issuer's, or the issuer is not in the
    /// enrolled-executor allowlist. This is the spec's `untrusted_issuer`
    /// condition — the device MUST NOT prompt; drop the request (optionally
    /// logging `reason`).
    #[error("untrusted issuer: {reason}")]
    UntrustedIssuer { reason: String },

    /// The request is authentic and from an enrolled issuer, but it is
    /// addressed to a different approver. The device MUST NOT prompt.
    ///
    /// **Separate from [`FfiError::UntrustedIssuer`] on purpose.** Nothing is
    /// wrong with the signature or the enrolment, so folding the two together
    /// would send whoever reads the log to check an allowlist that is correct.
    /// What failed is addressing: a document signed for one approver arriving
    /// at another is either misrouting or a valid prompt being replayed
    /// somewhere it can be answered by the wrong person, and the `recipient`
    /// member exists to make that refusable.
    #[error("addressed to {recipient}, not to this approver")]
    NotForThisApprover { recipient: String },
}
