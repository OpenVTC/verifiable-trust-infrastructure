//! AAL step-up — build the `auth/step-up/approve-response` document.
//!
//! **Slice 2** (build) + **slice 3** (signing handle). Blocked on the same
//! `trust-tasks-rs` republish as [`crate::task`].
//!
//! Planned surface (supports BOTH gates from the merged spec):
//! - `build_approve_response_did_signed(req, decision, key_handle) -> TaskJson`
//!     — gate = framework Data Integrity proof (subject DID signature).
//! - `build_approve_response_webauthn(req, assertion) -> TaskJson`
//!     — gate = WebAuthn `AuthenticatorAssertionResponse` over the challenge;
//!       the assertion is produced natively (ASAuthorization / Credential
//!       Manager) and passed in.
//!
//! The native layer decides which gate to use based on the request's
//! `acceptableEvidence`; this module assembles and (for did-signed) signs via
//! a [`crate::keys`] handle.
