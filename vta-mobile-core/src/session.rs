//! VTA session / authentication — wraps `vta-sdk`.
//!
//! **Slice 3** (async over the FFI boundary; needs `vta-sdk` `session` feature
//! and a UniFFI `async_runtime = "tokio"` export).
//!
//! Planned surface:
//! - `start_auth(vta_did) -> AuthChallenge`
//! - `complete_auth(challenge, signed) -> TokenBundle`
//! - `refresh(refresh_token) -> TokenBundle`
//!
//! Key material never crosses the boundary: signing is performed natively via
//! a [`crate::keys`] handle; this module orchestrates the challenge/response
//! and JWT lifecycle using `vta-sdk`'s client.
