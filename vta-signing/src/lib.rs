//! The VTA's signing core.
//!
//! One place builds the bytes that get signed and makes the signature, so a
//! fix lands once for every signer: the VTA's own operations (`vta-service`,
//! `vta-keys`) and any service that signs with keys of its own.
//!
//! What is here is what stays the same wherever a key signs:
//!
//! - [`SigningSecret`]: an Ed25519 or P-256 key that signs a message and
//!   zeroizes itself on drop.
//! - [`jws`]: the header rules, the RFC 8785 signing input and the compact
//!   serialisation of `keys/sign-jws/0.1`.
//! - [`di`]: the `eddsa-jcs-2022` proof configuration, hash data and proof of
//!   `keys/sign-document/0.1`.
//! - [`FormatRefusal`]: why a request cannot be turned into bytes to sign,
//!   each a code the specification declares.
//!
//! What is deliberately not here is everything a VTA does *around* a
//! signature: which key a caller may use, the quota, the audit row, where the
//! key lives. Those are policy and storage, and they differ per deployment.
//! This crate has no storage, no async code, no I/O and no dependency on any
//! other crate of this workspace.
//!
//! Every function that builds signed bytes builds them from the request alone
//! and never from bytes the caller chose, which is the property the VTA's
//! signing operations rest on (see `vta-service`'s `sign_formats`).

pub mod canonical;
pub mod di;
pub mod jws;
mod key;
mod refusal;

pub use key::{Algorithm, SecretError, SigningSecret};
pub use refusal::FormatRefusal;
