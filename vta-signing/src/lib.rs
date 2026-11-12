//! The VTA's signing core.
//!
//! One place builds the bytes that get signed and makes the signature, so a
//! fix lands once for every signer: the VTA's own operations (`vta-service`,
//! `vta-keys`) and any service that signs with keys of its own.
//!
//! What is here is what stays the same wherever a key signs:
//!
//! - [`SigningSecret`], [`PublicKey`] and the [`Signer`] trait: an Ed25519 or
//!   P-256 key that signs a message and zeroizes itself on drop, its public
//!   half, and the interface a hardware or remote key can implement too.
//! - [`framing`]: what a signature over bytes the signer did not build means.
//! - [`jws`]: the header rules, the RFC 8785 signing input and the compact
//!   serialisation of `keys/sign-jws/0.1`, and verification.
//! - [`di`]: the `eddsa-jcs-2022` proof configuration, hash data, proof and
//!   verification of `keys/sign-document/0.1`.
//! - [`sshsig`]: the statement `keys/sign-sshsig/0.1` signs.
//! - [`did_methods`]: which key may sign as which DID.
//! - [`FormatRefusal`]: why a request cannot be turned into bytes to sign, each
//!   a code the specification declares.
//!
//! What is deliberately not here is everything a VTA does *around* a
//! signature: which key a caller may use, the quota, the audit row, where the
//! key lives. Those are policy and storage, and they differ per deployment.
//! This crate has no storage, no async code, no I/O and no dependency on any
//! other crate of this workspace.
//!
//! Every function that builds signed bytes builds them from the request alone
//! and never from bytes the caller chose, which is the property the VTA's
//! signing operations rest on.

#![forbid(unsafe_code)]

pub mod canonical;
pub mod di;
pub mod did_methods;
mod error;
pub mod framing;
pub mod jws;
mod key;
mod refusal;
pub mod sshsig;

pub use error::{KeyParseError, SecretError, SignError, VerifyError};
pub use key::{Algorithm, PublicKey, Signer, SigningSecret, decode_ed25519_public_key_multibase};
pub use refusal::FormatRefusal;
