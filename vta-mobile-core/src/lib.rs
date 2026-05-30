//! `vta-mobile-core` — the shared engine behind the VTA mobile agent
//! (`vta-mobile-agent-android` / `vta-mobile-agent-ios`), exposed to both
//! platforms through a single UniFFI surface.
//!
//! ## Design
//!
//! The FFI surface is deliberately a set of **pure functions over bytes**.
//! Everything stateful or platform-bound stays *native* and is handed to this
//! crate as inputs:
//!
//! - key custody (Secure Enclave / StrongBox) and biometric gating,
//! - the mediator WebSocket transport and APNs/FCM push wake-up,
//! - the platform WebAuthn / passkey APIs,
//! - all UI.
//!
//! This crate wraps the existing Rust building blocks — `vta-sdk` (VTA auth /
//! session), `trust-tasks-rs` + `trust-tasks-proof` (Trust Task build/verify),
//! and the `affinidi-tdk` DIDComm/resolver/crypto stack — so the wire crypto
//! is written once and shared, never reimplemented per platform.
//!
//! ## Build-out slices
//!
//! 1. **this slice** — skeleton + minimal sync surface; prove the crate builds and Kotlin/Swift bindings generate.
//! 2. Trust Task build/verify (pure, sync) — see [`task`], [`stepup`].
//! 3. VTA auth — `auth/*` Trust Task build/parse (pure, sync) — see [`session`];
//!    DIDComm pack/unpack — see [`didcomm`]; async DID resolution — see
//!    [`resolver`]; push registration — see [`push`].

uniffi::setup_scaffolding!();

pub mod api;
mod error;
mod proof;

// Planned module surface. These are stubs in slice 1; each file documents the
// FFI it will expose and which slice wires it. They are kept as real modules
// so the crate layout matches the mapped design from day one.
pub mod didcomm;
pub mod keys;
pub mod push;
pub mod resolver;
pub mod session;
pub mod stepup;
pub mod task;

pub use api::*;
pub use error::FfiError;
