//! `vti-secrets` — pluggable secret-store backends + the integration
//! onboarding flow, shared across the Verifiable Trust Infrastructure
//! workspace **and** external integrations.
//!
//! ## What this crate provides
//!
//! - [`SeedStore`] — the storage trait (re-exported from `vti-common`) for
//!   BIP-32 master seeds / raw secret key material.
//! - The concrete backends ([`AwsSeedStore`], [`GcpSeedStore`],
//!   [`AzureSeedStore`], [`VaultSeedStore`], [`K8sSeedStore`],
//!   [`KeyringSeedStore`], [`PlaintextSeedStore`], and the TEE
//!   [`kms_tee`] backend), each behind the same feature flag the VTA uses.
//! - [`create_seed_store`] — the feature-aware factory that picks a backend
//!   from a [`SecretsConfig`].
//! - [`SecretsConfig`] — the `[secrets]` config shape.
//! - (feature `onboarding`) [`onboarding::IntegrationOnboarding`] — the
//!   ephemeral-`did:key` → ACL-grant → auto-rotate cold-start flow, wrapping
//!   `vta-sdk`'s `SessionStore`.
//!
//! ## Why a shared crate
//!
//! These backends + the factory previously lived inside `vta-service`, so an
//! external VTI integration (e.g. `vti-message-bridge`) could not reuse them
//! without depending on the whole service binary crate. Lifting them here lets
//! an integration persist its identity seed + per-connector credentials via the
//! exact same pluggable backends the VTA uses, and onboard the exact same way.
//!
//! `vta-service` depends on this crate and re-exports it from
//! `keys::seed_store`, so existing call sites are unchanged — this is a pure
//! extraction with no behavioural change.

pub mod config;
pub mod seed_store;

#[cfg(feature = "onboarding")]
pub mod onboarding;

pub use config::SecretsConfig;
pub use seed_store::{SeedStore, create_seed_store};
