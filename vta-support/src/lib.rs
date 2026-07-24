//! Shared mid-layer support services for the VTA, extracted from `vta-service`
//! so the subsystem crates can depend on them without depending on the whole
//! service.
//!
//! - [`contexts`] — trust-context storage (the BIP-32 key-hierarchy roots).
//! - [`seal`] — the sealed-transfer producer-side seal helper.
//! - [`sealed_nonce_store`] — the sealed-bootstrap anti-replay nonce store.
//!
//! Each is a self-contained near-leaf: they depend only on `vti-common`,
//! `vta-config`, `vta-keyspaces`, and `vta-sdk`, never on `vta-service`.
//! `vta-service` re-exports each as `crate::<module>`, so existing
//! `crate::contexts::…` / `crate::seal::…` / `crate::sealed_nonce_store::…`
//! paths are unchanged.

pub mod contexts;
pub mod did_templates;
pub mod seal;
pub mod sealed_nonce_store;
