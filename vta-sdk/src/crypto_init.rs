//! Register the rustls `aws-lc-rs` `CryptoProvider` as the process-wide
//! default.
//!
//! `tonic 0.12.x` (pulled in transitively via
//! `affinidi-did-resolver-cache-sdk`) hardcodes `features = ["ring"]` on
//! `tokio-rustls`, which propagates the `ring` cargo feature to `rustls
//! 0.23`. When a binary *also* links the `aws_lc_rs` backend — the
//! workspace default, dragged in via `kube`, `jsonwebtoken`,
//! reqwest-rustls, … — `rustls 0.23` ends up with two backends compiled in
//! and cannot auto-select one. The first call to `ClientConfig::builder()`
//! then panics with `no process-level CryptoProvider available`, which
//! happens *before any network connection is made* (e.g. when
//! `kube-client` initialises its HTTP client for the k8s-secrets backend).
//!
//! Every binary must call [`install_default_crypto_provider`] once at the
//! very top of `main()`, before any async runtime or TLS object is created.
//! This mirrors [`crate::keyring_init::install_default_store`].
//!
//! Note this is distinct from `jsonwebtoken`'s own `CryptoProvider`
//! (`jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER`), which governs JWT
//! signing — pinning that one does nothing for the rustls TLS panic.

/// Install the `aws-lc-rs` rustls `CryptoProvider` as the process default.
///
/// Idempotent: if a default provider is already installed (by a dependency
/// or a previous call) the redundant install is ignored, so this is safe to
/// call unconditionally for every build configuration. Returns `true` if
/// this call installed the provider, `false` if one was already present.
pub fn install_default_crypto_provider() -> bool {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_ok()
}
