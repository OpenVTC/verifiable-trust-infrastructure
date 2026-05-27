//! DID-cache configuration helper.
//!
//! Mirrors the toggle `vta-service` exposes via `config.resolver_url`:
//! when a WebSocket URL is supplied, the SDK dispatches every DID
//! resolution to an external `affinidi-did-resolver-cache-server`
//! (typically running alongside the VTA). When `None`, the SDK
//! resolves in-process and caches results in memory.
//!
//! ## Why the env-var path exists
//!
//! `pnm-cli` calls into SDK functions that construct their own
//! `DIDCacheClient` (`session::resolve_vta_endpoint`,
//! `session::resolve_vta_url`, `session::resolve_mediator_did`). Those
//! signatures don't take a config, so threading `PnmConfig.resolver_url`
//! through every call site would mean breaking the SDK's public API for
//! every consumer. Instead, PNM exports its setting as
//! `PNM_RESOLVER_URL` at startup, and the SDK helper picks it up —
//! a single config setting propagates to every resolver construction
//! without surface changes.
//!
//! `vta-service` / `vtc-service` ignore the env var and build their
//! resolver explicitly from their own config (`server.rs` calls
//! `with_network_mode(url)` directly), so PNM's setting does not leak
//! into long-running daemons that have their own opinion.

use affinidi_did_resolver_cache_sdk::config::{DIDCacheConfig, DIDCacheConfigBuilder};

/// Build a `DIDCacheConfig` honouring an optional remote-resolver URL.
/// When `url` is `Some`, network-mode is enabled — every resolution is
/// dispatched to that WebSocket endpoint. When `None`, the SDK resolves
/// in-process with an in-memory cache.
pub fn build_did_cache_config(url: Option<&str>) -> DIDCacheConfig {
    let mut builder = DIDCacheConfigBuilder::default();
    if let Some(u) = url {
        builder = builder.with_network_mode(u);
    }
    builder.build()
}

/// Read `PNM_RESOLVER_URL` and build a `DIDCacheConfig` accordingly.
/// Empty string or unset means local mode.
pub fn build_did_cache_config_from_env() -> DIDCacheConfig {
    let url = std::env::var("PNM_RESOLVER_URL")
        .ok()
        .filter(|s| !s.is_empty());
    build_did_cache_config(url.as_deref())
}
