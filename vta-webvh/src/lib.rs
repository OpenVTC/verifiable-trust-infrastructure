//! WebVH hosting infrastructure for the VTA, extracted from `vta-service` so
//! the DID-lifecycle subsystem (`operations/did_webvh`) and the other webvh
//! consumers can depend on it without pulling in the whole service.
//!
//! - [`webvh_store`] — the local `did:webvh` DID-record + server-record store
//!   (fjall `webvh` keyspace).
//! - [`webvh_client`] — the HTTP client to a remote `did:webvh` hosting server.
//! - [`webvh_auth`] — the DID-auth handshake the client uses against that host.
//!
//! Each depends only on `vti-common`, `vta-keyspaces`, `vta-sdk`, and
//! `affinidi-tdk` — never on `vta-service`. `vta-service` re-exports each as
//! `crate::<module>` (behind its `webvh` feature), so existing
//! `crate::webvh_store::…` / `crate::webvh_client::…` / `crate::webvh_auth::…`
//! paths are unchanged.

pub mod webvh_auth;
pub mod webvh_client;
pub mod webvh_store;
