//! WebVH hosting infrastructure for the VTA, extracted from `vta-service` so
//! the DID-lifecycle subsystem (`operations/did_webvh`) and the other webvh
//! consumers can depend on it without pulling in the whole service.
//!
//! - [`webvh_store`] — the local `did:webvh` DID-record + server-record store
//!   (fjall `webvh` keyspace).
//!
//! The client to a DID hosting service is `vta_service::webvh_host`: every
//! call is a Trust Task over the transport the host advertises, so it lives
//! beside the outbound seam that carries it. `vta-service` re-exports this
//! module as `crate::webvh_store` (behind its `webvh` feature).

pub mod webvh_store;
