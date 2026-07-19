pub mod auth;
pub mod drain_store;
pub mod drain_sweeper;
pub mod handlers;
#[cfg(all(feature = "webvh", feature = "didcomm"))]
pub mod handlers_protocol;
pub mod handshake;
#[cfg(feature = "didcomm")]
pub mod live_prover;
pub mod registry;
pub mod router;
/// Delivery-layer construction + protocol-routed inbound loop (D2 P2a).
#[cfg(feature = "didcomm")]
pub mod service;
/// Local replacements for the `affinidi-messaging-didcomm-service` types the
/// DIDComm handlers depend on (D2 P2a cut-over). See [`shim`].
pub mod shim;
#[cfg(all(feature = "webvh", feature = "didcomm"))]
pub mod transient_handshake;
#[cfg(feature = "tsp")]
pub mod tsp_inbound;
#[cfg(feature = "tsp")]
pub mod tsp_reach;
