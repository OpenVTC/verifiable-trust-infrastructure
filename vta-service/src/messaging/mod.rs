//! Mediator connection and inbound dispatch, for both transports.
//!
//! The split below is the one that matters: the **connection** is shared and
//! the **protocol surfaces** are not. `service` builds one `DidCommTransport`
//! over the mediator socket and its inbound loop hands DIDComm frames to the
//! DIDComm router and TSP frames to [`tsp_inbound`] — one socket per DID
//! carrying either protocol (ADR 0005). So `service`, `readiness` and `auth`
//! are gated on `any(didcomm, tsp)`, while the DIDComm protocol machinery
//! (routing, handlers, drain windows, the mediator registry, protocol
//! management) stays `didcomm`-only and is simply absent from a TSP-only build.
pub mod auth;
#[cfg(feature = "didcomm")]
pub mod drain_store;
#[cfg(feature = "didcomm")]
pub mod drain_sweeper;
#[cfg(feature = "didcomm")]
pub mod handlers;
#[cfg(all(feature = "webvh", feature = "didcomm"))]
pub mod handlers_protocol;
#[cfg(feature = "didcomm")]
pub mod handshake;
#[cfg(feature = "didcomm")]
pub mod live_prover;
/// Startup self-readiness gate for the mediator connection. Transport-neutral:
/// the mediator authenticates us by resolving our DID whichever protocol we
/// then speak on the socket.
pub mod readiness;
#[cfg(feature = "didcomm")]
pub mod registry;
#[cfg(feature = "didcomm")]
pub mod router;
/// Delivery-layer construction + protocol-routed inbound loop (D2 P2a).
pub mod service;
/// Local replacements for the `affinidi-messaging-didcomm-service` types the
/// DIDComm handlers depend on (D2 P2a cut-over). See [`shim`].
#[cfg(feature = "didcomm")]
pub mod shim;
#[cfg(all(feature = "webvh", feature = "didcomm"))]
pub mod transient_handshake;
#[cfg(feature = "tsp")]
pub mod tsp_inbound;
#[cfg(feature = "tsp")]
pub mod tsp_reach;
