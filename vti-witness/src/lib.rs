//! `vti-witness` — the witness as a host service
//! (`docs/05-design-notes/witness-host-service.md`, `docs/06-witness/`).
//!
//! A witness attests that an exchange between *other* parties happened, so it
//! runs apart from any node it might witness: its own binary, its own
//! identities, possibly its own operator. Each of up to ten witness identities
//! is a `did:webvh` minted by the operator's VTA from the `dtg-witness` template,
//! and each holds one mediator socket carrying TSP and DIDComm.
//!
//! P1 built the skeleton: setup, configuration, one supervised mediator
//! session per identity, and the dispatcher. P2 adds the witnessing itself —
//! `witness/session/0.2` and `witness/session/submit/0.2` ([`witness`]), the
//! presentation checks ([`presentation`]), session and attestation storage
//! ([`store`]) and the duplicate-execution record ([`replay`]).
//!
//! The library target exists for tests; the binary is the product.

pub mod config;
pub mod correlation;
pub mod dispatch;
pub mod keys;
pub mod messaging;
pub mod presentation;
pub mod replay;
pub mod run;
pub mod setup;
pub mod store;
pub mod witness;
