//! `vti-witness` — the witness as a host service
//! (`docs/05-design-notes/witness-host-service.md`, `docs/06-witness/`).
//!
//! A witness attests that an exchange between *other* parties happened, so it
//! runs apart from any node it might witness: its own binary, its own
//! identities, possibly its own operator. Each of up to ten witness identities
//! is a `did:webvh` minted by the operator's VTA from the `dtg-witness` template,
//! and each holds one mediator socket carrying TSP and DIDComm.
//!
//! This is phase P1, the skeleton: setup, configuration, one supervised
//! mediator session per identity, and a dispatcher that answers
//! `trust-task-discovery` and refuses everything else. The witnessing itself —
//! `witness/session/0.1` and `witness/session/submit/0.1` — is P2.
//!
//! The library target exists for tests; the binary is the product.

pub mod config;
pub mod correlation;
pub mod dispatch;
pub mod keys;
pub mod messaging;
pub mod run;
pub mod setup;
