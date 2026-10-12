//! Hidden-vetter admission (ZKP) on the Predicate Credential System (PCS): both halves.
//!
//! The applicant proves, in zero knowledge, that `k` distinct vetters of a community vetted
//! them, and the community learns nothing about which vetters did. In the scheme's own terms the
//! community is the *helper*; every vetter and every applicant holds a PCS secret key, `usk`.
//!
//! - **The community's half** — [`issuer`] (class credentials, the token drip) and [`verifier`]
//!   (the proof, turned into the `StatementFacts` the VTC already counts, with each vetter's tag
//!   where the vetter's DID used to be, so `requirements::evaluate` and `join.rego` are
//!   untouched). `vtc-service` runs it.
//! - **The member's half** — the [`vetter`] and [`applicant`] engines and their storable
//!   [`snapshot`]s. A VTA runs them as its principal's PCS engine (design §13 C7, the `vta/pcs/*`
//!   Trust Tasks), so the client carrying the messages never holds a `usk`.
//!
//! [`vtc`] (feature `harness`) is an in-process community built from the community's half, for
//! driving the member's half end to end in tests without a running VTC.
//!
//! Design: `design-docs/vetting-hidden-vetters-pcs.md`, §13 corrections applied.

pub mod applicant;
pub mod community;
pub mod error;
pub mod issuer;
pub mod meta;
pub mod scheme;
pub mod snapshot;
pub mod token;
pub mod verifier;
pub mod vetter;
#[cfg(any(test, feature = "harness"))]
pub mod vtc;
pub mod wire;

pub use error::ProtoError;

/// The `rand` the PCS algorithms take — 0.8, because `ark_std::rand` re-exports it and its
/// traits are what the randomized algorithms are written against.
///
/// Re-exported so a consumer on a newer `rand` (`vtc-service` is on 0.9) can still drive the
/// member-side calls that need an RNG, without a second `rand` in its own manifest pinned for
/// reasons that live here.
pub use rand;
