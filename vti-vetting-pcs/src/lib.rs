//! Hidden-vetter admission (ZKP): the VTC's half.
//!
//! The applicant proves, in zero knowledge, that `k` distinct vetters of this community vetted
//! them. This crate verifies that proof and turns it into the `StatementFacts` the VTC already
//! counts, with each vetter's tag where the vetter's DID used to be — so `requirements::evaluate`
//! and `join.rego` are untouched.
//!
//! Design: `docs/design/vetting-hidden-vetters-pcs.md` on the openvtc `zkp-pcs` branch, §13
//! corrections applied. `vetter`/`applicant` engines are not here: they belong to the member
//! side (the VTA), and live on the openvtc branch.
//!
//! Development branch.

pub mod community;
pub mod error;
pub mod issuer;
pub mod meta;
pub mod scheme;
pub mod token;
pub mod verifier;
pub mod wire;

pub use error::ProtoError;

/// The `rand` the PCS algorithms take — 0.8, because `ark_std::rand` re-exports it and its
/// traits are what the randomized algorithms are written against.
///
/// Re-exported so a consumer on a newer `rand` (`vtc-service` is on 0.9) can still drive the
/// member-side calls that need an RNG, without a second `rand` in its own manifest pinned for
/// reasons that live here.
pub use rand;
