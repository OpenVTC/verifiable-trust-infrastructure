//! Community voting on the Predicate Credential System (PCS): the cryptographic core.
//!
//! A community issues each eligible voter a **ticket** for one election: a PCS class credential
//! under `voter/<election>`, signed blind, so the community never sees the credential it made.
//! The voter **casts** by attesting, under that ticket, for a public point derived from the
//! election, with the ballot bound into the attestation's context. The attestation's **tag** is
//! fixed for one voter key and one election, and cannot be linked to the voter or across
//! elections: it is the nullifier that makes a second ballot replace the first, or be refused.
//!
//! Three halves, each for one party:
//!
//! - [`registrar`]: the community's. Holds the voting helper key and signs tickets. It checks
//!   nothing about the member: eligibility, and one ticket per member per election, are facts
//!   about the community's records, which its caller checks durably first.
//! - [`voter`]: the member's, run by their VTA. A fresh key per election, the blinded ticket
//!   request, the cast.
//! - [`ballot_box`]: the voting service's. Holds no secret: admits a cast on the community's
//!   published `hvk` alone, then records its tag.
//!
//! This crate is behaviour only. The wire forms that carry a ticket request, a ticket or a cast
//! are Trust Task payloads, and come from the specification once it exists.
//!
//! Requirements: VTI-VOT-001 – 100, the Community Voting chapter of the VTI specification.

pub mod audit;
pub mod ballot_box;
pub mod board;
pub mod ceremony;
pub mod election;
pub mod error;
pub mod registrar;
pub mod rules;
pub mod scheme;
pub mod service;
pub mod steps;
pub mod tally;
pub mod trustees;
pub mod voter;
pub mod wire;

pub use error::VotingError;

/// The `rand` the PCS algorithms take (0.8), re-exported for callers on a newer `rand`.
pub use rand;
