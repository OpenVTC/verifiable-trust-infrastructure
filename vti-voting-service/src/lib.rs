//! The voting service: a ballot box and board for community elections (VTI-VOT-001 – 100).
//!
//! # What this is, and what it deliberately is not
//!
//! A voting service is a **host service**, like a witness or a room host. Any number of
//! communities register elections with it; members' agents send it casts; the communities and
//! their auditors read its boards. It is not part of any community: it holds no roster, no
//! member DID and no issuance record, and nothing in this binary could consult one
//! (VTI-VOT-002, VTI-VOT-044). That absence is what keeps a ballot unlinkable to its voter:
//! the community knows who holds a ticket and never sees a ballot; this service sees every
//! ballot and never learns whose it is.
//!
//! It is also deliberately not part of the VTC. A cast arrives from a key made for that cast
//! alone, from a sender with no session (VTI-VOT-003, VTI-VOT-004), and the anonymous traffic,
//! its rate limiting and its abuse handling belong here, not on a community's authenticated
//! door.
//!
//! # How a request is authorized
//!
//! - **Registration, early close and cancellation**: the document's own proof names the
//!   signer, and the signer must be the community the payload names.
//! - **A cast**: nobody's identity. Its PCS attestation is the authority, checked against the
//!   community's registered voting key. The document is still signed, by the one-time key.
//! - **Reads**: anyone, on a public board; on a private board the community, the auditors its
//!   manifest names, and, for one entry's inclusion, the holder of its receipt token.
//!
//! # Answers are evidence
//!
//! Every answer is signed as this service's DID. A receipt is what a voter holds against the
//! service if their ballot goes missing, and a head is what a community checkpoints to hold
//! the board append-only (VTI-VOT-043, VTI-VOT-050, VTI-VOT-051); an unsigned one is evidence
//! of nothing.
//!
//! The ballot box itself — every rule of every task — is [`vti_voting::service::BallotBox`].
//! This crate is its host: identity, transport, signing and durability.

pub mod http;
pub mod identity;
pub mod journal;

pub use http::{AppState, router};
