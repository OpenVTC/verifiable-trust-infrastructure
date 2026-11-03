//! The Verifiable Trust Network (VTN) protocol, shared by the VTN service and the VTC.
//!
//! A VTN curates a nestable set of communities (VTCs) and other networks (VTNs). This
//! crate is the transport- and storage-free half of the implementation:
//!
//! - [`model`]: entries, their kind and state, and the network's own profile.
//! - [`lifecycle`]: the entry state machine (listing → acknowledgement → membership).
//! - [`credentials`]: building the DTG credentials every relationship is evidenced by.
//! - [`identity`] and [`verify`]: signing as the network, verifying what members sign.
//! - [`status`]: W3C Bitstring Status Lists for revocation and suspension.
//! - [`index`] and [`graph`]: the published network index and the DTG graph export.
//! - [`directory`]: the searchable member directory behind the network's landing page.
//! - [`groups`] and [`relay`]: network roles, registered groups, and signed broadcast
//!   envelopes that cascade through nested networks.
//! - [`rooms`]: network room passes, issued on a chain of group evidence.
//!
//! The normative requirements are `dtgwg-vti-spec/spec/11a-vtn.md` (VTI-VTN-*). Where the
//! DTG working group has not settled a question, the assumption this crate makes is
//! recorded in the verifiable-trust-network repository's `docs/assumptions.md` and named in the code as `A<n>`.

pub mod credentials;
pub mod did_key;
pub mod directory;
pub mod error;
pub mod graph;
pub mod groups;
pub mod identity;
pub mod index;
pub mod lifecycle;
pub mod model;
pub mod relay;
pub mod rooms;
pub mod status;
pub mod verify;
pub mod vocab;

pub use error::VtnError;

/// Talking to a network over HTTPS: `vtn/*` Trust Tasks, sign-in links, and status-list
/// checking.
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "client")]
pub mod link;
#[cfg(feature = "client")]
pub mod status_client;
#[cfg(feature = "client")]
pub mod tasks;
#[cfg(feature = "client")]
pub use client::{ClientError, VtnClient, encode_did, encode_query};
#[cfg(feature = "client")]
pub use link::SignInLink;
#[cfg(feature = "client")]
pub use status_client::{CredentialState, StatusChecker};
