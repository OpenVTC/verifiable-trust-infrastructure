#![allow(clippy::result_large_err)]

//! The receive side of a Trust Task service: everything a document goes
//! through between arriving and being answered, independent of which service
//! answers it.
//!
//! A service supplies its own pieces and gets the pipeline:
//!
//! | Piece | Trait | What the service provides |
//! |---|---|---|
//! | Spec policy | [`SpecPolicySource`] | Its generated spec crate's `schema_index::spec_policy_for` |
//! | Size | [`SizeGate`] | A per-type table ([`SizeTable`]) or its own gate |
//! | Proof | [`ProofVerifier`] | [`ResolverProofVerifier`] over its DID resolver |
//! | Recipient, extra gates | [`SpineHooks`] | Its DID; any pre- or post-verification rule of its own |
//! | Admission | [`VerifiedAdmission`] | Optional per-signer rate limit |
//! | Duplicate ids | [`AcceptedIdStore`] | Its keyspace ([`StoreAcceptedIds`]; [`InMemoryAcceptedIds`] for tests) |
//! | Routing | [`Dispatcher`] | Its `match type_uri` |
//! | Signing | [`ResponseSigner`] | Its response key |
//!
//! [`Spine::receive`] runs the pipeline (see [`spine`] for the order and the
//! rules each step enforces); [`http::routes`] mounts it at
//! `POST /v1/trust-tasks`. The [`reject`] and [`typed`] helpers build the
//! answers a handler returns.
//!
//! The crate depends on no service and no generated spec crate: which tasks
//! exist, and what their specifications require, is the service's to say.

pub mod accepted;
pub mod accepted_store;
pub mod context;
pub mod http;
pub mod outcome;
pub mod reject;
pub mod sign;
pub mod size;
pub mod spine;
pub mod typed;
pub mod verify;

pub use accepted::{
    Acceptance, AcceptedIdStore, AcceptedIdsError, Claim, ClaimSettle, FALLBACK_RETENTION_SECS,
    InMemoryAcceptedIds,
};
pub use accepted_store::StoreAcceptedIds;
pub use context::{ArrivalCtx, Transport};
pub use outcome::TrustTaskOutcome;
pub use sign::{ResponseSigner, sign_response};
pub use size::{SizeCharge, SizeGate, SizeTable};
pub use spine::{
    BoxFuture, Dispatcher, SpecPolicySource, Spine, SpineHooks, VerifiedAdmission,
    default_freshness_policy, retain_until,
};
pub use verify::{ProofVerifier, ResolverProofVerifier};
