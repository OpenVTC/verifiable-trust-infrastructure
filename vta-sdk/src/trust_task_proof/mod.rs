//! Verifying the Data-Integrity proof on a Trust-Task document.
//!
//! # Why this is in the SDK and not beside the services
//!
//! It used to live in `vti-common`, which is where the *services* verify their
//! inbound requests. That was the only consumer, so it was the only reasonable
//! home — until the other direction acquired one: a **client** verifying the
//! response it got back.
//!
//! Both directions are the same operation over the same document shape, and the
//! part worth not duplicating is [`vm_resolver`]. Resolving a
//! `verificationMethod` looks trivial and is not: a DID document may name its
//! methods absolutely (`did:webvh:…:glenn#key-0`) or relatively (`#key-0`),
//! while a proof always names them absolutely, so a resolver that accepts only
//! the spelling it expects rejects perfectly good documents from conforming
//! peers. A second copy of that would drift, and drift here means a verifier
//! that refuses honest documents or accepts dishonest ones.
//!
//! `vti-common` re-exports everything below, so every existing call site is
//! unchanged.
//!
//! # What verification does and does not establish
//!
//! It answers *who signed this, and is it unaltered*. It does **not** answer
//! whether that party was entitled to the outcome, and it does not check that
//! the signer is who you expected — [`verify::verify_trust_task_proof_with`]
//! returns the proven signer precisely so the caller can make that comparison
//! itself. A proof by somebody else's key verifies perfectly well.

pub mod verify;
pub mod vm_resolver;

pub use verify::{DiProofError, verify_trust_task_proof, verify_trust_task_proof_with};
pub use vm_resolver::TrustTaskVmResolver;
