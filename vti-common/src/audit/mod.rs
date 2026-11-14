//! Audit log infrastructure — versioned envelope with HMAC-hashed
//! actor / target identifiers and an in-store key history that
//! survives right-to-be-forgotten rotations.
//!
//! See spec §11 of `docs/05-design-notes/vtc-mvp.md` for the design
//! rationale.
//!
//! ## Module layout
//!
//! - **No event vocabulary.** The envelope and the writer are generic over
//!   the event payload; each service owns its own: `vtc-audit`'s
//!   `AuditEvent` for a community, `vta-audit`'s `VtaAuditEvent` for an
//!   agent (#2568). A community feature adding an event therefore edits
//!   and republishes `vtc-audit`, not this layer-0 crate.
//! - [`envelope`] — the [`AuditEnvelope`] wire shape (event id,
//!   version, timestamps, HMAC-hashed + plaintext identifier pairs).
//! - [`key_store`] — the [`AuditKeyStore`] managing per-community
//!   `audit_key` history: HKDF-derived initial, fresh-random
//!   rotations, indefinite retention so pre-rotation hashes stay
//!   verifiable during compliance investigations.
//! - [`writer`] — [`AuditWriter`] takes events + identifiers, hashes
//!   the identifiers with the active key, and persists the envelope
//!   into an `audit` keyspace.

pub mod checkpoint;
pub mod envelope;
pub mod key_store;
pub mod writer;

pub use checkpoint::{
    AuditCheckpoint, CheckpointAudit, CheckpointBreak, CheckpointClaim, genesis_claim,
    verify_checkpoints,
};
pub use envelope::{
    AuditEnvelope, ChainBreak, ChainVerifier, EVENT_VERSION, GENESIS_HASH, SCHEMA_VERSION,
    verify_chain,
};
pub use key_store::{AuditKey, AuditKeyStore, KeyId, RotationReason};
pub use writer::{AuditWriter, commit_reference};

#[cfg(test)]
pub(crate) mod test_event;
