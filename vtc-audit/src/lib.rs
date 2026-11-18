//! The Verifiable Trust Community's audit-event vocabulary.
//!
//! [`AuditEvent`] is the closed set of things that can happen to a community,
//! one variant per semantically distinct event, each with a purpose-built data
//! struct (see [`event`]). Everything around it — the envelope, the hash chain,
//! the HMAC actor hashing, the audit-key history, the writer and the signed
//! checkpoints — is node-neutral and lives in `vti_common::audit`, generic over
//! the event payload. This crate pins that payload to [`AuditEvent`] and
//! re-exports the rest, so a VTC subsystem names one crate for its audit
//! trail.
//!
//! It is a leaf (it depends only on `vti-common`) so that every VTC subsystem
//! can emit audit events without depending on `vtc-service` — the same reason
//! `vta-audit` exists for the VTA's subsystems. Before #2568 the vocabulary
//! lived in `vti-common` itself, so every community feature that added an
//! event republished the layer-0 crate every VTA subsystem depends on.
//!
//! ## Wire contract
//!
//! The serialized `type` / `data` tags are what the hash chain commits to (the
//! envelope's `entry_hash` covers the event's `serde_json` encoding), so a
//! renamed variant or field breaks verification of every stored chain that
//! holds it. `tests/stored_chain.rs` holds a chain written before the
//! vocabulary moved here and verifies it, byte for byte.

pub mod event;

pub use event::*;

/// The audit-key history (HKDF-derived initial key, rotations, retention).
pub use vti_common::audit::key_store;

/// Signed audit checkpoints over the chain head.
pub use vti_common::audit::checkpoint;

pub use vti_common::audit::{
    AuditCheckpoint, AuditKey, AuditKeyStore, ChainBreak, ChainVerifier, CheckpointAudit,
    CheckpointBreak, CheckpointClaim, EVENT_VERSION, GENESIS_HASH, KeyId, RotationReason,
    SCHEMA_VERSION, commit_reference, genesis_claim, verify_chain, verify_checkpoints,
};

/// A persisted community audit-log entry: the shared envelope carrying an
/// [`AuditEvent`].
pub type AuditEnvelope = vti_common::audit::AuditEnvelope<AuditEvent>;

/// The community's audit writer: the shared hash-chained writer, writing
/// [`AuditEvent`]s.
pub type AuditWriter = vti_common::audit::AuditWriter<AuditEvent>;
