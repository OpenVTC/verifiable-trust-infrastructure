//! Errors for the sealed transfer module.

use thiserror::Error;

/// Errors produced by sealed-transfer operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SealedTransferError {
    #[error("hpke error: {0}")]
    Hpke(String),

    #[error("cbor encode error: {0}")]
    CborEncode(String),

    #[error("cbor decode error: {0}")]
    CborDecode(String),

    #[error("base64 decode error: {0}")]
    Base64(String),

    #[error("armor parse error: {0}")]
    Armor(String),

    #[error("crc24 mismatch: expected {expected:06x}, got {got:06x}")]
    Crc24Mismatch { expected: u32, got: u32 },

    #[error("invalid wire format: {0}")]
    Wire(String),

    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("missing chunk(s) for bundle: have {have}, expected {expected}")]
    MissingChunks { have: usize, expected: usize },

    #[error("duplicate chunk index {0}")]
    DuplicateChunk(u16),

    #[error("chunk header mismatch: {0}")]
    ChunkMismatch(String),

    #[error("digest mismatch: expected {expected}, got {got}")]
    DigestMismatch { expected: String, got: String },

    #[error("nonce store: bundle_id already used")]
    NonceReplay,

    #[error("nonce store error: {0}")]
    NonceStore(String),

    #[error("missing producer assertion in chunk 0")]
    MissingAssertion,

    #[error("producer pubkey mismatch (chunk 0 declared {declared}, expected {expected})")]
    ProducerMismatch { declared: String, expected: String },

    #[error("assertion verification failed: {0}")]
    AssertionVerification(String),

    #[error(
        "producer uses PinnedOnly assertion but no expect_digest was supplied — \
         PinnedOnly has no in-band integrity anchor, so the OOB digest MUST be \
         pinned. Either use a DidSigned or Attested producer, or call \
         open_bundle with the digest communicated out-of-band."
    )]
    PinnedOnlyRequiresDigest,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl SealedTransferError {
    pub(crate) fn hpke<E: std::fmt::Display>(e: E) -> Self {
        Self::Hpke(e.to_string())
    }
}
