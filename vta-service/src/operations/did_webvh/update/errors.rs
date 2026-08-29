//! Errors produced by the `update` submodule + their mapping to
//! [`AppError`].

use crate::error::AppError;

/// Errors produced by
/// [`crate::operations::did_webvh::update::update_did_webvh`] and
/// [`crate::operations::did_webvh::update::rotate_did_webvh_keys`].
///
/// `From<UpdateDidWebvhError> for AppError` maps each variant to a stable
/// HTTP status: `NotFound` and `Forbidden` both surface as 404 to avoid
/// leaking cross-context existence information; validation errors — including
/// `Rejected`, a transition webvh refuses — map to 400; concurrency conflicts
/// map to 409; everything else is 500.
#[derive(Debug, thiserror::Error)]
pub enum UpdateDidWebvhError {
    /// SCID not found, or the DID exists but is owned by a different
    /// context than the caller has admin rights for. Both cases collapse
    /// to a single error variant + 404 status to avoid leaking
    /// cross-context existence.
    #[error("did not found: {0}")]
    NotFound(String),

    /// Caller authenticated successfully but is not an admin of the
    /// DID's context. Mapped to 404 by the REST/DIDComm boundary —
    /// see [`From<UpdateDidWebvhError> for AppError`].
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Optimistic-concurrency mismatch: the DID's `log_entry_count`
    /// changed between load and write. Caller should re-read and retry.
    #[error("concurrent update: {0}")]
    Conflict(String),

    /// Caller-supplied DID document is malformed (missing `@context`,
    /// `id` doesn't match the existing DID, verificationMethod entries
    /// missing required fields, …).
    #[error("invalid document: {0}")]
    InvalidDocument(String),

    /// Caller-supplied witness configuration is invalid (witness DID
    /// did not resolve, malformed witness entry, …).
    #[error("invalid witness configuration: {0}")]
    InvalidWitness(String),

    /// Caller-supplied watcher URL is invalid (parse error, wrong
    /// scheme, query/fragment present, …).
    #[error("invalid watcher: {0}")]
    InvalidWatcher(String),

    /// Underlying `didwebvh-rs` library error *other than* a refused
    /// transition: a malformed stored log, a missing record, an
    /// orchestration invariant that broke. Surface as 500 — there is
    /// nothing the caller can do differently.
    ///
    /// A transition webvh refuses is [`Self::Rejected`], not this.
    #[error("webvh library error: {0}")]
    Library(String),

    /// The webvh state machine refused the transition this request asked
    /// for — parameters that contradict the DID's current state, a
    /// pre-rotation commitment that cannot be satisfied, a document the
    /// chain will not accept.
    ///
    /// Split out from [`Self::Library`] because the two need opposite
    /// treatment at the wire boundary. An internal error is deliberately
    /// opaque: Trust Task framework 0.5.0 forbids an `internalError`
    /// message from revealing consumer-internal state, so the cause goes
    /// to the log and the caller gets a fixed string. That is right for a
    /// broken invariant and wrong here — it left an operator whose
    /// *request* was refused reading "internal error: the consumer could
    /// not complete this task" with the reason visible only in the VTA's
    /// log.
    ///
    /// Returning the reason leaks nothing: every value webvh can name in
    /// one (`updateKeys`, `nextKeyHashes`, version ids, the SCID) is
    /// published in the DID's own log, and reaching this code at all
    /// requires admin in that DID's context — so the caller can already
    /// fetch all of it.
    #[error("webvh rejected this update: {0}")]
    Rejected(String),

    /// Persistence failure (keys keyspace, webvh keyspace, contexts
    /// keyspace).
    #[error("persistence error: {0}")]
    Persistence(String),

    /// Failed to publish the new log entry to the webvh hosting server.
    /// The local log was written successfully; the operator can retry
    /// publication independently.
    #[error("publish error: {0}")]
    Publish(String),
}

impl From<UpdateDidWebvhError> for AppError {
    fn from(err: UpdateDidWebvhError) -> Self {
        match err {
            // Both NotFound and Forbidden map to NotFound at the wire
            // boundary so an admin of context A can't probe whether a
            // DID exists in context B.
            UpdateDidWebvhError::NotFound(msg) | UpdateDidWebvhError::Forbidden(msg) => {
                AppError::NotFound(msg)
            }
            UpdateDidWebvhError::Conflict(msg) => AppError::Conflict(msg),
            UpdateDidWebvhError::InvalidDocument(msg)
            | UpdateDidWebvhError::InvalidWitness(msg)
            | UpdateDidWebvhError::InvalidWatcher(msg) => AppError::Validation(msg),
            UpdateDidWebvhError::Library(msg)
            | UpdateDidWebvhError::Publish(msg)
            | UpdateDidWebvhError::Persistence(msg) => AppError::Internal(msg),
            // Framed rather than passed through bare, so the caller reads what
            // refused their update and not just its complaint. The wording
            // mirrors the variant's `#[error]` attribute above, and the
            // `rejected_carries_the_reason_to_the_caller` test pins it.
            UpdateDidWebvhError::Rejected(msg) => {
                AppError::Validation(format!("webvh rejected this update: {msg}"))
            }
        }
    }
}
