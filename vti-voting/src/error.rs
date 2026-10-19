//! Errors. Library errors keep their reason.

use predicate_credential_system::Error as PcsError;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum VotingError {
    #[error("pcs: {0}")]
    Pcs(#[from] PcsError),
    #[error("invalid election id {0:?}: 1 to 128 of A-Z a-z 0-9 . _ -")]
    InvalidElectionId(String),
    #[error("the community identifier must be non-empty and free of control characters")]
    InvalidCommunity,
    #[error("this key serves community {expected}, not {actual}")]
    WrongCommunity { expected: String, actual: String },
    #[error("the ticket is for another election")]
    WrongElection,
    #[error("the attestation is not under this election's voter class")]
    WrongClass,
    #[error("the cast does not verify: {0}")]
    ProofRejected(PcsError),
    #[error("a ballot under this ticket was already counted, and this election allows no revote")]
    AlreadyVoted,
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("nullifier store: {0}")]
    Store(String),
}
