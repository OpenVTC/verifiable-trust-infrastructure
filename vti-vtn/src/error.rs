use thiserror::Error;

use crate::model::EntryState;

#[derive(Debug, Error)]
pub enum VtnError {
    #[error("credential error: {0}")]
    Credential(#[from] dtg_credentials::DTGCredentialError),

    #[error("data integrity error: {0}")]
    DataIntegrity(#[from] affinidi_data_integrity::DataIntegrityError),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid DID: {0}")]
    InvalidDid(String),

    #[error("transition `{event}` is not allowed from state `{from}`")]
    InvalidTransition {
        from: EntryState,
        event: &'static str,
    },

    #[error("credential rejected: {0}")]
    Rejected(String),

    #[error("status list is full")]
    StatusListFull,

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T, E = VtnError> = std::result::Result<T, E>;
