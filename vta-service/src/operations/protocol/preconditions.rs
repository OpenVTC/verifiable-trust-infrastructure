//! Shared "load VTA document state" helper for the runtime
//! service-management ops.
//!
//! Every op under `protocol/` (`enable_rest`, `disable_rest`,
//! `update_rest`, `rollback_rest`, and the four DIDComm peers) used
//! to start with a near-identical 25-line block:
//!
//! - read `vta_did` from the AppConfig (or fail
//!   `VtaDidNotConfigured`),
//! - load the `WebvhDidRecord` for it (or fail
//!   `VtaDidRecordMissing`),
//! - load the on-disk `did.jsonl` (or fail `VtaDidLogMissing`),
//! - parse the latest log entry's state into a JSON document (or
//!   fail through `CurrentDocumentError`).
//!
//! That ~30 line × 8 op duplication is now this module's
//! [`load_vta_doc_state`] helper, with [`ProtocolPreconditionError`]
//! as the common error type. Each op converts the precondition
//! error into its own variant via `From` (the common variants —
//! `VtaDidNotConfigured`, `VtaDidRecordMissing`, etc. — already
//! exist on every per-op enum, so the `From` impl is small).

use std::sync::Arc;
use tokio::sync::RwLock;

use serde_json::Value as JsonValue;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::store::KeyspaceHandle;
use crate::webvh_store;
use vta_sdk::webvh::WebvhDidRecord;

use super::document::{CurrentDocumentError, current_document_from_log};

/// State every protocol op needs to read before doing anything else.
/// Returned by [`load_vta_doc_state`].
#[derive(Debug, Clone)]
pub struct VtaDocState {
    /// The VTA's own DID, copied out of `AppConfig` so callers can
    /// pass it through to [`crate::operations::did_webvh::
    /// update_did_webvh`] without re-reading the config lock.
    pub vta_did: String,
    /// The WebVH SCID for the VTA's DID. Stable across log entries.
    pub scid: String,
    /// Raw on-disk did.jsonl, exactly as the VTA published it.
    /// Carried through so callers that need to splice the new entry
    /// onto the existing log don't have to re-read.
    pub did_log: String,
    /// Latest log entry's `state` field as parsed JSON. Mutated by
    /// the per-op `with_*_service` / `without_*_service` patchers.
    pub current_doc: JsonValue,
    /// `WebvhDidRecord` for the VTA's DID — carried so callers that
    /// pass it to `update_did_webvh` don't re-load.
    pub record: WebvhDidRecord,
}

/// Failures from [`load_vta_doc_state`]. Each per-op error enum
/// implements `From<ProtocolPreconditionError> for SelfError` (a
/// 5-line mechanical wrap; see e.g. `disable_rest::DisableRestError`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolPreconditionError {
    #[error("VTA DID is not configured — run `vta setup` first")]
    VtaDidNotConfigured,
    #[error("VTA DID `{0}` has no webvh record — re-run `vta setup`")]
    VtaDidRecordMissing(String),
    #[error("VTA DID `{0}` has no published log on disk")]
    VtaDidLogMissing(String),
    #[error("the on-disk did.jsonl is empty — cannot read current document")]
    EmptyLog,
    #[error("storage error while loading VTA document state: {0}")]
    Storage(String),
    #[error("could not parse the VTA's current DID document from the log: {0}")]
    DocumentParse(String),
}

impl From<AppError> for ProtocolPreconditionError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<CurrentDocumentError> for ProtocolPreconditionError {
    fn from(value: CurrentDocumentError) -> Self {
        match value {
            CurrentDocumentError::EmptyLog => Self::EmptyLog,
            CurrentDocumentError::Parse(s) => Self::DocumentParse(s),
        }
    }
}

/// Load the four pieces of state every protocol op reads before doing
/// anything else. Cheap — just a config read, two fjall lookups, and
/// a JSON parse on the latest log entry.
///
/// The config lock is acquired *and dropped* inside this function
/// before the fjall I/O, matching the pattern the original per-op
/// `read_preconditions` used to avoid holding the read-lock across an
/// `await`.
pub async fn load_vta_doc_state(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<VtaDocState, ProtocolPreconditionError> {
    let vta_did = {
        let cfg = config.read().await;
        cfg.vta_did
            .clone()
            .ok_or(ProtocolPreconditionError::VtaDidNotConfigured)?
    };

    let record = webvh_store::get_did(webvh_ks, &vta_did)
        .await?
        .ok_or_else(|| ProtocolPreconditionError::VtaDidRecordMissing(vta_did.clone()))?;
    let scid = record.scid.clone();

    let did_log = webvh_store::get_did_log(webvh_ks, &vta_did)
        .await?
        .ok_or_else(|| ProtocolPreconditionError::VtaDidLogMissing(vta_did.clone()))?;
    let current_doc = current_document_from_log(&did_log)?;

    Ok(VtaDocState {
        vta_did,
        scid,
        did_log,
        current_doc,
        record,
    })
}
