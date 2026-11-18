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
//!   `VtaDidRecordMissing`) — or, for a `did:webs` VTA, its
//!   `WebsDidRecord` ([`super::webs_backing`]),
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
    /// pass it through to the publish step without re-reading the config lock.
    pub vta_did: String,
    /// The VTA's current DID document as JSON. Mutated by the per-op
    /// `with_*_service` / `without_*_service` patchers.
    pub current_doc: JsonValue,
    /// What the document is derived from, which is also what the publish step
    /// ([`super::service_lifecycle::publish_patch`]) writes a new version of.
    pub backing: VtaDocBacking,
}

/// What a VTA's own DID document is held as: the method-specific state the
/// publish step needs and the generic path never reads.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum VtaDocBacking {
    /// A `did:webvh` VTA: its record and its log. A new version is a new log
    /// entry (`update_did_webvh`).
    Webvh {
        /// The WebVH SCID for the VTA's DID. Stable across log entries.
        scid: String,
        /// Raw on-disk did.jsonl, exactly as the VTA published it.
        did_log: String,
        /// `WebvhDidRecord` for the VTA's DID.
        record: Box<WebvhDidRecord>,
    },
    /// A `did:webs` VTA (alpha, VTI-KEY-001): its record, whose key event
    /// stream the document is derived from. A new version is a set of
    /// interaction events replacing its designated services
    /// (`update_did_webs`); see [`super::webs_backing`].
    #[cfg(feature = "webs")]
    Webs {
        record: Box<crate::webs_store::WebsDidRecord>,
    },
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
    /// A `did:webs` VTA whose identity its host does not serve yet: first
    /// boot publishes it (`server::publish_own_webs_identity`), and nothing is
    /// published over it before then. Each op reports it as its
    /// `VtaDidLogMissing` — the DID has no published log.
    #[error(
        "VTA DID `{0}` is not published yet; it is published at first boot — restart the VTA once its host accepts it"
    )]
    VtaDidNotPublished(String),
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

/// Load the state every protocol op reads before doing anything else: the
/// VTA DID from the config, then its current document from its own store — a
/// `did:webvh`'s log (`webvh_ks`), or a `did:webs`'s key event stream
/// (`webs_ks`), switched on the DID's method.
///
/// The config lock is acquired *and dropped* inside this function
/// before the fjall I/O, matching the pattern the original per-op
/// `read_preconditions` used to avoid holding the read-lock across an
/// `await`.
pub async fn load_vta_doc_state(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
    webs_ks: &KeyspaceHandle,
) -> Result<VtaDocState, ProtocolPreconditionError> {
    let vta_did = {
        let cfg = config.read().await;
        cfg.vta_did
            .clone()
            .ok_or(ProtocolPreconditionError::VtaDidNotConfigured)?
    };

    #[cfg(feature = "webs")]
    if vta_did.starts_with("did:webs:") {
        return super::webs_backing::load(webs_ks, vta_did).await;
    }
    let _ = webs_ks;

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
        current_doc,
        backing: VtaDocBacking::Webvh {
            scid,
            did_log,
            record: Box::new(record),
        },
    })
}
