//! The `rooms/*` Trust Task handlers, once, for every host that serves a room.
//!
//! A data room is served by a **host**: a community (`vtc-service`) or a standalone delivery
//! service (`room-host`). The two are meant to be interchangeable — a room moves between hosts
//! without changing identity — so they must answer every task the same way. They used to do
//! that by holding two copies of the handler layer in step by hand, with parity tests named
//! after the other host (#2575). This crate is the one copy.
//!
//! # What a host supplies
//!
//! [`RoomHost`]: its keyspaces, its room-file host and watches, the resolver its chain
//! verifier and nomination checks use, and the few places where hosts legitimately differ:
//!
//! - **Registration** ([`RoomHost::register`]): who may register a room, and how many. A
//!   community asks its `rooms` policy; a standalone host holds its creator list and ceilings
//!   under one lock. The host also writes the room, because that lock spans the write.
//! - **Charging** ([`RoomHost::charge`]): a community charges each authorized operation to the
//!   presenter's budget in that room; a standalone host charges nothing.
//! - **Audit** ([`RoomHost::audit`]): a community writes its hash-chained audit trail; a
//!   standalone host logs. *What* may be recorded is decided here, by
//!   [`vti_rooms::audit::for_operation`], never by the host.
//! - **Limits** ([`RoomHost::host_limits`]): what `rooms/info/0.5` advertises — a community's
//!   64 KiB record document limit, a standalone host's body cap.
//!
//! # What a host does not
//!
//! Receive the document. The host's spine ([`vti_trust_task_server::Spine`]) verifies the
//! proof over the document as received and hands [`dispatch`] the proven signer: a room
//! operation is authorized by that signer and the chain the room issued, and nothing else
//! (invariant I5 of `docs/05-design-notes/data-rooms.md`). There is no session, ACL or roster
//! anywhere in this crate, and its absence is the point.

#![allow(clippy::result_large_err)]

use std::sync::Arc;

use serde_json::Value;
use trust_tasks_rs::{AsyncDispatcher, Payload, RejectReason, TrustTask};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_rooms::Room;
use vti_rooms::audit::RoomOperation;
use vti_rooms::authz::{AuthorizedAction, AuthorizedCreate};
use vti_trust_task_server::TrustTaskOutcome;

mod files;
mod records;
mod render;

/// Which of a presenter's budgets an authorized room operation is charged to
/// ([`RoomHost::charge`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomTraffic {
    /// Every room task but a file chunk.
    Operation,
    /// `rooms/blobs/upload/chunk` and `rooms/blobs/chunk`.
    Transfer,
}

/// What a room operation leaves in the host's audit trail ([`RoomHost::audit`]).
///
/// The actor is never here: it is the tier's to disclose, through
/// [`vti_rooms::audit::for_operation`] over the room and the authorization the host is
/// handed beside this.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum RoomAudit<'a> {
    /// An operation, and for a read the purpose it was served for (`rooms/records/get/0.4`,
    /// *Purpose of use* item 2; VTI-ACL-106).
    Operation {
        /// What was done.
        operation: RoomOperation,
        /// The record it named, if one.
        record_key: Option<&'a str>,
        /// The purpose a read was served for, or `unstated`.
        purpose: Option<&'a str>,
    },
    /// A retention act — a prune, or a change to the rule — with what the specification asks
    /// a host to keep, never anything a removed record said (`rooms/records/prune/0.2`, *The
    /// audit trail*).
    Retention {
        /// [`RoomOperation::PruneRecords`] or [`RoomOperation::SetRecordRetention`].
        operation: RoomOperation,
        /// The mark, the reason, the retention applied and the kinds asked.
        detail: &'a vti_rooms::record_tasks::RetentionAudit,
    },
    /// A signal-delay change (`rooms/signal-delay/set/0.1` item 5): the setting replaced, the
    /// one recorded and the reason.
    SignalDelay(&'a vti_rooms::signal_delay::SignalDelayAudit),
}

impl RoomAudit<'_> {
    /// The operation recorded.
    #[must_use]
    pub fn operation(&self) -> RoomOperation {
        match self {
            Self::Operation { operation, .. } | Self::Retention { operation, .. } => *operation,
            Self::SignalDelay(_) => RoomOperation::SetSignalDelay,
        }
    }
}

/// A room about to be registered, for the host to govern and write
/// ([`RoomHost::register`]).
#[derive(Debug)]
#[non_exhaustive]
pub struct Registration<'a> {
    /// The proven signer of the request.
    pub presenter: &'a str,
    /// The creation the room's own rule admitted: the presenter is the owner it names.
    pub authorized: &'a AuthorizedCreate,
    /// The room as it will be stored.
    pub room: &'a Room,
    /// The retention the creator asked for, if any — before this host's default filled it.
    pub requested_retention_days: Option<u32>,
}

/// Why a host refused a registration.
#[derive(Debug)]
#[non_exhaustive]
pub enum RegisterRefused {
    /// A storage or governance failure, rendered as every other `AppError` is.
    App(AppError),
    /// A refusal the host words itself.
    Reject(RejectReason),
}

impl From<AppError> for RegisterRefused {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

/// What a host lends the shared handlers: its state, and the few decisions that are its own.
///
/// Object-safe, so one dispatcher serves every host ([`dispatch`]).
#[async_trait::async_trait]
pub trait RoomHost: Send + Sync + 'static {
    /// The rooms (`vti_rooms::ROOMS_KEYSPACE`).
    fn rooms(&self) -> &KeyspaceHandle;
    /// The rooms' records.
    fn records(&self) -> &KeyspaceHandle;
    /// The rooms' epoch key chains and commits.
    fn epoch_links(&self) -> &KeyspaceHandle;
    /// Each room's revocation list.
    fn revocations(&self) -> &KeyspaceHandle;
    /// Room files.
    fn files(&self) -> &vti_rooms::blobs::BlobHost;
    /// The watches members armed.
    fn watches(&self) -> &vti_rooms::watch::RoomWatches;
    /// How a DID resolves to the key that signed a credential, for the chain verifier and a
    /// nomination's check.
    fn resolver(&self) -> vti_common::auth::TrustTaskVmResolver;
    /// What `rooms/info/0.5` advertises of this host's own limits.
    fn host_limits(&self) -> vti_rooms::signal_delay::HostLimits;
    /// Whether an `open` room's `message` or `reaction` takes a new version only from its
    /// original author (`rooms/records/put/0.5` Host item 15, a MAY).
    async fn refuses_rewrites_by_others(&self) -> bool;

    /// Charge an operation the room has just authorized to `presenter`'s budget in
    /// `room_id`, before any of its work is done. `false` refuses it: the task answers an
    /// empty `429`, which the host's transport replaces with its own refusal.
    fn charge(&self, _room_id: &str, _presenter: &str, _traffic: RoomTraffic) -> bool {
        true
    }

    /// Decide whether to host `registration.room` and, if so, write it
    /// (`vti_rooms::storage::create_room`) and do whatever this host does for a new room.
    /// The decision and the write are one step, so a host holding a ceiling under a lock
    /// cannot be overshot by concurrent registrations.
    async fn register(&self, registration: Registration<'_>) -> Result<(), RegisterRefused>;

    /// A room changed owner (`rooms/owner/{transfer,claim}`).
    fn owner_changed(&self, _room_id: &str) {}

    /// Record a room operation (§8 of the data-rooms design note). A failed write is the
    /// host's to log: the operation already succeeded.
    async fn audit(&self, room: &Room, authorized: &AuthorizedAction, event: RoomAudit<'_>);
}

/// What a `rooms/*` handler needs that is not in the document: the host, and the proven
/// signer.
///
/// Owned, because the dispatcher requires each handler's future to be `'static`.
#[derive(Clone)]
pub struct RoomCtx {
    host: Arc<dyn RoomHost>,
    presenter: String,
}

/// The registered handlers, and which of them only read.
struct Rooms {
    dispatcher: AsyncDispatcher<RoomCtx, TrustTaskOutcome>,
    reads: Vec<&'static str>,
}

impl Rooms {
    /// Register a task that changes room state.
    fn write<P, F, Fut>(mut self, handler: F) -> Self
    where
        P: Payload + 'static,
        F: Fn(TrustTask<P>, RoomCtx) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = TrustTaskOutcome> + Send + 'static,
    {
        self.dispatcher = self.dispatcher.on_async(handler);
        self
    }

    /// Register a task that only reads.
    fn read<P, F, Fut>(mut self, handler: F) -> Self
    where
        P: Payload + 'static,
        F: Fn(TrustTask<P>, RoomCtx) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = TrustTaskOutcome> + Send + 'static,
    {
        self.reads.push(<P as Payload>::TYPE_URI);
        self.dispatcher = self.dispatcher.on_async(handler);
        self
    }
}

/// The routing table, built once.
///
/// Each registration names a payload type and the framework derives the rest — the type URI
/// from `Payload::TYPE_URI`, the downcast, version routing, `unsupportedType` versus
/// `unsupportedVersion`. [`served_uris`] and [`is_consequential`] are read off it, so neither
/// can disagree with what is served.
static ROOMS: std::sync::LazyLock<Rooms> = std::sync::LazyLock::new(|| {
    use files as f;
    use records as r;
    Rooms {
        dispatcher: AsyncDispatcher::new(),
        reads: Vec::new(),
    }
    .write(r::handle_curate_record)
    .write(r::handle_mint_epoch)
    .read(r::handle_epoch_commits)
    .write(r::handle_transfer_owner)
    .write(r::handle_claim_owner)
    .read(f::handle_info_v3)
    .read(f::handle_info_v4)
    .read(f::handle_info_v5)
    .read(f::handle_list_records_v5)
    .read(f::handle_list_records_v6)
    .read(f::handle_list_records_v7)
    .read(f::handle_list_records_v8)
    .write(f::handle_records_prune)
    .read(f::handle_epoch_chain_v2)
    .write(f::handle_epoch_prune_v2)
    .read(f::handle_get_record_v2)
    .read(f::handle_get_record_v3)
    .read(f::handle_get_record_v4)
    .read(f::handle_download_chunk)
    .read(f::handle_usage)
    .write(f::handle_upload_begin_v2)
    .write(f::handle_upload_chunk_v2)
    .write(f::handle_upload_commit_v2)
    .write(f::handle_upload_abort_v2)
    .read(f::handle_blob_get_v2)
    .write(f::handle_watch)
    .write(f::handle_watch_v2)
});

/// Tasks whose payload carries members a host stores and serves back **exactly as
/// received**, so they are read from the document's JSON rather than a typed round trip
/// (which rewrites a `validUntil`, or an `ext` it does not model): `rooms/records/put` 0.3 –
/// 0.5 (an open room's cleartext, consumer item 11), `rooms/create` 0.2 and 0.3 and
/// `rooms/records/retention/set/0.1` (the record retention, recorded as given), and
/// `rooms/signal-delay/set/0.1`. Each is still checked against its generated type before
/// anything is stored. Every one changes room state.
const AS_RECEIVED_URIS: &[&str] = &[
    vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
    vti_rooms::wire::ROOMS_RECORDS_PUT_V4_TYPE,
    vti_rooms::wire::ROOMS_RECORDS_PUT_V5_TYPE,
    vti_rooms::wire::ROOMS_CREATE_V2_TYPE,
    vti_rooms::wire::ROOMS_RECORDS_RETENTION_SET_TYPE,
    vti_rooms::wire::ROOMS_CREATE_V3_TYPE,
    vti_rooms::wire::ROOMS_SIGNAL_DELAY_SET_TYPE,
];

/// `rooms/revocations/{put,get}/0.1`: served beside the dispatcher, over the payload as
/// received, because a list must reach its verifier exactly as the room signed it.
const REVOCATION_URIS: &[&str] = &[
    vti_rooms::revocation_tasks::PUT_TYPE,
    vti_rooms::revocation_tasks::GET_TYPE,
];

/// Does a host serve `type_uri` as a room task?
#[must_use]
pub fn serves(type_uri: &str) -> bool {
    ROOMS.dispatcher.registered_uris().contains(&type_uri)
        || REVOCATION_URIS.contains(&type_uri)
        || AS_RECEIVED_URIS.contains(&type_uri)
}

/// Every URI the family serves — the served list, not a copy of one.
#[must_use]
pub fn served_uris() -> Vec<&'static str> {
    let mut uris = ROOMS.dispatcher.registered_uris();
    uris.extend_from_slice(REVOCATION_URIS);
    uris.extend_from_slice(AS_RECEIVED_URIS);
    uris
}

/// Whether `type_uri` changes room state, and so has its answer kept in a host's
/// duplicate-execution record — a redelivered write is answered with the result it already
/// had, a duplicate read with nothing (a chunk download is large, and a replay is owed
/// nothing).
///
/// Read off the registrations: a task is a read only where it was registered as one, so a
/// new task nobody classified lands on the side that keeps its answer.
#[must_use]
pub fn is_consequential(type_uri: &str) -> bool {
    !(ROOMS.reads.contains(&type_uri) || type_uri == vti_rooms::revocation_tasks::GET_TYPE)
}

/// Dispatch a room task to its handler, as `presenter` — the signer the host's spine proved.
///
/// Whatever moved the room — a put of any kind, a curation, a retraction, a prune, a profile
/// written — then fires the watches it put past their watermark, alike (`rooms/watch/0.1`
/// Host item 6): only after the task committed, and never failing it.
pub async fn dispatch(
    host: Arc<dyn RoomHost>,
    doc: TrustTask<Value>,
    presenter: &str,
) -> TrustTaskOutcome {
    let moved_room = doc.payload["roomId"].as_str().map(str::to_string);
    let ctx = RoomCtx {
        host: Arc::clone(&host),
        presenter: presenter.to_string(),
    };
    let outcome = dispatch_task(doc, ctx).await;
    if outcome.status.is_success()
        && let Some(room_id) = &moved_room
    {
        host.watches().room_moved(room_id).await;
    }
    outcome
}

/// [`dispatch`], without the watches.
async fn dispatch_task(doc: TrustTask<Value>, ctx: RoomCtx) -> TrustTaskOutcome {
    let type_uri = doc.type_uri.to_string();
    if AS_RECEIVED_URIS.contains(&type_uri.as_str()) {
        return match type_uri.as_str() {
            vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE => {
                files::handle_put_record_v3(doc, ctx).await
            }
            vti_rooms::wire::ROOMS_RECORDS_PUT_V4_TYPE => {
                files::handle_put_record_v4(doc, ctx).await
            }
            vti_rooms::wire::ROOMS_RECORDS_PUT_V5_TYPE => {
                files::handle_put_record_v5(doc, ctx).await
            }
            vti_rooms::wire::ROOMS_CREATE_V2_TYPE => files::handle_create_v2(doc, ctx).await,
            vti_rooms::wire::ROOMS_CREATE_V3_TYPE => files::handle_create_v3(doc, ctx).await,
            vti_rooms::wire::ROOMS_SIGNAL_DELAY_SET_TYPE => {
                files::handle_signal_delay_set(doc, ctx).await
            }
            _ => files::handle_retention_set(doc, ctx).await,
        };
    }
    if REVOCATION_URIS.contains(&type_uri.as_str()) {
        let put = type_uri == vti_rooms::revocation_tasks::PUT_TYPE;
        return files::handle_revocations(doc, ctx, put).await;
    }
    match ROOMS
        .dispatcher
        .dispatch_or_reject(doc, ctx, format!("urn:uuid:{}", uuid::Uuid::new_v4()))
        .await
    {
        Ok(outcome) => outcome,
        Err(err_doc) => vti_trust_task_server::reject::error_response(err_doc),
    }
}

/// Seconds since the Unix epoch.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every served URI is either registered as a read or kept as a write, and the two
    /// classes are what room-host's hand list said before it was derived.
    #[test]
    fn reads_are_the_reads() {
        let reads: Vec<&str> = served_uris()
            .into_iter()
            .filter(|u| !is_consequential(u))
            .collect();
        for uri in [
            vti_rooms::wire::ROOMS_EPOCH_CHAIN_V2_TYPE,
            vti_rooms::wire::ROOMS_EPOCH_COMMITS_TYPE,
            vti_rooms::blob_tasks::BLOB_GET_V2_TYPE,
            vti_rooms::blob_tasks::DOWNLOAD_CHUNK_TYPE,
            vti_rooms::blob_tasks::USAGE_TYPE,
            vti_rooms::blob_tasks::GET_V2_TYPE,
            vti_rooms::blob_tasks::GET_V3_TYPE,
            vti_rooms::blob_tasks::GET_V4_TYPE,
            vti_rooms::record_tasks::LIST_V5_TYPE,
            vti_rooms::record_tasks::LIST_V6_TYPE,
            vti_rooms::record_tasks::LIST_V7_TYPE,
            vti_rooms::record_tasks::LIST_V8_TYPE,
            vti_rooms::record_tasks::INFO_V3_TYPE,
            vti_rooms::signal_delay::INFO_V4_TYPE,
            vti_rooms::signal_delay::INFO_V5_TYPE,
            vti_rooms::revocation_tasks::GET_TYPE,
        ] {
            assert!(reads.contains(&uri), "{uri} is a read");
        }
        assert_eq!(reads.len(), 16, "no other task is a read: {reads:?}");
        for uri in AS_RECEIVED_URIS {
            assert!(is_consequential(uri), "{uri} changes room state");
        }
    }

    /// Nothing is served twice.
    #[test]
    fn every_uri_is_served_once() {
        let mut uris = served_uris();
        let n = uris.len();
        uris.sort_unstable();
        uris.dedup();
        assert_eq!(uris.len(), n);
    }
}
