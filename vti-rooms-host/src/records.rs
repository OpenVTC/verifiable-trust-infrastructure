//! Rooms, records, epochs and ownership: `rooms/create`, `rooms/records/{put,get,list,curate}`,
//! `rooms/epoch/{mint,chain,prune,commits}` and `rooms/owner/{transfer,claim}`.
//!
//! Every handler does the same four things in the same order — parse, load the room,
//! authorize, act — and each of those lives in `vti-rooms`: `wire` owns the shapes, `storage`
//! the invariants, `authz` the decision. The room is loaded first and the presentation
//! authorized **against that room**: visibility is a property of the room, and the
//! private-tier subject-binding requirement cannot be checked without knowing the tier.

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_common::error::AppError;
use vti_rooms::audit::RoomOperation;
use vti_rooms::authz::{self, Action};
use vti_rooms::storage;
use vti_rooms::wire::{
    ChainBody, ChainResponse, ClaimOwnerBody, CommitsBody, CommitsResponse, CreateRoomBody,
    CreateRoomResponse, CurateRecordBody, CurateRecordResponse, GetRecordBody, GetRecordResponse,
    ListRecordsBody, ListRecordsResponse, MintEpochBody, MintEpochResponse, OwnerResponse,
    PruneBody, PruneResponse, PutRecordBody, PutRecordResponse, TransferOwnerBody,
};
use vti_rooms::{Record, RecordStatus, Room};
use vti_rooms_dtg::{DataIntegrityKeys, nomination};
use vti_trust_task_server::TrustTaskOutcome;
use vti_trust_task_server::reject::{reject_with, success_response};

use crate::render::{app_error_to_reject, refused, render};
use crate::{RegisterRefused, Registration, RoomAudit, RoomCtx, RoomTraffic, now};

/// Default retention when a creator does not state one.
///
/// Ninety days after the epoch lapses. Long enough that a room is not lost to a quiet month,
/// short enough that an abandoned one does not accumulate forever.
pub const DEFAULT_RETENTION_DAYS: u32 = 90;

/// One epoch lifetime in seconds — how long a newly created room is live before it needs
/// renewing. Not a per-room parameter yet: `rooms/create` has no member for it, and inventing
/// one locally would put a host's rooms out of conformance with the schema.
const EPOCH_LIFETIME_DAYS_SECS: u64 =
    vti_rooms::lifecycle::DEFAULT_EPOCH_LIFETIME_DAYS as u64 * 24 * 60 * 60;

/// Register a room: `rooms/create/0.2`, which also records the room's record retention as
/// given and echoes it, and `rooms/create/0.3` (`signal_delay` given), which also records and
/// always echoes the signal delay.
///
/// The creator brings the room's identifier; a host does not assign one. A room identified by
/// something its host chose could not move to another host without changing identity, and
/// portability is the property the whole family rests on.
pub(crate) async fn create_room<P>(
    doc: &TrustTask<P>,
    ctx: &RoomCtx,
    req: &CreateRoomBody,
    record_retention: Option<vti_rooms::record_retention::RecordRetention>,
    signal_delay: Option<vti_rooms::signal_delay::SignalDelay>,
) -> TrustTaskOutcome {
    let presenter = ctx.presenter.as_str();

    // The one room operation no chain can authorize: the room has issued nothing yet, so all
    // a host has is the proof on the request, which the host's spine verified. That proof is
    // what makes `ownerDid` a fact rather than a field.
    let terms = match vti_rooms::wire::CreateRoomTerms::from_request(req) {
        Ok(t) => t,
        Err(reason) => return app_error_to_reject(doc, &AppError::Validation(reason)),
    };
    let authorized = match authz::authorize_create(&req.room_id, &req.owner_did, presenter) {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    if let Err(o) = ctx.charged(authorized.room_id(), presenter, RoomTraffic::Operation) {
        return o;
    }

    let room = Room {
        room_id: authorized.room_id().to_string(),
        // From the authorization rather than the payload. The two are equal — that is what
        // was just established — and taking it from here is what keeps them equal if this
        // ever grows a second way to be authorized.
        owner_did: authorized.owner_did().to_string(),
        visibility: terms.visibility,
        // The owner's choice, `chained` when unstated: joining a room means being able to
        // read it, and the alternative loses the room's contents at each membership change.
        retention_policy: terms.retention_policy,
        // What the caller asked for, or the default that draws no expectation.
        anchor_cadence: terms.anchor_cadence,
        epoch: 1,
        next_version: 1,
        retention_days: terms.retention_days.unwrap_or(DEFAULT_RETENTION_DAYS),
        // A room is live from creation for one epoch lifetime; minting the next epoch renews
        // it. Nothing else moves this clock — see `vti_rooms::lifecycle`.
        epoch_expires_at: Some(now() + EPOCH_LIFETIME_DAYS_SECS),
        created_at: now(),
        updated_at: now(),
        mirror_of: None,
        // As given (create 0.2): never shortened, and `{}` records none.
        record_retention: record_retention.filter(|r| !r.is_empty() || r.ext.is_some()),
        last_prune: None,
        // As given (create 0.3), `randomised` when absent or at 0.2.
        signal_delay: signal_delay.unwrap_or_default(),
        epoch_floor: None,
        frozen_at: None,
    };

    // Registering a room is asking a host for its disk, which is the host's to refuse; every
    // operation *within* the room stays authorized by the room's own credentials.
    let registered = ctx
        .host
        .register(Registration {
            presenter,
            authorized: &authorized,
            room: &room,
            requested_retention_days: terms.retention_days,
        })
        .await;
    match registered {
        Ok(()) => {}
        Err(RegisterRefused::App(e)) => return app_error_to_reject(doc, &e),
        Err(RegisterRefused::Reject(reason)) => return reject_with(doc, reason),
    }

    let response = CreateRoomResponse {
        room_id: req.room_id.clone(),
        epoch: 1,
        // What was recorded, never what was asked: the two differ on a host that predates
        // this member, and echoing the request would tell a caller their choice took effect
        // when it did not.
        anchor_cadence: Some(room.anchor_cadence),
    };
    // 0.3 echoes the signal delay, always; 0.2 has no member for it.
    let body = match signal_delay {
        Some(_) => vti_rooms::signal_delay::create_v3_response(
            response,
            room.record_retention.as_ref(),
            room.signal_delay,
        ),
        None => {
            vti_rooms::record_tasks::create_v2_response(response, room.record_retention.as_ref())
        }
    };
    render(doc, body)
}

/// Write a record: `rooms/records/put` 0.3 – 0.5, read as [`PutRecordBody`] with its `blobs`.
/// A write that names no blobs releases any the record's previous version named.
///
/// `cleartext_as_received` is the write's `cleartext`, provenance, expiry and file included,
/// stored in place of the body's exactly as the writer sent it (consumer item 11).
/// `open_files` is 0.4's: an open room's `blobs` must be the file its cleartext describes.
pub(crate) async fn put_record<P>(
    doc: &TrustTask<P>,
    ctx: &RoomCtx,
    req: PutRecordBody,
    blobs: Vec<String>,
    cleartext_as_received: Option<Value>,
    open_files: bool,
) -> TrustTaskOutcome {
    let host = &ctx.host;
    let room = match storage::get_room(host.rooms(), &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        Action::Write,
        &ctx.presenter,
        now(),
        &ctx.verifier(),
        host.revocations(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    if let Err(o) = ctx.charged(&room.room_id, &ctx.presenter, RoomTraffic::Operation) {
        return o;
    }
    // A record sealed under a superseded epoch is the declared `epochMismatch`, not a generic
    // validation failure: the writer's remedy (apply the commit it missed) follows from the
    // code alone.
    if let Some(refusal) =
        vti_rooms::blob_tasks::record_epoch_refused(&room, req.sealed.as_ref().map(|s| s.epoch))
    {
        return refused(doc, refusal);
    }
    // Before `blobNotFound`, and before anything changes (put 0.4 Host item 12).
    if open_files
        && let Some(refusal) =
            vti_rooms::blob_tasks::open_file_refused(&room, &blobs, cleartext_as_received.as_ref())
    {
        return refused(doc, refusal);
    }

    // Held across the write: the blobs it names cannot be collected, and their limits cannot
    // change, between this check and the references it records.
    let references = match host
        .files()
        .prepare_record(&room, authorized.member(), &req.key, &blobs)
        .await
    {
        Ok(r) => r,
        Err(e) => return refused(doc, vti_rooms::blob_tasks::record_blobs_refused(e)),
    };
    // Put/0.5 Host item 15, under the lock `references` holds, so the record it judges is the
    // one this write replaces — and before anything changes. Applied whichever put version
    // carries the write: a 0.4 rewrite of another member's message is the same rewrite, and
    // would otherwise be the way round the refusal.
    if host.refuses_rewrites_by_others().await && room.visibility.stores_cleartext() {
        let current = match storage::get_record(host.records(), &req.room_id, &req.key).await {
            Ok(r) => Some(r),
            Err(AppError::NotFound(_)) => None,
            Err(e) => return app_error_to_reject(doc, &e),
        };
        if let Some(refusal) = vti_rooms::blob_tasks::rewrite_by_other_refused(
            &room,
            current.as_ref(),
            authorized.subject(),
        ) {
            return refused(doc, refusal);
        }
    }

    // The author is recorded only where the tier discloses one. On a private room authorship
    // lives inside the sealed body, and the storage layer refuses it here.
    //
    // It is the *verified* subject — who the chain says is acting — not the room's owner.
    // Recording the owner would have credited every write to one person, which on the
    // attributed tier is the whole of what the tier is for.
    let author = room
        .visibility
        .discloses_actor()
        .then(|| authorized.subject().to_string());

    let record = Record {
        key: req.key.clone(),
        version: 0, // assigned by the store from the room's counter
        epoch: req.sealed.as_ref().map(|s| s.epoch),
        status: RecordStatus::Active,
        pinned: false,
        sealed: req.sealed.as_ref().map(|s| s.ciphertext.clone()),
        nonce: req.sealed.as_ref().map(|s| s.nonce.clone()),
        sealed_version: None,
        cleartext: req.cleartext.as_ref().map(|c| {
            cleartext_as_received
                .clone()
                .unwrap_or_else(|| serde_json::to_value(c).unwrap_or(Value::Null))
        }),
        author,
        updated_at: 0,
        created_at: None,
        created_by: None,
        body_stored_at: None,
    };

    match storage::put_record(
        host.rooms(),
        host.records(),
        &req.room_id,
        record,
        req.expected_version,
        now(),
    )
    .await
    {
        Ok(stored) => {
            if let Err(e) = references.apply().await {
                // The record is written; only its blob references are not. Said loudly,
                // because usage now disagrees with the room by one file.
                tracing::error!(error = %e, room = %req.room_id, record = %stored.key,
                    "record stored but its blob references were not updated");
            }
            ctx.audit(
                &room,
                &authorized,
                RoomOperation::PutRecord,
                Some(&stored.key),
            )
            .await;
            success_response(
                doc,
                PutRecordResponse {
                    key: stored.key,
                    version: stored.version,
                    epoch: stored.epoch,
                },
            )
        }
        Err(e) => app_error_to_reject(doc, &e),
    }
}

/// Read a record: `rooms/records/get/0.2`, which also names its blobs, and at 0.3 (`v3`) the
/// host's `createdAt`, `createdBy` and `bodyStoredAt`.
///
/// A read presents exactly as a write does. Authorizing reads by session would record a
/// member identifier on every access, and a period of those records reconstructs the
/// membership a sealed room exists to withhold — without breaking any cryptography.
///
/// Every read is purpose-bound (VTI-ACL-110): `purpose` is what a get/0.4 request named, and
/// `declares_purpose` whether the version served declares `purposeNotGranted`. An earlier
/// version is decided as a request naming none.
pub(crate) async fn get_record<P>(
    doc: &TrustTask<P>,
    ctx: &RoomCtx,
    req: GetRecordBody,
    v3: bool,
    purpose: Option<String>,
    declares_purpose: bool,
) -> TrustTaskOutcome {
    let host = &ctx.host;
    let room = match storage::get_room(host.rooms(), &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        Action::Read,
        &ctx.presenter,
        now(),
        &ctx.verifier(),
        host.revocations(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    if let Err(o) = ctx.charged(&room.room_id, &ctx.presenter, RoomTraffic::Operation) {
        return o;
    }
    // After the chain verified and before any record is read, so the refusal says nothing
    // about whether the record exists.
    let decision = authorized.admit_purpose(purpose.as_deref());
    if !decision.is_granted() {
        tracing::info!(
            room = %room.room_id,
            purpose = decision.audit_label(),
            "a room read refused: the chain does not grant its purpose"
        );
        return refused(
            doc,
            vti_rooms::blob_tasks::read_purpose_refused(&decision, declares_purpose),
        );
    }

    // Read under the lock every record write holds — and every prune: a 0.2 read names the
    // blobs of the version it returns, and every read's head must be one snapshot with its
    // root, which a prune moves both of (`HeadVersion`).
    let snapshot = host.files().read_snapshot(&req.room_id).await;
    match storage::get_record(host.records(), &req.room_id, &req.key).await {
        Ok(record) => {
            host.audit(
                &room,
                &authorized,
                RoomAudit::Operation {
                    operation: RoomOperation::GetRecord,
                    record_key: Some(&req.key),
                    purpose: Some(decision.audit_label()),
                },
            )
            .await;
            // The response is a type, not the stored record with a member bolted on.
            // Serialising `Record` was what put a bare `sealed` string and six undeclared
            // members on the wire — see `GetRecordResponse`.
            let (commitment, trace) = record_verification(ctx, &req.room_id, &req.key).await;
            let response = GetRecordResponse::of(&record, commitment.as_ref(), trace);
            // get/0.3 adds the host's record times; none is committed, so the leaf and trace
            // above are get/0.2's.
            let result = if v3 {
                vti_rooms::blob_tasks::get_v3_response(&snapshot, &room, &record, response).await
            } else {
                vti_rooms::blob_tasks::get_v2_response(&snapshot, &req.room_id, &req.key, response)
                    .await
            };
            render(doc, result)
        }
        Err(e) => app_error_to_reject(doc, &e),
    }
}

/// The version a `rooms/records/list` is answered at.
pub use vti_rooms::record_tasks::ListAt;

/// `rooms/records/list/0.5`: rows name their blobs, every page carries the room's
/// `lastPrune`, and the continuation token is `nextCursor`. From 0.6 the rows are
/// `RecordMetadataV3`; at 0.7 they come oldest or newest first; at 0.8 within an exclusive
/// `beforeVersion` too.
///
/// Returns metadata, never bodies — and returns tombstones to a watermark caller, because a
/// puller that never sees a retraction resurrects the record on its next full rebuild.
pub(crate) async fn list_records<P>(
    doc: &TrustTask<P>,
    ctx: &RoomCtx,
    req: ListRecordsBody,
    at: ListAt,
) -> TrustTaskOutcome {
    let v6 = at.rows_v3();
    let host = &ctx.host;
    let room = match storage::get_room(host.rooms(), &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        Action::Read,
        &ctx.presenter,
        now(),
        &ctx.verifier(),
        host.revocations(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    if let Err(o) = ctx.charged(&room.room_id, &ctx.presenter, RoomTraffic::Operation) {
        return o;
    }

    // Under the record-write lock, which a prune also holds: the page, the head and the
    // room's `lastPrune` are one snapshot.
    let snapshot = host.files().read_snapshot(&req.room_id).await;
    // Paginated honestly: the page the caller asked for, and a cursor when more remain.
    let page = match vti_rooms::record_tasks::list_page(host.records(), &req, at).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(doc, &e),
    };

    // A listing names no single record, so the entry records the room and the fact of a
    // listing — which is the event: who has seen what this room holds.
    ctx.audit(&room, &authorized, RoomOperation::ListRecords, None)
        .await;
    let head = room_head(ctx, &req.room_id).await;
    let response = ListRecordsResponse {
        // 0.6's rows are `RecordMetadataV3`: what the room's tier may disclose of the kind
        // and the host's record times.
        records: page
            .records
            .iter()
            .map(|r| {
                if v6 {
                    r.metadata_v3(room.visibility)
                } else {
                    r.metadata()
                }
            })
            .collect(),
        cursor: page.cursor,
        // One head, so the three values a reader compares cannot come from three moments.
        data_commitment: head
            .as_ref()
            .map(|h| vti_rooms::merkle::to_multibase(&h.root)),
        record_count: head.as_ref().map(|h| h.record_count),
        head_version: head.as_ref().map(|h| h.head_version),
    };
    match storage::get_room(host.rooms(), &req.room_id).await {
        // The room as it stands under the lock: its `lastPrune` is the one the page and head
        // were taken with.
        Ok(now_room) => render(
            doc,
            vti_rooms::record_tasks::list_response(&snapshot, &now_room, response, at).await,
        ),
        Err(e) => app_error_to_reject(doc, &e),
    }
}

/// The room's commitment and this record's trace, from one snapshot.
///
/// Both or neither. A trace with no commitment is a path to a root the reader was not given —
/// the specification forbids it with `dependentRequired`.
///
/// A failure is answered with neither rather than with an error: these are additional
/// guarantees the specification makes OPTIONAL precisely so a host that cannot assert one
/// says nothing instead of something false.
async fn record_verification(
    ctx: &RoomCtx,
    room_id: &str,
    key: &str,
) -> (
    Option<vti_rooms::merkle::TreeHead>,
    Option<vti_rooms::merkle::InclusionProof>,
) {
    match storage::room_tree_head_with_trace(ctx.host.rooms(), ctx.host.records(), room_id, key)
        .await
    {
        Ok((head, trace)) => (Some(head), trace),
        Err(e) => {
            tracing::error!(
                room = %room_id,
                error = %e,
                "could not commit the room; answering the read without a commitment or a trace"
            );
            (None, None)
        }
    }
}

/// The room's data commitment, or `None` if it could not be computed.
///
/// **A failure here must not fail the read**, for the reason [`record_verification`] gives.
/// Logged rather than swallowed: a host that has quietly stopped committing looks, to a
/// member, exactly like a host that never did.
async fn room_head(ctx: &RoomCtx, room_id: &str) -> Option<vti_rooms::merkle::TreeHead> {
    match storage::room_tree_head(ctx.host.rooms(), ctx.host.records(), room_id).await {
        Ok(head) => Some(head),
        Err(e) => {
            tracing::error!(
                room = %room_id,
                error = %e,
                "could not compute the room's data commitment; answering without one"
            );
            None
        }
    }
}

/// `rooms/epoch/mint/0.1`.
///
/// Restricted to `admin`. If any key-holder could mint an epoch, any member could evict any
/// other by minting one and declining to seal them the new key — silently, and with no check
/// possible on a host that cannot see the membership. Binding it to an action the *room*
/// confers is what makes the restriction enforceable by a host that knows nothing about the
/// membership.
pub(crate) async fn handle_mint_epoch(
    doc: TrustTask<MintEpochBody>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let host = &ctx.host;
    let req = &doc.payload;

    let room = match storage::get_room(host.rooms(), &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        Action::Admin,
        &ctx.presenter,
        now(),
        &ctx.verifier(),
        host.revocations(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Err(o) = ctx.charged(&room.room_id, &ctx.presenter, RoomTraffic::Operation) {
        return o;
    }

    // The room's policy governs whether it has a chain at all, so a rung for a room that does
    // not chain is refused rather than dropped. Storing it would give the room a chain it
    // declared it would not have; dropping it silently would let a client believe the room's
    // history was being retained when it was not.
    if req.link.is_some() && !room.retention_policy.links_epochs() {
        return app_error_to_reject(
            &doc,
            &AppError::Validation(format!(
                "room `{}` does not keep an epoch key chain, so it accepts no epoch link",
                req.room_id
            )),
        );
    }

    // The rung, before the advance. A link that does not describe *this* advance is refused
    // outright rather than stored beside it: a host that accepted a mismatched one would be
    // laundering someone else's key material into this room's history.
    if let Some(link) = &req.link
        && link.epoch != req.epoch
    {
        return app_error_to_reject(
            &doc,
            &AppError::Validation(format!(
                "the epoch link is for epoch {} but this mint advances to {}",
                link.epoch, req.epoch
            )),
        );
    }

    match storage::advance_epoch(host.rooms(), &req.room_id, req.epoch, now()).await {
        Ok(updated) => {
            // After the advance, so a rejected advance leaves no orphan rung. `put_epoch_link`
            // refuses to replace one it already holds, which is what makes a retried mint
            // safe and a second, different rung impossible.
            if let Some(link) = &req.link
                && let Err(e) =
                    storage::put_epoch_link_above_floor(host.epoch_links(), &updated, link).await
            {
                return app_error_to_reject(&doc, &e);
            }
            // The commit, on the same terms and for the same reason: this is the moment the
            // committer holds it, and a room that advances without leaving it somewhere
            // fetchable forks every member who was not online. `put_commit` refuses to
            // replace one, because the first published is the one members may already have
            // applied.
            if let Some(commit) = &req.commit
                && let Err(e) =
                    storage::put_commit(host.epoch_links(), &req.room_id, req.epoch, commit).await
            {
                return app_error_to_reject(&doc, &e);
            }
            ctx.audit(&room, &authorized, RoomOperation::MintEpoch, None)
                .await;
            success_response(
                &doc,
                MintEpochResponse {
                    room_id: updated.room_id,
                    epoch: updated.epoch,
                },
            )
        }
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// Prune the chain: `rooms/epoch/prune/0.2`, which raises the room's epoch floor to
/// `beforeEpoch − 1` (trust-tasks-tf #869) and returns it: the floor is the room's, not the
/// request's.
///
/// The **rungs** go, not the records: a pruned room still holds every record and a host still
/// serves them, and what is gone is the ability to derive the keys they were sealed under.
pub(crate) async fn epoch_prune<P>(
    doc: &TrustTask<P>,
    ctx: &RoomCtx,
    req: &PruneBody,
) -> TrustTaskOutcome {
    let host = &ctx.host;
    let room = match storage::get_room(host.rooms(), &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    // `admin`, not `curate`: pruning makes no statement about any record, and every member
    // who can write can curate — which would put "end the room's readable history" within
    // reach of every writer.
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        Action::Admin,
        &ctx.presenter,
        now(),
        &ctx.verifier(),
        host.revocations(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    if let Err(o) = ctx.charged(&room.room_id, &ctx.presenter, RoomTraffic::Operation) {
        return o;
    }

    // Refused rather than performed. `beforeEpoch: currentEpoch` reads like "keep from here"
    // and would drop every rung. The declared `notAhead`, with the room's current epoch in
    // `details.epoch`.
    if let Some(refusal) = vti_rooms::blob_tasks::prune_floor_refused(&room, req.before_epoch) {
        return refused(doc, refusal);
    }

    let (pruned, earliest_rung, floor) = match storage::prune_chain_to_floor(
        host.rooms(),
        host.epoch_links(),
        &req.room_id,
        req.before_epoch,
        now(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(doc, &e),
    };

    ctx.audit(&room, &authorized, RoomOperation::PruneEpoch, None)
        .await;
    let response = PruneResponse {
        room_id: req.room_id.clone(),
        pruned: pruned as u32,
        earliest_rung,
    };
    render(
        doc,
        vti_rooms::record_tasks::epoch_prune_v2_response(response, floor),
    )
}

/// `rooms/epoch/commits/0.1`: the commits a member missed.
///
/// Relaying these is safe on every tier — a commit is ciphertext plus a leaf index and
/// **names nobody**, which is the difference from a Welcome, and why a host is deliberately
/// off that path and on this one.
pub(crate) async fn handle_epoch_commits(
    doc: TrustTask<CommitsBody>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let host = &ctx.host;
    let req = &doc.payload;

    let room = match storage::get_room(host.rooms(), &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        Action::Read,
        &ctx.presenter,
        now(),
        &ctx.verifier(),
        host.revocations(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Err(o) = ctx.charged(&room.room_id, &ctx.presenter, RoomTraffic::Operation) {
        return o;
    }

    let commits = match storage::commits_since(
        host.epoch_links(),
        &req.room_id,
        req.since_epoch,
        req.limit.unwrap_or(100).clamp(1, 100) as usize,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    ctx.audit(&room, &authorized, RoomOperation::ListRecords, None)
        .await;
    success_response(
        &doc,
        CommitsResponse {
            room_id: req.room_id.clone(),
            commits,
            // Read from the room, never computed from the answer. They differ exactly when a
            // commit is missing, and that difference is what tells a member a delivery is
            // missing rather than their own state being broken.
            room_epoch: room.epoch,
        },
    )
}

/// `rooms/epoch/chain/0.2`: the room's epoch key chain, so a member can read what was written
/// before they joined, or before the last membership change they were absent for.
///
/// Gated on `read`: reading the room and reading what was written before you joined are the
/// same act. What leaves is ciphertext — the key that opens a rung is a storage key a host
/// never holds — so a party with the whole chain and no epoch key learns only how many epochs
/// the room has had, which its epoch number already told them.
///
/// Every response carries the room's epoch floor, and no rung at or below it
/// (trust-tasks-tf #869).
pub(crate) async fn epoch_chain<P>(
    doc: &TrustTask<P>,
    ctx: &RoomCtx,
    req: &ChainBody,
) -> TrustTaskOutcome {
    let host = &ctx.host;
    let room = match storage::get_room(host.rooms(), &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        Action::Read,
        &ctx.presenter,
        now(),
        &ctx.verifier(),
        host.revocations(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    if let Err(o) = ctx.charged(&room.room_id, &ctx.presenter, RoomTraffic::Operation) {
        return o;
    }

    let mut links = match storage::servable_epoch_links(host.epoch_links(), &room).await {
        Ok(l) => l,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    // Highest epoch first: the chain is walked downwards, so a member reads it in the order
    // they will use it.
    links.reverse();
    if let Some(from) = req.from_epoch {
        links.retain(|l| l.epoch <= from);
    }
    if let Some(limit) = req.limit {
        links.truncate(limit as usize);
    }

    ctx.audit(&room, &authorized, RoomOperation::ListRecords, None)
        .await;
    let response = ChainResponse {
        room_id: req.room_id.clone(),
        links,
    };
    render(
        doc,
        vti_rooms::record_tasks::epoch_chain_v2_response(response, &room),
    )
}

/// `rooms/owner/transfer/0.1`: an owner hands the room to another member, deliberately and
/// while still present.
///
/// Gated on `admin` — the same grant that mints epochs, because transferring is the more
/// consequential of the two and it would be strange for the lesser act to ask for more.
///
/// **A host cannot check that the incoming owner is a member**: it holds no roster and no
/// group state. The spec's `notAMember` is for a host that "could independently establish"
/// it; inventing a check would refuse every correct transfer, a worse failure than the one
/// it imagines it is preventing. What protects the incoming owner is that the outgoing one
/// holds `admin` and knows the roster.
pub(crate) async fn handle_transfer_owner(
    doc: TrustTask<TransferOwnerBody>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let host = &ctx.host;
    let req = &doc.payload;

    let room = match storage::get_room(host.rooms(), &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let operation = RoomOperation::TransferOwner;
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        operation.required_action(),
        &ctx.presenter,
        now(),
        &ctx.verifier(),
        host.revocations(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Err(o) = ctx.charged(&room.room_id, &ctx.presenter, RoomTraffic::Operation) {
        return o;
    }

    match storage::set_owner(host.rooms(), &req.room_id, &req.new_owner_did, now()).await {
        Ok(updated) => {
            host.owner_changed(&updated.room_id);
            ctx.audit(&room, &authorized, operation, None).await;
            success_response(
                &doc,
                OwnerResponse {
                    room_id: updated.room_id,
                    owner_did: updated.owner_did,
                },
            )
        }
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `rooms/owner/claim/0.1`: a nominated successor takes a room whose owner has stopped
/// renewing it.
///
/// # Three conditions, checked in the order that gives the most useful answer
///
/// 1. **A nomination the room issued**, naming this claimant, in its window, rooted at the
///    room ([`vti_rooms_dtg::nomination`]).
/// 2. **The room is dormant** — not merely lapsed.
/// 3. **The claimant holds membership**, which is the presentation every other room task
///    carries, gated at `read`.
///
/// A claimant whose nomination is bad should hear that first, because it is the one they can
/// do nothing about by waiting. An owner who was merely away defeats every pending claim by
/// minting an epoch — which is what they would have done anyway. And a claim does not renew
/// the room ([`storage::set_owner`]).
pub(crate) async fn handle_claim_owner(
    doc: TrustTask<ClaimOwnerBody>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let host = &ctx.host;
    let presenter = ctx.presenter.as_str();
    let req = &doc.payload;

    let room = match storage::get_room(host.rooms(), &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    // 1. The nomination, against the party who actually signed this request — never against
    //    a DID named in the payload, which the claimant chooses.
    let keys = DataIntegrityKeys(host.resolver());
    let nominated = match nomination::verify(&req.nomination, &room.room_id, presenter, &keys).await
    {
        Ok(n) => n,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    // 2. Dormant, not merely lapsed. An epoch expiring is frequently somebody on holiday.
    let lifecycle = room.lifecycle(now());
    if !lifecycle.admits_a_claim() {
        return app_error_to_reject(
            &doc,
            &AppError::Forbidden(format!(
                "room `{}` is {} — a room becomes claimable only once its epoch has \
                 lapsed and the grace window after it has also passed without a renewal",
                room.room_id,
                lifecycle.as_str()
            )),
        );
    }

    // 3. Membership, which is also the pooling defence and the chain-reaches-the-room check.
    let operation = RoomOperation::ClaimOwner;
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        operation.required_action(),
        presenter,
        now(),
        &ctx.verifier(),
        host.revocations(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // A nomination is a credential the room issued, and a revocation list governs succession
    // like every other task (`rooms/revocations/put`, *Enforcement* item 2).
    if let Err(e) = authorized.also_unrevoked(nominated.facts()) {
        return app_error_to_reject(&doc, &e);
    }
    if let Err(o) = ctx.charged(&room.room_id, presenter, RoomTraffic::Operation) {
        return o;
    }

    match storage::set_owner(host.rooms(), &req.room_id, presenter, now()).await {
        Ok(updated) => {
            host.owner_changed(&updated.room_id);
            ctx.audit(&room, &authorized, operation, None).await;
            success_response(
                &doc,
                OwnerResponse {
                    room_id: updated.room_id,
                    owner_did: updated.owner_did,
                },
            )
        }
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `rooms/records/curate/0.1`.
///
/// Gated on `Action::Curate`, which is deliberately not implied by `write`: deciding what a
/// room's shared knowledge is worth is a different grant from the ability to add to it.
pub(crate) async fn handle_curate_record(
    doc: TrustTask<CurateRecordBody>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let host = &ctx.host;
    let req = &doc.payload;
    if req.status.is_none() && req.pinned.is_none() {
        return app_error_to_reject(
            &doc,
            &AppError::Validation(
                "a curation must change something: supply `status`, `pinned`, or both".into(),
            ),
        );
    }

    let room = match storage::get_room(host.rooms(), &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        Action::Curate,
        &ctx.presenter,
        now(),
        &ctx.verifier(),
        host.revocations(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Err(o) = ctx.charged(&room.room_id, &ctx.presenter, RoomTraffic::Operation) {
        return o;
    }

    // Held across the curation, so a 0.2 read never sees a retracted record still naming the
    // blobs the retraction released.
    let release = match host.files().prepare_release(&req.room_id, &req.key).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    match storage::curate_record(
        host.rooms(),
        host.records(),
        &req.room_id,
        &req.key,
        storage::Curation {
            status: req.status,
            pinned: req.pinned,
            expected_version: req.expected_version,
        },
        now(),
    )
    .await
    {
        Ok(curated) => {
            // A retraction keeps no body, so it keeps no file: every blob the record named is
            // released, and orphaned if nothing else names it.
            if curated.status == RecordStatus::Retracted
                && let Err(e) = release.apply().await
            {
                tracing::error!(error = %e, room = %req.room_id, record = %curated.key,
                    "record retracted but its blobs were not released");
            }
            ctx.audit(
                &room,
                &authorized,
                RoomOperation::CurateRecord,
                Some(&curated.key),
            )
            .await;
            success_response(
                &doc,
                CurateRecordResponse {
                    key: curated.key,
                    version: curated.version,
                    status: curated.status,
                    pinned: curated.pinned,
                },
            )
        }
        Err(e) => app_error_to_reject(&doc, &e),
    }
}
