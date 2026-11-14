//! The tasks keyed on a generated payload type or read as received: room files
//! (`rooms/blobs/*`, `rooms/usage`), `rooms/info`, `rooms/records/{put,get,list}` at each
//! served version, record retention, the signal delay, watches and revocation lists.
//!
//! What each does is `vti_rooms::{blob_tasks, record_tasks, signal_delay, watch,
//! revocation_tasks}`; what is here is the version each is served at and the reply.
//!
//! A host holds ciphertext only. A file's key is derived in the member's VTA and never
//! reaches a host, and nothing here could use one.

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_rooms::authz::Action;
use vti_rooms::blob_tasks;
use vti_rooms::record_tasks;
use vti_rooms::storage;
use vti_rooms::wire::{GetRecordBody, ListRecordsBody, PutRecordBody};
use vti_specs_rooms::rooms::blobs::chunk::v0_1 as download_chunk;
use vti_specs_rooms::rooms::blobs::get::v0_2 as blob_get_v2;
use vti_specs_rooms::rooms::blobs::upload::{
    abort::v0_2 as upload_abort_v2, begin::v0_2 as upload_begin_v2, chunk::v0_2 as upload_chunk_v2,
    commit::v0_2 as upload_commit_v2,
};
use vti_specs_rooms::rooms::records::get::v0_2 as get_v2;
use vti_specs_rooms::rooms::records::get::v0_3 as get_v3;
use vti_specs_rooms::rooms::records::get::v0_4 as get_v4;
use vti_specs_rooms::rooms::records::list::v0_6 as list_v6;
#[allow(deprecated)] // still served beside list/0.8 (trust-tasks-tf #1289)
use vti_specs_rooms::rooms::records::list::v0_7 as list_v7;
use vti_specs_rooms::rooms::records::list::v0_8 as list_v8;
use vti_specs_rooms::rooms::usage::v0_1 as rooms_usage;
use vti_specs_rooms::rooms::watch::v0_1 as watch_v1;
use vti_specs_rooms::rooms::watch::v0_2 as watch_v2;
use vti_specs_rooms::rooms::{
    epoch::chain::v0_2 as epoch_chain_v2, epoch::prune::v0_2 as epoch_prune_v2,
    info::v0_3 as info_v3, info::v0_4 as info_v4, info::v0_5 as info_v5,
    records::list::v0_5 as list_v5, records::prune::v0_2 as records_prune,
};
use vti_trust_task_server::TrustTaskOutcome;
use vti_trust_task_server::reject::success_response;

use crate::records::{self, ListAt};
use crate::render::{
    app_error_to_reject, as_v0_1, authorize, charge_transfer, charge_upload_v2, held_step,
    malformed, payload_json, refused, render,
};
use crate::{RoomAudit, RoomCtx, RoomTraffic, now};

/// `rooms/revocations/put/0.1` (`put`) or `rooms/revocations/get/0.1`, over the payload **as
/// received**.
///
/// Not through the typed dispatcher: the generated `RevocationList` types its timestamps, and
/// a list read into it and written back is not byte-for-byte the list the room signed — its
/// signature and its head digest are over the room's own serialization.
pub(crate) async fn handle_revocations(
    doc: TrustTask<Value>,
    ctx: RoomCtx,
    put: bool,
) -> TrustTaskOutcome {
    let payload = doc.payload.clone();
    let room_id = payload["roomId"].as_str().unwrap_or_default();
    let room = match storage::get_room(ctx.host.rooms(), room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let verifier = ctx.verifier();
    let revocations = ctx.host.revocations();
    let (result, operation) = if put {
        (
            vti_rooms::revocation_tasks::put(
                &room,
                &ctx.presenter,
                &payload,
                &verifier,
                revocations,
            )
            .await,
            vti_rooms::audit::RoomOperation::PutRevocations,
        )
    } else {
        (
            vti_rooms::revocation_tasks::get(
                &room,
                &ctx.presenter,
                &payload,
                &verifier,
                revocations,
            )
            .await,
            vti_rooms::audit::RoomOperation::GetRevocations,
        )
    };
    match result {
        Ok((body, authorized)) => {
            ctx.audit(&room, &authorized, operation, None).await;
            success_response(&doc, body)
        }
        Err(r) => refused(&doc, r),
    }
}

/// `rooms/records/put/0.3`: 0.2, and an `open` room's `cleartext` may carry the record's
/// provenance and `validUntil` — stored and served exactly as received, never acted on
/// (consumer item 11). A sealed write is 0.2's: those members travel inside the body.
pub(crate) async fn handle_put_record_v3(doc: TrustTask<Value>, ctx: RoomCtx) -> TrustTaskOutcome {
    let payload = doc.payload.clone();
    let (blobs, cleartext) = match blob_tasks::put_v3_parts(&payload) {
        Ok(parts) => parts,
        Err(r) => return refused(&doc, r),
    };
    let req: PutRecordBody = match serde_json::from_value(blob_tasks::put_v3_as_v0_1(payload)) {
        Ok(r) => r,
        Err(e) => return malformed(&doc, e),
    };
    records::put_record(&doc, &ctx, req, blobs, cleartext, false).await
}

/// `rooms/records/put/0.4`: 0.3, and an `open` room's `cleartext` may carry a `file` — its
/// manifest and the random key its blob is sealed under — stored and served as received
/// (Host item 13), once the record's `blobs` is checked against it (Host item 12).
pub(crate) async fn handle_put_record_v4(doc: TrustTask<Value>, ctx: RoomCtx) -> TrustTaskOutcome {
    let payload = doc.payload.clone();
    let (blobs, cleartext) = match blob_tasks::put_v4_parts(&payload) {
        Ok(parts) => parts,
        Err(r) => return refused(&doc, r),
    };
    let req: PutRecordBody = match serde_json::from_value(blob_tasks::put_v4_as_v0_1(payload)) {
        Ok(r) => r,
        Err(e) => return malformed(&doc, e),
    };
    records::put_record(&doc, &ctx, req, blobs, cleartext, true).await
}

/// `rooms/records/put/0.5`: 0.4, and an `open` room's `cleartext` may say what kind of record
/// it is, what it answers and when it was written and edited, and its `file` an image's size
/// and preview — each held to its schema, then stored and served as received and never acted
/// on (Host item 14).
pub(crate) async fn handle_put_record_v5(doc: TrustTask<Value>, ctx: RoomCtx) -> TrustTaskOutcome {
    let payload = doc.payload.clone();
    let (blobs, cleartext) = match blob_tasks::put_v5_parts(&payload) {
        Ok(parts) => parts,
        Err(r) => return refused(&doc, r),
    };
    let req: PutRecordBody = match serde_json::from_value(blob_tasks::put_v5_as_v0_1(payload)) {
        Ok(r) => r,
        Err(e) => return malformed(&doc, e),
    };
    records::put_record(&doc, &ctx, req, blobs, cleartext, true).await
}

/// `rooms/records/get/0.2`: the 0.1 read, whose answer also names the record's blobs.
#[allow(deprecated)] // get/0.2 is served beside get/0.3, to readers that ask for it
pub(crate) async fn handle_get_record_v2(
    doc: TrustTask<get_v2::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let req: GetRecordBody = match payload_json(&doc).and_then(|p| as_v0_1(&doc, p)) {
        Ok(r) => r,
        Err(o) => return o,
    };
    records::get_record(&doc, &ctx, req, false, None, false).await
}

/// `rooms/records/get/0.3`: 0.2, and the host's `createdAt`, `createdBy` and `bodyStoredAt`
/// for the record.
#[allow(deprecated)] // get/0.3 is served beside get/0.4, to readers that ask for it
pub(crate) async fn handle_get_record_v3(
    doc: TrustTask<get_v3::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let req: GetRecordBody = match payload_json(&doc).and_then(|p| as_v0_1(&doc, p)) {
        Ok(r) => r,
        Err(o) => return o,
    };
    records::get_record(&doc, &ctx, req, true, None, false).await
}

/// `rooms/records/get/0.4`: 0.3, and the `purpose` the reader will use the record for,
/// refused with `purposeNotGranted` where the presented chain does not grant it
/// (VTI-ACL-110).
pub(crate) async fn handle_get_record_v4(
    doc: TrustTask<get_v4::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let mut payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let purpose = match blob_tasks::get_v4_purpose(&mut payload) {
        Ok(p) => p,
        Err(r) => return refused(&doc, r),
    };
    let req: GetRecordBody = match as_v0_1(&doc, payload) {
        Ok(r) => r,
        Err(o) => return o,
    };
    records::get_record(&doc, &ctx, req, true, purpose, true).await
}

/// `rooms/records/list/0.5`: the 0.1 listing, each row naming its blobs, the room's
/// `lastPrune` on every page and the continuation token named `nextCursor`.
#[allow(deprecated)] // list/0.5 is served beside list/0.6, to readers that ask for it
pub(crate) async fn handle_list_records_v5(
    doc: TrustTask<list_v5::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let req: ListRecordsBody = match payload_json(&doc).and_then(|p| as_v0_1(&doc, p)) {
        Ok(r) => r,
        Err(o) => return o,
    };
    records::list_records(&doc, &ctx, req, ListAt::V5).await
}

/// `rooms/records/list/0.6`: 0.5, with each row's `kind` on an `open` room and the host's
/// `createdAt`, `createdBy` and `bodyStoredAt`.
#[allow(deprecated)] // still served beside list/0.7, to readers that ask for it (trust-tasks-tf #1088)
pub(crate) async fn handle_list_records_v6(
    doc: TrustTask<list_v6::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let req: ListRecordsBody = match payload_json(&doc).and_then(|p| as_v0_1(&doc, p)) {
        Ok(r) => r,
        Err(o) => return o,
    };
    records::list_records(&doc, &ctx, req, ListAt::V6).await
}

/// `rooms/records/list/0.7`: 0.6, oldest or newest first, its cursor bound to the order it
/// was issued under — refused as `invalidCursor` under the other (trust-tasks-tf #1088).
#[allow(deprecated)] // still served beside list/0.8 (trust-tasks-tf #1289)
pub(crate) async fn handle_list_records_v7(
    doc: TrustTask<list_v7::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let (order, v0_1) = match record_tasks::list_v7_parts(&payload) {
        Ok(parts) => parts,
        Err(r) => return refused(&doc, r),
    };
    let req: ListRecordsBody = match as_v0_1(&doc, v0_1) {
        Ok(r) => r,
        Err(o) => return o,
    };
    records::list_records(&doc, &ctx, req, ListAt::V7(order)).await
}

/// `rooms/records/list/0.8`: 0.7, and an exclusive `beforeVersion` under either order; its
/// cursor bound to the order and both bounds — refused as `invalidCursor` under any other
/// (trust-tasks-tf #1289).
pub(crate) async fn handle_list_records_v8(
    doc: TrustTask<list_v8::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let (at, v0_1) = match record_tasks::list_v8_parts(&payload) {
        Ok(parts) => parts,
        Err(r) => return refused(&doc, r),
    };
    let req: ListRecordsBody = match as_v0_1(&doc, v0_1) {
        Ok(r) => r,
        Err(o) => return o,
    };
    records::list_records(&doc, &ctx, req, at).await
}

/// `rooms/create/0.2`: 0.1, and the room's record retention, recorded as given.
pub(crate) async fn handle_create_v2(doc: TrustTask<Value>, ctx: RoomCtx) -> TrustTaskOutcome {
    let (retention, v0_1) = match record_tasks::create_v2_parts(&doc.payload) {
        Ok(parts) => parts,
        Err(r) => return refused(&doc, r),
    };
    let req: vti_rooms::wire::CreateRoomBody = match serde_json::from_value(v0_1) {
        Ok(r) => r,
        Err(e) => return malformed(&doc, e),
    };
    records::create_room(&doc, &ctx, &req, retention, None).await
}

/// `rooms/create/0.3`: 0.2, and the room's signal delay, recorded as given and always echoed.
/// A host applies either setting (`rooms/signal-delay/set/0.1` Host item 2).
pub(crate) async fn handle_create_v3(doc: TrustTask<Value>, ctx: RoomCtx) -> TrustTaskOutcome {
    let (retention, delay, v0_1) = match vti_rooms::signal_delay::create_v3_parts(&doc.payload)
        .and_then(|(r, d, p)| {
            vti_rooms::signal_delay::create_v3_permitted(
                d,
                vti_rooms::signal_delay::SignalDelayPolicy::Either,
            )?;
            Ok((r, d, p))
        }) {
        Ok(parts) => parts,
        Err(r) => return refused(&doc, r),
    };
    let req: vti_rooms::wire::CreateRoomBody = match serde_json::from_value(v0_1) {
        Ok(r) => r,
        Err(e) => return malformed(&doc, e),
    };
    records::create_room(&doc, &ctx, &req, retention, Some(delay)).await
}

/// `rooms/info/0.3`. Needs `read`: 0.1's answer, the record retention in force and the room's
/// latest prune (`prunedAt`).
#[allow(deprecated)] // still served beside info/0.4 (trust-tasks-tf #1084)
pub(crate) async fn handle_info_v3(
    doc: TrustTask<info_v3::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let (room, authorized) = match authorize(&doc, &ctx, &payload, Action::Read).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    render(
        &doc,
        record_tasks::info_v3(ctx.host.files(), &room, &authorized, &payload).await,
    )
}

/// `rooms/info/0.4`. Needs `read`: 0.3's answer, and the room's signal delay.
#[allow(deprecated)] // still served beside info/0.5 (trust-tasks-tf #1289)
pub(crate) async fn handle_info_v4(
    doc: TrustTask<info_v4::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let (room, authorized) = match authorize(&doc, &ctx, &payload, Action::Read).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    render(
        &doc,
        vti_rooms::signal_delay::info_v4(ctx.host.files(), &room, &authorized, &payload).await,
    )
}

/// `rooms/info/0.5`. Needs `read`: 0.4's answer, and the host's own limits
/// ([`crate::RoomHost::host_limits`]).
pub(crate) async fn handle_info_v5(
    doc: TrustTask<info_v5::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let (room, authorized) = match authorize(&doc, &ctx, &payload, Action::Read).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    render(
        &doc,
        vti_rooms::signal_delay::info_v5(
            ctx.host.files(),
            &room,
            &authorized,
            &payload,
            ctx.host.host_limits(),
        )
        .await,
    )
}

/// `rooms/signal-delay/set/0.1`: change whether a host waits a randomised interval before the
/// room's watch signals. Needs `admin`; audited with the setting replaced, the one recorded
/// and the reason.
pub(crate) async fn handle_signal_delay_set(
    doc: TrustTask<Value>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = doc.payload.clone();
    if let Err(r) =
        blob_tasks::parse::<vti_specs_rooms::rooms::signal_delay::set::v0_1::Payload>(&payload)
    {
        return refused(&doc, r);
    }
    let (room, authorized) = match authorize(&doc, &ctx, &payload, Action::Admin).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    let host = &ctx.host;
    match vti_rooms::signal_delay::set(
        host.files(),
        host.rooms(),
        &room,
        &authorized,
        &payload,
        vti_rooms::signal_delay::SignalDelayPolicy::Either,
        now(),
    )
    .await
    {
        Ok((body, audit)) => {
            host.audit(&room, &authorized, RoomAudit::SignalDelay(&audit))
                .await;
            // `rooms/watch/0.2` Host item 6: a room set back to `randomised` holds no live
            // watch, from now — ended without a signal.
            if audit.recorded.is_randomised() {
                host.watches().end_live_watches(&room.room_id).await;
            }
            render(&doc, Ok(body))
        }
        Err(r) => refused(&doc, r),
    }
}

/// `rooms/epoch/chain/0.2`: the 0.1 chain, and the room's epoch floor on every response.
pub(crate) async fn handle_epoch_chain_v2(
    doc: TrustTask<epoch_chain_v2::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let req: vti_rooms::wire::ChainBody = match payload_json(&doc).and_then(|p| as_v0_1(&doc, p)) {
        Ok(r) => r,
        Err(o) => return o,
    };
    records::epoch_chain(&doc, &ctx, &req).await
}

/// `rooms/epoch/prune/0.2`: the 0.1 prune, and the room's epoch floor it leaves.
pub(crate) async fn handle_epoch_prune_v2(
    doc: TrustTask<epoch_prune_v2::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let req: vti_rooms::wire::PruneBody = match payload_json(&doc).and_then(|p| as_v0_1(&doc, p)) {
        Ok(r) => r,
        Err(o) => return o,
    };
    records::epoch_prune(&doc, &ctx, &req).await
}

/// `rooms/records/prune/0.2`: remove what the room's record retention makes eligible. Needs
/// `admin` — never `curate` or `write`.
pub(crate) async fn handle_records_prune(
    doc: TrustTask<records_prune::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let (room, authorized) = match authorize(&doc, &ctx, &payload, Action::Admin).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    let host = &ctx.host;
    match record_tasks::prune(
        host.files(),
        host.rooms(),
        host.records(),
        &room,
        &authorized,
        &payload,
        now(),
    )
    .await
    {
        Ok((body, audit)) => {
            if let Some(audit) = audit {
                host.audit(
                    &room,
                    &authorized,
                    RoomAudit::Retention {
                        operation: vti_rooms::audit::RoomOperation::PruneRecords,
                        detail: &audit,
                    },
                )
                .await;
            }
            render(&doc, Ok(body))
        }
        Err(r) => refused(&doc, r),
    }
}

/// `rooms/records/retention/set/0.1`: replace the room's record retention. Needs `admin`.
pub(crate) async fn handle_retention_set(doc: TrustTask<Value>, ctx: RoomCtx) -> TrustTaskOutcome {
    let payload = doc.payload.clone();
    if let Err(r) = blob_tasks::parse::<
        vti_specs_rooms::rooms::records::retention::set::v0_1::Payload,
    >(&payload)
    {
        return refused(&doc, r);
    }
    let (room, authorized) = match authorize(&doc, &ctx, &payload, Action::Admin).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    let host = &ctx.host;
    match record_tasks::retention_set(
        host.files(),
        host.rooms(),
        &room,
        &authorized,
        &payload,
        None,
        now(),
    )
    .await
    {
        Ok((body, audit)) => {
            host.audit(
                &room,
                &authorized,
                RoomAudit::Retention {
                    operation: vti_rooms::audit::RoomOperation::SetRecordRetention,
                    detail: &audit,
                },
            )
            .await;
            render(&doc, Ok(body))
        }
        Err(r) => refused(&doc, r),
    }
}

/// `rooms/blobs/chunk/0.1`. Authorized by owning the download.
pub(crate) async fn handle_download_chunk(
    doc: TrustTask<download_chunk::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let p = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    if let Err(o) = charge_transfer(&ctx, &p, "downloadId", RoomTraffic::Transfer).await {
        return o;
    }
    // This step presents nothing: the credentials that opened the transfer stand for it,
    // held to the room's revocation list (`rooms/revocations/put`, *Enforcement* item 3).
    let _gate = match held_step(&doc, &ctx, &p).await {
        Ok(g) => g,
        Err(o) => return o,
    };
    render(
        &doc,
        blob_tasks::download_chunk(ctx.host.files(), &ctx.presenter, &p).await,
    )
}

/// `rooms/blobs/upload/begin/0.2`. Needs `write`; answers how the bytes move.
pub(crate) async fn handle_upload_begin_v2(
    doc: TrustTask<upload_begin_v2::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let (room, authorized) = match authorize(&doc, &ctx, &payload, Action::Write).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    render(
        &doc,
        blob_tasks::begin_v2(
            ctx.host.files(),
            &room,
            &ctx.presenter,
            &authorized,
            &payload,
        )
        .await,
    )
}

/// `rooms/blobs/upload/chunk/0.2`. Authorized by being the upload's key.
pub(crate) async fn handle_upload_chunk_v2(
    doc: TrustTask<upload_chunk_v2::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let p = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    if let Err(o) = charge_upload_v2(&ctx, &p, RoomTraffic::Transfer).await {
        return o;
    }
    // This step presents nothing: the credentials that opened the transfer stand for it,
    // held to the room's revocation list (`rooms/revocations/put`, *Enforcement* item 3).
    let _gate = match held_step(&doc, &ctx, &p).await {
        Ok(g) => g,
        Err(o) => return o,
    };
    render(
        &doc,
        blob_tasks::upload_chunk_v2(ctx.host.files(), &ctx.presenter, &p).await,
    )
}

/// `rooms/blobs/upload/commit/0.2`. Authorized by being the upload's key.
pub(crate) async fn handle_upload_commit_v2(
    doc: TrustTask<upload_commit_v2::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let p = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    if let Err(o) = charge_upload_v2(&ctx, &p, RoomTraffic::Operation).await {
        return o;
    }
    // The step that commits an upload begun before a list was accepted is refused if the
    // list withdraws what began it (*Enforcement* item 3).
    let _gate = match held_step(&doc, &ctx, &p).await {
        Ok(g) => g,
        Err(o) => return o,
    };
    render(
        &doc,
        blob_tasks::commit_v2(ctx.host.files(), &ctx.presenter, &p).await,
    )
}

/// `rooms/blobs/upload/abort/0.2`. Authorized by being the upload's key.
pub(crate) async fn handle_upload_abort_v2(
    doc: TrustTask<upload_abort_v2::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let p = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    if let Err(o) = charge_upload_v2(&ctx, &p, RoomTraffic::Operation).await {
        return o;
    }
    render(
        &doc,
        blob_tasks::abort_v2(ctx.host.files(), &ctx.presenter, &p).await,
    )
}

/// `rooms/blobs/get/0.2`. Needs `read`; direct from storage where the room's tier, the
/// host's configuration and the blob's store allow, else proxied.
pub(crate) async fn handle_blob_get_v2(
    doc: TrustTask<blob_get_v2::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let (room, authorized) = match authorize(&doc, &ctx, &payload, Action::Read).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    render(
        &doc,
        blob_tasks::get_v2(
            ctx.host.files(),
            &room,
            &ctx.presenter,
            &authorized,
            &payload,
        )
        .await,
    )
}

/// `rooms/usage/0.1`. Needs `admin`: who is using the room's space is the owner's question,
/// not a member's.
pub(crate) async fn handle_usage(
    doc: TrustTask<rooms_usage::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let (room, authorized) = match authorize(&doc, &ctx, &payload, Action::Admin).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    render(
        &doc,
        blob_tasks::usage(ctx.host.files(), &room, &authorized, &payload).await,
    )
}

/// `rooms/watch/0.1`: arm, re-arm or cancel one content-free signal to an address the member
/// names, authorized exactly as a listing (`read`). The watch is the host's state and nothing
/// else ([`vti_rooms::watch`]).
#[allow(deprecated)] // rooms/watch/0.1, still served beside 0.2
pub(crate) async fn handle_watch(
    doc: TrustTask<watch_v1::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    watch_at(&doc, ctx, payload, false).await
}

/// `rooms/watch/0.2`: 0.1, and a live watch — a signal per change, coalesced — on a room
/// whose signal delay is `none` (`liveNotPermitted` otherwise), leased for at most 120 s.
pub(crate) async fn handle_watch_v2(
    doc: TrustTask<watch_v2::Payload>,
    ctx: RoomCtx,
) -> TrustTaskOutcome {
    let payload = match payload_json(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };
    watch_at(&doc, ctx, payload, true).await
}

async fn watch_at<P>(
    doc: &TrustTask<P>,
    ctx: RoomCtx,
    payload: Value,
    v2: bool,
) -> TrustTaskOutcome {
    let checked = if v2 {
        vti_rooms::watch::check_payload_v2(&payload)
    } else {
        vti_rooms::watch::check_payload(&payload)
    };
    if let Err(r) = checked {
        return refused(doc, r);
    }
    let room_id = payload["roomId"].as_str().unwrap_or_default();
    let room = match storage::get_room(ctx.host.rooms(), room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    if let Err(r) = vti_rooms::watch::presentation(&payload, &room) {
        return refused(doc, r);
    }
    let (room, authorized) = match authorize(doc, &ctx, &payload, Action::Read).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    let watches = ctx.host.watches();
    let now = chrono::Utc::now();
    let result = if v2 {
        watches.watch_v2(&room, authorized, &payload, now).await
    } else {
        watches.watch(&room, authorized, &payload, now).await
    };
    render(doc, result)
}
