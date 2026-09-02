//! Trust-Task handlers for the `rooms/*` family.
//!
//! These are deliberately thin. Every one does the same four things in the same order —
//! parse, load the room, authorize, act — and each of those lives somewhere else:
//! [`super::wire`] owns the shapes, [`super::storage`] owns the invariants, and
//! [`super::authz`] owns the decision. A handler that starts making its own storage or
//! authorization judgements is a handler that has drifted from the other four.
//!
//! # Authorization order
//!
//! The room is loaded first, then the presentation is authorized **against that room**.
//! That ordering matters: visibility is a property of the room, and the private-tier
//! subject-binding requirement cannot be checked without knowing the tier. Authorizing
//! before loading would mean either guessing the tier or checking it twice.
//!
//! # What a handler never does
//!
//! Reach for `state.acl_ks`, `state.members_ks`, or the caller's session. A room operation
//! is authorized by the chain the room issued and nothing else — invariant I5. There is no
//! `AuthClaims` parameter here, and its absence is the point rather than an omission.

use serde_json::Value;
use trust_tasks_rs::TrustTask;

use crate::rooms::authz::{self, Action};
use crate::rooms::storage;
use crate::rooms::wire::{
    CreateRoomBody, CreateRoomResponse, GetRecordBody, ListRecordsBody, ListRecordsResponse,
    MintEpochBody, MintEpochResponse, PutRecordBody, PutRecordResponse,
};
use crate::rooms::{Record, RecordStatus, Room};
use crate::server::AppState;
use crate::trust_tasks::helpers::{
    TrustTaskOutcome, app_error_to_reject, parse_payload, success_response,
};

/// Seconds since the Unix epoch.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Default retention when a creator does not state one.
///
/// Ninety days after the epoch lapses. Long enough that a room is not lost to a quiet
/// month, short enough that an abandoned one does not accumulate forever.
const DEFAULT_RETENTION_DAYS: u32 = 90;

/// `rooms/create/0.1`.
///
/// The creator brings the room's identifier; this service does not assign one. A room
/// identified by something its host chose could not move to another host without changing
/// identity, and portability is the property the whole family rests on.
pub(crate) async fn handle_create(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let req: CreateRoomBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let room = Room {
        room_id: req.room_id.clone(),
        owner_did: req.owner_did,
        visibility: req.visibility,
        epoch: 1,
        next_version: 1,
        retention_days: req.retention_days.unwrap_or(DEFAULT_RETENTION_DAYS),
        created_at: now(),
        updated_at: now(),
    };

    if let Err(e) = storage::create_room(&state.rooms_ks, &room).await {
        return app_error_to_reject(&doc, &e);
    }

    success_response(
        &doc,
        CreateRoomResponse {
            room_id: req.room_id,
            epoch: 1,
        },
    )
}

/// `rooms/records/put/0.1`.
pub(crate) async fn handle_put_record(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let req: PutRecordBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let room = match storage::get_room(&state.rooms_ks, &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Err(e) = authz::authorize(&room, &req.presentation, Action::Write) {
        return app_error_to_reject(&doc, &e);
    }

    // The author is recorded only where the tier discloses one. On a private room
    // authorship lives inside the sealed body, and the storage layer refuses it here.
    let author = room
        .visibility
        .discloses_actor()
        .then(|| room.owner_did.clone());

    let record = Record {
        key: req.key.clone(),
        version: 0, // assigned by the store from the room's counter
        epoch: req.sealed.as_ref().map(|s| s.epoch),
        status: RecordStatus::Active,
        sealed: req.sealed.as_ref().map(|s| s.ciphertext.clone()),
        nonce: req.sealed.as_ref().map(|s| s.nonce.clone()),
        cleartext: req
            .cleartext
            .as_ref()
            .map(|c| serde_json::to_value(c).unwrap_or(Value::Null)),
        author,
        updated_at: 0,
    };

    match storage::put_record(
        &state.rooms_ks,
        &state.room_records_ks,
        &req.room_id,
        record,
        req.expected_version,
        now(),
    )
    .await
    {
        Ok(stored) => success_response(
            &doc,
            PutRecordResponse {
                key: stored.key,
                version: stored.version,
                epoch: stored.epoch,
            },
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `rooms/records/get/0.1`.
///
/// A read presents exactly as a write does. Authorizing reads by session would record a
/// member identifier on every access, and a period of those records reconstructs the
/// membership a sealed room exists to withhold — without breaking any cryptography.
pub(crate) async fn handle_get_record(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let req: GetRecordBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let room = match storage::get_room(&state.rooms_ks, &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Err(e) = authz::authorize(&room, &req.presentation, Action::Read) {
        return app_error_to_reject(&doc, &e);
    }

    match storage::get_record(&state.room_records_ks, &req.room_id, &req.key).await {
        Ok(record) => success_response(&doc, record),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `rooms/records/list/0.1`.
///
/// Returns metadata, never bodies — and returns tombstones to a watermark caller, because a
/// puller that never sees a retraction resurrects the record on its next full rebuild.
pub(crate) async fn handle_list_records(
    state: &AppState,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: ListRecordsBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let room = match storage::get_room(&state.rooms_ks, &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Err(e) = authz::authorize(&room, &req.presentation, Action::Read) {
        return app_error_to_reject(&doc, &e);
    }

    let records = match storage::list_records(
        &state.room_records_ks,
        &req.room_id,
        req.prefix.as_deref(),
        req.since_version,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    let limit = req.limit.unwrap_or(usize::MAX);
    success_response(
        &doc,
        ListRecordsResponse {
            records: records.iter().take(limit).map(|r| r.metadata()).collect(),
        },
    )
}

/// `rooms/epoch/mint/0.1`.
///
/// Restricted to `admin`. If any key-holder could mint an epoch, any member could evict any
/// other by minting one and declining to seal them the new key — silently, and with no
/// check possible here on a room whose membership this service cannot see. Binding it to an
/// action the *room* confers is what makes the restriction enforceable by a service that
/// knows nothing about the membership.
pub(crate) async fn handle_mint_epoch(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let req: MintEpochBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let room = match storage::get_room(&state.rooms_ks, &req.room_id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Err(e) = authz::authorize(&room, &req.presentation, Action::Admin) {
        return app_error_to_reject(&doc, &e);
    }

    match storage::advance_epoch(&state.rooms_ks, &req.room_id, req.epoch, now()).await {
        Ok(updated) => success_response(
            &doc,
            MintEpochResponse {
                room_id: updated.room_id,
                epoch: updated.epoch,
            },
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::build_test_vtc;
    use serde_json::json;
    use trust_tasks_rs::TypeUri;

    fn doc(uri: &str, payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = uri.parse().expect("rooms uri");
        TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
    }

    fn presentation() -> Value {
        json!({ "membership": "vmc", "authority": ["vac-leaf", "vac-root"] })
    }

    async fn create(state: &AppState, id: &str, visibility: &str) -> TrustTaskOutcome {
        handle_create(
            state,
            doc(
                crate::rooms::wire::ROOMS_CREATE_TYPE,
                json!({ "roomId": id, "visibility": visibility, "ownerDid": "did:key:zOwner" }),
            ),
        )
        .await
    }

    fn payload_of(out: &TrustTaskOutcome) -> Value {
        let d: Value = serde_json::from_slice(&out.body).expect("response is JSON");
        d.get("payload").cloned().unwrap_or(Value::Null)
    }

    #[tokio::test]
    async fn a_room_is_created_and_a_record_round_trips() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        assert!(create(state, "r1", "open").await.status.is_success());

        let out = handle_put_record(
            state,
            doc(
                crate::rooms::wire::ROOMS_RECORDS_PUT_TYPE,
                json!({
                    "roomId": "r1", "key": "k1", "presentation": presentation(),
                    "cleartext": { "body": "a decision" }
                }),
            ),
        )
        .await;
        assert!(out.status.is_success(), "put should succeed");
        assert_eq!(payload_of(&out)["version"], 1);

        let out = handle_get_record(
            state,
            doc(
                crate::rooms::wire::ROOMS_RECORDS_GET_TYPE,
                json!({ "roomId": "r1", "key": "k1", "presentation": presentation() }),
            ),
        )
        .await;
        assert!(out.status.is_success());
        assert_eq!(payload_of(&out)["cleartext"]["body"], "a decision");
    }

    /// The invariant the whole family rests on: authorization is the chain, and a request
    /// without one is refused regardless of who is asking.
    #[tokio::test]
    async fn an_operation_with_no_authority_chain_is_refused() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        create(state, "r1", "open").await;

        let out = handle_put_record(
            state,
            doc(
                crate::rooms::wire::ROOMS_RECORDS_PUT_TYPE,
                json!({
                    "roomId": "r1", "key": "k1",
                    "presentation": { "membership": "vmc", "authority": [] },
                    "cleartext": { "body": "x" }
                }),
            ),
        )
        .await;
        assert!(
            !out.status.is_success(),
            "an empty chain authorizes nothing"
        );
    }

    #[tokio::test]
    async fn a_private_room_refuses_a_presentation_without_a_subject_binding() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        create(state, "p1", "private").await;

        let out = handle_get_record(
            state,
            doc(
                crate::rooms::wire::ROOMS_RECORDS_GET_TYPE,
                json!({ "roomId": "p1", "key": "k", "presentation": presentation() }),
            ),
        )
        .await;
        assert!(!out.status.is_success());
        let body = String::from_utf8_lossy(&out.body);
        assert!(body.contains("subject binding"), "{body}");
    }

    #[tokio::test]
    async fn listing_returns_metadata_and_never_bodies() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        create(state, "r1", "open").await;
        for k in ["a", "b"] {
            handle_put_record(
                state,
                doc(
                    crate::rooms::wire::ROOMS_RECORDS_PUT_TYPE,
                    json!({
                        "roomId": "r1", "key": k, "presentation": presentation(),
                        "cleartext": { "body": "secret-body-text" }
                    }),
                ),
            )
            .await;
        }

        let out = handle_list_records(
            state,
            doc(
                crate::rooms::wire::ROOMS_RECORDS_LIST_TYPE,
                json!({ "roomId": "r1", "presentation": presentation() }),
            ),
        )
        .await;
        assert!(out.status.is_success());
        let body = String::from_utf8_lossy(&out.body);
        assert!(body.contains("\"key\""), "metadata is returned");
        assert!(
            !body.contains("secret-body-text"),
            "a listing must never carry bodies: {body}"
        );
    }

    #[tokio::test]
    async fn a_room_cannot_be_created_twice() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        assert!(create(state, "r1", "open").await.status.is_success());
        assert!(
            !create(state, "r1", "open").await.status.is_success(),
            "re-creating would reset the epoch and version counter"
        );
    }

    #[tokio::test]
    async fn minting_an_epoch_requires_admin_and_advances_by_one() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        create(state, "r1", "open").await;

        let out = handle_mint_epoch(
            state,
            doc(
                crate::rooms::wire::ROOMS_EPOCH_MINT_TYPE,
                json!({ "roomId": "r1", "epoch": 2, "presentation": presentation() }),
            ),
        )
        .await;
        assert!(out.status.is_success());
        assert_eq!(payload_of(&out)["epoch"], 2);

        // A gap is refused: it would seal records under an epoch nobody holds a key for.
        let out = handle_mint_epoch(
            state,
            doc(
                crate::rooms::wire::ROOMS_EPOCH_MINT_TYPE,
                json!({ "roomId": "r1", "epoch": 9, "presentation": presentation() }),
            ),
        )
        .await;
        assert!(!out.status.is_success());
    }

    /// An unknown member on a payload carrying an authorization decision is a request that
    /// means something this service did not understand.
    #[tokio::test]
    async fn an_unknown_payload_member_is_refused() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        create(state, "r1", "open").await;
        let out = handle_get_record(
            state,
            doc(
                crate::rooms::wire::ROOMS_RECORDS_GET_TYPE,
                json!({
                    "roomId": "r1", "key": "k", "presentation": presentation(),
                    "escalate": true
                }),
            ),
        )
        .await;
        assert!(!out.status.is_success(), "deny_unknown_fields must hold");
    }
}
