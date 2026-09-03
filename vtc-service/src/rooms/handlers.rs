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

use crate::server::AppState;
use crate::trust_tasks::helpers::{
    TrustTaskOutcome, app_error_to_reject, parse_payload, success_response, verify_trust_task_proof,
};
use vti_rooms::authz::{self, Action};
use vti_rooms::storage;
use vti_rooms::wire::{
    CreateRoomBody, CreateRoomResponse, GetRecordBody, ListRecordsBody, ListRecordsResponse,
    MintEpochBody, MintEpochResponse, PutRecordBody, PutRecordResponse,
};
use vti_rooms::{Record, RecordStatus, Room};
use vti_rooms_dtg::{DataIntegrityKeys, DtgChainVerifier};

/// The DID that actually signed this request, and the verifier to judge its chain with.
///
/// Two things a room operation needs and a session does not supply. The presenter comes
/// from the document's own `eddsa-jcs-2022` proof — not from any field in the payload —
/// because a presentation names what may be done, not who is doing it: unbound, it is a
/// bearer token that anyone observing it inherits.
async fn presenter_and_verifier(
    state: &AppState,
    doc: &TrustTask<Value>,
) -> Result<(String, DtgChainVerifier), vti_common::error::AppError> {
    let presenter = verify_trust_task_proof(state, doc).await?;
    // `without_zk`: this service has no zero-knowledge profile for a private room's subject
    // binding, and the verifier refuses those rather than serving a pooling defence nobody
    // checked. Swap for `with_zk` when the working group settles the profile.
    Ok((
        presenter,
        DtgChainVerifier::without_zk(Box::new(DataIntegrityKeys(state.trust_task_vm_resolver()))),
    ))
}

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

/// One epoch lifetime in seconds — how long a newly created room is live before it needs
/// renewing. Not a per-room parameter yet: `rooms/create/0.1` has no member for it, and
/// inventing one locally would put this host's rooms out of conformance with the schema.
const EPOCH_LIFETIME_DAYS_SECS: u64 =
    vti_rooms::lifecycle::DEFAULT_EPOCH_LIFETIME_DAYS as u64 * 24 * 60 * 60;

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
        // A room is live from creation for one epoch lifetime; minting the next epoch
        // renews it. Nothing else moves this clock — see `vti_rooms::lifecycle`.
        epoch_expires_at: Some(now() + EPOCH_LIFETIME_DAYS_SECS),
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
    let (presenter, verifier) = match presenter_and_verifier(state, &doc).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        Action::Write,
        &presenter,
        now(),
        &verifier,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    // The author is recorded only where the tier discloses one. On a private room
    // authorship lives inside the sealed body, and the storage layer refuses it here.
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
    let (presenter, verifier) = match presenter_and_verifier(state, &doc).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Err(e) = authz::authorize(
        &room,
        &req.presentation,
        Action::Read,
        &presenter,
        now(),
        &verifier,
    )
    .await
    {
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
    let (presenter, verifier) = match presenter_and_verifier(state, &doc).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Err(e) = authz::authorize(
        &room,
        &req.presentation,
        Action::Read,
        &presenter,
        now(),
        &verifier,
    )
    .await
    {
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
    let (presenter, verifier) = match presenter_and_verifier(state, &doc).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    if let Err(e) = authz::authorize(
        &room,
        &req.presentation,
        Action::Admin,
        &presenter,
        now(),
        &verifier,
    )
    .await
    {
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
    use vti_rooms::Visibility;
    use vti_rooms_dtg::test_support::RoomFixture;

    /// A **signed** room document.
    ///
    /// Signing is not ceremony here: the presenter comes from this proof, and every handler
    /// below refuses an unsigned request before it looks at any chain.
    async fn doc(
        state: &AppState,
        uri: &str,
        payload: Value,
        signer_did: &str,
        signer_key: &str,
    ) -> TrustTask<Value> {
        let recipient = state
            .config
            .read()
            .await
            .vtc_did
            .clone()
            .unwrap_or_else(|| "did:key:zVtc".to_string());
        let signed = vta_sdk::trust_task_sign::build_signed(
            uri, payload, signer_did, signer_key, &recipient,
        )
        .await
        .expect("sign the request");
        serde_json::from_str(&signed).expect("a signed document is a document")
    }

    fn payload_of(out: &TrustTaskOutcome) -> Value {
        let d: Value = serde_json::from_slice(&out.body).expect("response is JSON");
        d.get("payload").cloned().unwrap_or(Value::Null)
    }

    /// Register the fixture's room with this VTC.
    async fn create(state: &AppState, f: &RoomFixture) -> TrustTaskOutcome {
        handle_create(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_CREATE_TYPE,
                json!({
                    "roomId": f.room.room_id,
                    "visibility": f.room.visibility,
                    "ownerDid": f.room.owner_did,
                }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await
    }

    #[tokio::test]
    async fn a_room_is_created_and_a_record_round_trips() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        let f = RoomFixture::new(Visibility::Open).await;
        assert!(create(state, &f).await.status.is_success());

        let out = handle_put_record(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
                json!({
                    "roomId": f.room.room_id, "key": "k1", "presentation": f.as_owner(),
                    "cleartext": { "body": "a decision" }
                }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(out.status.is_success(), "put: {}", payload_of(&out));
        assert_eq!(payload_of(&out)["version"], 1);

        let out = handle_get_record(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
                json!({ "roomId": f.room.room_id, "key": "k1", "presentation": f.as_owner() }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(out.status.is_success());
        let got = payload_of(&out);
        assert_eq!(got["cleartext"]["body"], "a decision");
        assert_eq!(
            got["author"], f.owner.did,
            "the author is the subject the chain established, not the room's owner field"
        );
    }

    /// The invariant the whole family rests on: authorization is the chain, and a request
    /// without one is refused regardless of who is asking.
    #[tokio::test]
    async fn an_operation_with_no_authority_chain_is_refused() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        let f = RoomFixture::new(Visibility::Open).await;
        create(state, &f).await;

        let out = handle_get_record(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
                json!({
                    "roomId": f.room.room_id, "key": "k1",
                    "presentation": { "membership": f.membership, "authority": [] }
                }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(!out.status.is_success());
    }

    /// The agent case, through the VTC rather than a standalone host — the two must reach
    /// the same conclusion, because both go through the same `vti-rooms-dtg`.
    #[tokio::test]
    async fn an_agent_reads_under_a_narrower_chain_and_cannot_write() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        let f = RoomFixture::new(Visibility::Open).await;
        create(state, &f).await;

        handle_put_record(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
                json!({
                    "roomId": f.room.room_id, "key": "k", "presentation": f.as_owner(),
                    "cleartext": { "body": "for the agent" }
                }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;

        let out = handle_get_record(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
                json!({ "roomId": f.room.room_id, "key": "k", "presentation": f.as_agent() }),
                &f.agent.did,
                &f.agent.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(
            out.status.is_success(),
            "the agent reads: {}",
            payload_of(&out)
        );

        let out = handle_put_record(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
                json!({
                    "roomId": f.room.room_id, "key": "k2", "presentation": f.as_agent(),
                    "cleartext": { "body": "but must not write" }
                }),
                &f.agent.did,
                &f.agent.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(!out.status.is_success(), "a read-only chain must not write");
    }

    /// A private room is refused for want of a zero-knowledge profile — and the refusal is
    /// the same one a standalone room host gives, because it comes from the shared crate.
    #[tokio::test]
    async fn a_private_room_is_refused_for_want_of_a_zk_profile() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        let f = RoomFixture::new(Visibility::Private).await;
        create(state, &f).await;

        let mut p = f.as_owner();
        p.subject_binding = Some("a-binding-nobody-can-check".into());

        let out = handle_get_record(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
                json!({ "roomId": f.room.room_id, "key": "k", "presentation": p }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(!out.status.is_success());
        assert!(
            payload_of(&out)["message"]
                .as_str()
                .unwrap_or_default()
                .contains("zero-knowledge profile"),
            "{}",
            payload_of(&out)
        );
    }

    /// A private room refuses a presentation with no binding at all before any credential
    /// is parsed — the shape check, which is `vti-rooms`' half.
    #[tokio::test]
    async fn a_private_room_refuses_a_presentation_without_a_subject_binding() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        let f = RoomFixture::new(Visibility::Private).await;
        create(state, &f).await;

        let out = handle_get_record(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
                json!({ "roomId": f.room.room_id, "key": "k", "presentation": f.as_owner() }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(!out.status.is_success());
        assert!(
            payload_of(&out)["message"]
                .as_str()
                .unwrap_or_default()
                .contains("subject binding"),
            "{}",
            payload_of(&out)
        );
    }

    #[tokio::test]
    async fn listing_returns_metadata_and_never_bodies() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        let f = RoomFixture::new(Visibility::Open).await;
        create(state, &f).await;

        handle_put_record(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
                json!({
                    "roomId": f.room.room_id, "key": "a", "presentation": f.as_owner(),
                    "cleartext": { "body": "secret-body-text" }
                }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;

        let out = handle_list_records(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE,
                json!({ "roomId": f.room.room_id, "presentation": f.as_owner() }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(out.status.is_success());
        let text = payload_of(&out).to_string();
        assert!(text.contains("\"key\""));
        assert!(
            !text.contains("secret-body-text"),
            "a listing must never carry bodies: {text}"
        );
    }

    /// `admin`, not `write`: if any key-holder could mint an epoch, any member could evict
    /// any other, and the service — which cannot see the membership — would never know.
    #[tokio::test]
    async fn minting_an_epoch_requires_admin_and_advances_by_one() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        let f = RoomFixture::new(Visibility::Open).await;
        create(state, &f).await;

        // The agent's chain confers `read` alone.
        let out = handle_mint_epoch(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_EPOCH_MINT_TYPE,
                json!({ "roomId": f.room.room_id, "epoch": 2, "presentation": f.as_agent() }),
                &f.agent.did,
                &f.agent.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(!out.status.is_success(), "read may not mint an epoch");

        // The owner's confers `admin`.
        let out = handle_mint_epoch(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_EPOCH_MINT_TYPE,
                json!({ "roomId": f.room.room_id, "epoch": 2, "presentation": f.as_owner() }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(out.status.is_success(), "{}", payload_of(&out));
        assert_eq!(payload_of(&out)["epoch"], 2);

        // And it advances by exactly one — skipping would seal records under an epoch no
        // member was ever given a key for.
        let out = handle_mint_epoch(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_EPOCH_MINT_TYPE,
                json!({ "roomId": f.room.room_id, "epoch": 5, "presentation": f.as_owner() }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(!out.status.is_success(), "an epoch may not skip");
    }
}
