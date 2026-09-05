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
use vti_common::audit::{AuditEvent, RoomOperationData};
use vti_rooms::audit::{self as rooms_audit, RoomOperation};
use vti_rooms::authz::{self, Action};
use vti_rooms::storage;
use vti_rooms::wire::{
    ClaimOwnerBody, CreateRoomBody, CreateRoomResponse, CurateRecordBody, CurateRecordResponse,
    GetRecordBody, ListRecordsBody, ListRecordsResponse, MintEpochBody, MintEpochResponse,
    OwnerResponse, PutRecordBody, PutRecordResponse, TransferOwnerBody,
};
use vti_rooms::{Record, RecordStatus, Room};
use vti_rooms_dtg::{DataIntegrityKeys, DtgChainVerifier, nomination};

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

/// Record a room operation, per §8 of the design note.
///
/// **What may be recorded is decided by `vti_rooms::audit`, never here.** On a `private`
/// room the actor is the actorless marker rather than a DID, because an audit log naming
/// every actor *is* the membership this service was built never to learn — assembled one
/// entry at a time by the component least able to notice it is doing so.
///
/// A failed write is logged and swallowed. The alternative is refusing an operation that
/// already succeeded, which turns an audit outage into a room outage and tells the caller
/// their write failed when it did not. The audit chain's own integrity is protected by its
/// hash chain, which makes a gap visible to a verifier — that is the right place for this
/// to be noticed, not in a handler's return value.
async fn audit_room(
    state: &AppState,
    room: &Room,
    authorized: &authz::AuthorizedAction,
    operation: RoomOperation,
    record_key: Option<&str>,
) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    let entry = rooms_audit::for_operation(room.visibility, authorized, record_key);
    let action = operation.action_name();

    if let Err(e) = writer
        .write(
            entry.actor.as_str(),
            None,
            AuditEvent::RoomOperation(RoomOperationData {
                room_id: entry.room_id,
                action: action.to_string(),
                record_key: entry.record_key,
                visibility: format!("{:?}", room.visibility).to_lowercase(),
            }),
        )
        .await
    {
        tracing::error!(error = %e, action, "failed to record a room audit entry");
    }
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
        pinned: false,
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
        Ok(stored) => {
            audit_room(
                state,
                &room,
                &authorized,
                RoomOperation::PutRecord,
                Some(&stored.key),
            )
            .await;
            success_response(
                &doc,
                PutRecordResponse {
                    key: stored.key,
                    version: stored.version,
                    epoch: stored.epoch,
                },
            )
        }
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
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        Action::Read,
        &presenter,
        now(),
        &verifier,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    match storage::get_record(&state.room_records_ks, &req.room_id, &req.key).await {
        Ok(record) => {
            audit_room(
                state,
                &room,
                &authorized,
                RoomOperation::GetRecord,
                Some(&req.key),
            )
            .await;
            success_response(&doc, record)
        }
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
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        Action::Read,
        &presenter,
        now(),
        &verifier,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

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
    // A listing names no single record, so the entry records the room and the fact of a
    // listing — which is the event: who has seen what this room holds.
    audit_room(state, &room, &authorized, RoomOperation::ListRecords, None).await;
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
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        Action::Admin,
        &presenter,
        now(),
        &verifier,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    match storage::advance_epoch(&state.rooms_ks, &req.room_id, req.epoch, now()).await {
        Ok(updated) => {
            audit_room(state, &room, &authorized, RoomOperation::MintEpoch, None).await;
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

/// `rooms/owner/transfer/0.1`.
///
/// An owner hands the room to another member, deliberately and while still present.
///
/// Gated on `admin` — the same grant that mints epochs, because transferring is the more
/// consequential of the two and it would be strange for the lesser act to ask for more.
///
/// # What this handler does not check, and why that is correct
///
/// That the incoming owner is a member. The spec requires them to be one, and **this host
/// cannot see the MLS group**: it holds no roster and no group state. The temptation is to
/// invent a check anyway — demand a credential, or refuse when unsure — and both are worse
/// than doing nothing. A host that refuses what it cannot verify fails *every* transfer,
/// including every correct one, and a host that treats its own ignorance as evidence has
/// converted "I don't know" into "no".
///
/// The spec says as much in the error code itself: `notAMember` is raised only when a host
/// "could independently establish" it, and this one cannot. What protects the incoming
/// owner is that the outgoing one holds `admin` and knows the roster.
pub(crate) async fn handle_transfer_owner(
    state: &AppState,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: TransferOwnerBody = match parse_payload(&doc) {
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
    let operation = RoomOperation::TransferOwner;
    let authorized = match authz::authorize(
        &room,
        &req.presentation,
        operation.required_action(),
        &presenter,
        now(),
        &verifier,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    match storage::set_owner(&state.rooms_ks, &req.room_id, &req.new_owner_did, now()).await {
        Ok(updated) => {
            audit_room(state, &room, &authorized, operation, None).await;
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

/// `rooms/owner/claim/0.1`.
///
/// A nominated successor takes a room whose owner has stopped renewing it.
///
/// # Three conditions, checked in the order that gives the most useful answer
///
/// 1. **A nomination the room issued**, naming this claimant, in its window, rooted at the
///    room. [`vti_rooms_dtg::nomination`].
/// 2. **The room is dormant** — not merely lapsed. [`Lifecycle::admits_a_claim`].
/// 3. **The claimant holds membership**, which is the presentation every other room task
///    carries, gated at `read`.
///
/// The order is deliberate. A claimant whose nomination is bad should hear that first,
/// because it is the one they can do nothing about by waiting; telling them "the room is
/// still live" when their credential was never valid sends them back in thirty days to
/// receive the real answer.
///
/// # Renewing is the defence, and it is the same act as ordinary use
///
/// Condition 2 is why a hostile nomination is survivable. An owner who was merely away
/// defeats every pending claim by minting an epoch — which is what they would have done
/// anyway. Nothing has to be revoked and no dispute has to be raised, so an owner who is
/// present is structurally safe from succession without ever thinking about it.
///
/// # And a claim does not renew the room
///
/// [`storage::set_owner`] leaves a dormant room dormant. The new owner's first act should
/// be the one that proves they can perform it; see that function for why.
pub(crate) async fn handle_claim_owner(
    state: &AppState,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: ClaimOwnerBody = match parse_payload(&doc) {
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

    // 1. The nomination, against the party who actually signed this request — never against
    //    a DID named in the payload, which the claimant chooses.
    let keys = DataIntegrityKeys(state.trust_task_vm_resolver());
    if let Err(e) = nomination::verify(&req.nomination, &room.room_id, &presenter, &keys).await {
        return app_error_to_reject(&doc, &e);
    }

    // 2. Dormant, not merely lapsed. An epoch expiring is frequently somebody on holiday.
    let lifecycle = room.lifecycle(now());
    if !lifecycle.admits_a_claim() {
        return app_error_to_reject(
            &doc,
            &vti_common::error::AppError::Forbidden(format!(
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
        &presenter,
        now(),
        &verifier,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    match storage::set_owner(&state.rooms_ks, &req.room_id, &presenter, now()).await {
        Ok(updated) => {
            audit_room(state, &room, &authorized, operation, None).await;
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
/// room's shared knowledge is worth is a different grant from the ability to add to it. A
/// community can hand an agent `write` without handing it the standing to demote what a
/// person wrote.
pub(crate) async fn handle_curate_record(
    state: &AppState,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: CurateRecordBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if req.status.is_none() && req.pinned.is_none() {
        return app_error_to_reject(
            &doc,
            &vti_common::error::AppError::Validation(
                "a curation must change something: supply `status`, `pinned`, or both".into(),
            ),
        );
    }

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
        Action::Curate,
        &presenter,
        now(),
        &verifier,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    match storage::curate_record(
        &state.rooms_ks,
        &state.room_records_ks,
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
            audit_room(
                state,
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

    /// Every room operation leaves a trail. §8: on shared material, reads are the
    /// interesting event — a write log says what a room holds, a read log says who has
    /// seen it.
    #[tokio::test]
    async fn room_operations_are_audited() {
        let tv = crate::test_support::TestVtc::builder()
            .with_audit(true)
            .build()
            .await;
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
                    "cleartext": { "body": "x" }
                }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;

        handle_get_record(
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

        let rows = audit_rows(state).await;
        assert!(
            rows.contains("room.records.put") && rows.contains("room.records.get"),
            "both the write and the read must be recorded: {rows}"
        );
        assert!(
            rows.contains(&f.owner.did),
            "an open room discloses the actor: {rows}"
        );
    }

    /// The property this whole slice exists to protect. An audit log naming every actor on
    /// a private room *is* the membership the service was built never to learn — assembled
    /// one entry at a time, with nothing breaking and no test going red.
    #[tokio::test]
    async fn a_private_rooms_audit_trail_never_names_the_actor() {
        let tv = crate::test_support::TestVtc::builder()
            .with_audit(true)
            .build()
            .await;
        let state = &tv.state;
        let f = RoomFixture::new(Visibility::Private).await;
        create(state, &f).await;

        // A private room is refused for want of a ZK profile, so drive the audit path
        // directly with an authorization the verifier produced — the point under test is
        // what gets *recorded*, not what gets served.
        let room = storage::get_room(&state.rooms_ks, &f.room.room_id)
            .await
            .expect("room");
        let mut presentation = f.as_owner();
        presentation.subject_binding = Some("a-binding".into());
        let authorized = authz::authorize(
            &room,
            &presentation,
            Action::Read,
            &f.owner.did,
            now(),
            &AlwaysVouches,
        )
        .await
        .expect("authorized");

        audit_room(
            state,
            &room,
            &authorized,
            RoomOperation::GetRecord,
            Some("opaque-key"),
        )
        .await;

        let rows = audit_rows(state).await;
        assert!(
            rows.contains("room.records.get"),
            "the operation is recorded: {rows}"
        );
        assert!(
            rows.contains("opaque-key"),
            "the record is recorded — an opaque key identifies without describing: {rows}"
        );
        assert!(
            !rows.contains(&f.owner.did),
            "but the actor must appear nowhere in the audit trail: {rows}"
        );
    }

    /// Stands in for the chain verifier so the audit path can be reached on a tier the
    /// service otherwise refuses to serve.
    struct AlwaysVouches;

    #[async_trait::async_trait]
    impl vti_rooms::authz::ChainVerifier for AlwaysVouches {
        async fn verify(
            &self,
            _: &vti_rooms::Room,
            _: &vti_rooms::wire::AuthorityPresentation,
            _: Action,
            presenter: &str,
        ) -> Result<vti_rooms::authz::VerifiedChain, vti_common::error::AppError> {
            Ok(vti_rooms::authz::VerifiedChain {
                subject: presenter.to_string(),
                actions: vec!["read".into()],
            })
        }
    }

    /// Every audit row, as one string to assert over.
    async fn audit_rows(state: &AppState) -> String {
        let raw = state
            .audit_ks
            .prefix_iter_raw(Vec::<u8>::new())
            .await
            .expect("read the audit keyspace");
        raw.into_iter()
            .map(|(_, v)| String::from_utf8_lossy(&v).into_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The grant separation, end to end. The fixture's agent chain confers `read` alone,
    /// so an agent that can read a room cannot demote what a person wrote in it.
    #[tokio::test]
    async fn curating_needs_its_own_grant_and_is_not_implied_by_write() {
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
                    "cleartext": { "body": "a decision" }
                }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;

        let out = handle_curate_record(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_RECORDS_CURATE_TYPE,
                json!({
                    "roomId": f.room.room_id, "key": "k",
                    "presentation": f.as_agent(), "status": "deprecated"
                }),
                &f.agent.did,
                &f.agent.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(
            !out.status.is_success(),
            "a read-only agent must not curate: {}",
            payload_of(&out)
        );

        // The owner's chain confers curate.
        let out = handle_curate_record(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_RECORDS_CURATE_TYPE,
                json!({
                    "roomId": f.room.room_id, "key": "k",
                    "presentation": f.as_owner(), "status": "deprecated", "pinned": true
                }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(out.status.is_success(), "{}", payload_of(&out));
        let body = payload_of(&out);
        assert_eq!(body["status"], "deprecated");
        assert_eq!(body["pinned"], true, "pinned and deprecated at once");
        assert_eq!(body["version"], 2, "curation assigns a new version");
    }

    /// A retraction drops the body and keeps the tombstone, and the tombstone is what a
    /// caller synchronising on `sinceVersion` needs in order to converge.
    #[tokio::test]
    async fn a_retraction_leaves_a_tombstone_a_listing_still_reports() {
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
                    "cleartext": { "body": "secret-body-text" }
                }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;

        handle_curate_record(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_RECORDS_CURATE_TYPE,
                json!({
                    "roomId": f.room.room_id, "key": "k",
                    "presentation": f.as_owner(), "status": "retracted"
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
        let text = payload_of(&out).to_string();
        assert!(
            text.contains("retracted"),
            "the tombstone must still be listed, or sync cannot converge: {text}"
        );

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
        assert!(
            !payload_of(&out).to_string().contains("secret-body-text"),
            "but the body is gone: {}",
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

    /// Register the fixture's room with a chosen epoch expiry, bypassing the handler.
    ///
    /// Succession is entirely about the passage of time; writing the room in the state a
    /// year would produce is the only way to test it without waiting one.
    async fn create_expiring(state: &AppState, f: &RoomFixture, epoch_expires_at: Option<u64>) {
        storage::create_room(
            &state.rooms_ks,
            &Room {
                epoch_expires_at,
                ..f.room.clone()
            },
        )
        .await
        .expect("register the room");
    }

    fn days_ago(n: u64) -> Option<u64> {
        Some(now() - n * 24 * 60 * 60)
    }

    async fn claim(state: &AppState, f: &RoomFixture, payload: Value) -> TrustTaskOutcome {
        handle_claim_owner(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_OWNER_CLAIM_TYPE,
                payload,
                &f.successor.did,
                &f.successor.secret_multibase,
            )
            .await,
        )
        .await
    }

    /// `admin`, and the audit entry names the operation rather than the authority.
    #[tokio::test]
    async fn transferring_requires_admin_and_names_the_new_owner() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        let f = RoomFixture::new(Visibility::Open).await;
        create(state, &f).await;

        // `read` is not enough; the agent's chain is the narrower one a member delegates.
        let out = handle_transfer_owner(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_OWNER_TRANSFER_TYPE,
                json!({
                    "roomId": f.room.room_id,
                    "newOwnerDid": f.agent.did,
                    "presentation": f.as_agent(),
                }),
                &f.agent.did,
                &f.agent.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(
            !out.status.is_success(),
            "an agent may not hand away the room"
        );

        let out = handle_transfer_owner(
            state,
            doc(
                state,
                vti_rooms::wire::ROOMS_OWNER_TRANSFER_TYPE,
                json!({
                    "roomId": f.room.room_id,
                    "newOwnerDid": f.successor.did,
                    "presentation": f.as_owner(),
                    "reason": "stepping back",
                }),
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await,
        )
        .await;
        assert!(out.status.is_success(), "{}", payload_of(&out));
        assert_eq!(payload_of(&out)["ownerDid"], f.successor.did);

        let stored = storage::get_room(&state.rooms_ks, &f.room.room_id)
            .await
            .unwrap();
        assert_eq!(stored.owner_did, f.successor.did, "and it persisted");
    }

    /// The whole point of the pair: a room outlives one person's availability.
    #[tokio::test]
    async fn a_nominated_successor_claims_a_dormant_room() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        let f = RoomFixture::new(Visibility::Open).await;
        create_expiring(state, &f, days_ago(60)).await;

        let out = claim(
            state,
            &f,
            json!({
                "roomId": f.room.room_id,
                "nomination": f.nominate(&f.successor.did, Some(24)).await,
                "presentation": f.as_successor(),
                "reason": "unreachable since March",
            }),
        )
        .await;
        assert!(out.status.is_success(), "{}", payload_of(&out));
        assert_eq!(payload_of(&out)["ownerDid"], f.successor.did);

        // A claim hands over a dormant room; it does not revive one. The new owner's first
        // act should be the one that proves they can perform it.
        let stored = storage::get_room(&state.rooms_ks, &f.room.room_id)
            .await
            .unwrap();
        assert!(!stored.lifecycle(now()).accepts_writes());
    }

    /// The defence, and it is the same act as ordinary use: an owner who was merely away
    /// renews, and every pending claim stops working. Nothing has to be revoked.
    #[tokio::test]
    async fn renewing_defeats_a_pending_claim() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        let f = RoomFixture::new(Visibility::Open).await;
        create_expiring(state, &f, days_ago(60)).await;

        let nomination = f.nominate(&f.successor.did, Some(24)).await;

        // The owner returns and mints an epoch — ordinary use, nothing succession-specific.
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

        let out = claim(
            state,
            &f,
            json!({
                "roomId": f.room.room_id,
                "nomination": nomination,
                "presentation": f.as_successor(),
            }),
        )
        .await;
        assert!(
            !out.status.is_success(),
            "the same nomination that would have worked a moment ago: {}",
            payload_of(&out)
        );

        let stored = storage::get_room(&state.rooms_ks, &f.room.room_id)
            .await
            .unwrap();
        assert_eq!(stored.owner_did, f.owner.did, "and the owner kept the room");
    }

    /// Dormancy alone confers nothing, or any member of any quiet room could take it.
    #[tokio::test]
    async fn a_member_of_a_dormant_room_cannot_claim_without_being_named() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        let f = RoomFixture::new(Visibility::Open).await;
        create_expiring(state, &f, days_ago(60)).await;

        // A genuine nomination the room issued — naming somebody else.
        let out = claim(
            state,
            &f,
            json!({
                "roomId": f.room.room_id,
                "nomination": f.nominate(&f.agent.did, Some(24)).await,
                "presentation": f.as_successor(),
            }),
        )
        .await;
        assert!(
            !out.status.is_success(),
            "a nomination is bound to the party it names: {}",
            payload_of(&out)
        );
    }

    /// The order the handler checks in, which is the difference between an answer a
    /// claimant can act on and one that sends them back in a month for the real one.
    #[tokio::test]
    async fn a_bad_nomination_is_reported_before_the_room_is_still_live() {
        let tv = build_test_vtc().await;
        let state = &tv.state;
        let f = RoomFixture::new(Visibility::Open).await;
        create_expiring(state, &f, Some(now() + 30 * 24 * 60 * 60)).await;

        let out = claim(
            state,
            &f,
            json!({
                "roomId": f.room.room_id,
                "nomination": f.nominate(&f.agent.did, Some(24)).await,
                "presentation": f.as_successor(),
            }),
        )
        .await;
        assert!(!out.status.is_success());
        let body = payload_of(&out).to_string();
        assert!(
            !body.contains("dormant"),
            "the nomination was never valid; saying `still live` hides that: {body}"
        );
    }
}
