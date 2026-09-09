//! A room host: it stores data-room records and serves them back.
//!
//! # What this is, and what it deliberately is not
//!
//! A room host is a **delivery service**. It holds records — ciphertext, on any tier but
//! `open` — and answers `rooms/*` Trust Tasks against them. It is not a community: it has no
//! member roster, no policy engine, no credential issuance, no admin surface, and no opinion
//! about who belongs to any room it stores.
//!
//! That is not minimalism for its own sake. **A room is authorized by credentials the room
//! itself issued**, so a host that kept its own record of who belongs would become part of
//! that room's membership, and the room could no longer move to a different host without
//! reissuing credentials. The absence of a roster here is the portability guarantee, made
//! structural: there is nothing in this binary that could consult one.
//!
//! # Why it exists as its own binary
//!
//! Topology T1 of the data-rooms design is a person hosting their own rooms on
//! infrastructure they control. Before `vti-rooms` was extracted, doing that meant running a
//! whole community service — member lifecycle, policy, credentials, a website, an admin SPA
//! — to store some ciphertext. This is the same room protocol with none of that.
//!
//! It is also deliberately **not** part of the VTA. The process guarding a master seed
//! should not also terminate presentations from arbitrary DIDs, which is why the design
//! makes a room host an ordinary provisioned integration with its own DID (the `room-host`
//! DID template) rather than a new surface on the agent.
//!
//! # How a request is authorized
//!
//! Two things this host takes from a request and nothing else:
//!
//! - the **presenter**, from the document's own `eddsa-jcs-2022` proof. Not from a payload
//!   field — a presentation says what may be done, not who is doing it, so an unbound one
//!   is a bearer token anyone observing it inherits.
//! - the **chain**, verified by [`vti_rooms_dtg`] against credentials the room issued.
//!
//! Neither is a lookup in anything this host stores, which is the whole of invariant I5.
//!
//! # Status
//!
//! `open` and `attributed` rooms serve. A `private` room is refused, because its subject
//! binding has to be proved in zero knowledge and the working group has not settled the
//! profile — the refusal comes from `vti-rooms-dtg`, which is also what a VTC uses, so the
//! two cannot disagree about what is safe to serve.

pub mod mirror;

/// Being reachable at a mediator, as well as at a URL.
#[cfg(feature = "didcomm")]
pub mod didcomm;

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;

use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};
use trust_tasks_https::status_for_code;
use trust_tasks_rs::{RejectReason, TrustTask};
use uuid::Uuid;
use vti_common::config::StoreConfig;
use vti_common::error::AppError;
use vti_common::store::{KeyspaceHandle, Store};
use vti_rooms::audit::{self as rooms_audit, RoomOperation};
use vti_rooms::wire::{
    ChainBody, ChainResponse, ClaimOwnerBody, CreateRoomBody, CreateRoomResponse, CurateRecordBody,
    CurateRecordResponse, GetRecordBody, GetRecordResponse, ListRecordsBody, ListRecordsResponse,
    MintEpochBody, MintEpochResponse, OwnerResponse, PutRecordBody, PutRecordResponse,
    ROOMS_CREATE_TYPE, ROOMS_EPOCH_CHAIN_TYPE, ROOMS_EPOCH_MINT_TYPE, ROOMS_OWNER_CLAIM_TYPE,
    ROOMS_OWNER_TRANSFER_TYPE, ROOMS_RECORDS_CURATE_TYPE, ROOMS_RECORDS_GET_TYPE,
    ROOMS_RECORDS_LIST_TYPE, ROOMS_RECORDS_PUT_TYPE, TransferOwnerBody,
};
use vti_rooms::{
    ROOM_RECORDS_KEYSPACE, ROOMS_KEYSPACE, Record, RecordStatus, Room,
    authz::{self, Action},
    storage,
};
use vti_rooms_dtg::{DataIntegrityKeys, DtgChainVerifier, nomination};

/// Default retention after a room's epoch lapses without renewal.
const DEFAULT_RETENTION_DAYS: u32 = 90;

/// One epoch lifetime in seconds — how long a newly created room is live before it needs
/// renewing. Not a per-room parameter yet: `rooms/create/0.1` has no member for it, and
/// inventing one locally would put this host's rooms out of conformance with the schema.
const EPOCH_LIFETIME_DAYS_SECS: u64 =
    vti_rooms::lifecycle::DEFAULT_EPOCH_LIFETIME_DAYS as u64 * 24 * 60 * 60;

/// Everything this host holds. Two keyspaces and a verifier — and note what is not here.
#[derive(Clone)]
pub struct HostState {
    rooms: KeyspaceHandle,
    records: KeyspaceHandle,
    /// The rooms' epoch key chains. Wrapped key material this host cannot read.
    epoch_links: KeyspaceHandle,
    /// How a DID resolves to the key that signed a credential.
    ///
    /// A room's credentials are issued by the room, which is normally a `did:webvh`, so a
    /// host restricted to `did:key` can serve almost nothing. It is still the default when
    /// no resolver is configured: refusing what it cannot verify is correct, and quietly
    /// resolving over the network for an unauthenticated caller is not.
    resolver: vti_common::auth::TrustTaskVmResolver,
}

impl HostState {
    /// The room keyspace.
    ///
    /// This crate already exports `open_state` and `router` so a host can be embedded; this
    /// is the third thing an embedder needs — placing a room in a state no wire call can
    /// produce. Restoring from a backup is one such case. Ageing a room past its epoch, so
    /// succession can be demonstrated without waiting a year, is the one the `data_room`
    /// example uses it for.
    ///
    /// It is deliberately the *rooms* keyspace and not the records one: seeding rooms is a
    /// legitimate administrative act, and handing out the record store would let an embedder
    /// write records around every authorization check in this file.
    pub fn rooms(&self) -> &KeyspaceHandle {
        &self.rooms
    }

    /// The record keyspace, for the mirror puller.
    ///
    /// Deliberately *not* the general-purpose escape hatch `rooms()` is careful
    /// not to be: a mirror writes records this host did not authorize, which is
    /// exactly what a copy is, and `storage::store_mirrored_record` refuses to
    /// do it on a room this host primaries. An embedder reaching for this to
    /// write records around the authorization checks would be writing them into
    /// a room whose version counter disagrees.
    pub fn records(&self) -> &KeyspaceHandle {
        &self.records
    }

    /// The presenter — proven by the document's own proof, never claimed in its payload.
    ///
    /// Split out from [`Self::presenter_and_verifier`] because `rooms/create` needs this half
    /// and only this half: a room that does not exist yet has issued no credentials, so there
    /// is no chain to judge and nothing for a verifier to do.
    async fn presenter(&self, doc: &TrustTask<Value>) -> Result<String, AppError> {
        vti_common::auth::verify_trust_task_proof_with(doc, &self.resolver)
            .await
            .map_err(|e| AppError::Forbidden(format!("request proof: {e}")))
    }

    /// The presenter — proven, not claimed — and the verifier to judge their chain with.
    async fn presenter_and_verifier(
        &self,
        doc: &TrustTask<Value>,
    ) -> Result<(String, DtgChainVerifier), AppError> {
        let presenter = self.presenter(doc).await?;

        Ok((
            presenter,
            // `without_zk`: no zero-knowledge profile, so private rooms are refused rather
            // than served on a pooling defence nobody checked.
            DtgChainVerifier::without_zk(Box::new(DataIntegrityKeys(self.resolver.clone()))),
        ))
    }
}

/// Record a room operation — §8, with the tier decision made by `vti_rooms::audit`.
///
/// This host has no audit chain: it is a delivery service, and standing up an HMAC key
/// store and a hash chain here would be most of a community service again, which is the
/// thing it exists not to be. So the trail goes to `tracing`, where an operator's own log
/// pipeline collects it.
///
/// What is **not** different from a VTC is *what may be recorded*. The actor comes from
/// [`vti_rooms::audit::for_operation`], so a `private` room logs that a member acted and
/// never who — a host that logged the DID because its own logging happened to be simpler
/// would have handed itself the membership by the back door.
fn audit_room(
    room: &Room,
    authorized: &authz::AuthorizedAction,
    operation: RoomOperation,
    record_key: Option<&str>,
) {
    let entry = rooms_audit::for_operation(room.visibility, authorized, record_key);
    tracing::info!(
        action = operation.action_name(),
        room = %entry.room_id,
        actor = %entry.actor.as_str(),
        record = entry.record_key.as_deref().unwrap_or("-"),
        visibility = ?room.visibility,
        "room operation"
    );
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What answering a request produces: **the document, and separately a status.**
///
/// The document is the answer. It is a routed Trust-Task `#response` or `trust-task-error`,
/// self-describing — it carries its own `type` and, when it refuses, a framework `code` — so
/// a caller switches on what is *in* it and never on how it arrived.
///
/// The status is the same fact restated for one carrier that insists on having it out of
/// band. HTTP does; DIDComm and TSP do not, and on those wires it is simply dropped. Keeping
/// them as two fields rather than one `Response` is what lets one dispatch serve all three:
/// the moment a handler builds an HTTP response, every other carrier has to take it apart
/// again to find the answer inside.
pub struct Answer {
    /// The HTTP status this answer would be, derived from the document's own code.
    pub status: u16,
    /// The routed Trust-Task document. **This is the answer.**
    pub document: Value,
}

impl axum::response::IntoResponse for Answer {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(self.document),
        )
            .into_response()
    }
}

/// Refuse a request, as a routed `trust-task-error` document.
///
/// A room host and a VTC serve the same protocol, so they must refuse it the same way: a
/// bare `{"error": …}` is not a Trust Task document, and a client that parses one host's
/// reply cannot parse the other's. The `data_room` example found exactly that — every call
/// in it failed on `missing field \`id\`` before this existed.
///
/// The reason text distinguishes the cases for an operator reading logs; the framework code
/// is what a caller switches on.
fn reject(doc: &TrustTask<Value>, reason: RejectReason) -> Answer {
    let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reason);
    Answer {
        status: status_for_code(&routed.payload.code),
        document: serde_json::to_value(&routed).unwrap_or(Value::Null),
    }
}

/// Answer a request, as a routed `#response` document.
fn respond<R: serde::Serialize>(doc: &TrustTask<Value>, payload: R) -> Answer {
    let response = doc.respond_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
    Answer {
        status: 200,
        document: serde_json::to_value(&response).unwrap_or(Value::Null),
    }
}

/// An `AppError` from the storage or authorization layer, as a rejection.
///
/// One mapping, so this host and the VTC classify the same failure identically. Both
/// services reach these from shared code in `vti-rooms`; disagreeing here would mean the
/// same refusal read as a different kind of problem depending on who was hosting.
fn from_app_error(doc: &TrustTask<Value>, e: &AppError) -> Answer {
    let reason = e.to_string();
    reject(
        doc,
        match e {
            AppError::Forbidden(_) => RejectReason::PermissionDenied { reason },
            AppError::Validation(_) => RejectReason::MalformedRequest { reason },
            // `TaskFailed` for both, following the VTC: a room that does not exist and a
            // version precondition that lost a race are caller-visible outcomes, not server
            // faults, and `InternalError` would tell the caller to retry.
            AppError::NotFound(_) | AppError::Conflict(_) => RejectReason::TaskFailed {
                reason,
                details: None,
            },
            _ => RejectReason::InternalError { reason },
        },
    )
}

/// The HTTP mount. Everything it does is [`dispatch`]; this only says which carrier asked.
async fn trust_task(State(state): State<Arc<HostState>>, body: Bytes) -> Answer {
    dispatch(&state, &body).await
}

/// **The one entry point**: a `rooms/*` document, routed by its own `type`, whatever carried
/// it here.
///
/// One mount rather than five routes, because the document's `type` is its identity — the
/// same shape the VTC's holder-facing surface uses. And one function rather than one per
/// carrier, because a host that routed or authorized differently depending on how a request
/// arrived would have as many authorization models as it has wires. HTTP, DIDComm and TSP
/// all land here with the same bytes.
///
/// Nothing about *who* is asking comes from the carrier. The presenter is taken from the
/// document's own `eddsa-jcs-2022` proof and the authority from the chain it carries, so a
/// request is exactly as authorized over a socket as over a POST — and a transport that
/// authenticated its sender confers nothing extra, which is the property that lets this be
/// one function at all.
pub async fn dispatch(state: &Arc<HostState>, body: &[u8]) -> Answer {
    // A body that is not a Trust Task document cannot be *routed* — there is no issuer to
    // address a rejection to and no thread to correlate it with — so this one case answers
    // with an unrouted error, exactly as the VTC's `body_parse_error_response` does.
    let doc: TrustTask<Value> = match serde_json::from_slice(body) {
        Ok(d) => d,
        Err(e) => {
            return Answer {
                status: 400,
                document: json!({
                    "error": format!("body is not a Trust Task document: {e}"),
                }),
            };
        }
    };

    let payload = doc.payload.clone();
    match doc.type_uri.to_string().as_str() {
        ROOMS_CREATE_TYPE => create(state, &doc, payload).await,
        ROOMS_RECORDS_PUT_TYPE => put(state, &doc, payload).await,
        ROOMS_RECORDS_GET_TYPE => get(state, &doc, payload).await,
        ROOMS_RECORDS_LIST_TYPE => list(state, &doc, payload).await,
        ROOMS_RECORDS_CURATE_TYPE => curate(state, &doc, payload).await,
        ROOMS_EPOCH_MINT_TYPE => mint(state, &doc, payload).await,
        ROOMS_EPOCH_CHAIN_TYPE => epoch_chain(state, &doc, payload).await,
        ROOMS_OWNER_TRANSFER_TYPE => transfer_owner(state, &doc, payload).await,
        ROOMS_OWNER_CLAIM_TYPE => claim_owner(state, &doc, payload).await,
        other => reject(
            &doc,
            // The framework's own code for this: a host that does not implement a task
            // says so by naming the type, and a client can tell that from a task it
            // implements but refused.
            RejectReason::UnsupportedType {
                type_uri: other.to_string(),
            },
        ),
    }
}

async fn create(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    let req: CreateRoomBody = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => {
            return reject(
                doc,
                RejectReason::MalformedRequest {
                    reason: e.to_string(),
                },
            );
        }
    };
    // The one operation no chain can authorize, and therefore the one that needs its own
    // check: the room has issued nothing yet, so all this host has is who signed the
    // request. `authorize_create` lives in `vti-rooms` so this host and a VTC cannot come to
    // different conclusions about who may register a room.
    let presenter = match state.presenter(doc).await {
        Ok(p) => p,
        Err(e) => return from_app_error(doc, &e),
    };
    let authorized = match authz::authorize_create(&req.room_id, &req.owner_did, &presenter) {
        Ok(a) => a,
        Err(e) => return from_app_error(doc, &e),
    };

    let room = Room {
        room_id: authorized.room_id().to_string(),
        // From the authorization, not the payload. They are equal — that is what was just
        // checked — and reading it from here is what keeps them equal if this ever grows a
        // second way to be authorized.
        owner_did: authorized.owner_did().to_string(),
        visibility: req.visibility,
        // Every room this host creates is chained: joining a room means being able to read
        // it, and the alternative silently loses the room's contents at the first membership
        // change. Not yet a per-room choice because `rooms/create/0.1` has no member for one
        // and its schema is `additionalProperties: false` — inventing a field locally would
        // put these rooms out of conformance. A room wanting `FromJoin` is a spec change
        // first, exactly as `retention_days` was.
        retention_policy: vti_rooms::RetentionPolicy::Chained,
        epoch: 1,
        next_version: 1,
        retention_days: req.retention_days.unwrap_or(DEFAULT_RETENTION_DAYS),
        // A room is live from creation for one epoch lifetime; minting the next epoch
        // renews it. Nothing else moves this clock — see `vti_rooms::lifecycle`.
        epoch_expires_at: Some(now() + EPOCH_LIFETIME_DAYS_SECS),
        created_at: now(),
        updated_at: now(),
        mirror_of: None,
    };
    match storage::create_room(&state.rooms, &room).await {
        Ok(()) => respond(
            doc,
            CreateRoomResponse {
                room_id: req.room_id,
                epoch: 1,
            },
        ),
        Err(e) => from_app_error(doc, &e),
    }
}

async fn put(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    let req: PutRecordBody = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => {
            return reject(
                doc,
                RejectReason::MalformedRequest {
                    reason: e.to_string(),
                },
            );
        }
    };
    let room = match storage::get_room(&state.rooms, &req.room_id).await {
        Ok(r) => r,
        Err(e) => return from_app_error(doc, &e),
    };
    let (presenter, verifier) = match state.presenter_and_verifier(doc).await {
        Ok(p) => p,
        Err(e) => return from_app_error(doc, &e),
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
        Err(e) => return from_app_error(doc, &e),
    };

    let record = Record {
        key: req.key.clone(),
        version: 0,
        epoch: req.sealed.as_ref().map(|s| s.epoch),
        status: RecordStatus::Active,
        pinned: false,
        sealed: req.sealed.as_ref().map(|s| s.ciphertext.clone()),
        nonce: req.sealed.as_ref().map(|s| s.nonce.clone()),
        cleartext: req
            .cleartext
            .as_ref()
            .map(|c| serde_json::to_value(c).unwrap_or(Value::Null)),
        // The verified subject where the tier discloses an actor — who the chain says is
        // acting, not the room's owner. On a private room authorship lives inside the
        // sealed body, and the storage layer refuses it here.
        author: room
            .visibility
            .discloses_actor()
            .then(|| authorized.subject().to_string()),
        updated_at: 0,
    };

    match storage::put_record(
        &state.rooms,
        &state.records,
        &req.room_id,
        record,
        req.expected_version,
        now(),
    )
    .await
    {
        Ok(stored) => {
            audit_room(
                &room,
                &authorized,
                RoomOperation::PutRecord,
                Some(&stored.key),
            );
            respond(
                doc,
                PutRecordResponse {
                    key: stored.key,
                    version: stored.version,
                    epoch: stored.epoch,
                },
            )
        }
        Err(e) => from_app_error(doc, &e),
    }
}

async fn get(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    let req: GetRecordBody = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => {
            return reject(
                doc,
                RejectReason::MalformedRequest {
                    reason: e.to_string(),
                },
            );
        }
    };
    let room = match storage::get_room(&state.rooms, &req.room_id).await {
        Ok(r) => r,
        Err(e) => return from_app_error(doc, &e),
    };
    let (presenter, verifier) = match state.presenter_and_verifier(doc).await {
        Ok(p) => p,
        Err(e) => return from_app_error(doc, &e),
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
        Err(e) => return from_app_error(doc, &e),
    };
    match storage::get_record(&state.records, &req.room_id, &req.key).await {
        Ok(record) => {
            audit_room(&room, &authorized, RoomOperation::GetRecord, Some(&req.key));
            // Answered through the response type for the same reason the VTC is:
            // `respond(doc, record)` put the *storage* record on the wire.
            let (commitment, trace) = record_verification(state, &req.room_id, &req.key).await;
            respond(
                doc,
                GetRecordResponse::of(&record, commitment.as_ref(), trace),
            )
        }
        Err(e) => from_app_error(doc, &e),
    }
}

async fn list(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    let req: ListRecordsBody = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => {
            return reject(
                doc,
                RejectReason::MalformedRequest {
                    reason: e.to_string(),
                },
            );
        }
    };
    let room = match storage::get_room(&state.rooms, &req.room_id).await {
        Ok(r) => r,
        Err(e) => return from_app_error(doc, &e),
    };
    let (presenter, verifier) = match state.presenter_and_verifier(doc).await {
        Ok(p) => p,
        Err(e) => return from_app_error(doc, &e),
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
        Err(e) => return from_app_error(doc, &e),
    };
    match storage::list_records(
        &state.records,
        &req.room_id,
        req.prefix.as_deref(),
        req.since_version,
    )
    .await
    {
        Ok(records) => {
            let limit = req.limit.unwrap_or(usize::MAX);
            // Metadata, never bodies — the same rule the VTC serves under, because it is a
            // property of the task rather than of any one host.
            // A listing names no single record; the event is that the room was surveyed.
            audit_room(&room, &authorized, RoomOperation::ListRecords, None);
            let head = room_head(state, &req.room_id).await;
            respond(
                doc,
                ListRecordsResponse {
                    records: records.iter().take(limit).map(|r| r.metadata()).collect(),
                    // The reference host commits too. A host that served
                    // listings without one would be a working example of the
                    // thing the commitment exists to make detectable.
                    // One head, so the three values a reader compares cannot come
                    // from three moments.
                    data_commitment: head
                        .as_ref()
                        .map(|h| vti_rooms::merkle::to_multibase(&h.root)),
                    record_count: head.as_ref().map(|h| h.record_count),
                    head_version: head.as_ref().map(|h| h.head_version),
                },
            )
        }
        Err(e) => from_app_error(doc, &e),
    }
}

/// The room's commitment and this record's trace, from one snapshot.
///
/// Both or neither. A trace with no commitment is a path to a root the reader
/// was not given — the specification forbids it with `dependentRequired`, and
/// serving one would be a host offering evidence it withheld the subject of.
///
/// A failure is answered with neither rather than with an error: these are
/// additional guarantees the specification makes OPTIONAL precisely so a host
/// that cannot assert one says nothing instead of something false. A member who
/// asked for a record and got an error because the *tree* was unhappy has lost
/// a working operation to an advisory one.
async fn record_verification(
    state: &HostState,
    room_id: &str,
    key: &str,
) -> (
    Option<vti_rooms::merkle::TreeHead>,
    Option<vti_rooms::merkle::InclusionProof>,
) {
    match storage::tree_head_with_trace(&state.records, room_id, key).await {
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
/// **A failure here must not fail the read.** The commitment is an additional
/// guarantee and the specification makes it OPTIONAL precisely so a host that
/// cannot assert one says nothing rather than something false — a member who
/// asked for records and got an error because the *tree* was unhappy has lost a
/// working operation to an advisory one.
///
/// Logged rather than swallowed: a host that has quietly stopped committing
/// looks, to a member, exactly like one that never did.
///
/// One function for both reads, mirroring the VTC's, because a listing and a
/// read that disagreed about the room's root would be this host equivocating
/// with itself.
async fn room_head(state: &HostState, room_id: &str) -> Option<vti_rooms::merkle::TreeHead> {
    match storage::tree_head(&state.records, room_id).await {
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

/// `rooms/epoch/chain/0.1` — serve the room's epoch key chain.
///
/// Gated on `read`: reading the room and reading what was written before you joined are the
/// same act. What leaves is ciphertext — the key that opens a rung is a storage key this
/// host never holds — so a party with the whole chain and no epoch key learns only how many
/// epochs the room has had, which its epoch number already told them.
async fn epoch_chain(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    let req: ChainBody = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => {
            return reject(
                doc,
                RejectReason::MalformedRequest {
                    reason: e.to_string(),
                },
            );
        }
    };
    let room = match storage::get_room(&state.rooms, &req.room_id).await {
        Ok(r) => r,
        Err(e) => return from_app_error(doc, &e),
    };
    let (presenter, verifier) = match state.presenter_and_verifier(doc).await {
        Ok(p) => p,
        Err(e) => return from_app_error(doc, &e),
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
        Err(e) => return from_app_error(doc, &e),
    };

    let mut links = match storage::list_epoch_links(&state.epoch_links, &req.room_id).await {
        Ok(l) => l,
        Err(e) => return from_app_error(doc, &e),
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

    audit_room(&room, &authorized, RoomOperation::ListRecords, None);
    respond(
        doc,
        ChainResponse {
            room_id: req.room_id,
            links,
        },
    )
}

async fn mint(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    let req: MintEpochBody = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => {
            return reject(
                doc,
                RejectReason::MalformedRequest {
                    reason: e.to_string(),
                },
            );
        }
    };
    let room = match storage::get_room(&state.rooms, &req.room_id).await {
        Ok(r) => r,
        Err(e) => return from_app_error(doc, &e),
    };
    // `admin`, not `write`: if any key-holder could mint an epoch, any member could evict
    // any other by declining to seal them the new key — and this host, which cannot see the
    // membership, would have no way to notice.
    let (presenter, verifier) = match state.presenter_and_verifier(doc).await {
        Ok(p) => p,
        Err(e) => return from_app_error(doc, &e),
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
        Err(e) => return from_app_error(doc, &e),
    };
    // The room's policy governs whether it has a chain at all, so a rung for a room that
    // does not chain is refused rather than dropped. Storing it would give the room a chain
    // it declared it would not have; dropping it silently would let a client believe the
    // room's history was being retained when it was not.
    if req.link.is_some() && !room.retention_policy.links_epochs() {
        return from_app_error(
            doc,
            &vti_common::error::AppError::Validation(format!(
                "room `{}` does not keep an epoch key chain, so it accepts no epoch link",
                req.room_id
            )),
        );
    }

    // A rung that does not describe *this* advance is refused rather than stored beside it:
    // accepting a mismatched one would launder someone else's key material into this room's
    // history, and the members who walked the original would never see the difference.
    if let Some(link) = &req.link
        && link.epoch != req.epoch
    {
        return from_app_error(
            doc,
            &vti_common::error::AppError::Validation(format!(
                "the epoch link is for epoch {} but this mint advances to {}",
                link.epoch, req.epoch
            )),
        );
    }

    match storage::advance_epoch(&state.rooms, &req.room_id, req.epoch, now()).await {
        Ok(updated) => {
            // After the advance, so a rejected advance leaves no orphan rung.
            if let Some(link) = &req.link
                && let Err(e) =
                    storage::put_epoch_link(&state.epoch_links, &req.room_id, link).await
            {
                return from_app_error(doc, &e);
            }
            audit_room(&room, &authorized, RoomOperation::MintEpoch, None);
            respond(
                doc,
                MintEpochResponse {
                    room_id: updated.room_id,
                    epoch: updated.epoch,
                },
            )
        }
        Err(e) => from_app_error(doc, &e),
    }
}

/// `rooms/owner/transfer/0.1`.
///
/// The owner hands the room to another member while still present. Gated on `admin`, the
/// same grant that mints epochs.
///
/// **This host cannot check that the incoming owner is a member** — it holds no roster and
/// no group state, and a delivery service never will. The spec's `notAMember` is for a host
/// that "could independently establish" it; inventing a check here would refuse every
/// correct transfer, which is a worse failure than the one it imagines it is preventing.
async fn transfer_owner(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    let req: TransferOwnerBody = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => {
            return reject(
                doc,
                RejectReason::MalformedRequest {
                    reason: e.to_string(),
                },
            );
        }
    };
    let room = match storage::get_room(&state.rooms, &req.room_id).await {
        Ok(r) => r,
        Err(e) => return from_app_error(doc, &e),
    };
    let (presenter, verifier) = match state.presenter_and_verifier(doc).await {
        Ok(p) => p,
        Err(e) => return from_app_error(doc, &e),
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
        Err(e) => return from_app_error(doc, &e),
    };
    match storage::set_owner(&state.rooms, &req.room_id, &req.new_owner_did, now()).await {
        Ok(updated) => {
            audit_room(&room, &authorized, operation, None);
            respond(
                doc,
                OwnerResponse {
                    room_id: updated.room_id,
                    owner_did: updated.owner_did,
                },
            )
        }
        Err(e) => from_app_error(doc, &e),
    }
}

/// `rooms/owner/claim/0.1`.
///
/// A nominated successor takes a room whose owner stopped renewing it. Three conditions,
/// all required: a nomination the room issued to this claimant, a room that has gone
/// dormant, and membership.
///
/// Checked nomination-first, because a bad nomination is the answer a claimant can act on
/// and "the room is still live" would send them back in a month to hear the real one.
///
/// The claim does not renew the room — see [`storage::set_owner`].
async fn claim_owner(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    let req: ClaimOwnerBody = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => {
            return reject(
                doc,
                RejectReason::MalformedRequest {
                    reason: e.to_string(),
                },
            );
        }
    };
    let room = match storage::get_room(&state.rooms, &req.room_id).await {
        Ok(r) => r,
        Err(e) => return from_app_error(doc, &e),
    };
    let (presenter, verifier) = match state.presenter_and_verifier(doc).await {
        Ok(p) => p,
        Err(e) => return from_app_error(doc, &e),
    };

    // Against the party who signed the request, never a DID from the payload.
    let keys = DataIntegrityKeys(state.resolver.clone());
    if let Err(e) = nomination::verify(&req.nomination, &room.room_id, &presenter, &keys).await {
        return from_app_error(doc, &e);
    }

    let lifecycle = room.lifecycle(now());
    if !lifecycle.admits_a_claim() {
        return from_app_error(
            doc,
            &AppError::Forbidden(format!(
                "room `{}` is {} — a room becomes claimable only once its epoch has \
                 lapsed and the grace window after it has also passed without a renewal",
                room.room_id,
                lifecycle.as_str()
            )),
        );
    }

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
        Err(e) => return from_app_error(doc, &e),
    };
    match storage::set_owner(&state.rooms, &req.room_id, &presenter, now()).await {
        Ok(updated) => {
            audit_room(&room, &authorized, operation, None);
            respond(
                doc,
                OwnerResponse {
                    room_id: updated.room_id,
                    owner_did: updated.owner_did,
                },
            )
        }
        Err(e) => from_app_error(doc, &e),
    }
}

/// `rooms/records/curate/0.1`.
///
/// Gated on `Action::Curate` — not implied by `write`, because deciding what a room's shared
/// knowledge is worth is a different grant from being able to add to it.
async fn curate(state: &HostState, doc: &TrustTask<Value>, payload: Value) -> Answer {
    let req: CurateRecordBody = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => {
            return reject(
                doc,
                RejectReason::MalformedRequest {
                    reason: e.to_string(),
                },
            );
        }
    };
    if req.status.is_none() && req.pinned.is_none() {
        return reject(
            doc,
            RejectReason::MalformedRequest {
                reason: "a curation must change something: supply `status`, `pinned`, or both"
                    .into(),
            },
        );
    }

    let room = match storage::get_room(&state.rooms, &req.room_id).await {
        Ok(r) => r,
        Err(e) => return from_app_error(doc, &e),
    };
    let (presenter, verifier) = match state.presenter_and_verifier(doc).await {
        Ok(p) => p,
        Err(e) => return from_app_error(doc, &e),
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
        Err(e) => return from_app_error(doc, &e),
    };

    match storage::curate_record(
        &state.rooms,
        &state.records,
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
                &room,
                &authorized,
                RoomOperation::CurateRecord,
                Some(&curated.key),
            );
            respond(
                doc,
                CurateRecordResponse {
                    key: curated.key,
                    version: curated.version,
                    status: curated.status,
                    pinned: curated.pinned,
                },
            )
        }
        Err(e) => from_app_error(doc, &e),
    }
}

/// Build the router. Separated from `main` so tests can drive it without a socket.
pub fn router(state: Arc<HostState>) -> Router {
    Router::new()
        .route("/trust-tasks", post(trust_task))
        .route("/health", axum::routing::get(|| async { "ok" }))
        .with_state(state)
}

/// [`router`], reachable from a browser at the named origins.
///
/// A room's own client may be a web page — a member is a party holding credentials, not a
/// party running a server, and increasingly that means a tab. Without a CORS layer a
/// browser cannot reach this host at all: the request is made and the response is discarded
/// before any script sees it, so the failure surfaces as a network error with nothing in it
/// about origins, and the page's author goes looking at the wrong end.
///
/// Off unless asked for, and by explicit origin rather than `*`. This host stores rooms it
/// does not govern; which sites may talk to it from a user's browser is an operator's
/// decision, and a wildcard is the one answer that cannot be reviewed. Mirrors
/// `vta-service`'s layer, including its refusal to partially apply: a half-configured CORS
/// surface is worse than none, because it looks configured.
///
/// Note this changes nothing about **authorization**. A browser reaching this host is still
/// a request carrying a proof and a chain, refused exactly as any other would be. CORS
/// decides who may ask, never what the answer is.
pub fn router_with_origins(state: Arc<HostState>, allowed_origins: &[String]) -> Router {
    let router = router(state);
    match cors_layer(allowed_origins) {
        Some(layer) => router.layer(layer),
        None => router,
    }
}

/// The CORS layer for `allowed_origins`, or `None` when there is nothing usable to apply.
fn cors_layer(allowed_origins: &[String]) -> Option<tower_http::cors::CorsLayer> {
    use axum::http::{HeaderName, HeaderValue, Method};
    use tower_http::cors::{AllowOrigin, CorsLayer};

    if allowed_origins.is_empty() {
        return None;
    }
    // `AllowOrigin::list` panics on a wildcard, and falling through to `any()` is not the
    // intent — an operator who wants every origin can say so in a proxy, where it is
    // visible. Malformed entries are dropped for the same reason a typo should show up in
    // the startup log rather than silently widen anything.
    let parsed: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter(|o| !o.is_empty() && *o != "*")
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    if parsed.is_empty() {
        tracing::warn!(
            "every --allow-origin value was empty, a wildcard, or unparseable; serving with \
             no CORS layer rather than a partial one"
        );
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(parsed))
            // One route takes a body, and it is a POST. Nothing here is a GET a browser
            // would send credentials with.
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([HeaderName::from_static("content-type")])
            .max_age(std::time::Duration::from_secs(60)),
    )
}

/// Open the store with a `did:key`-only verifier.
///
/// The conservative construction, and what a test or the example wants: no network
/// resolution can be triggered by an unauthenticated request. A deployment serving a
/// `did:webvh` room wants [`open_state_with_resolver`].
pub fn open_state(data_dir: &std::path::Path) -> anyhow::Result<Arc<HostState>> {
    open_state_with_resolver(
        data_dir,
        vti_common::auth::TrustTaskVmResolver::did_key_only(),
    )
}

/// Open the store with a specific verification-method resolver.
pub fn open_state_with_resolver(
    data_dir: &std::path::Path,
    resolver: vti_common::auth::TrustTaskVmResolver,
) -> anyhow::Result<Arc<HostState>> {
    let store = Store::open(&StoreConfig {
        data_dir: data_dir.to_path_buf(),
    })?;
    Ok(Arc::new(HostState {
        rooms: store.keyspace(ROOMS_KEYSPACE)?,
        records: store.keyspace(ROOM_RECORDS_KEYSPACE)?,
        epoch_links: store.keyspace(vti_rooms::ROOM_EPOCH_LINKS_KEYSPACE)?,
        resolver,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    use vti_rooms::Visibility;
    use vti_rooms_dtg::test_support::{Party, RoomFixture};

    /// A host over a temporary store.
    ///
    /// `did:key`-only resolution is not a limitation being worked around here: the fixture's
    /// room, owner and agent are all `did:key`, so every credential in these tests verifies
    /// with no network at all. That is deliberate — a test that reached the network would be
    /// testing the network.
    fn state() -> (tempfile::TempDir, Arc<HostState>) {
        let dir = tempfile::tempdir().unwrap();
        let state = open_state(dir.path()).expect("open store");
        (dir, state)
    }

    /// Send a **signed** document and return the status plus the response payload.
    ///
    /// Signing is not ceremony: the host reads the presenter from this proof, and an
    /// unsigned request is refused before any chain is looked at.
    async fn call(
        app: &Router,
        type_uri: &str,
        payload: Value,
        signer: &Party,
    ) -> (StatusCode, Value) {
        let doc = vta_sdk::trust_task_sign::build_signed(
            type_uri,
            payload,
            &signer.did,
            &signer.secret_multibase,
            "did:key:zHost",
        )
        .await
        .expect("sign the request");

        let resp = app
            .clone()
            .oneshot(
                Request::post("/trust-tasks")
                    .header("content-type", "application/json")
                    .body(Body::from(doc))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert!(
            doc.get("id").is_some(),
            "every reply must be a Trust Task document: {doc}"
        );
        (status, doc.get("payload").cloned().unwrap_or(Value::Null))
    }

    // ── read mirrors, end to end (§7.3) ─────────────────────────────────────

    /// Serve `app` on an ephemeral port and hand back its base URL.
    ///
    /// A mirror reaches its primary over HTTP like any other client, so the
    /// primary in these tests is a real socket rather than a direct call: a
    /// mirror that only worked in-process would prove nothing about the pull.
    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    /// The whole point of a mirror: records written at the primary become
    /// readable at the copy, under the primary's own version numbers.
    #[tokio::test]
    async fn a_mirror_serves_what_its_primary_wrote() {
        let (_pd, primary_state) = state();
        let (_md, mirror_state) = state();
        let f = RoomFixture::new(Visibility::Open).await;

        // The primary: an ordinary room with two records in it.
        let primary_app = router(primary_state.clone());
        register(&primary_app, &f).await;
        for (key, body) in [("decision/one", "first"), ("decision/two", "second")] {
            let (status, out) = call(
                &primary_app,
                ROOMS_RECORDS_PUT_TYPE,
                serde_json::json!({
                    "roomId": f.room.room_id,
                    "key": key,
                    "presentation": f.as_owner(),
                    "cleartext": { "body": body },
                }),
                &f.owner,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{out}");
        }
        let primary_url = serve(primary_app).await;

        // The mirror: the same room id, registered as a copy of that primary.
        vti_rooms::storage::create_room(
            mirror_state.rooms(),
            &vti_rooms::Room {
                mirror_of: Some(primary_url.clone()),
                next_version: 1,
                ..f.room.clone()
            },
        )
        .await
        .unwrap();

        let outcome = crate::mirror::pull_once(
            &mirror_state,
            &crate::mirror::MirroredRoom {
                room_id: f.room.room_id.clone(),
                primary_url,
                primary_did: Some("did:key:zHost".into()),
                membership: f.membership.clone(),
                authority: f.owner_chain.clone(),
                signer_did: f.owner.did.clone(),
                signer_key_multibase: f.owner.secret_multibase.clone(),
            },
        )
        .await
        .expect("the mirror pulls from its primary");
        assert_eq!(outcome.copied, 2, "both records copied");

        // Readable from the copy, with the primary's numbering intact — which is
        // what makes a sealed record openable and a watermark comparable.
        let mirror_app = router(mirror_state.clone());
        let (status, body) = call(
            &mirror_app,
            ROOMS_RECORDS_GET_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/one",
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["cleartext"]["body"], "first");
        assert_eq!(
            body["version"], 1,
            "the primary's version, not the mirror's"
        );

        // A second pull is a no-op: the watermark resumed where the first left off.
        let again = crate::mirror::pull_once(
            &mirror_state,
            &crate::mirror::MirroredRoom {
                room_id: f.room.room_id.clone(),
                // Deliberately unreachable: an unreachable primary must leave
                // the mirror serving what it has rather than losing it.
                primary_url: "http://127.0.0.1:1".to_string(),
                primary_did: None,
                membership: f.membership.clone(),
                authority: f.owner_chain.clone(),
                signer_did: f.owner.did.clone(),
                signer_key_multibase: f.owner.secret_multibase.clone(),
            },
        )
        .await;
        assert!(again.is_err(), "an unreachable primary is an error");
        let (status, body) = call(
            &mirror_app,
            ROOMS_RECORDS_GET_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/one",
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "still serving the copy it has: {body}"
        );
    }

    /// The refusal that makes a mirror a mirror, over the wire — and it names
    /// the primary, so an operator knows where the write belongs.
    #[tokio::test]
    async fn a_mirror_refuses_a_write_and_says_where_it_goes() {
        let (_d, st) = state();
        let f = RoomFixture::new(Visibility::Open).await;
        vti_rooms::storage::create_room(
            st.rooms(),
            &vti_rooms::Room {
                mirror_of: Some("https://primary.example.org".into()),
                ..f.room.clone()
            },
        )
        .await
        .unwrap();

        let app = router(st);
        let (status, body) = call(
            &app,
            ROOMS_RECORDS_PUT_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/three",
                "presentation": f.as_owner(),
                "cleartext": { "body": "not here" },
            }),
            &f.owner,
        )
        .await;
        assert_ne!(status, StatusCode::OK, "a mirror performs no writes");
        assert!(
            body.to_string().contains("primary.example.org"),
            "the refusal must name the primary: {body}"
        );
    }

    /// Register `f`'s room with the host.
    async fn register(app: &Router, f: &RoomFixture) {
        let (status, body) = call(
            app,
            ROOMS_CREATE_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "ownerDid": f.room.owner_did,
                "visibility": f.room.visibility,
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// **The same bytes, answered identically, whichever carrier brought them.**
    ///
    /// This is the property the whole carrier-neutral split exists for, and it is asserted
    /// rather than assumed: a host that routed or authorized differently depending on how a
    /// request arrived would have as many authorization models as it has wires, and the
    /// difference would show up as "it works over HTTP but not over DIDComm" — a report with
    /// nowhere to start looking.
    ///
    /// A DIDComm or TSP listener calls `dispatch` with exactly these bytes; only the framing
    /// around them differs, and none of it reaches here. So driving `dispatch` directly is
    /// driving what those carriers drive.
    #[tokio::test]
    async fn one_dispatch_answers_the_same_over_any_carrier() {
        let (_dir, st) = state();
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let document = vta_sdk::trust_task_sign::build_signed(
            ROOMS_RECORDS_LIST_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "presentation": f.as_owner(),
            }),
            &f.owner.did,
            &f.owner.secret_multibase,
            "did:key:zHost",
        )
        .await
        .expect("sign the request");

        // Over HTTP, through the router.
        let http = app
            .clone()
            .oneshot(
                Request::post("/trust-tasks")
                    .header("content-type", "application/json")
                    .body(Body::from(document.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let http_status = http.status();
        let http_body: Value = serde_json::from_slice(
            &axum::body::to_bytes(http.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();

        // Straight into `dispatch`, which is what a mediator listener does.
        let carried = dispatch(&st, document.as_bytes()).await;

        assert_eq!(http_status, StatusCode::OK, "{http_body}");
        assert_eq!(
            carried.status, 200,
            "the status is derived from the document, so both carriers agree on it"
        );
        // Guard the guard: comparing fields neither document has would pass while asserting
        // nothing, and the framework's field names are not this crate's to choose.
        // Everything that says *what happened* and *to whom*. `id` and `issuedAt` are
        // per-answer and correctly differ between two dispatches of one request.
        let says_what_happened = ["type", "payload", "threadId", "recipient", "issuer"];
        for field in says_what_happened {
            assert!(
                http_body.get(field).is_some(),
                "the response document has no `{field}` to compare — this test would pass \
                 vacuously: {http_body}"
            );
        }
        for field in says_what_happened {
            assert_eq!(
                http_body.get(field),
                carried.document.get(field),
                "`{field}` must not depend on the carrier"
            );
        }
    }

    /// **A TSP reply is the document, with nothing around it.**
    ///
    /// This host used to wrap it as `{ thid, document }`, on the reasoning that TSP has no
    /// headers so correlation had to be added. It does not: a routed response carries its own
    /// `threadId`, set to the request's `id`. The wrapper said the same thing twice and made
    /// this host's replies unreadable to a client written against `vtc-service`, which sends
    /// the document bare — two hosts of one protocol disagreeing about the wire.
    ///
    /// Asserted as a property of `dispatch` rather than of a framing function, because there
    /// is no longer a framing function and that is the point.
    #[tokio::test]
    async fn a_tsp_answer_is_the_document_and_threads_on_the_request() {
        let (_dir, st) = state();
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let document = vta_sdk::trust_task_sign::build_signed(
            ROOMS_RECORDS_LIST_TYPE,
            serde_json::json!({ "roomId": f.room.room_id, "presentation": f.as_owner() }),
            &f.owner.did,
            &f.owner.secret_multibase,
            "did:key:zHost",
        )
        .await
        .unwrap();
        let request_id: Value = serde_json::from_str(&document).unwrap();
        let request_id = request_id["id"].as_str().unwrap().to_string();

        // What the TSP arm sends is exactly this — `send_tsp` serialises it unchanged.
        let answer = dispatch(&st, document.as_bytes()).await.document;

        assert_eq!(
            answer["threadId"], request_id,
            "the document threads itself, which is why nothing needs to wrap it"
        );
        assert!(
            answer.get("thid").is_none(),
            "and it carries no second, disagreeing copy of that: {answer}"
        );
    }

    /// Registration is the one verb no chain can authorize, so the proof on the request
    /// is the whole of its defence — and `ownerDid` is a payload field until something
    /// checks it against the signer.
    #[tokio::test]
    async fn a_room_cannot_be_registered_in_somebody_elses_name() {
        let (_d, st) = state();
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Open).await;
        let mallory = Party::new();

        let (status, body) = call(
            &app,
            ROOMS_CREATE_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "ownerDid": f.room.owner_did,
                "visibility": f.room.visibility,
            }),
            &mallory,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        // And nothing was stored: a refused registration must not leave the id taken,
        // or refusing it would still deny the room to its owner.
        assert!(
            vti_rooms::storage::get_room(st.rooms(), &f.room.room_id)
                .await
                .is_err(),
            "a refused registration must not create the room"
        );

        // The owner's own registration still works, which is what makes the check a gate
        // rather than a wall.
        register(&app, &f).await;
    }

    /// A document with no proof has no presenter, and a registration nobody signed
    /// records an owner nobody proved.
    #[tokio::test]
    async fn an_unsigned_registration_is_refused() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;

        let doc = serde_json::json!({
            "id": "urn:uuid:unsigned",
            "type": ROOMS_CREATE_TYPE,
            "issuer": f.room.owner_did,
            "recipient": "did:key:zHost",
            "payload": {
                "roomId": f.room.room_id,
                "ownerDid": f.room.owner_did,
                "visibility": f.room.visibility,
            },
        });
        let resp = app
            .oneshot(
                Request::post("/trust-tasks")
                    .header("content-type", "application/json")
                    .body(Body::from(doc.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "an unsigned registration must not be accepted"
        );
    }

    #[tokio::test]
    async fn a_record_round_trips_under_a_chain_the_room_issued() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let (status, body) = call(
            &app,
            ROOMS_RECORDS_PUT_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/pricing",
                "presentation": f.as_owner(),
                "cleartext": { "body": "a decision" },
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["version"], 1);

        let (status, body) = call(
            &app,
            ROOMS_RECORDS_GET_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/pricing",
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["cleartext"]["body"], "a decision");
        assert_eq!(
            body["author"], f.owner.did,
            "the author is the verified subject, not the room's owner field"
        );
    }

    /// The arrangement the whole design exists for, end to end through a host.
    #[tokio::test]
    async fn an_agent_reads_under_a_narrower_chain_and_cannot_write() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;
        call(
            &app,
            ROOMS_RECORDS_PUT_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": f.as_owner(),
                "cleartext": { "body": "for the agent to read" },
            }),
            &f.owner,
        )
        .await;

        let (status, body) = call(
            &app,
            ROOMS_RECORDS_GET_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": f.as_agent(),
            }),
            &f.agent,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the agent reads: {body}");

        let (status, body) = call(
            &app,
            ROOMS_RECORDS_PUT_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k2",
                "presentation": f.as_agent(),
                "cleartext": { "body": "but it must not write" },
            }),
            &f.agent,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    /// A presentation is not a bearer token: the agent's chain, presented by its human.
    #[tokio::test]
    async fn a_captured_presentation_does_not_work_for_someone_else() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let (status, body) = call(
            &app,
            ROOMS_RECORDS_GET_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": f.as_agent(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    /// A stranger with a perfectly valid chain of their own gets nothing here — because the
    /// chain does not reach *this* room.
    #[tokio::test]
    async fn a_chain_from_another_room_confers_nothing() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        let elsewhere = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let (status, body) = call(
            &app,
            ROOMS_RECORDS_GET_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": elsewhere.as_owner(),
            }),
            &elsewhere.owner,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    #[tokio::test]
    async fn an_operation_with_no_chain_is_refused() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let (status, _) = call(
            &app,
            ROOMS_RECORDS_PUT_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": { "membership": f.membership, "authority": [] },
                "cleartext": { "body": "x" },
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// A private room is refused with the message `vti-rooms-dtg` gives it, which is the
    /// same message a VTC gives — the two cannot disagree about what is safe to serve.
    #[tokio::test]
    async fn a_private_room_is_refused_for_want_of_a_zk_profile() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Private).await;
        register(&app, &f).await;

        let mut p = f.as_owner();
        p.subject_binding = Some("a-binding-nobody-can-check".into());

        let (status, body) = call(
            &app,
            ROOMS_RECORDS_GET_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": p,
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("zero-knowledge profile"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn a_listing_returns_metadata_and_never_bodies() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;
        call(
            &app,
            ROOMS_RECORDS_PUT_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "a",
                "presentation": f.as_owner(),
                "cleartext": { "body": "secret-body-text" },
            }),
            &f.owner,
        )
        .await;

        let (status, body) = call(
            &app,
            ROOMS_RECORDS_LIST_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let text = body.to_string();
        assert!(text.contains("\"key\""));
        assert!(
            !text.contains("secret-body-text"),
            "a listing must never carry bodies: {text}"
        );
    }

    #[tokio::test]
    async fn an_unknown_task_is_not_served() {
        let (_d, st) = state();
        let (status, body) = call(
            &router(st),
            "https://trusttasks.org/spec/vtc/members/list/0.1",
            serde_json::json!({}),
            &Party::new(),
        )
        .await;
        assert!(
            !status.is_success(),
            "a room host serves rooms and nothing else"
        );
        assert_eq!(
            body["code"], "unsupportedType",
            "and says so with the framework's own code: {body}"
        );
    }

    /// Register `f`'s room with a chosen epoch expiry, bypassing the create handler.
    ///
    /// Succession is entirely about the passage of time, and the only honest way to test it
    /// without waiting a year is to write the room in the state a year would produce.
    async fn register_expiring(
        st: &Arc<HostState>,
        f: &RoomFixture,
        epoch_expires_at: Option<u64>,
    ) {
        let room = Room {
            epoch_expires_at,
            ..f.room.clone()
        };
        storage::create_room(&st.rooms, &room)
            .await
            .expect("register the room");
    }

    /// A room that does not chain refuses a rung, rather than storing one it said it would
    /// not have.
    ///
    /// Written straight to the store because `FromJoin` is not reachable over the wire —
    /// `rooms/create` has no member for it yet. That is the same reason this guard is worth
    /// a test now: an unreachable branch is exactly the kind that rots, and the policy it
    /// enforces was inert code until this test existed.
    #[tokio::test]
    async fn a_room_that_does_not_chain_refuses_an_epoch_link() {
        let (_d, st) = state();
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Attributed).await;

        let room = Room {
            retention_policy: vti_rooms::RetentionPolicy::FromJoin,
            ..f.room.clone()
        };
        storage::create_room(&st.rooms, &room)
            .await
            .expect("register the room");

        let (status, body) = call(
            &app,
            ROOMS_EPOCH_MINT_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "epoch": f.room.epoch + 1,
                "presentation": f.as_owner(),
                "link": {
                    "epoch": f.room.epoch + 1,
                    "wrapped": "9jK2_QhV1sVvR0m5xAqZ7A",
                    "nonce": "b0Zt8Qm2Yq1sVvR0"
                }
            }),
            &f.owner,
        )
        .await;

        assert_ne!(status, StatusCode::OK, "a rung must be refused: {body}");
        assert!(
            body.to_string()
                .contains("does not keep an epoch key chain"),
            "expected a policy refusal, got: {body}"
        );

        // And the same mint without a rung is fine: the policy refuses the link, not the
        // advance. A room that does not chain still advances its epochs.
        let (status, body) = call(
            &app,
            ROOMS_EPOCH_MINT_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "epoch": f.room.epoch + 1,
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["epoch"].as_u64(),
            Some(u64::from(f.room.epoch + 1)),
            "an unlinked advance must still work: {body}"
        );
    }

    fn days_ago(n: u64) -> Option<u64> {
        Some(now() - n * 24 * 60 * 60)
    }

    #[tokio::test]
    async fn an_owner_transfers_the_room_to_another_member() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let (status, body) = call(
            &app,
            ROOMS_OWNER_TRANSFER_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "newOwnerDid": f.successor.did,
                "presentation": f.as_owner(),
                "reason": "stepping back from this project",
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ownerDid"], f.successor.did);
    }

    /// `admin`, not `read`. The agent's chain is the narrower one a member hands their
    /// agent, and an agent that could give the room away would make attenuation pointless.
    #[tokio::test]
    async fn read_may_not_transfer_the_room() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let (status, _) = call(
            &app,
            ROOMS_OWNER_TRANSFER_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "newOwnerDid": f.agent.did,
                "presentation": f.as_agent(),
            }),
            &f.agent,
        )
        .await;
        assert!(!status.is_success(), "an agent may not hand away the room");
    }

    /// The whole point: a room outlives one person's availability.
    #[tokio::test]
    async fn a_nominated_successor_claims_a_dormant_room() {
        let (_d, st) = state();
        let f = RoomFixture::new(Visibility::Open).await;
        register_expiring(&st, &f, days_ago(60)).await;
        let app = router(st.clone());

        let (status, body) = call(
            &app,
            ROOMS_OWNER_CLAIM_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "nomination": f.nominate(&f.successor.did, 24).await,
                "presentation": f.as_successor(),
                "reason": "the owner has been unreachable since March",
            }),
            &f.successor,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ownerDid"], f.successor.did);

        // And the claim did not renew it. The new owner's first act should be the one that
        // proves they can perform it.
        let room = storage::get_room(&st.rooms, &f.room.room_id).await.unwrap();
        assert!(
            !room.lifecycle(now()).accepts_writes(),
            "a claim hands over a dormant room, it does not revive one"
        );
    }

    /// The defence against a hostile claim, and it is the same act as ordinary use: an
    /// owner who was merely away renews, and every pending claim stops working.
    #[tokio::test]
    async fn a_live_room_cannot_be_claimed() {
        let (_d, st) = state();
        let f = RoomFixture::new(Visibility::Open).await;
        register_expiring(&st, &f, Some(now() + 30 * 24 * 60 * 60)).await;
        let app = router(st);

        let (status, body) = call(
            &app,
            ROOMS_OWNER_CLAIM_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "nomination": f.nominate(&f.successor.did, 24).await,
                "presentation": f.as_successor(),
            }),
            &f.successor,
        )
        .await;
        assert!(!status.is_success(), "the owner is still here: {body}");
    }

    /// A lapse is not dormancy. An epoch expiring is frequently somebody on holiday, and a
    /// takeover window that opened the moment one expired would make every holiday one.
    #[tokio::test]
    async fn a_merely_lapsed_room_is_not_yet_claimable() {
        let (_d, st) = state();
        let f = RoomFixture::new(Visibility::Open).await;
        register_expiring(&st, &f, days_ago(3)).await;
        let app = router(st);

        let (status, body) = call(
            &app,
            ROOMS_OWNER_CLAIM_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "nomination": f.nominate(&f.successor.did, 24).await,
                "presentation": f.as_successor(),
            }),
            &f.successor,
        )
        .await;
        assert!(
            !status.is_success(),
            "three days is a holiday, not an abandonment: {body}"
        );
    }

    /// Dormancy alone confers nothing. Otherwise any member of any quiet room could take it.
    #[tokio::test]
    async fn a_member_without_a_nomination_cannot_claim() {
        let (_d, st) = state();
        let f = RoomFixture::new(Visibility::Open).await;
        register_expiring(&st, &f, days_ago(60)).await;
        let app = router(st);

        // A real nomination — for somebody else.
        let (status, body) = call(
            &app,
            ROOMS_OWNER_CLAIM_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "nomination": f.nominate(&f.agent.did, 24).await,
                "presentation": f.as_successor(),
            }),
            &f.successor,
        )
        .await;
        assert!(
            !status.is_success(),
            "a nomination is bound to the party it names: {body}"
        );
    }

    /// Every URI `vti_rooms::wire` says is dispatched must actually route here.
    ///
    /// The failure this catches is adding a handler to the wire crate's list and forgetting
    /// the `match` arm — which does not fail to compile, and shows up as `unsupportedType`
    /// on a verb the host claims to serve.
    #[tokio::test]
    async fn every_dispatched_uri_routes() {
        let (_d, st) = state();
        let app = router(st);
        let signer = Party::new();

        for uri in vti_rooms::wire::ROOMS_DISPATCHED_URIS {
            // An empty payload, so every one of these fails — the question is only *how*.
            let (_, body) = call(&app, uri, serde_json::json!({}), &signer).await;
            assert_ne!(
                body["code"], "unsupportedType",
                "{uri} is declared dispatched but has no route"
            );
        }
    }
}
