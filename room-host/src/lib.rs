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
//! # Status
//!
//! The dispatch surface here is the `open` tier. Sealed tiers are refused by
//! [`vti_rooms::authz`] until chain verification is wired, and that refusal lives in the
//! shared crate rather than here — so this host and a VTC cannot disagree about what is
//! safe to serve.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};
use trust_tasks_https::status_for_code;
use trust_tasks_rs::{RejectReason, TrustTask};
use uuid::Uuid;
use vti_common::config::StoreConfig;
use vti_common::error::AppError;
use vti_common::store::{KeyspaceHandle, Store};
use vti_rooms::wire::{
    CreateRoomBody, CreateRoomResponse, GetRecordBody, ListRecordsBody, ListRecordsResponse,
    MintEpochBody, MintEpochResponse, PutRecordBody, PutRecordResponse, ROOMS_CREATE_TYPE,
    ROOMS_EPOCH_MINT_TYPE, ROOMS_RECORDS_GET_TYPE, ROOMS_RECORDS_LIST_TYPE, ROOMS_RECORDS_PUT_TYPE,
};
use vti_rooms::{
    ROOM_RECORDS_KEYSPACE, ROOMS_KEYSPACE, Record, RecordStatus, Room,
    authz::{self, Action},
    storage,
};

/// Default retention after a room's epoch lapses without renewal.
const DEFAULT_RETENTION_DAYS: u32 = 90;

/// Everything this host holds. Two keyspaces — and note what is not here.
#[derive(Clone)]
pub struct HostState {
    rooms: KeyspaceHandle,
    records: KeyspaceHandle,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
fn reject(doc: &TrustTask<Value>, reason: RejectReason) -> axum::response::Response {
    let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reason);
    (
        StatusCode::from_u16(status_for_code(&routed.payload.code))
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(serde_json::to_value(&routed).unwrap_or(Value::Null)),
    )
        .into_response()
}

/// Answer a request, as a routed `#response` document.
fn respond<R: serde::Serialize>(doc: &TrustTask<Value>, payload: R) -> axum::response::Response {
    let response = doc.respond_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
    Json(serde_json::to_value(&response).unwrap_or(Value::Null)).into_response()
}

/// An `AppError` from the storage or authorization layer, as a rejection.
///
/// One mapping, so this host and the VTC classify the same failure identically. Both
/// services reach these from shared code in `vti-rooms`; disagreeing here would mean the
/// same refusal read as a different kind of problem depending on who was hosting.
fn from_app_error(doc: &TrustTask<Value>, e: &AppError) -> axum::response::Response {
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

/// The one entry point: a `rooms/*` document, routed by its own `type`.
///
/// One mount rather than five routes, because the document's `type` is its identity — the
/// same shape the VTC's holder-facing surface uses.
async fn trust_task(State(state): State<Arc<HostState>>, body: Bytes) -> axum::response::Response {
    // A body that is not a Trust Task document cannot be *routed* — there is no issuer to
    // address a rejection to and no thread to correlate it with — so this one case answers
    // with an unrouted error, exactly as the VTC's `body_parse_error_response` does.
    let doc: TrustTask<Value> = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("body is not a Trust Task document: {e}"),
                })),
            )
                .into_response();
        }
    };

    let payload = doc.payload.clone();
    match doc.type_uri.to_string().as_str() {
        ROOMS_CREATE_TYPE => create(&state, &doc, payload).await,
        ROOMS_RECORDS_PUT_TYPE => put(&state, &doc, payload).await,
        ROOMS_RECORDS_GET_TYPE => get(&state, &doc, payload).await,
        ROOMS_RECORDS_LIST_TYPE => list(&state, &doc, payload).await,
        ROOMS_EPOCH_MINT_TYPE => mint(&state, &doc, payload).await,
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

async fn create(
    state: &HostState,
    doc: &TrustTask<Value>,
    payload: Value,
) -> axum::response::Response {
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

async fn put(
    state: &HostState,
    doc: &TrustTask<Value>,
    payload: Value,
) -> axum::response::Response {
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
    if let Err(e) = authz::authorize(&room, &req.presentation, Action::Write) {
        return from_app_error(doc, &e);
    }

    let record = Record {
        key: req.key.clone(),
        version: 0,
        epoch: req.sealed.as_ref().map(|s| s.epoch),
        status: RecordStatus::Active,
        sealed: req.sealed.as_ref().map(|s| s.ciphertext.clone()),
        nonce: req.sealed.as_ref().map(|s| s.nonce.clone()),
        cleartext: req
            .cleartext
            .as_ref()
            .map(|c| serde_json::to_value(c).unwrap_or(Value::Null)),
        // Only where the tier discloses an actor. On a private room authorship lives inside
        // the sealed body, and the storage layer refuses it here.
        author: room
            .visibility
            .discloses_actor()
            .then(|| room.owner_did.clone()),
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
        Ok(stored) => respond(
            doc,
            PutRecordResponse {
                key: stored.key,
                version: stored.version,
                epoch: stored.epoch,
            },
        ),
        Err(e) => from_app_error(doc, &e),
    }
}

async fn get(
    state: &HostState,
    doc: &TrustTask<Value>,
    payload: Value,
) -> axum::response::Response {
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
    if let Err(e) = authz::authorize(&room, &req.presentation, Action::Read) {
        return from_app_error(doc, &e);
    }
    match storage::get_record(&state.records, &req.room_id, &req.key).await {
        Ok(record) => respond(doc, record),
        Err(e) => from_app_error(doc, &e),
    }
}

async fn list(
    state: &HostState,
    doc: &TrustTask<Value>,
    payload: Value,
) -> axum::response::Response {
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
    if let Err(e) = authz::authorize(&room, &req.presentation, Action::Read) {
        return from_app_error(doc, &e);
    }
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
            respond(
                doc,
                ListRecordsResponse {
                    records: records.iter().take(limit).map(|r| r.metadata()).collect(),
                },
            )
        }
        Err(e) => from_app_error(doc, &e),
    }
}

async fn mint(
    state: &HostState,
    doc: &TrustTask<Value>,
    payload: Value,
) -> axum::response::Response {
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
    if let Err(e) = authz::authorize(&room, &req.presentation, Action::Admin) {
        return from_app_error(doc, &e);
    }
    match storage::advance_epoch(&state.rooms, &req.room_id, req.epoch, now()).await {
        Ok(updated) => respond(
            doc,
            MintEpochResponse {
                room_id: updated.room_id,
                epoch: updated.epoch,
            },
        ),
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

pub fn open_state(data_dir: &std::path::Path) -> anyhow::Result<Arc<HostState>> {
    let store = Store::open(&StoreConfig {
        data_dir: data_dir.to_path_buf(),
    })?;
    Ok(Arc::new(HostState {
        rooms: store.keyspace(ROOMS_KEYSPACE)?,
        records: store.keyspace(ROOM_RECORDS_KEYSPACE)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn state() -> (tempfile::TempDir, Arc<HostState>) {
        let dir = tempfile::tempdir().unwrap();
        let state = open_state(dir.path()).expect("open store");
        (dir, state)
    }

    /// Send a request and return the status plus the response document's **payload**.
    ///
    /// Building a real document here rather than `{type, payload}` is the point: the
    /// `data_room` example failed on every call against the looser shape, because a client
    /// parses the reply as a Trust Task document and a bare payload has no `id`.
    async fn call(app: &Router, type_uri: &str, payload: Value) -> (StatusCode, Value) {
        let doc = json!({
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "type": type_uri,
            "issuer": "did:key:zCaller",
            "recipient": "did:key:zHost",
            "payload": payload,
        });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/trust-tasks")
                    .header("content-type", "application/json")
                    .body(Body::from(doc.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        // Every reply is a routed document; the test cares about what it carries.
        assert!(
            doc.get("id").is_some(),
            "every reply must be a Trust Task document: {doc}"
        );
        (status, doc.get("payload").cloned().unwrap_or(Value::Null))
    }

    fn presentation() -> Value {
        json!({ "membership": "vmc", "authority": ["vac-leaf", "vac-root"] })
    }

    #[tokio::test]
    async fn a_room_is_created_and_a_record_round_trips() {
        let (_d, st) = state();
        let app = router(st);

        let (status, _) = call(
            &app,
            ROOMS_CREATE_TYPE,
            json!({ "roomId": "r1", "visibility": "open", "ownerDid": "did:key:zOwner" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = call(
            &app,
            ROOMS_RECORDS_PUT_TYPE,
            json!({ "roomId": "r1", "key": "k1", "presentation": presentation(),
                    "cleartext": { "body": "a decision" } }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["version"], 1);

        let (status, body) = call(
            &app,
            ROOMS_RECORDS_GET_TYPE,
            json!({ "roomId": "r1", "key": "k1", "presentation": presentation() }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["cleartext"]["body"], "a decision");
    }

    /// The property that makes this host usable by a room it does not govern: it decides
    /// from the chain, and there is nothing else it could decide from.
    #[tokio::test]
    async fn an_operation_with_no_chain_is_refused() {
        let (_d, st) = state();
        let app = router(st);
        call(
            &app,
            ROOMS_CREATE_TYPE,
            json!({ "roomId": "r1", "visibility": "open", "ownerDid": "did:key:zOwner" }),
        )
        .await;

        let (status, _) = call(
            &app,
            ROOMS_RECORDS_PUT_TYPE,
            json!({ "roomId": "r1", "key": "k", "presentation": { "membership": "vmc", "authority": [] },
                    "cleartext": { "body": "x" } }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// The shared crate decides this, not the host — so a room host and a VTC cannot
    /// disagree about what is safe to serve.
    #[tokio::test]
    async fn sealed_tiers_are_refused_here_exactly_as_they_are_on_a_vtc() {
        let (_d, st) = state();
        let app = router(st);
        call(
            &app,
            ROOMS_CREATE_TYPE,
            json!({ "roomId": "p1", "visibility": "private", "ownerDid": "did:key:zOwner" }),
        )
        .await;

        let (status, body) = call(
            &app,
            ROOMS_RECORDS_GET_TYPE,
            json!({ "roomId": "p1", "key": "k", "presentation": presentation() }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("subject binding"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn a_listing_returns_metadata_and_never_bodies() {
        let (_d, st) = state();
        let app = router(st);
        call(
            &app,
            ROOMS_CREATE_TYPE,
            json!({ "roomId": "r1", "visibility": "open", "ownerDid": "did:key:zOwner" }),
        )
        .await;
        call(
            &app,
            ROOMS_RECORDS_PUT_TYPE,
            json!({ "roomId": "r1", "key": "a", "presentation": presentation(),
                    "cleartext": { "body": "secret-body-text" } }),
        )
        .await;

        let (status, body) = call(
            &app,
            ROOMS_RECORDS_LIST_TYPE,
            json!({ "roomId": "r1", "presentation": presentation() }),
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
            json!({}),
        )
        .await;
        assert!(
            !status.is_success(),
            "a room host serves rooms and nothing else"
        );
        assert_eq!(
            body["code"], "unsupportedType",
            "and says so with the framework's own code, so a client can tell it apart \
             from a task this host implements but refused: {body}"
        );
    }
}
