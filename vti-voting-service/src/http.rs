//! The HTTPS Trust Task binding: one `POST /trust-tasks` door for every `voting/*` task.
//!
//! The binding a cast must always be accepted on (VTI-VOT-004): its sender is a key made for
//! that one cast, with no mediator session to receive a reply on, so the receipt comes back in
//! the synchronous response.

use std::sync::{Arc, Mutex};

use axum::{Json, Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use chrono::Utc;
use serde_json::Value;
use trust_tasks_rs::{ErrorPayload, TrustTask, TrustTaskCode};
use uuid::Uuid;
use vti_voting::service::{BallotBox, Caller, Failure};

use crate::identity::Identity;

const SPEC: &str = "https://trusttasks.org/spec/";

pub struct AppState {
    pub ballot_box: Mutex<BallotBox>,
    pub identity: Identity,
    pub resolver: vti_common::auth::TrustTaskVmResolver,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("did", &self.identity.did)
            .finish_non_exhaustive()
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/trust-tasks", post(trust_task))
        .with_state(state)
}

/// What a request's type names: one of this service's tasks, by slug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Task {
    Register,
    Show,
    Close,
    Cancel,
    Cast,
    Head,
    Read,
    Inclusion,
    Consistency,
    Result,
}

impl Task {
    fn from_type(type_uri: &str) -> Option<Self> {
        let rest = type_uri.strip_prefix(SPEC)?.strip_suffix("/0.1#request")?;
        Some(match rest {
            "voting/election/register" => Task::Register,
            "voting/election/show" => Task::Show,
            "voting/election/close" => Task::Close,
            "voting/election/cancel" => Task::Cancel,
            "voting/ballot/cast" => Task::Cast,
            "voting/board/head" => Task::Head,
            "voting/board/read" => Task::Read,
            "voting/board/inclusion" => Task::Inclusion,
            "voting/board/consistency" => Task::Consistency,
            "voting/result/show" => Task::Result,
            _ => return None,
        })
    }

    fn slug(self) -> &'static str {
        match self {
            Task::Register => "voting/election/register",
            Task::Show => "voting/election/show",
            Task::Close => "voting/election/close",
            Task::Cancel => "voting/election/cancel",
            Task::Cast => "voting/ballot/cast",
            Task::Head => "voting/board/head",
            Task::Read => "voting/board/read",
            Task::Inclusion => "voting/board/inclusion",
            Task::Consistency => "voting/board/consistency",
            Task::Result => "voting/result/show",
        }
    }

    /// Tasks whose request proof is REQUIRED.
    fn needs_proof(self) -> bool {
        matches!(
            self,
            Task::Register | Task::Close | Task::Cancel | Task::Cast
        )
    }
}

fn status_for(code: &TrustTaskCode) -> StatusCode {
    match code.to_string().as_str() {
        "malformedRequest" => StatusCode::BAD_REQUEST,
        "proofRequired" | "proofInvalid" => StatusCode::UNAUTHORIZED,
        "permissionDenied" => StatusCode::FORBIDDEN,
        "unsupportedType" | "unsupportedVersion" => StatusCode::NOT_FOUND,
        "expired" => StatusCode::BAD_REQUEST,
        "internalError" => StatusCode::INTERNAL_SERVER_ERROR,
        "unavailable" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    }
}

/// Sign `doc` as this service and answer with it. An answer that cannot be signed is not sent:
/// an unsigned receipt or head is evidence of nothing.
async fn signed(state: &AppState, status: StatusCode, doc: Value) -> (StatusCode, Json<Value>) {
    let mut typed: TrustTask<Value> = match serde_json::from_value(doc) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "an answer did not form a Trust Task document");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(Value::Null));
        }
    };
    if let Err(e) =
        vta_sdk::trust_task_sign::sign_in_place_with(&mut typed, &state.identity.key).await
    {
        tracing::error!(error = %e, "could not sign the answer; not sending it");
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Value::Null));
    }
    (
        status,
        Json(serde_json::to_value(&typed).unwrap_or(Value::Null)),
    )
}

fn error_doc(doc: &TrustTask<Value>, code: TrustTaskCode, message: &str) -> Value {
    let payload = ErrorPayload::new(code).with_message(message);
    let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
    serde_json::to_value(&routed).unwrap_or(Value::Null)
}

async fn refuse(
    state: &AppState,
    doc: &TrustTask<Value>,
    code: TrustTaskCode,
    message: &str,
) -> (StatusCode, Json<Value>) {
    let status = status_for(&code);
    signed(state, status, error_doc(doc, code, message)).await
}

fn standard(code: &str) -> TrustTaskCode {
    code.parse()
        .unwrap_or_else(|_| "internalError".parse().expect("a standard code"))
}

async fn trust_task(State(state): State<Arc<AppState>>, body: Bytes) -> (StatusCode, Json<Value>) {
    let received: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(Value::Null)),
    };
    let doc: TrustTask<Value> = match serde_json::from_value(received.clone()) {
        Ok(d) => d,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(Value::Null)),
    };
    let Some(task) = Task::from_type(&doc.type_uri.to_string()) else {
        return refuse(
            &state,
            &doc,
            standard("unsupportedType"),
            "not a task this service serves",
        )
        .await;
    };
    let now = Utc::now();
    if doc.expires_at.is_some_and(|t| t < now) {
        return refuse(
            &state,
            &doc,
            standard("expired"),
            "the document has expired",
        )
        .await;
    }
    if doc
        .recipient
        .as_deref()
        .is_some_and(|r| r != state.identity.did)
    {
        return refuse(
            &state,
            &doc,
            standard("wrongRecipient"),
            "addressed to another party",
        )
        .await;
    }

    // The signer, proven by the document's own proof over the bytes as received, and required
    // to be the document's issuer (framework SPEC §4.7).
    let signer = if doc.proof.is_some() {
        match vti_common::auth::verify_trust_task_proof_value(&received, &state.resolver).await {
            Ok(s) if doc.issuer.as_deref() == Some(s.as_str()) => Some(s),
            Ok(_) => {
                return refuse(
                    &state,
                    &doc,
                    standard("proofInvalid"),
                    "the proof is not the issuer's",
                )
                .await;
            }
            Err(e) => {
                return refuse(&state, &doc, standard("proofInvalid"), &e.to_string()).await;
            }
        }
    } else {
        None
    };
    if task.needs_proof() && signer.is_none() {
        return refuse(
            &state,
            &doc,
            standard("proofRequired"),
            "this task must be signed",
        )
        .await;
    }

    // The ballot box is synchronous: hold its lock for the call and never across an await.
    let outcome = 'locked: {
        let Ok(mut bb) = state.ballot_box.lock() else {
            break 'locked Err(Failure {
                local: "internalError",
                standard: true,
                reason: "ballot box unavailable".into(),
            });
        };
        let caller = signer.as_deref().map_or(Caller::Anonymous, Caller::Did);
        let signer_did = signer.as_deref().unwrap_or_default();
        let p = &doc.payload;
        match task {
            Task::Register => bb.register(signer_did, p, now),
            Task::Show => bb.show(caller, p, now),
            Task::Close => bb.close(signer_did, p, now),
            Task::Cancel => bb.cancel(signer_did, p, now),
            Task::Cast => bb.cast(p, now),
            Task::Head => bb.board_head(caller, p, now),
            Task::Read => bb.board_read(caller, p, now),
            Task::Inclusion => bb.board_inclusion(caller, p, now),
            Task::Consistency => bb.board_consistency(caller, p, now),
            Task::Result => bb.result(caller, p, now),
        }
    };

    match outcome {
        Ok(payload) => {
            let response = doc.respond_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
            let value = serde_json::to_value(&response).unwrap_or(Value::Null);
            signed(&state, StatusCode::OK, value).await
        }
        Err(Failure {
            local,
            standard: is_standard,
            reason,
            ..
        }) => {
            let code = if is_standard {
                standard(local)
            } else {
                TrustTaskCode::new_extended(task.slug(), local)
                    .unwrap_or_else(|_| standard("taskFailed"))
            };
            tracing::info!(task = task.slug(), code = %code, %reason, "refused");
            refuse(&state, &doc, code, &reason).await
        }
    }
}
