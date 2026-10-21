//! The dispatch core: one inbound `voting/*` document in, one signed answer out. No transport —
//! the HTTPS door ([`crate::http`]) and the mediator session ([`crate::messaging`]) hand it the
//! bytes as received and, where the transport proved one, the sender, and carry back what it
//! returns.

use std::sync::Mutex;

use axum::http::StatusCode;
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

/// One answer: the signed document, and the HTTP status the HTTPS binding gives it. `doc` is
/// `None` when nothing could be answered — bytes that are not a document, or an answer that
/// could not be signed.
#[derive(Debug)]
pub struct Answer {
    pub status: StatusCode,
    pub doc: Option<Value>,
}

impl Answer {
    fn none(status: StatusCode) -> Self {
        Self { status, doc: None }
    }
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
    CastEncrypted,
    Enrol,
    Deal,
    Confirm,
    Justify,
    Decrypt,
    TrusteeStatus,
    Authorize,
}

impl Task {
    fn from_type(type_uri: &str) -> Option<Self> {
        // A request's `#request` fragment is optional (framework SPEC §4.4.1): the generated
        // payload types, and so every peer sending through them, use the bare form.
        let bare = type_uri.strip_suffix("#request").unwrap_or(type_uri);
        let rest = bare.strip_prefix(SPEC)?.strip_suffix("/0.1")?;
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
            "voting/ballot/cast-encrypted" => Task::CastEncrypted,
            "voting/trustees/enrol" => Task::Enrol,
            "voting/trustees/deal" => Task::Deal,
            "voting/trustees/confirm" => Task::Confirm,
            "voting/trustees/justify" => Task::Justify,
            "voting/trustees/decrypt" => Task::Decrypt,
            "voting/trustees/status" => Task::TrusteeStatus,
            "voting/trustees/authorize" => Task::Authorize,
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
            Task::CastEncrypted => "voting/ballot/cast-encrypted",
            Task::Enrol => "voting/trustees/enrol",
            Task::Deal => "voting/trustees/deal",
            Task::Confirm => "voting/trustees/confirm",
            Task::Justify => "voting/trustees/justify",
            Task::Decrypt => "voting/trustees/decrypt",
            Task::TrusteeStatus => "voting/trustees/status",
            Task::Authorize => "voting/trustees/authorize",
        }
    }

    /// Tasks whose request proof is REQUIRED.
    fn needs_proof(self) -> bool {
        matches!(
            self,
            Task::Register
                | Task::Close
                | Task::Cancel
                | Task::Cast
                | Task::CastEncrypted
                | Task::Enrol
                | Task::Deal
                | Task::Confirm
                | Task::Justify
                | Task::Decrypt
                | Task::Authorize
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
async fn signed(state: &AppState, status: StatusCode, doc: Value) -> Answer {
    let mut typed: TrustTask<Value> = match serde_json::from_value(doc) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "an answer did not form a Trust Task document");
            return Answer::none(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    if let Err(e) =
        vta_sdk::trust_task_sign::sign_in_place_with(&mut typed, &state.identity.key).await
    {
        tracing::error!(error = %e, "could not sign the answer; not sending it");
        return Answer::none(StatusCode::INTERNAL_SERVER_ERROR);
    }
    Answer {
        status,
        doc: serde_json::to_value(&typed).ok(),
    }
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
) -> Answer {
    let status = status_for(&code);
    signed(state, status, error_doc(doc, code, message)).await
}

fn standard(code: &str) -> TrustTaskCode {
    code.parse()
        .unwrap_or_else(|_| "internalError".parse().expect("a standard code"))
}

/// Answer one document, `body` exactly as received.
///
/// `transport_sender` is the sender a transport proved (TSP, DIDComm authcrypt); `None` on a
/// binding that proves nobody (HTTPS). Where there is one, the document's `issuer` must be it
/// (framework §7.2 item 6, VTI-VOT-005) — a party cannot relay another's request as its own.
pub async fn answer(state: &AppState, body: &[u8], transport_sender: Option<&str>) -> Answer {
    let received: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return Answer::none(StatusCode::BAD_REQUEST),
    };
    let doc: TrustTask<Value> = match serde_json::from_value(received.clone()) {
        Ok(d) => d,
        Err(_) => return Answer::none(StatusCode::BAD_REQUEST),
    };
    // A reply or an error is never answered: answering an error with an error is the loop only
    // a rate limiter ends. This service sends no requests, so nothing waits for one either.
    let type_uri = doc.type_uri.to_string();
    if type_uri.ends_with("#response") || type_uri.contains("/trust-task-error/") {
        return Answer::none(StatusCode::BAD_REQUEST);
    }
    if let Some(sender) = transport_sender
        && doc.issuer.as_deref() != Some(sender)
    {
        return refuse(
            state,
            &doc,
            standard("permissionDenied"),
            "the issuer is not the sender",
        )
        .await;
    }
    let Some(task) = Task::from_type(&doc.type_uri.to_string()) else {
        return refuse(
            state,
            &doc,
            standard("unsupportedType"),
            "not a task this service serves",
        )
        .await;
    };
    let now = Utc::now();
    if doc.expires_at.is_some_and(|t| t < now) {
        return refuse(state, &doc, standard("expired"), "the document has expired").await;
    }
    if doc
        .recipient
        .as_deref()
        .is_some_and(|r| r != state.identity.did)
    {
        return refuse(
            state,
            &doc,
            standard("wrongRecipient"),
            "addressed to another party",
        )
        .await;
    }

    // A signed request names its recipient (SPEC §4.8.2), and a consequential one when it was
    // issued (each task's issuedAt requirement): a captured document is not a bearer token for
    // ever, and not one for another ballot box.
    if doc.proof.is_some() && doc.recipient.is_none() {
        return refuse(
            state,
            &doc,
            standard("malformedRequest"),
            "a signed request names its recipient",
        )
        .await;
    }
    if task.needs_proof() {
        match doc.issued_at {
            None => {
                return refuse(
                    state,
                    &doc,
                    standard("malformedRequest"),
                    "issuedAt is required",
                )
                .await;
            }
            Some(at) if at > now + chrono::Duration::minutes(5) => {
                return refuse(
                    state,
                    &doc,
                    standard("malformedRequest"),
                    "issuedAt is in the future",
                )
                .await;
            }
            Some(_) => {}
        }
    }
    // A cast is signed by a key made for it alone (VTI-VOT-003): a did:key, which resolves
    // without fetching anything an anonymous sender chose.
    if matches!(task, Task::Cast | Task::CastEncrypted)
        && !doc
            .issuer
            .as_deref()
            .is_some_and(|i| i.starts_with("did:key:"))
    {
        return refuse(
            state,
            &doc,
            standard("proofInvalid"),
            "a cast is signed by a did:key made for it",
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
                    state,
                    &doc,
                    standard("proofInvalid"),
                    "the proof is not the issuer's",
                )
                .await;
            }
            Err(e) => {
                // The resolver's own words stay in the log: they can name what it fetched.
                tracing::debug!(error = %e, "a request proof did not verify");
                return refuse(
                    state,
                    &doc,
                    standard("proofInvalid"),
                    "the proof does not verify",
                )
                .await;
            }
        }
    } else {
        None
    };
    if task.needs_proof() && signer.is_none() {
        return refuse(
            state,
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
            Task::CastEncrypted => bb.cast_encrypted(p, now),
            // A trustee's step goes on the board as the request received, proof included
            // (CONVENTIONS §9.6).
            Task::Enrol => bb.trustees_enrol(signer_did, &received, now),
            Task::Deal => bb.trustees_deal(signer_did, &received, now),
            Task::Confirm => bb.trustees_confirm(signer_did, &received, now),
            Task::Justify => bb.trustees_justify(signer_did, &received, now),
            Task::Decrypt => bb.trustees_decrypt(signer_did, &received, now),
            Task::TrusteeStatus => bb.trustees_status(caller, p, now),
            // The community's authorization goes on the board as received (CONVENTIONS §9.7).
            Task::Authorize => bb.trustees_authorize(signer_did, &received, now),
        }
    };

    match outcome {
        Ok(payload) => {
            let response = doc.respond_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
            let value = serde_json::to_value(&response).unwrap_or(Value::Null);
            signed(state, StatusCode::OK, value).await
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
            refuse(state, &doc, code, &reason).await
        }
    }
}
