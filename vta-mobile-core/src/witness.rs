//! Witnessing through the holder's VTA (`vta/witness/*`, the VTA as the witnessed party).
//!
//! A witness observes a relationship exchange and attests to it in a Verifiable Witness
//! Credential (VWC). The party opens a `witness/session` under its relationship DID, presents
//! its relationship credential bound to the session's challenge, and receives the VWC. A wallet
//! holds neither the relationship DID's signing key nor the credentials — its VTA does — so the
//! VTA builds and signs every document **as the relationship DID**, and the wallet **carries**
//! them: it sends each one to the witness from the relationship DID and hands each answer back.
//! The VTA never contacts the witness (`vta/_shared/0.6/CONVENTIONS.md`).
//!
//! The round, as the native app drives it:
//!
//! 1. [`build_witness_task`] [`WitnessTask::Open`] → the VTA; [`parse_witness_response`] gives
//!    `{sessionId, document, expiresAt}`.
//! 2. [`check_witness_document`] the `document` (a `witness/session`), then send it to the
//!    witness from the relationship DID — over the transport [`resolve_witness_route`] picks
//!    (TSP > DIDComm). [`classify_witness_reply`] the answer.
//! 3. [`WitnessTask::Present`] with `{sessionId, response: <the witness's answer>}` → the VTA;
//!    its `document` is the `witness/session/submit`. Check it, send it, classify the answer,
//!    and **discard the submit document** once the witness has answered (it carries the
//!    principal's presentations; CONVENTIONS §6).
//! 4. [`WitnessTask::Accept`] with `{sessionId, response: <the witness's answer>}` → the VTA;
//!    `{credentialId, witness, vwcDigestMultibase, evidence}`: the VWC is stored.
//!
//! [`WitnessTask::List`] (`{relationshipDid?, witness?, pageSize?, cursor?}`) reads back every
//! stored VWC with that same evidence, oldest first; a page with `truncated: true` continues with
//! its `cursor`. Present to a verifier only the VWCs the user selects.
//!
//! A refusal from the witness ([`WitnessReply::Refused`]) ends the session at the wallet and is
//! **not** handed back; the VTA's record expires on its own. Open a new session to try again.
//! Every VTA step is safe to repeat. Never resend a document to the witness under a new `id`:
//! the same document again is a retry, a rebuilt one is a second request.
//!
//! The transport stays where the relationship DID's connection is: a
//! [`TspMediatorSession`](crate::tsp::TspMediatorSession) or
//! [`MediatorSession`](crate::mediator::MediatorSession) whose holder is the relationship DID,
//! sending to the witness DID as its peer. Both refuse a document not issued by their holder or
//! not addressed to the peer, as [`check_witness_document`] does. A `did:peer:2` relationship
//! DID holds independent signing and key-agreement keys, so open its session with
//! `connect_with_secrets` and its keys as [`HolderSecret`](crate::holder_secrets::HolderSecret)s,
//! not `connect`, which derives both from one `did:key` seed.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use trust_tasks_rs::specs::vta::witness as vta_witness;
use trust_tasks_rs::specs::witness::session;
use trust_tasks_rs::validate::ValidatedPayload;
use trust_tasks_rs::{ErrorPayload, Payload, TrustTask};
use vta_sdk::inbound::{Inbound, classify};
use vta_sdk::protocol::matching::{Protocol, ServiceCapabilities, select_protocol};

use crate::error::FfiError;
use crate::keys::Signer;
use crate::proof::attach_did_signed_proof;
use crate::session::AuthEnvelope;

/// The `vta/witness/*` task a document is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WitnessTask {
    /// `vta/witness/open/0.2` — the `witness/session` document to carry.
    Open,
    /// `vta/witness/present/0.2` — hand back the session answer; the submit document to carry.
    Present,
    /// `vta/witness/accept/0.2` — hand back the submit answer; the stored VWC.
    Accept,
    /// `vta/witness/list/0.1` — read back the stored VWCs, each with its outcome evidence as
    /// stored: how a wallet that lost `accept`'s answer, or a second device, rebuilds its record.
    List,
}

/// The document of the session the wallet is about to carry to the witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WitnessDocument {
    /// `witness/session/0.2`, from [`WitnessTask::Open`].
    Session,
    /// `witness/session/submit/0.2`, from [`WitnessTask::Present`].
    Submit,
}

impl WitnessDocument {
    fn type_uri(self) -> &'static str {
        match self {
            Self::Session => <session::v0_2::Payload as Payload>::TYPE_URI,
            Self::Submit => <session::submit::v0_2::Payload as Payload>::TYPE_URI,
        }
    }
}

/// Which declared refusal a witness answered with, so the wallet can say the right thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WitnessRefusal {
    /// `witness/session:refused` — the witness will not witness this exchange (policy,
    /// capacity, or the parties). Not retryable; another witness may.
    SessionRefused,
    /// `witness/session/submit:challengeMismatch` — the submission is not bound to a live
    /// session of this witness (expired, already spent, or another session's). Open a new
    /// session.
    ChallengeMismatch,
    /// `witness/session/submit:presentationInvalid` — the witness did not accept the
    /// presented credentials (a proof, a validity window, or a community it does not serve).
    PresentationInvalid,
    /// Any other code — a standard one (`malformedRequest`, `permissionDenied`, …) or one this
    /// engine does not know. `code` carries it.
    Other,
}

/// What a witness answered, once the answer is proven to be the witness's.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum WitnessReply {
    /// The witness's `#response`: hand `response_json` back to the VTA, unaltered, as the
    /// `response` of [`WitnessTask::Present`] (after the session) or [`WitnessTask::Accept`]
    /// (after the submission).
    Answered { response_json: String },
    /// A `trust-task-error`: the session ends here. Do not hand it to the VTA.
    Refused {
        refusal: WitnessRefusal,
        /// The code as received, e.g. `witness/session:refused`.
        code: String,
        /// The witness's message, for logs; never parse it.
        message: Option<String>,
        /// Whether the witness says the same document may be sent again.
        retryable: bool,
    },
}

/// The transport to carry a session's documents on, and where each side is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WitnessTransport {
    Tsp,
    Didcomm,
}

/// How to reach a witness from a relationship DID: the highest-preference transport both DID
/// documents advertise (TSP, then DIDComm), matched on service `type`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WitnessRoute {
    pub transport: WitnessTransport,
    /// The mediator the relationship DID's session connects through.
    pub relationship_mediator_did: String,
    /// The witness's mediator: the `mediator_did` for
    /// [`TspMediatorSession::send_trust_task`](crate::tsp::TspMediatorSession::send_trust_task).
    pub witness_mediator_did: String,
}

fn invalid<E: std::fmt::Display>(e: E) -> FfiError {
    FfiError::InvalidInput {
        reason: e.to_string(),
    }
}

fn decode<E: std::fmt::Display>(e: E) -> FfiError {
    FfiError::Decode {
        reason: format!("not a valid vta/witness response: {e}"),
    }
}

fn signed<P: Payload + Serialize + DeserializeOwned + ValidatedPayload>(
    env: &AuthEnvelope,
    payload_json: &str,
    signer: &dyn Signer,
) -> Result<String, FfiError> {
    // The schema first (a bound like `pageSize ≤ 100` is the schema's, not the type's), then
    // the generated type.
    let value: Value = serde_json::from_str(payload_json).map_err(invalid)?;
    P::validate_value(&value).map_err(|e| FfiError::InvalidInput {
        reason: format!("the payload does not match the task's schema: {e}"),
    })?;
    let payload: P = serde_json::from_value(value).map_err(invalid)?;
    let issued_at = chrono::DateTime::parse_from_rfc3339(&env.issued_at)
        .map_err(|e| FfiError::InvalidInput {
            reason: format!("issued_at is not an RFC 3339 timestamp: {e}"),
        })?
        .with_timezone(&chrono::Utc);
    let mut doc = TrustTask::for_payload(env.id.clone(), payload);
    doc.issuer = Some(env.holder_did.clone());
    doc.recipient = Some(env.vta_did.clone());
    doc.issued_at = Some(issued_at);
    attach_did_signed_proof(&mut doc, signer, &env.issued_at)?;
    serde_json::to_string(&doc).map_err(invalid)
}

fn response<R: Serialize + DeserializeOwned>(json: &str) -> Result<String, FfiError> {
    let doc: TrustTask<R> = serde_json::from_str(json).map_err(decode)?;
    serde_json::to_string(&doc.payload).map_err(decode)
}

/// Build a holder-signed `vta/witness/*` request to the holder's VTA.
///
/// `payload_json` is the task's payload, checked against the task's generated type before
/// anything is signed. For [`WitnessTask::Present`] and [`WitnessTask::Accept`] it is
/// `{"sessionId": …, "response": <the witness's answer, as received>}`.
#[uniffi::export]
pub fn build_witness_task(
    env: AuthEnvelope,
    task: WitnessTask,
    payload_json: String,
    signer: Box<dyn Signer>,
) -> Result<String, FfiError> {
    let s = &*signer;
    let p = payload_json.as_str();
    match task {
        WitnessTask::Open => signed::<vta_witness::open::v0_2::Payload>(&env, p, s),
        WitnessTask::Present => signed::<vta_witness::present::v0_2::Payload>(&env, p, s),
        WitnessTask::Accept => signed::<vta_witness::accept::v0_2::Payload>(&env, p, s),
        WitnessTask::List => signed::<vta_witness::list::v0_1::Payload>(&env, p, s),
    }
}

/// Check a `vta/witness/*#response` against the task's generated response type and return its
/// payload as JSON. A `trust-task-error` from the VTA (`sessionUnknown`, `responseInvalid`,
/// `vwcInvalid`, …) is not a response and fails here with `Decode`; the native layer reads its
/// `payload.code` itself, as for every other VTA task.
#[uniffi::export]
pub fn parse_witness_response(task: WitnessTask, json: String) -> Result<String, FfiError> {
    let j = json.as_str();
    match task {
        WitnessTask::Open => response::<vta_witness::open::v0_2::Response>(j),
        WitnessTask::Present => response::<vta_witness::present::v0_2::Response>(j),
        WitnessTask::Accept => response::<vta_witness::accept::v0_2::Response>(j),
        WitnessTask::List => response::<vta_witness::list::v0_1::Response>(j),
    }
}

/// Refuse to carry `document_json` unless it is the `kind` document of session `session_id`,
/// signed and issued by `relationship_did`, and addressed to `witness_did`.
///
/// The VTA builds these documents; this is the wallet's own check that what it is about to
/// send in the relationship DID's name is what it asked for, to the witness it named
/// (CONVENTIONS §6: send each document only to its `recipient`). A session document's `id` is
/// the session id; a submit document is threaded to it.
#[uniffi::export]
pub fn check_witness_document(
    document_json: String,
    kind: WitnessDocument,
    session_id: String,
    relationship_did: String,
    witness_did: String,
) -> Result<(), FfiError> {
    let doc: Value = serde_json::from_str(&document_json).map_err(|e| FfiError::InvalidInput {
        reason: format!("the witness document is not JSON: {e}"),
    })?;
    let refuse = |reason: String| {
        Err(FfiError::InvalidInput {
            reason: format!("refusing to carry the witness document: {reason}"),
        })
    };
    let field = |name: &str| doc.get(name).and_then(Value::as_str);

    match field("type") {
        Some(t) if t == kind.type_uri() => {}
        other => {
            return refuse(format!(
                "it is a `{}`, not a `{}`",
                other.unwrap_or("(no type)"),
                kind.type_uri()
            ));
        }
    }
    let bound = match kind {
        WitnessDocument::Session => ("id", field("id")),
        WitnessDocument::Submit => ("threadId", field("threadId")),
    };
    if bound.1 != Some(session_id.as_str()) {
        return refuse(format!(
            "its `{}` is `{}`, not the session `{session_id}`",
            bound.0,
            bound.1.unwrap_or("(none)")
        ));
    }
    crate::reply::require_signed_request(&doc, &relationship_did, &witness_did)
}

/// Classify the witness's answer to `request_json` (the document the wallet carried), once it
/// is proven to be `witness_did`'s.
///
/// The answer must pass [`verify_trust_task_reply`](crate::reply::verify_trust_task_reply)
/// first — a proof by the witness under `authentication`, threaded to the document, addressed
/// to the relationship DID — or this is [`FfiError::UnverifiedReply`]: discard it unread. A
/// refusal is held to the same rule as a success, so a forged refusal cannot make the wallet
/// abandon a session.
///
/// Over DIDComm, [`MediatorSession::send_trust_task`](crate::mediator::MediatorSession) has
/// already verified the reply; checking again here costs a cached resolution.
#[uniffi::export(async_runtime = "tokio")]
pub async fn classify_witness_reply(
    request_json: String,
    reply_json: String,
    witness_did: String,
) -> Result<WitnessReply, FfiError> {
    let request: Value =
        serde_json::from_str(&request_json).map_err(|e| FfiError::InvalidInput {
            reason: format!("the carried document is not JSON: {e}"),
        })?;
    let reply: Value =
        serde_json::from_str(&reply_json).map_err(|e| FfiError::UnverifiedReply {
            reason: format!("the reply is not JSON: {e}"),
        })?;
    crate::proof::verify_reply(&request, &reply, &witness_did).await?;
    classify_verified(reply_json, &reply)
}

/// [`classify_witness_reply`] after verification. `verify_reply` already holds a `#response`
/// to the request's own type, so only the error/response split is left.
fn classify_verified(reply_json: String, reply: &Value) -> Result<WitnessReply, FfiError> {
    match classify(reply) {
        Inbound::Response => Ok(WitnessReply::Answered {
            response_json: reply_json,
        }),
        Inbound::Error => {
            let error: TrustTask<ErrorPayload> =
                serde_json::from_value(reply.clone()).map_err(|e| FfiError::Decode {
                    reason: format!("the witness's trust-task-error does not parse: {e}"),
                })?;
            let code = error.payload.code.to_string();
            Ok(WitnessReply::Refused {
                refusal: refusal_for(&code),
                code,
                message: error.payload.message,
                retryable: error.payload.retryable,
            })
        }
        Inbound::Request => Err(FfiError::UnverifiedReply {
            reason: "the witness sent a request, not an answer".into(),
        }),
    }
}

fn refusal_for(code: &str) -> WitnessRefusal {
    use session::submit::v0_2::error_codes as submit;
    use session::v0_2::error_codes as open;
    if code == open::REFUSED.code {
        WitnessRefusal::SessionRefused
    } else if code == submit::CHALLENGE_MISMATCH.code {
        WitnessRefusal::ChallengeMismatch
    } else if code == submit::PRESENTATION_INVALID.code {
        WitnessRefusal::PresentationInvalid
    } else {
        WitnessRefusal::Other
    }
}

/// Resolve the relationship DID and the witness DID and pick the transport to carry the
/// session on: the highest-preference one both advertise (TSP, then DIDComm), matched on
/// service `type`. REST is never a candidate — a witness answers the transport-proven sender,
/// which an HTTPS POST does not prove. Neither in common is `InvalidInput` naming both sets.
#[uniffi::export(async_runtime = "tokio")]
pub async fn resolve_witness_route(
    relationship_did: String,
    witness_did: String,
) -> Result<WitnessRoute, FfiError> {
    let ours = resolve_json(&relationship_did).await?;
    let theirs = resolve_json(&witness_did).await?;
    select_witness_route(&ours, &theirs, &witness_did)
}

async fn resolve_json(did: &str) -> Result<Value, FfiError> {
    let json = crate::resolver::resolve_did(did.to_string()).await?;
    serde_json::from_str(&json).map_err(|e| FfiError::Decode {
        reason: format!("the DID document of {did} is not JSON: {e}"),
    })
}

/// [`resolve_witness_route`] over two resolved documents. Pure, for tests.
fn select_witness_route(
    relationship_doc: &Value,
    witness_doc: &Value,
    witness_did: &str,
) -> Result<WitnessRoute, FfiError> {
    let carriers = |doc: &Value| ServiceCapabilities {
        rest: None,
        ..ServiceCapabilities::from_did_document(doc)
    };
    let ours = carriers(relationship_doc);
    let matched = select_protocol(&ours, &carriers(witness_doc), witness_did).map_err(invalid)?;
    let transport = match matched.protocol {
        Protocol::Tsp => WitnessTransport::Tsp,
        Protocol::Didcomm => WitnessTransport::Didcomm,
        Protocol::Rest => unreachable!("REST was removed from both sides"),
    };
    Ok(WitnessRoute {
        transport,
        relationship_mediator_did: ours
            .endpoint(matched.protocol)
            .unwrap_or_default()
            .to_string(),
        witness_mediator_did: matched.peer_endpoint,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::proof::REPLY_PROOF_PURPOSE;
    use crate::proof::test_support::{did_for, sign_as_with_purpose};

    const RELATIONSHIP: u8 = 31;
    const WITNESS: u8 = 32;
    const OTHER: u8 = 33;
    const SESSION: &str = "urn:uuid:9e8d7c6b-0000-4000-8000-0000000000aa";

    fn session_doc() -> Value {
        json!({
            "id": SESSION,
            "type": <session::v0_2::Payload as Payload>::TYPE_URI,
            "issuer": did_for(RELATIONSHIP),
            "recipient": did_for(WITNESS),
            "issuedAt": "2026-10-15T10:00:00Z",
            "payload": {},
            "proof": { "type": "DataIntegrityProof" }
        })
    }

    fn submit_doc() -> Value {
        json!({
            "id": "urn:uuid:submit-1",
            "type": <session::submit::v0_2::Payload as Payload>::TYPE_URI,
            "threadId": SESSION,
            "issuer": did_for(RELATIONSHIP),
            "recipient": did_for(WITNESS),
            "issuedAt": "2026-10-15T10:00:05Z",
            "payload": { "vp": {} },
            "proof": { "type": "DataIntegrityProof" }
        })
    }

    fn check(doc: &Value, kind: WitnessDocument) -> Result<(), FfiError> {
        check_witness_document(
            doc.to_string(),
            kind,
            SESSION.into(),
            did_for(RELATIONSHIP),
            did_for(WITNESS),
        )
    }

    fn refused(r: Result<(), FfiError>, needle: &str) {
        match r {
            Err(FfiError::InvalidInput { reason }) => {
                assert!(
                    reason.contains(needle),
                    "expected `{needle}`, got `{reason}`"
                )
            }
            other => panic!("expected a refusal mentioning `{needle}`, got {other:?}"),
        }
    }

    #[test]
    fn only_the_sessions_own_documents_are_carried_to_the_witness() {
        check(&session_doc(), WitnessDocument::Session).expect("the session document");
        check(&submit_doc(), WitnessDocument::Submit).expect("the submit document");

        refused(check(&session_doc(), WitnessDocument::Submit), "not a");
        refused(check(&submit_doc(), WitnessDocument::Session), "not a");

        let mut other_session = submit_doc();
        other_session["threadId"] = json!("urn:uuid:another-session");
        refused(check(&other_session, WitnessDocument::Submit), "threadId");
        let mut renamed = session_doc();
        renamed["id"] = json!("urn:uuid:another-session");
        refused(check(&renamed, WitnessDocument::Session), "`id`");

        let mut elsewhere = session_doc();
        elsewhere["recipient"] = json!(did_for(OTHER));
        refused(check(&elsewhere, WitnessDocument::Session), "addressed to");

        let mut foreign = submit_doc();
        foreign["issuer"] = json!(did_for(OTHER));
        refused(check(&foreign, WitnessDocument::Submit), "issued by");

        let mut unsigned = submit_doc();
        unsigned.as_object_mut().unwrap().remove("proof");
        refused(check(&unsigned, WitnessDocument::Submit), "no proof");
    }

    /// The witness's answer to the session document, unsigned.
    fn answer(payload: Value) -> Value {
        json!({
            "id": "urn:uuid:answer-1",
            "type": format!("{}#response", <session::v0_2::Payload as Payload>::TYPE_URI),
            "threadId": SESSION,
            "issuer": did_for(WITNESS),
            "recipient": did_for(RELATIONSHIP),
            "issuedAt": "2026-10-15T10:00:01Z",
            "payload": payload
        })
    }

    fn error(code: &str, retryable: bool) -> Value {
        let mut e = answer(json!({ "code": code, "message": "no", "retryable": retryable }));
        e["type"] = json!("https://trusttasks.org/spec/trust-task-error/0.5");
        e
    }

    async fn signed(mut doc: Value, seed: u8) -> Value {
        sign_as_with_purpose(&mut doc, seed, REPLY_PROOF_PURPOSE).await;
        doc
    }

    async fn classify_reply(reply: &Value) -> Result<WitnessReply, FfiError> {
        classify_witness_reply(
            session_doc().to_string(),
            reply.to_string(),
            did_for(WITNESS),
        )
        .await
    }

    // One runtime for the process-wide resolver, as in `reply.rs`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn witness_replies_are_verified_then_classified() {
        let ok = signed(answer(json!({ "challenge": "c" })), WITNESS).await;
        match classify_reply(&ok).await.expect("the witness's answer") {
            WitnessReply::Answered { response_json } => {
                let back: Value = serde_json::from_str(&response_json).unwrap();
                assert_eq!(back, ok, "the answer is handed back as received");
            }
            other => panic!("expected an answer, got {other:?}"),
        }

        for (code, refusal) in [
            ("witness/session:refused", WitnessRefusal::SessionRefused),
            (
                "witness/session/submit:challengeMismatch",
                WitnessRefusal::ChallengeMismatch,
            ),
            (
                "witness/session/submit:presentationInvalid",
                WitnessRefusal::PresentationInvalid,
            ),
            ("malformedRequest", WitnessRefusal::Other),
        ] {
            let reply = signed(error(code, false), WITNESS).await;
            assert_eq!(
                classify_reply(&reply).await.expect("a signed refusal"),
                WitnessReply::Refused {
                    refusal,
                    code: code.into(),
                    message: Some("no".into()),
                    retryable: false,
                }
            );
        }

        // A refusal nobody can attribute to the witness is not one.
        let forged = signed(error("witness/session:refused", false), OTHER).await;
        assert!(matches!(
            classify_reply(&forged).await,
            Err(FfiError::UnverifiedReply { .. })
        ));
        assert!(matches!(
            classify_reply(&error("witness/session:refused", false)).await,
            Err(FfiError::UnverifiedReply { .. })
        ));
    }

    fn doc_with(services: Value) -> Value {
        json!({ "id": "did:example:x", "service": services })
    }

    fn tsp(m: &str) -> Value {
        json!({ "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": m })
    }

    fn didcomm(m: &str) -> Value {
        json!({ "id": "#didcomm", "type": "DIDCommMessaging", "serviceEndpoint": { "uri": m } })
    }

    #[test]
    fn the_route_is_the_best_transport_both_sides_advertise() {
        let both = |m| doc_with(json!([didcomm(m), tsp(m)]));
        let route = select_witness_route(&both("did:m:ours"), &both("did:m:theirs"), "did:w")
            .expect("TSP in common");
        assert_eq!(
            route,
            WitnessRoute {
                transport: WitnessTransport::Tsp,
                relationship_mediator_did: "did:m:ours".into(),
                witness_mediator_did: "did:m:theirs".into(),
            }
        );

        let route = select_witness_route(
            &doc_with(json!([didcomm("did:m:ours")])),
            &both("did:m:theirs"),
            "did:w",
        )
        .expect("DIDComm in common");
        assert_eq!(route.transport, WitnessTransport::Didcomm);

        // REST is never a carrier: a witness answers the transport-proven sender.
        let rest = doc_with(json!([{ "id": "#rest", "type": "VTARest",
                                     "serviceEndpoint": "https://w.example" }]));
        let err = select_witness_route(&rest, &rest, "did:w").unwrap_err();
        assert!(matches!(err, FfiError::InvalidInput { .. }), "{err:?}");
    }

    #[test]
    fn a_payload_the_schema_refuses_is_not_signed() {
        struct Refuse;
        impl Signer for Refuse {
            fn did(&self) -> String {
                "did:key:z6MkHolder".into()
            }
            fn sign(&self, _payload: Vec<u8>) -> Result<Vec<u8>, FfiError> {
                panic!("the signer must not be reached");
            }
        }
        let env = AuthEnvelope {
            id: "urn:uuid:1".into(),
            holder_did: "did:key:z6MkHolder".into(),
            vta_did: "did:key:z6MkVta".into(),
            issued_at: "2026-10-15T09:00:00Z".into(),
        };
        let err = build_witness_task(
            env,
            WitnessTask::Present,
            r#"{"sessionId":"s-1"}"#.into(),
            Box::new(Refuse),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::InvalidInput { .. }), "{err:?}");
    }

    /// `vta/witness/list`: a page size the schema refuses is never signed, and a response is
    /// checked against the generated type before it is handed back.
    #[test]
    fn list_is_checked_both_ways() {
        struct Refuse;
        impl Signer for Refuse {
            fn did(&self) -> String {
                "did:key:z6MkHolder".into()
            }
            fn sign(&self, _payload: Vec<u8>) -> Result<Vec<u8>, FfiError> {
                panic!("the signer must not be reached");
            }
        }
        let env = AuthEnvelope {
            id: "urn:uuid:2".into(),
            holder_did: "did:key:z6MkHolder".into(),
            vta_did: "did:key:z6MkVta".into(),
            issued_at: "2026-10-16T09:00:00Z".into(),
        };
        let err = build_witness_task(
            env,
            WitnessTask::List,
            r#"{"pageSize":101}"#.into(),
            Box::new(Refuse),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::InvalidInput { .. }), "{err:?}");

        let list_type = <vta_witness::list::v0_1::Payload as Payload>::TYPE_URI;
        let page = serde_json::json!({
            "id": "urn:uuid:r",
            "type": format!("{list_type}#response"),
            "threadId": "urn:uuid:2",
            "payload": { "witnessings": [], "truncated": false },
        });
        let parsed = parse_witness_response(WitnessTask::List, page.to_string()).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&parsed).unwrap(),
            serde_json::json!({ "witnessings": [], "truncated": false })
        );
        let bad = serde_json::json!({ "payload": { "witnessings": [] } });
        assert!(parse_witness_response(WitnessTask::List, bad.to_string()).is_err());
    }
}
