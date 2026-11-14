//! The dispatch core: one inbound Trust Task document in, at most one signed
//! reply out. No socket, no transport — the messaging layer hands it the
//! document bytes and the transport-proven sender, and carries back whatever
//! it returns.
//!
//! # What a witness identity serves
//!
//! | type | answer |
//! |---|---|
//! | `trust-task-discovery/0.4` | this identity's own task list |
//! | `trust-task-discovery/0.3` | the same, superseded, without the expiry horizon |
//! | `witness/session/0.2` | a session and its challenge ([`crate::witness`]) |
//! | `witness/session/submit/0.2` | the VWC and its digest ([`crate::witness`]) |
//!
//! The 0.1 witness tasks are not served: another version of a served family is
//! `unsupportedVersion`, so a 0.1 party is told to re-ask at 0.2.
//! | anything else | `unsupportedType` (or `unsupportedVersion` for another version of a served family) |
//!
//! [`SERVED`] is the one table both discovery and routing read, so discovery
//! cannot list a task nobody routes. Only an **enabled** identity is served at
//! all (`vti-witness run` connects no other), so "listed in discovery" and
//! "enabled" are the same fact.
//!
//! # The §7.2 pipeline
//!
//! Classify, then the workspace's one receive pipeline,
//! [`vti_trust_task_server::Spine`] (#2576):
//!
//! 1. **Classify** (`vta_sdk::inbound`). A `trust-task-error` or a
//!    `#response` is a reply. This service sends no requests, so no waiter
//!    holds any reply: it is dropped, never answered — answering an error
//!    with an error is the loop that only a rate limiter ends.
//! 2. **Parse** the document. Bytes that are not a Trust Task document have
//!    no thread to answer on and are dropped.
//! 3. **Freshness** (§7.2 item 13, VTI-OPS-024): the acceptance window every
//!    VTI node applies, `issuedAt` required.
//! 4. **Expiry and recipient** (items 4–5). `recipient` must be this
//!    identity's DID. Each identity holds its own socket, so the frame
//!    reached *this* identity; a document addressed to anyone else — another
//!    witness of this service, the operator's VTA — is refused here.
//! 5. **Specification policy** (items 5b, 7a, 8, §7.3 17): what the task's
//!    own specification declares — recipient, proof, `issuedAt` required.
//! 6. **Consistency** (item 6, [`Gate`]): an in-band `issuer` must be the
//!    transport-proven sender; and **routing**: an unserved type is refused
//!    before any proof is verified, so an unanswerable request cannot make
//!    this service resolve DIDs.
//! 7. **Proof** (item 7): verified over the document *as received*, and its
//!    signer must be the document's `issuer` (§4.7) and the sender. A
//!    document with no proof runs only where its specification makes the
//!    proof OPTIONAL (discovery), as it would over HTTPS (VTI-OPS-021).
//! 8. **Duplicate execution** (item 11, VTI-OPS-025 … 029): the document's
//!    `id` is claimed in the store-backed record
//!    ([`vti_trust_task_server::StoreAcceptedIds`]) with a digest of the
//!    whole document. The same document again is answered with the first
//!    reply; a different document under the same `id` is `idConflict`.
//!
//! # Every reply is this identity's
//!
//! A reply's `issuer` is this identity's DID — set explicitly, never copied
//! from the request (a framework builder would copy the request's
//! `recipient`, which on a misaddressed document names someone else) — its
//! `recipient` is the proven sender it goes back to, and it is signed with
//! this identity's own key. A reply that cannot be signed is not sent. No
//! reply names, or is signed as, the operator's VTA.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
#[allow(deprecated)] // 0.3 is superseded, and still answered
use trust_tasks_rs::specs::trust_task_discovery::v0_3;
use trust_tasks_rs::specs::trust_task_discovery::v0_4;
use trust_tasks_rs::validate::ValidatedPayload;
use vti_specs::witness::session;

use trust_tasks_rs::{Payload, RejectReason, TransportContext, TransportHandler, TrustTask};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::trust_task_sign::{HolderKey, sign_in_place_with};
use vti_common::error::AppError;
use vti_common::trust_task::discovery;
use vti_trust_task_server::reject::{app_error_to_reject, error_response, reject_with};
use vti_trust_task_server::{
    ArrivalCtx, BoxFuture, Dispatcher, ProofVerifier, ResponseSigner, SizeTable, Spine, SpineHooks,
    TrustTaskOutcome,
};

use crate::witness::Witnessing;

/// `trust-task-discovery/0.4` — the version the VTA and VTC both answer.
pub const DISCOVERY_V0_4: &str = discovery::DISCOVERY_V0_4;
/// `trust-task-discovery/0.3`, superseded by 0.4 and still answered.
pub const DISCOVERY_V0_3: &str = discovery::DISCOVERY_V0_3;
/// `witness/session/0.2`.
pub const WITNESS_SESSION_V0_2: &str = <session::v0_2::Payload as Payload>::TYPE_URI;
/// `witness/session/submit/0.2`.
pub const WITNESS_SESSION_SUBMIT_V0_2: &str = <session::submit::v0_2::Payload as Payload>::TYPE_URI;

/// Every type a witness identity serves — the one table routing and the
/// discovery answer both read, so discovery cannot list a task nobody routes.
pub const SERVED: &[&str] = &[
    DISCOVERY_V0_4,
    DISCOVERY_V0_3,
    WITNESS_SESSION_V0_2,
    WITNESS_SESSION_SUBMIT_V0_2,
];

/// One witness identity, as the dispatcher needs it: who it is, the key it
/// signs with (replies and VWCs alike: `#key-0` is both `authentication` and
/// `assertionMethod` in the `dtg-witness` template), and what it witnesses.
pub struct IdentityContext {
    name: String,
    did: String,
    signing_key: HolderKey,
    witnessing: Arc<Witnessing>,
}

/// Hand-written: the signing key's own `Debug` already redacts, and this
/// keeps it out of view entirely.
impl std::fmt::Debug for IdentityContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityContext")
            .field("name", &self.name)
            .field("did", &self.did)
            .finish_non_exhaustive()
    }
}

impl IdentityContext {
    /// An identity that signs with `signing_key`, which must be one of
    /// `did`'s own verification methods.
    pub fn new(
        name: impl Into<String>,
        did: impl Into<String>,
        signing_key: HolderKey,
        witnessing: Witnessing,
    ) -> anyhow::Result<Self> {
        let did = did.into();
        if signing_key.holder_did() != did {
            anyhow::bail!(
                "the signing key {} is not a verification method of {did}",
                signing_key.verification_method()
            );
        }
        Ok(Self {
            name: name.into(),
            did,
            signing_key,
            witnessing: Arc::new(witnessing),
        })
    }

    /// The identity's witnessing state.
    pub fn witnessing(&self) -> &Witnessing {
        &self.witnessing
    }

    /// The identity's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The operator's name for the identity.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// What to do with one inbound document.
#[derive(Debug)]
pub enum Outcome {
    /// Send this signed document back to the sender.
    Reply(Value),
    /// Send nothing.
    Drop(DropReason),
}

/// Why nothing is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// The bytes are not JSON.
    NotJson,
    /// JSON, but not a Trust Task document — there is no thread to answer on.
    NotATrustTask,
    /// A `trust-task-error`, which is never answered.
    Error,
    /// A `#response`. This service sends no requests, so nothing awaits it.
    UnclaimedReply,
    /// The reply could not be signed, and an unsigned reply is never sent.
    SigningFailed,
    /// A duplicate of a document still being executed, or whose first
    /// execution left no answer to repeat (SPEC §7.2, *Disposition of a
    /// duplicate*: never `taskFailed`).
    Duplicate,
}

/// The largest document an identity reads: the workspace's request cap (`MAX_BODY_SIZE`). A
/// task whose specification declares a larger bound is held to that instead.
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Answer one inbound document addressed to `identity`, from the
/// transport-proven `sender`.
///
/// `now` is the instant the witness tasks themselves run at (session expiry,
/// eviction, the VWC's dates). The pipeline's acceptance window is decided on
/// the clock, as every node's is.
pub async fn answer(
    identity: &IdentityContext,
    sender: &str,
    document: &[u8],
    resolver: &TrustTaskVmResolver,
    now: DateTime<Utc>,
) -> Outcome {
    // 1. Classify, on the JSON as received: a reply is never answered.
    let Ok(received) = serde_json::from_slice::<Value>(document) else {
        return Outcome::Drop(DropReason::NotJson);
    };
    if !vta_sdk::inbound::classify(&received).may_answer() {
        return Outcome::Drop(DropReason::Error);
    }
    if vta_sdk::inbound::names_a_reply(&received) {
        return Outcome::Drop(DropReason::UnclaimedReply);
    }
    // 2. Bytes that are not a document have no thread to answer on.
    if serde_json::from_value::<TrustTask<Value>>(received).is_err() {
        return Outcome::Drop(DropReason::NotATrustTask);
    }

    // Steps 3 – 9: the workspace's one receive pipeline (#2576).
    let size = SizeTable::new(
        MAX_DOCUMENT_BYTES,
        vti_specs::schema_index::max_document_bytes_for,
    );
    // The policy of a task this identity serves: an unserved type is
    // `unsupportedType` ([`Gate`]), never refused for a proof another
    // service's specification requires.
    let policy = |type_uri: &str| {
        SERVED
            .contains(&type_uri)
            .then(|| vti_specs::schema_index::spec_policy_for(type_uri))
            .flatten()
    };
    let gate = Gate { identity, sender };
    let verifier = Verifier { resolver };
    let accepted = identity.witnessing.accepted_ids();
    let routes = Routes {
        identity,
        sender,
        document,
        resolver,
        now,
    };
    let signer = ReplySigner { identity, sender };
    let outcome = Spine::new(&policy, &verifier, &gate, &accepted, &routes)
        .with_size_gate(&size)
        .with_signer(Some(&signer))
        // Discovery is asked unsigned; its proof is OPTIONAL on every transport.
        .accepting_unsigned_optional_over_messaging()
        .receive(&ArrivalCtx::didcomm(sender.to_string()), document)
        .await;

    // A duplicate still running, or whose first answer was not kept: nothing
    // to repeat (SPEC §7.2, *Disposition of a duplicate*: never `taskFailed`).
    if outcome.body.is_empty() {
        return Outcome::Drop(DropReason::Duplicate);
    }
    match serde_json::from_slice::<Value>(&outcome.body) {
        Ok(reply) if reply.get("proof").is_some() => Outcome::Reply(reply),
        _ => {
            tracing::error!(
                identity = %identity.name,
                "could not sign a reply; sending nothing rather than an unsigned answer"
            );
            Outcome::Drop(DropReason::SigningFailed)
        }
    }
}

/// This identity's own checks before any proof is read: the in-band parties
/// against what the transport proved, and routing, so an unanswerable request
/// cannot make this service resolve DIDs.
struct Gate<'a> {
    identity: &'a IdentityContext,
    sender: &'a str,
}

#[async_trait::async_trait]
impl SpineHooks for Gate<'_> {
    /// Each identity holds its own socket, so the frame reached *this*
    /// identity; a document addressed to anyone else is refused.
    async fn recipient(&self) -> Option<String> {
        Some(self.identity.did.clone())
    }

    async fn before_proof(
        &self,
        doc: &TrustTask<Value>,
        type_uri: &str,
    ) -> Option<TrustTaskOutcome> {
        let transport = WitnessTransport {
            sender: self.sender,
            recipient: &self.identity.did,
        };
        if let Err(mismatch) = transport.resolve_parties(doc) {
            return Some(reject_with(doc, RejectReason::IdentityMismatch(mismatch)));
        }
        if !SERVED.contains(&type_uri) {
            return Some(reject_with(doc, unserved(type_uri)));
        }
        None
    }
}

/// The proof over the document as received. A proof that does not verify is
/// `proofInvalid`, with the verifier's reason.
struct Verifier<'a> {
    resolver: &'a TrustTaskVmResolver,
}

#[async_trait::async_trait]
impl ProofVerifier for Verifier<'_> {
    async fn verify(&self, received: &Value, _type_uri: &str) -> Result<String, AppError> {
        vti_trust_task_server::verify::verify_received_proof(self.resolver, received).await
    }

    fn refusal(&self, doc: &TrustTask<Value>, err: &AppError) -> TrustTaskOutcome {
        match err {
            AppError::Unauthorized(reason) => reject_with(
                doc,
                RejectReason::ProofInvalid {
                    reason: reason.clone(),
                },
            ),
            other => app_error_to_reject(doc, other),
        }
    }
}

/// Every reply is this identity's: its `issuer` is this identity's DID — set
/// here, never copied from the request (a framework builder copies the
/// request's `recipient`, which on a misaddressed document names someone
/// else) — its `recipient` the proven sender it goes back to, and it is signed
/// with this identity's own key. Refusals the pipeline makes included.
struct ReplySigner<'a> {
    identity: &'a IdentityContext,
    sender: &'a str,
}

#[async_trait::async_trait]
impl ResponseSigner for ReplySigner<'_> {
    async fn sign_response_document(&self, reply: &mut Value) -> Result<(), AppError> {
        let mut doc: TrustTask<Value> = serde_json::from_value(reply.clone())
            .map_err(|e| AppError::Internal(format!("a reply is not a document: {e}")))?;
        doc.issuer = Some(self.identity.did.clone());
        doc.recipient = Some(self.sender.to_string());
        sign_in_place_with(&mut doc, &self.identity.signing_key)
            .await
            .map_err(|e| AppError::Internal(format!("could not sign a reply: {e}")))?;
        *reply = serde_json::to_value(doc)?;
        Ok(())
    }
}

/// The routing table behind the pipeline: [`SERVED`].
struct Routes<'a> {
    identity: &'a IdentityContext,
    sender: &'a str,
    /// The document exactly as its bytes arrived: a session is kept verbatim,
    /// because the VWC's task digest is computed over it.
    document: &'a [u8],
    resolver: &'a TrustTaskVmResolver,
    now: DateTime<Utc>,
}

impl Dispatcher for Routes<'_> {
    fn dispatch<'a>(
        &'a self,
        _ctx: &'a ArrivalCtx,
        doc: TrustTask<Value>,
        type_uri: &'a str,
        _received: Arc<Value>,
    ) -> BoxFuture<'a, TrustTaskOutcome> {
        Box::pin(self.route(doc, type_uri))
    }
}

impl Routes<'_> {
    async fn route(&self, doc: TrustTask<Value>, type_uri: &str) -> TrustTaskOutcome {
        let answered = |payload: Value| respond(&doc, self.now, payload);
        match type_uri {
            DISCOVERY_V0_4 => {
                if let Err(e) = v0_4::Payload::validate_value(&doc.payload) {
                    return reject_with(&doc, malformed(format!("payload: {e}")));
                }
                match serde_json::from_value::<v0_4::Payload>(doc.payload.clone()) {
                    Ok(query) => answered(to_value(discovery::respond_v0_4(
                        SERVED.iter().copied(),
                        &query,
                    ))),
                    Err(e) => reject_with(&doc, malformed(format!("payload: {e}"))),
                }
            }
            #[allow(deprecated)]
            DISCOVERY_V0_3 => {
                if let Err(e) = v0_3::Payload::validate_value(&doc.payload) {
                    return reject_with(&doc, malformed(format!("payload: {e}")));
                }
                match serde_json::from_value::<v0_3::Payload>(doc.payload.clone()) {
                    Ok(query) => answered(to_value(discovery::respond_v0_3(
                        SERVED.iter().copied(),
                        &query,
                    ))),
                    Err(e) => reject_with(&doc, malformed(format!("payload: {e}"))),
                }
            }
            WITNESS_SESSION_V0_2 | WITNESS_SESSION_SUBMIT_V0_2 => {
                let witness = crate::witness::Witness {
                    did: &self.identity.did,
                    name: &self.identity.name,
                    key: &self.identity.signing_key,
                    state: &self.identity.witnessing,
                };
                let outcome = if type_uri == WITNESS_SESSION_V0_2 {
                    crate::witness::open_session(
                        &witness,
                        &doc,
                        self.document,
                        self.sender,
                        self.now,
                    )
                    .await
                } else {
                    crate::witness::submit(&witness, &doc, self.sender, self.resolver, self.now)
                        .await
                };
                match outcome {
                    Ok(payload) => answered(payload),
                    Err(error) => {
                        let mut refusal = doc.reject_with(new_id(), *error);
                        refusal.issued_at = Some(self.now);
                        error_response(refusal)
                    }
                }
            }
            // `SERVED` and these arms are one list, and [`Gate`] refused
            // anything else; a URI in one and not the other is a bug this keeps
            // loud rather than silently unanswered.
            other => reject_with(&doc, unserved(other)),
        }
    }
}

/// The refusal for a type this identity does not serve.
fn unserved(type_uri: &str) -> RejectReason {
    // Another version of a family this identity serves is a version mismatch,
    // not an unknown type — the caller can re-ask at a version listed in
    // discovery.
    let family = |uri: &str| uri.rsplit_once('/').map(|(family, _)| family.to_string());
    let same_family = family(type_uri).is_some_and(|f| {
        SERVED
            .iter()
            .any(|served| family(served).as_deref() == Some(&f))
    });
    if same_family {
        RejectReason::UnsupportedVersion {
            type_uri: type_uri.to_string(),
        }
    } else {
        RejectReason::UnsupportedType {
            type_uri: type_uri.to_string(),
        }
    }
}

fn to_value<R: Serialize>(payload: R) -> Value {
    serde_json::to_value(payload).unwrap_or(Value::Null)
}

fn malformed(reason: String) -> RejectReason {
    RejectReason::MalformedRequest { reason }
}

/// A `#response` to `doc`, issued at `now` ([`ReplySigner`] addresses it).
fn respond(doc: &TrustTask<Value>, now: DateTime<Utc>, payload: Value) -> TrustTaskOutcome {
    let mut reply = doc.respond_with(new_id(), payload);
    reply.issued_at = Some(now);
    match serde_json::to_vec(&reply) {
        Ok(body) => TrustTaskOutcome {
            status: axum::http::StatusCode::OK,
            body,
        },
        Err(e) => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("the reply is unserialisable: {e}"),
            },
        ),
    }
}

fn new_id() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
}

/// What the transport proved about one inbound frame: who sent it, and that
/// it reached this identity's own socket.
struct WitnessTransport<'a> {
    sender: &'a str,
    recipient: &'a str,
}

impl TransportHandler for WitnessTransport<'_> {
    fn binding_uri(&self) -> &str {
        // Either binding: both prove the sender, and the recipient is the
        // identity whose socket the frame arrived on.
        "https://trusttasks.org/binding/tsp/0.1"
    }

    fn derive_parties(&self) -> TransportContext {
        TransportContext {
            issuer: Some(self.sender.to_string()),
            recipient: Some(self.recipient.to_string()),
        }
    }
}

#[cfg(test)]
mod tests;
