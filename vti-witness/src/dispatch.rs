//! The dispatch core: one inbound Trust Task document in, at most one signed
//! reply out. No socket, no transport — the messaging layer hands it the
//! document bytes and the transport-proven sender, and carries back whatever
//! it returns.
//!
//! # What a witness identity serves in P1
//!
//! | type | answer |
//! |---|---|
//! | `trust-task-discovery/0.3`, `/0.1` | this identity's own task list |
//! | `witness/session/0.1`, `witness/session/submit/0.1` | `unsupportedType`, saying witnessing is not enabled yet |
//! | anything else | `unsupportedType` (or `unsupportedVersion` for another version of a served family) |
//!
//! ## Why the witness tasks are refused as `unsupportedType`, and not listed
//!
//! The design note (§3.1) has each identity serve the two witness tasks and
//! discovery. P1 is the skeleton: the witnessing itself (§3.2–§3.4) is P2.
//! Until then this service does not implement those types, and it says so the
//! way the framework defines for a type a consumer does not implement —
//! `unsupportedType` — with a message naming why. For that to be honest,
//! discovery must not list them: discovery answers "which Trust Tasks does
//! this agent serve", and a listed type that is always refused would tell a
//! client to send something it can never get answered. So [`SERVED`] is the
//! one table both discovery and routing read, and P2 adds the witness types
//! to it when it serves them.
//!
//! The alternatives were worse. `witness/session:refused` is the session
//! task's own code for a witness that *declines* — policy, capacity, the
//! exchange — which tells a client this witness weighed its request; and
//! `submit` declares no such code. `unavailable` promises a retry will work
//! "temporarily", which in P1 it never will.
//!
//! # The §7.2 pipeline
//!
//! In order, each step deciding before the next does any work:
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
//! 5. **Consistency** (item 6): an in-band `issuer` must be the
//!    transport-proven sender.
//! 6. **Routing**: an unserved type is refused before any proof is verified,
//!    so an unanswerable request cannot make this service resolve DIDs.
//! 7. **Specification policy** (items 5b, 7a, 8, §7.3 17): what the task's
//!    own specification declares — recipient, proof, `issuedAt` required.
//! 8. **Proof** (item 7): verified over the document *as received*, and its
//!    signer must be the document's `issuer` (§4.7).
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
use trust_tasks_rs::specs::trust_task_discovery::{v0_1, v0_3};
use trust_tasks_rs::specs::witness::session;
use trust_tasks_rs::validate::ValidatedPayload;
use trust_tasks_rs::{
    ErrorPayload, Payload, RejectReason, StandardCode, TransportContext, TransportHandler,
    TrustTask,
};
use vta_sdk::trust_task_proof::{TrustTaskVmResolver, verify_trust_task_proof_value};
use vta_sdk::trust_task_sign::{HolderKey, sign_in_place_with};
use vti_common::trust_task::acceptance::VTI_ACCEPTANCE_WINDOW;
use vti_common::trust_task::discovery;

/// `trust-task-discovery/0.3` — the version the VTA and VTC both answer.
pub const DISCOVERY_V0_3: &str = discovery::DISCOVERY_V0_3;
/// `trust-task-discovery/0.1` — still what `VtaClient` asks.
pub const DISCOVERY_V0_1: &str = <v0_1::Payload as Payload>::TYPE_URI;
/// `witness/session/0.1`.
pub const WITNESS_SESSION_V0_1: &str = <session::v0_1::Payload as Payload>::TYPE_URI;
/// `witness/session/submit/0.1`.
pub const WITNESS_SESSION_SUBMIT_V0_1: &str = <session::submit::v0_1::Payload as Payload>::TYPE_URI;

/// Every type a witness identity serves — the one table routing and the
/// discovery answer both read, so discovery cannot list a task nobody routes.
pub const SERVED: &[&str] = &[DISCOVERY_V0_1, DISCOVERY_V0_3];

/// The witness role's own tasks, which P2 serves. Refused until then, and not
/// in [`SERVED`]; see the module docs.
pub const NOT_YET_SERVED: &[&str] = &[WITNESS_SESSION_V0_1, WITNESS_SESSION_SUBMIT_V0_1];

/// One witness identity, as the dispatcher needs it: who it is and the key it
/// signs with.
pub struct IdentityContext {
    name: String,
    did: String,
    signing_key: HolderKey,
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
        })
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
}

/// Answer one inbound document addressed to `identity`, from the
/// transport-proven `sender`.
pub async fn answer(
    identity: &IdentityContext,
    sender: &str,
    document: &[u8],
    resolver: &TrustTaskVmResolver,
    now: DateTime<Utc>,
) -> Outcome {
    let unsigned = match evaluate(identity, sender, document, resolver, now).await {
        Ok(reply) => reply,
        Err(reason) => return Outcome::Drop(reason),
    };
    match sign(identity, unsigned).await {
        Ok(signed) => Outcome::Reply(signed),
        Err(e) => {
            tracing::error!(
                identity = %identity.name,
                error = %e,
                "could not sign a reply; sending nothing rather than an unsigned answer"
            );
            Outcome::Drop(DropReason::SigningFailed)
        }
    }
}

/// The §7.2 pipeline, ending in an unsigned reply or a reason to send none.
async fn evaluate(
    identity: &IdentityContext,
    sender: &str,
    document: &[u8],
    resolver: &TrustTaskVmResolver,
    now: DateTime<Utc>,
) -> Result<Value, DropReason> {
    // 1. Classify, on the JSON as received.
    let received: Value = serde_json::from_slice(document).map_err(|_| DropReason::NotJson)?;
    if !vta_sdk::inbound::classify(&received).may_answer() {
        return Err(DropReason::Error);
    }
    if vta_sdk::inbound::names_a_reply(&received) {
        return Err(DropReason::UnclaimedReply);
    }

    // 2. Parse.
    let doc: TrustTask<Value> =
        serde_json::from_value(received.clone()).map_err(|_| DropReason::NotATrustTask)?;

    let refuse = |payload: ErrorPayload| Ok(refusal(&doc, identity, sender, payload, now));
    let reject = |reason: RejectReason| refuse(reason.into());

    // 3. Freshness — the window every VTI node applies, `issuedAt` required.
    let policy = VTI_ACCEPTANCE_WINDOW
        .freshness_policy()
        .requiring_issued_at();
    if let Err(reason) = doc.validate_freshness(now, &policy) {
        return reject(reason);
    }

    // 4. Expiry, and `recipient` = this identity.
    if let Err(reason) = doc.validate_basic(now, &identity.did) {
        return reject(reason);
    }

    // 5. In-band parties against what the transport proved.
    let transport = WitnessTransport {
        sender,
        recipient: &identity.did,
    };
    if let Err(mismatch) = transport.resolve_parties(&doc) {
        return reject(RejectReason::IdentityMismatch(mismatch));
    }

    // 6. Routing, before any verification work.
    let type_uri = doc.type_uri.to_string();
    if !SERVED.contains(&type_uri.as_str()) {
        return refuse(unserved(&type_uri));
    }

    // 7. What the task's own specification declares.
    if let Some(spec) = trust_tasks_rs::schema_index::spec_policy_for(&type_uri)
        && let Err(reason) = spec.enforce(&doc)
    {
        return reject(reason);
    }

    // 8. The proof, over the document as received, by the issuer.
    if doc.proof.is_some() {
        match verify_trust_task_proof_value(&received, resolver).await {
            Ok(signer) if doc.issuer.as_deref() == Some(signer.as_str()) => {}
            Ok(_) => {
                return reject(RejectReason::ProofInvalid {
                    reason: "the proof's verificationMethod does not belong to the document's \
                             issuer (SPEC §4.7)"
                        .to_string(),
                });
            }
            Err(e) => {
                return reject(RejectReason::ProofInvalid {
                    reason: e.to_string(),
                });
            }
        }
    }

    // Dispatch.
    match type_uri.as_str() {
        DISCOVERY_V0_3 => {
            if let Err(e) = v0_3::Payload::validate_value(&doc.payload) {
                return reject(malformed(format!("payload: {e}")));
            }
            match serde_json::from_value::<v0_3::Payload>(doc.payload.clone()) {
                Ok(query) => Ok(response(
                    &doc,
                    identity,
                    sender,
                    discovery::respond_v0_3(SERVED.iter().copied(), &query),
                    now,
                )),
                Err(e) => reject(malformed(format!("payload: {e}"))),
            }
        }
        DISCOVERY_V0_1 => {
            if let Err(e) = v0_1::Payload::validate_value(&doc.payload) {
                return reject(malformed(format!("payload: {e}")));
            }
            match serde_json::from_value::<v0_1::Payload>(doc.payload.clone()) {
                Ok(query) => Ok(response(
                    &doc,
                    identity,
                    sender,
                    discovery::respond_v0_1(SERVED.iter().copied(), &query),
                    now,
                )),
                Err(e) => reject(malformed(format!("payload: {e}"))),
            }
        }
        // `SERVED` and these arms are one list; a URI in one and not the
        // other is a bug this keeps loud rather than silently unanswered.
        other => refuse(unserved(other)),
    }
}

/// The refusal for a type this identity does not serve.
fn unserved(type_uri: &str) -> ErrorPayload {
    if NOT_YET_SERVED.contains(&type_uri) {
        return ErrorPayload::new(StandardCode::UnsupportedType).with_message(format!(
            "{type_uri} is not served yet: witnessing is not enabled in this release of \
             vti-witness, which answers only trust-task-discovery. It is not listed in this \
             witness's trust-task-discovery answer for the same reason."
        ));
    }
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
        .into()
    } else {
        RejectReason::UnsupportedType {
            type_uri: type_uri.to_string(),
        }
        .into()
    }
}

fn malformed(reason: String) -> RejectReason {
    RejectReason::MalformedRequest { reason }
}

/// A `#response` from `identity` to `sender`.
fn response<R: Serialize>(
    doc: &TrustTask<Value>,
    identity: &IdentityContext,
    sender: &str,
    payload: R,
    now: DateTime<Utc>,
) -> Value {
    let payload = serde_json::to_value(payload).unwrap_or(Value::Null);
    let mut reply = doc.respond_with(new_id(), payload);
    reply.issuer = Some(identity.did.clone());
    reply.recipient = Some(sender.to_string());
    reply.issued_at = Some(now);
    serde_json::to_value(reply).unwrap_or(Value::Null)
}

/// A `trust-task-error` from `identity` to `sender`.
fn refusal(
    doc: &TrustTask<Value>,
    identity: &IdentityContext,
    sender: &str,
    payload: ErrorPayload,
    now: DateTime<Utc>,
) -> Value {
    let mut reply = doc.reject_with_recipient(new_id(), payload, Some(sender.to_string()));
    reply.issuer = Some(identity.did.clone());
    reply.issued_at = Some(now);
    serde_json::to_value(reply).unwrap_or(Value::Null)
}

fn new_id() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
}

/// Sign `reply` with the identity's own key.
async fn sign(identity: &IdentityContext, reply: Value) -> anyhow::Result<Value> {
    let mut doc: TrustTask<Value> = serde_json::from_value(reply)?;
    if doc.issuer.as_deref() != Some(identity.did.as_str()) {
        anyhow::bail!("refusing to sign a reply whose issuer is not this identity");
    }
    sign_in_place_with(&mut doc, &identity.signing_key).await?;
    Ok(serde_json::to_value(doc)?)
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
