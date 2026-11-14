//! The document **as received**, for verifying its proof (VTI-45).
//!
//! A Data Integrity proof covers the JSON its producer signed. A handler holds a
//! `TrustTask<Value>`, whose timestamps `trust-tasks-rs` parsed as
//! `DateTime<Utc>` and writes back in its own spelling, whose `null` optional
//! members are gone, and whose proof lost any member the framework type does
//! not model. Verifying that re-serialisation refuses correctly signed
//! documents — `2026-09-25T12:37:33.000Z`, the spelling JavaScript's
//! `toISOString()` gives every whole second, is one of them.
//!
//! So the spine records the received JSON for the duration of a dispatch, and
//! the handlers that check a proof themselves (the step-up gate, task-consent
//! decisions, the attestation mnemonic export) verify it through
//! [`verify_trust_task_proof`] / [`verify_approval_proof`] here. A task-local
//! rather than a parameter for the reason `transport` and `wire_v0_2` are: the
//! handler signature is uniform across ~200 tasks and three of them read it.
//!
//! The recorded JSON is used only for the document it is: it must parse to a
//! `TrustTask<Value>` equal to the one being verified. Anything else — a
//! document a handler built or extracted itself, a down-converted 0.2 request,
//! a direct handler call in a test — is verified in its typed form, as before.
//! That fallback can only refuse more than the received form, never accept
//! more: it verifies the same signature over bytes that differ from the signed
//! ones only where re-serialisation rewrote them.

use std::sync::Arc;

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_common::auth::{DiProofError, TrustTaskVmResolver};

/// What a dispatch records about the document it is running.
pub(crate) struct Received {
    /// The JSON as it arrived.
    value: Arc<Value>,
    /// Its parse, compared against the document a handler verifies. Parsed
    /// once here rather than at every verification (#2624).
    parsed: Option<TrustTask<Value>>,
    /// The signer its proof already verified as, when the transport's sender
    /// binding verified it ([`VerifiedDocument`]).
    proof: Option<VerifiedSigner>,
}

tokio::task_local! {
    static RECEIVED: Arc<Received>;
}

/// The DID a received document's proof verifies as — the raw result of
/// `verify_trust_task_proof_value` over that document as received, with the
/// node's own resolver. Constructible only by running that verification
/// ([`verify_received`]), so holding one is having verified.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedSigner(String);

impl VerifiedSigner {
    /// The signer as the verification reported it (it may carry a fragment).
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Verify `received`'s proof as received.
pub(crate) async fn verify_received(
    received: &Value,
    resolver: &TrustTaskVmResolver,
) -> Result<VerifiedSigner, DiProofError> {
    vti_common::auth::verify_trust_task_proof_value(received, resolver)
        .await
        .map(VerifiedSigner)
}

/// A document bound to its transport-proven sender: parsed once from the bytes
/// received, and its proof — when it carries one — verified once
/// (`trust_tasks::bind_document_to_sender`). The spine takes this rather than
/// the bytes, so the proof is not verified again for the same document
/// (#2624; the workspace's typestate rule for verified wire forms).
pub(crate) struct VerifiedDocument {
    received: Arc<Value>,
    doc: TrustTask<Value>,
    proof: Option<VerifiedSigner>,
}

impl VerifiedDocument {
    /// Pair `received` — and `doc`, its parse — with the verification already
    /// run over it. `proof` is `None` only for a document that carries no
    /// proof. Only the sender binding constructs one.
    pub(crate) fn new(
        received: Value,
        doc: TrustTask<Value>,
        proof: Option<VerifiedSigner>,
    ) -> Self {
        Self {
            received: Arc::new(received),
            doc,
            proof,
        }
    }

    /// The typed document.
    pub(crate) fn doc(&self) -> &TrustTask<Value> {
        &self.doc
    }

    /// The verified signer, when the document carries a proof.
    #[cfg(test)]
    pub(crate) fn signer(&self) -> Option<&VerifiedSigner> {
        self.proof.as_ref()
    }

    /// Its parts: the JSON as received, the typed document, the verification.
    pub(crate) fn into_parts(self) -> (Arc<Value>, TrustTask<Value>, Option<VerifiedSigner>) {
        (self.received, self.doc, self.proof)
    }
}

/// Run `f` with `received` — the inbound document parsed from its wire bytes —
/// recorded for its duration.
///
/// A plain function returning tokio's future, not an `async fn` around it. An
/// `async fn` wrapper moves `f` — the whole dispatch future — through a
/// temporary in its own poll frame on first poll, and in a debug build that
/// frame stays live under every handler: about 64 KiB, enough to put
/// `contexts/create` past the VTI-08 stack budget.
#[cfg(test)]
pub(crate) fn scope<F>(
    received: Arc<Value>,
    f: F,
) -> tokio::task::futures::TaskLocalFuture<Arc<Received>, F>
where
    F: std::future::Future,
{
    let parsed = <TrustTask<Value> as serde::Deserialize>::deserialize(&*received).ok();
    scope_parsed(received, parsed, None, f)
}

/// [`scope`] with the parse already made and, for a [`VerifiedDocument`], the
/// signer its proof verified as. `parsed` must be the parse of `received`.
pub(crate) fn scope_parsed<F>(
    received: Arc<Value>,
    parsed: Option<TrustTask<Value>>,
    proof: Option<VerifiedSigner>,
    f: F,
) -> tokio::task::futures::TaskLocalFuture<Arc<Received>, F>
where
    F: std::future::Future,
{
    RECEIVED.scope(
        Arc::new(Received {
            value: received,
            parsed,
            proof,
        }),
        f,
    )
}

/// The recorded document, when it is `doc` as received.
fn received_form_of(doc: &TrustTask<Value>) -> Option<Arc<Received>> {
    let received = RECEIVED.try_with(Arc::clone).ok()?;
    (received.parsed.as_ref()? == doc).then_some(received)
}

/// `doc` as received when this dispatch recorded it; its typed form re-serialised otherwise
/// (a direct handler call in a test). A handler that keeps a document whole — a held
/// notification, so a client can verify it later (VTI-NTF-050) — keeps this.
pub(crate) fn document_as_received(doc: &TrustTask<Value>) -> Value {
    match received_form_of(doc) {
        Some(received) => (*received.value).clone(),
        None => serde_json::to_value(doc).unwrap_or(Value::Null),
    }
}

/// Verify `doc`'s proof over the JSON it arrived as, when this dispatch
/// recorded it; over its typed form otherwise. See the module docs.
///
/// When the transport's sender binding already verified this very document
/// (a [`VerifiedDocument`] dispatch), that result is returned rather than
/// verifying it again (#2624): the same function over the same JSON with the
/// same resolver — every caller passes the node's `trust_task_vm_resolver`.
pub(crate) async fn verify_trust_task_proof(
    doc: &TrustTask<Value>,
    resolver: &TrustTaskVmResolver,
) -> Result<String, DiProofError> {
    match received_form_of(doc) {
        Some(received) => match &received.proof {
            Some(signer) => Ok(signer.0.clone()),
            None => {
                vti_common::auth::verify_trust_task_proof_value(&received.value, resolver).await
            }
        },
        None => vti_common::auth::verify_trust_task_proof_with(doc, resolver).await,
    }
}

/// [`verify_trust_task_proof`] for a human approver's own decision: the proof
/// must be made for `assertionMethod`.
pub(crate) async fn verify_approval_proof(
    doc: &TrustTask<Value>,
    resolver: &TrustTaskVmResolver,
) -> Result<String, DiProofError> {
    match received_form_of(doc) {
        Some(received) => {
            vti_common::auth::verify_approval_proof_value(&received.value, resolver).await
        }
        None => vti_common::auth::verify_approval_proof_with(doc, resolver).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn javascript_decision() -> Value {
        let now = crate::test_support::javascript_whole_second_now();
        let mut doc = json!({
            "id": "urn:uuid:45454545-4545-4545-8545-000000000001",
            "type": "https://trusttasks.org/spec/task-consent/decision/0.2",
            "issuer": crate::test_support::test_admin_did().0,
            "recipient": "did:key:z6MkVta",
            "issuedAt": now,
            "threadId": null,
            "payload": { "decision": "approve" },
        });
        crate::test_support::sign_received_as(
            crate::test_support::TEST_ADMIN_SEED[0],
            "assertionMethod",
            &now,
            &mut doc,
        );
        doc
    }

    /// VTI-45: inside a dispatch, a handler's own proof check verifies the
    /// document as received — so a `.000Z` decision verifies — while outside
    /// one it falls back to the typed form, which this document breaks.
    #[tokio::test]
    async fn vti_45_a_handler_verifies_the_recorded_document_as_received() {
        let received = javascript_decision();
        let doc: TrustTask<Value> = serde_json::from_value(received.clone()).unwrap();
        let resolver = TrustTaskVmResolver::did_key_only();
        let signer = crate::test_support::test_admin_did().0;

        let inside = scope(Arc::new(received.clone()), async {
            (
                verify_approval_proof(&doc, &resolver).await,
                verify_trust_task_proof(&doc, &resolver).await,
            )
        })
        .await;
        assert_eq!(inside.0.as_deref().ok(), Some(signer.as_str()));
        assert_eq!(inside.1.as_deref().ok(), Some(signer.as_str()));

        assert!(verify_approval_proof(&doc, &resolver).await.is_err());
    }

    /// The recorded document is used only for the document it is. A different
    /// document under the same `id` is verified in its own (typed) form, so the
    /// recorded proof cannot vouch for it.
    #[tokio::test]
    async fn vti_45_the_recorded_document_never_vouches_for_another() {
        let received = javascript_decision();
        let mut other: TrustTask<Value> = serde_json::from_value(received.clone()).unwrap();
        other.payload = json!({ "decision": "deny" });
        let resolver = TrustTaskVmResolver::did_key_only();

        let result = scope(Arc::new(received), async {
            verify_approval_proof(&other, &resolver).await
        })
        .await;
        assert!(
            matches!(result, Err(DiProofError::VerifyFailed(_))),
            "{result:?}"
        );
    }

    /// Purpose binding survives: an `authentication` proof is not an approval,
    /// verified as received or not.
    #[tokio::test]
    async fn vti_45_an_approval_still_needs_an_assertion_proof() {
        let now = crate::test_support::javascript_whole_second_now();
        let mut received = javascript_decision();
        crate::test_support::sign_received_as(
            crate::test_support::TEST_ADMIN_SEED[0],
            "authentication",
            &now,
            &mut received,
        );
        let doc: TrustTask<Value> = serde_json::from_value(received.clone()).unwrap();
        let resolver = TrustTaskVmResolver::did_key_only();
        let result = scope(Arc::new(received), async {
            verify_approval_proof(&doc, &resolver).await
        })
        .await;
        assert!(
            matches!(result, Err(DiProofError::WrongPurpose { .. })),
            "{result:?}"
        );
    }
}
