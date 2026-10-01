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

tokio::task_local! {
    static RECEIVED: Arc<Value>;
}

/// Run `f` with `received` — the inbound document parsed from its wire bytes —
/// recorded for its duration.
pub(crate) async fn scope<F, T>(received: Arc<Value>, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    RECEIVED.scope(received, f).await
}

/// The received JSON, when it is `doc` as received.
fn received_form_of(doc: &TrustTask<Value>) -> Option<Arc<Value>> {
    let received = RECEIVED.try_with(Arc::clone).ok()?;
    let parsed: TrustTask<Value> = serde_json::from_value((*received).clone()).ok()?;
    (&parsed == doc).then_some(received)
}

/// Verify `doc`'s proof over the JSON it arrived as, when this dispatch
/// recorded it; over its typed form otherwise. See the module docs.
pub(crate) async fn verify_trust_task_proof(
    doc: &TrustTask<Value>,
    resolver: &TrustTaskVmResolver,
) -> Result<String, DiProofError> {
    match received_form_of(doc) {
        Some(received) => {
            vti_common::auth::verify_trust_task_proof_value(&received, resolver).await
        }
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
        Some(received) => vti_common::auth::verify_approval_proof_value(&received, resolver).await,
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
            "type": "https://trusttasks.org/spec/task-consent/decision/0.1",
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
