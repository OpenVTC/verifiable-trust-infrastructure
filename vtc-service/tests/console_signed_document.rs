//! A document signed by the admin console verifies against this service's own
//! verifier (#1684).
//!
//! The console's own vitest suite proves its signer agrees with a reader of
//! its output, which would remain true if both halves shared a mistake — an
//! inverted hash order, `proof` left in the canonicalised document, a
//! `proofValue` that made it into the hashed proof config. Each of those
//! yields a signature that verifies nowhere, and only the other stack can say
//! so.
//!
//! `tests/fixtures/console-signed-document.json` is a real document produced
//! by `admin-ui/src/lib/console-key.ts`. Regenerate it with:
//!
//! ```text
//! cd vtc-service/admin-ui && npx vite-node scripts/write-rust-fixture.ts
//! ```
//!
//! The verifier here is the one `POST /v1/trust-tasks` reaches:
//! `vtc-service/src/trust_tasks/helpers.rs::verify_trust_task_proof` is an
//! adapter over `vta_sdk::trust_task_proof::verify_trust_task_proof`, the
//! `did:key`-only form, which is what a console key always is. No network, no
//! `AppState`, no fixture of ours on the signing side.

use serde_json::Value;
use trust_tasks_rs::TrustTask;

const FIXTURE: &str = include_str!("fixtures/console-signed-document.json");

fn fixture() -> TrustTask<Value> {
    serde_json::from_str(FIXTURE).expect("the console's document parses as a Trust Task")
}

/// VTI-OPS-020: the producer signs the document it sends, and the consumer can
/// check it.
#[tokio::test]
async fn a_document_signed_by_the_admin_console_verifies() {
    let doc = fixture();
    let signer = vta_sdk::trust_task_proof::verify_trust_task_proof(&doc)
        .await
        .expect("the console's eddsa-jcs-2022 proof verifies");

    // SPEC §4.7 — the binding the dispatch spine makes after verifying. The
    // console issues from the console key's own DID precisely so this holds;
    // issuing as the operator's admin DID would fail here, which is why the
    // delegation is resolved from the *signer* rather than carried in-band.
    assert_eq!(
        Some(signer.as_str()),
        doc.issuer.as_deref(),
        "the proven signer must be the document's issuer"
    );
    assert!(
        signer.starts_with("did:key:z6Mk"),
        "a console key is an Ed25519 did:key; got {signer}"
    );
}

/// The proof covers the document, so a changed payload must not still verify.
/// Worth asserting because a canonicalisation that silently dropped a member
/// would pass the test above and fail here.
#[tokio::test]
async fn tampering_with_the_payload_breaks_the_proof() {
    let mut doc = fixture();
    doc.payload = serde_json::json!({ "did": "did:key:z6MkSomebodyElse" });

    assert!(
        vta_sdk::trust_task_proof::verify_trust_task_proof(&doc)
            .await
            .is_err(),
        "a document whose payload was swapped must not verify"
    );
}

/// And the envelope too — `recipient` is the audience binding, so a document
/// re-addressed to another community must not carry its proof with it.
#[tokio::test]
async fn re_addressing_the_document_breaks_the_proof() {
    let mut doc = fixture();
    doc.recipient = Some("did:webvh:QmOther:elsewhere.example:vtc".to_string());

    assert!(
        vta_sdk::trust_task_proof::verify_trust_task_proof(&doc)
            .await
            .is_err(),
        "a document re-addressed to another recipient must not verify"
    );
}
