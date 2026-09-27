//! The proof-purpose classifier, pinned from outside the crate.
//!
//! These cases live here rather than beside `purpose_for_document_type`
//! because most of them are deliberately *wrong* Type URIs — lookalike
//! authorities, case tricks, nested slugs. The binding census in
//! `vtc-service/tests/trust_task_manifest.rs` reads every
//! `trusttasks.org/spec/` literal under `vta-sdk/src` as a URI the code binds,
//! and a fixture that exists to be refused is not a binding.
#![cfg(feature = "proof-verify")]

use vta_sdk::trust_task_proof::{ProofPurpose, purpose_for_document_type};

fn purpose_of(uri: &str) -> ProofPurpose {
    purpose_for_document_type(&uri.parse().expect("type URI"))
}

/// Case tricks and a stray fragment do not parse as a Type URI at all, so
/// the vault refuses them before choosing any purpose.
#[test]
fn a_type_that_is_not_a_type_uri_is_not_classified() {
    for uri in [
        "HTTPS://trusttasks.org/spec/task-consent/decision/0.1",
        "https://trusttasks.org/spec/Task-Consent/decision/0.1",
        "https://trusttasks.org/spec/task-consent/decision/0.1#Response",
        "https://trusttasks.org/spec/task-consent/decision/0.1#attestation",
        "http://trusttasks.org/spec/task-consent/decision/0.1",
    ] {
        assert!(uri.parse::<trust_tasks_rs::TypeUri>().is_err(), "{uri}");
    }
}

#[test]
fn approver_decisions_are_signed_for_assertion_method() {
    for uri in [
        "https://trusttasks.org/spec/auth/step-up/approve-response/0.5",
        "https://trusttasks.org/spec/auth/step-up/approve-response/0.3#request",
        "https://trusttasks.org/spec/task-consent/decision/0.1",
        "https://trusttasks.org/spec/confirm/response/0.1",
    ] {
        assert_eq!(purpose_of(uri), ProofPurpose::AssertionMethod, "{uri}");
    }
}

#[test]
fn operational_documents_are_signed_for_authentication() {
    for uri in [
        "https://trusttasks.org/spec/acl/grant/0.1",
        "https://trusttasks.org/spec/auth/step-up/start/0.1",
        "https://trusttasks.org/spec/auth/step-up/approve-request/0.3",
        "https://trusttasks.org/spec/did-management/did/list/0.2",
        // The executor's reply to a decision is its own operational message.
        "https://trusttasks.org/spec/task-consent/decision/0.1#response",
        // A private registry reusing a slug does not inherit its meaning.
        "https://registry.example/spec/task-consent/decision/0.1",
        "https://trusttasks.org/prefix/spec/confirm/response/0.1",
        // Lookalike authorities are private registries, not the registry.
        "https://trusttasks.org.example/spec/task-consent/decision/0.1",
        "https://TrustTasks.org/spec/task-consent/decision/0.1",
        "https://trusttasks.org:443/spec/task-consent/decision/0.1",
        "https://user@trusttasks.org/spec/task-consent/decision/0.1",
        // A slug that only ends in, or nests, an attestation slug.
        "https://trusttasks.org/spec/x/task-consent/decision/0.1",
        "https://trusttasks.org/spec/task-consent/decision-extra/0.1",
    ] {
        assert_eq!(purpose_of(uri), ProofPurpose::Authentication, "{uri}");
    }
}
