//! `git-ns/namespace/reseat/0.3`, the only reseat version the VTC serves.
//!
//! trust-tasks-rs 0.23 now carries the generated
//! `trust_tasks_rs::specs::git_ns::namespace::reseat::v0_3`; its entry
//! already came out of `UNPUBLISHED_CANONICAL_OK` in
//! `tests/trust_task_manifest.rs`. TODO: replace this hand-written module
//! with that generated one — it is a distinct type from 0.2's, not merely a
//! wrapper, so `ops::namespace_reseat` and its callers need to move onto it
//! too.
//!
//! 0.3 is wire-identical to 0.2, so the payloads are 0.2's generated types
//! under the 0.3 type URI. What 0.3 changes is what the VTC does: step 8
//! queues no namespace-level forge projection, and step 4 refuses a reseat
//! to the administrator who asks (`git-ns:selfGrantNotAllowed`, separation
//! of duties — `git-ns/right/break-glass` is the way to do that).

use serde::{Deserialize, Serialize};
use trust_tasks_rs::specs::git_ns::namespace::reseat::v0_2 as base;

pub use base::error_codes;

/// `git-ns:selfGrantNotAllowed` — 0.3's step 4: the subject is the
/// administrator reseating. 0.2's generated `error_codes` does not declare it.
/// TODO: use the generated `reseat::v0_3::error_codes::SELF_GRANT_NOT_ALLOWED`
/// once this module moves onto the generated 0.3 type.
pub const SELF_GRANT_NOT_ALLOWED: &str = "git-ns:selfGrantNotAllowed";

/// The bare type URI.
pub const TYPE_URI: &str = "https://trusttasks.org/spec/git-ns/namespace/reseat/0.3";

/// The request, as 0.2's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Payload(pub base::Payload);

/// The response, as 0.2's.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Response(pub base::Response);

impl trust_tasks_rs::Payload for Payload {
    const TYPE_URI: &'static str = TYPE_URI;
    const IS_PROOF_REQUIRED: bool = true;
    const IS_ISSUED_AT_REQUIRED: bool = true;
    const IS_RECIPIENT_REQUIRED: bool = true;
    const PAYLOAD_SCHEMA: Option<&'static str> = base::Payload::PAYLOAD_SCHEMA;
}

impl trust_tasks_rs::Payload for Response {
    const TYPE_URI: &'static str =
        "https://trusttasks.org/spec/git-ns/namespace/reseat/0.3#response";
    const IS_PROOF_REQUIRED: bool = true;
    const IS_ISSUED_AT_REQUIRED: bool = true;
    const IS_RECIPIENT_REQUIRED: bool = true;
    const PAYLOAD_SCHEMA: Option<&'static str> = base::Response::PAYLOAD_SCHEMA;
}

impl trust_tasks_rs::RequestPayload for Payload {
    type Response = Response;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_served_as_0_3_with_0_2_s_rules() {
        assert_eq!(<Payload as trust_tasks_rs::Payload>::TYPE_URI, TYPE_URI);
        const { assert!(<Payload as trust_tasks_rs::Payload>::IS_PROOF_REQUIRED) };
        let p: Payload = serde_json::from_value(serde_json::json!({
            "namespace": "ns_1", "subject": "did:key:z6Mkcarol", "statement": "why"
        }))
        .unwrap();
        assert_eq!(p.0.subject.to_string(), "did:key:z6Mkcarol");
        // 0.2's DID Core syntax applies.
        assert!(
            serde_json::from_value::<Payload>(serde_json::json!({
                "namespace": "ns_1", "subject": "did:key:z6Mk#frag", "statement": "why"
            }))
            .is_err()
        );
    }
}
