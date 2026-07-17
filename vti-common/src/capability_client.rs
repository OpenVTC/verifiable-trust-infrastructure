//! Client-side primitives for capability Trust Tasks (`governance/capability/*`,
//! `git-trust/*`): document building, Data-Integrity signing, DIDComm envelope
//! parsing, and reply classification.
//!
//! Transport-free by design — each consumer (vtc-service hooks, the openvtc
//! TUI) already owns its send plumbing; this module owns the wire *documents*
//! so the two sides cannot drift. Writes carry an `eddsa-jcs-2022` proof
//! signed by the caller's authority key, bound to the document `issuer` (the
//! registry enforces the binding plus its admin ACL).

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use uuid::Uuid;

/// The `trust-tasks-didcomm` binding envelope type (what the registry's
/// DIDComm Trust Task handler listens for). Kept in sync with
/// `trust_tasks_didcomm::ENVELOPE_TYPE`.
pub const TRUST_TASK_ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

/// `git-trust/*` type URIs.
pub const GIT_TRUST_GRANT_TYPE: &str = "https://trusttasks.org/spec/git-trust/grant/0.1";
pub const GIT_TRUST_REVOKE_TYPE: &str = "https://trusttasks.org/spec/git-trust/revoke/0.1";

/// Errors from document construction/signing.
#[derive(Debug, thiserror::Error)]
pub enum CapabilityClientError {
    #[error("capability document error: {0}")]
    Document(String),
    #[error("capability document signing failed: {0}")]
    Signing(String),
}

/// Build a capability Trust Task addressed `issuer` → `recipient`.
pub fn build_document(
    issuer_did: &str,
    recipient_did: &str,
    type_uri: &str,
    payload: Value,
) -> Result<TrustTask<Value>, CapabilityClientError> {
    let type_uri = type_uri
        .parse()
        .map_err(|e| CapabilityClientError::Document(format!("invalid type URI: {e}")))?;
    let mut doc = TrustTask::new(format!("urn:uuid:{}", Uuid::new_v4()), type_uri, payload);
    doc.issuer = Some(issuer_did.to_string());
    doc.recipient = Some(recipient_did.to_string());
    doc.issued_at = Some(chrono::Utc::now());
    Ok(doc)
}

/// Build a `git-trust/grant` document: grant `subject` commit-signing trust
/// for `resource` (an org or `org/repo` slug).
pub fn build_git_trust_grant(
    authority_did: &str,
    registry_did: &str,
    subject_did: &str,
    resource: &str,
) -> Result<TrustTask<Value>, CapabilityClientError> {
    build_document(
        authority_did,
        registry_did,
        GIT_TRUST_GRANT_TYPE,
        serde_json::json!({ "subject": subject_did, "resource": resource }),
    )
}

/// Build a `git-trust/revoke` document.
pub fn build_git_trust_revoke(
    authority_did: &str,
    registry_did: &str,
    subject_did: &str,
    resource: &str,
    reason: Option<&str>,
) -> Result<TrustTask<Value>, CapabilityClientError> {
    let mut payload = serde_json::json!({ "subject": subject_did, "resource": resource });
    if let Some(reason) = reason {
        payload["reason"] = serde_json::json!(reason);
    }
    build_document(authority_did, registry_did, GIT_TRUST_REVOKE_TYPE, payload)
}

/// Attach an `eddsa-jcs-2022` Data-Integrity proof over `doc` minus its
/// `proof` member — the exact canonical form the registry's verifier checks.
/// The secret's key id becomes the verification method and must belong to
/// the document `issuer`.
pub async fn sign_document(
    doc: &mut TrustTask<Value>,
    signing_secret: &Secret,
) -> Result<(), CapabilityClientError> {
    let mut doc_value = serde_json::to_value(&*doc)
        .map_err(|e| CapabilityClientError::Document(format!("serialise document: {e}")))?;
    if let Some(obj) = doc_value.as_object_mut() {
        obj.remove("proof");
    }
    let proof = DataIntegrityProof::sign(&doc_value, signing_secret, SignOptions::default())
        .await
        .map_err(|e| CapabilityClientError::Signing(e.to_string()))?;
    let proof_value = serde_json::to_value(&proof)
        .map_err(|e| CapabilityClientError::Signing(format!("serialise proof: {e}")))?;
    doc.proof = Some(
        serde_json::from_value(proof_value)
            .map_err(|e| CapabilityClientError::Signing(format!("convert proof: {e}")))?,
    );
    Ok(())
}

/// Parse a DIDComm envelope body into `(threadId, document)`. `None` when
/// the body is not a threaded Trust Task document.
pub fn parse_envelope_document(body: &Value) -> Option<(String, TrustTask<Value>)> {
    let doc: TrustTask<Value> = serde_json::from_value(body.clone()).ok()?;
    let thid = doc.thread_id.clone()?;
    Some((thid, doc))
}

/// The hook-facing classification of a capability write reply.
///
/// `IdempotentSuccess` is the load-bearing variant: redelivered jobs make the
/// registry answer `already_granted` (grant) or `not_granted` (revoke) — the
/// desired end state already holds, so the job is done, not failed.
#[derive(Debug, Clone, PartialEq)]
pub enum WriteOutcome {
    /// The `#response` document acknowledged the write.
    Success,
    /// The registry rejected the write because the end state already holds.
    IdempotentSuccess,
    /// Any other rejection: the machine-readable trust-task code plus the
    /// human detail. Permanent from the hook's perspective.
    Rejected {
        code: String,
        message: Option<String>,
    },
}

/// Classify the reply to a `git-trust/grant` or `git-trust/revoke` write.
/// `None` when `doc` is neither the matching `#response` nor an error doc —
/// i.e. not a reply to this family at all.
pub fn classify_git_trust_reply(doc: &TrustTask<Value>) -> Option<WriteOutcome> {
    let slug = doc.type_uri.slug();
    if slug == "trust-task-error" {
        let code = doc
            .payload
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let message = doc
            .payload
            .get("message")
            .and_then(Value::as_str)
            .map(str::to_string);
        // The registry encodes the idempotent cases as taskFailed with a
        // documented `already_granted:` / `not_granted:` reason marker (the
        // wire message arrives as "task failed: already_granted: …").
        let reason = message.as_deref().unwrap_or("");
        if code == "taskFailed"
            && (reason.contains("already_granted:") || reason.contains("not_granted:"))
        {
            return Some(WriteOutcome::IdempotentSuccess);
        }
        return Some(WriteOutcome::Rejected { code, message });
    }
    if doc.type_uri.is_response() && matches!(slug, "git-trust/grant" | "git-trust/revoke") {
        return Some(WriteOutcome::Success);
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use trust_tasks_rs::RejectReason;

    #[test]
    fn grant_and_revoke_documents_are_well_formed() {
        let grant = build_git_trust_grant(
            "did:example:authority",
            "did:example:registry",
            "did:example:signer",
            "openvtc",
        )
        .unwrap();
        assert_eq!(grant.issuer.as_deref(), Some("did:example:authority"));
        assert_eq!(grant.recipient.as_deref(), Some("did:example:registry"));
        assert_eq!(grant.type_uri.slug(), "git-trust/grant");
        assert_eq!(grant.payload["subject"], "did:example:signer");

        let revoke = build_git_trust_revoke(
            "did:example:authority",
            "did:example:registry",
            "did:example:signer",
            "openvtc",
            Some("membership ended"),
        )
        .unwrap();
        assert_eq!(revoke.type_uri.slug(), "git-trust/revoke");
        assert_eq!(revoke.payload["reason"], "membership ended");
    }

    fn reserialize(doc: &trust_tasks_rs::ErrorResponse) -> TrustTask<Value> {
        serde_json::from_value(serde_json::to_value(doc).unwrap()).unwrap()
    }

    #[test]
    fn reply_classification_matches_hook_semantics() {
        let grant = build_git_trust_grant("did:a", "did:r", "did:s", "org").unwrap();

        let ok = grant.respond_with(
            "urn:uuid:r".to_string(),
            serde_json::json!({ "subject": "did:s", "resource": "org", "granted": true }),
        );
        assert_eq!(classify_git_trust_reply(&ok), Some(WriteOutcome::Success));

        let already = reserialize(
            &grant.reject_with(
                "urn:uuid:e".to_string(),
                RejectReason::TaskFailed {
                    reason: "already_granted: an active grant exists for this subject and resource"
                        .to_string(),
                    details: None,
                },
            ),
        );
        assert_eq!(
            classify_git_trust_reply(&already),
            Some(WriteOutcome::IdempotentSuccess)
        );

        let denied = reserialize(&grant.reject_with(
            "urn:uuid:e2".to_string(),
            RejectReason::PermissionDenied {
                reason: "not on the admin ACL".to_string(),
            },
        ));
        assert!(matches!(
            classify_git_trust_reply(&denied),
            Some(WriteOutcome::Rejected { .. })
        ));

        let foreign = TrustTask::new(
            "urn:uuid:f".to_string(),
            "https://trusttasks.org/spec/registry/authorization/0.1#response"
                .parse()
                .unwrap(),
            serde_json::json!({}),
        );
        assert_eq!(classify_git_trust_reply(&foreign), None);
    }

    #[test]
    fn envelope_parse_requires_a_thread_id() {
        let grant = build_git_trust_grant("did:a", "did:r", "did:s", "org").unwrap();
        let reply = grant.respond_with("urn:uuid:r".to_string(), serde_json::json!({}));
        let body = serde_json::to_value(&reply).unwrap();
        let (thid, _) = parse_envelope_document(&body).unwrap();
        assert_eq!(thid, grant.id);

        let unthreaded = serde_json::to_value(&grant).unwrap();
        assert!(parse_envelope_document(&unthreaded).is_none());
    }
}
