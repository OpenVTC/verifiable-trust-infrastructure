//! Ceremony tasks — the mechanism by which authority is granted, as distinct
//! from the operations that consume it.
//!
//! Three Type URIs carry their **own** authority in the document: a
//! `task-consent/decision` is authorized by the approver's Data-Integrity proof
//! plus membership of the policy-named approver set; a step-up
//! `approve-response` by the approver's proof plus the pending step-up it
//! echoes. In neither case does the submitting peer's standing at this VTA
//! decide anything — the handlers read the proven signer, and
//! [`is_ceremony_task`] is what keeps the PDP from re-gating them (approving a
//! task must not itself require approval).
//!
//! ## Why this module exists
//!
//! The predicate used to be private to `policy_gate`, which meant only *one* of
//! the two gates in front of a handler knew about it. The other — the ACL check
//! every intrinsic-sender transport runs on the authcrypt/TSP sender before
//! dispatch — applied to ceremony tasks like any other, and refused them.
//!
//! That inverts the model. The consent subsystem is explicitly built for an
//! approver that holds no authority to *act*: `task_consent::
//! compute_delegated_contexts` and `policy_gate`'s eligibility count both read
//! "absent from the ACL" as **confers nothing**, never as **cannot speak**.
//! `handle_decision` does not so much as look at its `AuthClaims`. The
//! least-privilege approver the whole `approve_scope` axis exists to serve — a
//! device that can confer a context and act in none — was nonetheless turned
//! away at the door, before any of the code written to accommodate it ran.
//!
//! Worse, it failed *silently*: the transport replies with a `permissionDenied`
//! envelope that an approver wallet has no reason to recognise, so the operator
//! sees an approval that was given, accepted by the human, and then simply
//! never took effect — while the requester re-submits into a pending that will
//! never be granted.
//!
//! So the two gates now share one predicate, and `messaging::auth::
//! auth_for_trust_task_envelope` lets a ceremony task through on a
//! zero-authority claim when — and only when — the ACL turns its sender away.

#[cfg(any(feature = "didcomm", feature = "tsp"))]
use crate::auth::AuthClaims;

/// Does this Type URI name a ceremony task?
///
/// Ceremony tasks carry their own authority (an approver's proof, a step-up
/// approve-response) and must NOT themselves be gated — else approving a task
/// could itself require consent/step-up, ad infinitum.
#[allow(deprecated)]
pub(crate) fn is_ceremony_task(type_uri: &str) -> bool {
    use vta_sdk::trust_tasks as t;
    type_uri == t::TASK_TASK_CONSENT_DECISION_0_1
        || type_uri == t::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_1
        || type_uri == t::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_2
}

/// Could `sender_did` conceivably be an approver for a ceremony of this type?
///
/// A cheap pre-filter, run *before* the carve-out lets an unenrolled sender past
/// the ACL. It answers only "is this sender in the population this ceremony is
/// for", never "is this decision valid" — the handlers still decide that, and
/// nothing here grants anything.
///
/// ## Why it exists
///
/// The carve-out costs the VTA a durable write. A `task-consent/decision` that
/// verifies but cites a digest with no live pending records
/// `consent.decision / denied:no_pending`, and audit retention is time-based,
/// not size-capped — so without a filter a remote party who can reach the
/// mediator could flood the audit log with rows that persist for the retention
/// window. That is not privilege escalation, but it is a new capability, and it
/// is cheap to remove.
///
/// For a consent decision the answer is an in-memory config read: membership of
/// *some* configured approver set. That is the entire population the carve-out
/// serves, so the filter costs nothing in function while shrinking the reachable
/// set from "any DID" to "the DIDs the operator named". The handler still checks
/// the specific set the pending named — this is a floor, not the decision.
///
/// Step-up `approve-response` is unfiltered, deliberately. Its authorized signer
/// is `pending.approver`, recorded when the step-up was minted and **not**
/// required to hold an ACL entry — that is the delegated phone-as-authorizer,
/// and no cheap membership test covers it. It needs no filter either:
/// `handle_approve_response` writes no audit row on `challenge_unknown`,
/// `subject_mismatch` or `approver_unauthorized`, so an unknown sender leaves no
/// durable trace to flood.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
pub(crate) async fn may_attempt_ceremony(
    state: &crate::server::AppState,
    type_uri: &str,
    sender_did: &str,
) -> bool {
    if type_uri != vta_sdk::trust_tasks::TASK_TASK_CONSENT_DECISION_0_1 {
        return true;
    }
    // Row-first, via the one resolver the whole ceremony shares. Reading
    // `config.policy.approver_sets` directly here — as this did — turned an
    // approver added with `pnm approvals approvers add` away at the *transport*
    // gate, before the decision reached a handler at all. A store error is not a
    // membership answer, so it fails closed rather than admitting the sender.
    super::policy_gate::is_named_approver(state, sender_did)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                "could not resolve approver sets for the ceremony transport gate; \
                 refusing this decision"
            );
            false
        })
}

/// Read just the `type` member out of a Trust-Task envelope.
///
/// Deliberately not a full `TrustTask<Value>` parse: this runs *before*
/// authentication, on bytes from a peer we have not yet authorized, and it must
/// answer exactly one question — "is this a ceremony task?" — without taking a
/// position on anything else in the document. A body that doesn't parse, or
/// carries no `type`, yields `None` and is treated as an ordinary task, so a
/// malformed envelope can never talk its way past the ACL.
///
/// The envelope is re-parsed and fully validated by the dispatch spine
/// afterwards; nothing here is trusted beyond routing this one decision.
///
/// Only the intrinsic-sender transports need this — REST authenticates on a JWT
/// the caller had to obtain first, so there is no pre-auth routing decision to
/// make there.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
pub(crate) fn peek_type_uri(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct TypeOnly {
        #[serde(rename = "type")]
        type_uri: String,
    }
    serde_json::from_slice::<TypeOnly>(body)
        .ok()
        .map(|t| t.type_uri)
}

/// Claims for a ceremony task from a sender the ACL does not know.
///
/// Carries the **proven** sender DID — the authcrypt/TSP unpack established it,
/// and the replay-dedup key, the audit trail and `handle_approve_response`'s
/// `issuer == caller` check all read it — over the least-privileged role in the
/// system with no contexts. Per the workspace's act-scope rule, a non-`Admin`
/// role with an empty `allowed_contexts` is authorized *nowhere*, so if a
/// ceremony handler ever does consult its claims it is handed standing to do
/// precisely nothing.
///
/// No session row is created. An unenrolled approver is not a session-holder at
/// this VTA, and minting a session for one would let any DID that can reach the
/// mediator write a row. `session_id` mirrors the DID-keyed convention
/// [`vti_common::auth::session::resolve_did_session`] uses so the value lines up
/// with what an enrolled peer would see, without persisting anything.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
pub(crate) fn ceremony_claims(sender_did: &str) -> AuthClaims {
    AuthClaims {
        did: sender_did.to_string(),
        // `Role::Monitor` is the crate's least-privileged role and its
        // `Default` — infrastructure-only, and with no contexts it reaches
        // nothing.
        role: crate::acl::Role::Monitor,
        allowed_contexts: Vec::new(),
        session_id: sender_did.to_string(),
        // No JWT, hence no access-token expiry — same as every other
        // intrinsic-sender caller. `issued_at` is 0 for the stronger reason
        // that no session row exists at all: there is nothing that was issued.
        access_expires_at: 0,
        issued_at: 0,
        amr: vec!["did".to_string()],
        acr: "aal1".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    use crate::acl::Role;

    #[test]
    fn the_three_ceremony_uris_are_recognised_and_nothing_else_is() {
        use vta_sdk::trust_tasks as t;
        assert!(is_ceremony_task(t::TASK_TASK_CONSENT_DECISION_0_1));
        #[allow(deprecated)]
        {
            assert!(is_ceremony_task(t::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_1));
        }
        assert!(is_ceremony_task(t::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_2));

        // The operations a ceremony authorizes are emphatically not ceremonies.
        assert!(!is_ceremony_task(t::TASK_ACL_GRANT_0_1));
        assert!(!is_ceremony_task(t::TASK_KEYS_REVOKE_0_1));
        assert!(!is_ceremony_task(
            "https://trusttasks.org/spec/vta/webvh/dids/update/1.0"
        ));
        assert!(!is_ceremony_task(""));
    }

    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    #[test]
    fn peek_reads_the_type_and_ignores_the_rest() {
        let body = br#"{"id":"urn:uuid:1","type":"https://example.com/a/0.1",
                        "issuer":"did:key:zA","payload":{"x":1}}"#;
        assert_eq!(
            peek_type_uri(body).as_deref(),
            Some("https://example.com/a/0.1")
        );
    }

    /// A body we cannot read must fall through to the ordinary ACL path, not
    /// past it. This is the only reason the function returns `Option` rather
    /// than defaulting to something.
    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    #[test]
    fn an_unreadable_body_is_not_a_ceremony_task() {
        assert!(peek_type_uri(b"not json").is_none());
        assert!(peek_type_uri(b"{}").is_none());
        assert!(peek_type_uri(br#"{"type":42}"#).is_none());
        assert!(peek_type_uri(b"").is_none());
    }

    /// The claim must confer nothing. If this ever loosens, an unenrolled DID
    /// that can reach the mediator gains standing at the VTA.
    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    #[test]
    fn ceremony_claims_are_authorized_nowhere() {
        let auth = ceremony_claims("did:key:zApprover");
        assert_eq!(auth.did, "did:key:zApprover");
        assert_eq!(auth.role, Role::Monitor);
        assert!(auth.allowed_contexts.is_empty());
        assert!(
            !auth.is_super_admin(),
            "an empty context list must not read as unrestricted for a non-admin role"
        );
        assert!(!auth.has_context_access("default"));
        assert!(!auth.act_scope().is_unrestricted());
        assert_ne!(auth.acr, "aal2", "a ceremony claim is never pre-elevated");
    }
}
