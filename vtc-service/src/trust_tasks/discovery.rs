//! `trust-task-discovery/0.3` — which Trust Tasks this VTC serves, and the
//! acceptance window it applies to them (VTI-TRN-047).
//!
//! The answer is built by
//! [`vti_common::trust_task::discovery::respond_v0_3`], the builder the VTA
//! answers with, so the two node types answer alike. It advertises
//! [`VTI_ACCEPTANCE_WINDOW`](vti_common::trust_task::acceptance::VTI_ACCEPTANCE_WINDOW)
//! at response level — the value [`super::freshness_policy`] applies, so the
//! advertised window cannot be wider than the enforced one.
//!
//! The listed Type URIs are read from the routing table itself — the
//! `DISPATCHED_URIS` arms plus the rooms and `git-ns` dispatchers' own
//! registrations, the same set [`super::unsupported_type_or_version`] names
//! served versions from — so the answer cannot list a task nobody routes.
//!
//! Identified callers only, as on the VTA: a capability list is a fingerprint
//! of the deployment (discovery 0.3, *Privacy considerations*). The version
//! hint an unrouted URI earns already names the served versions of one family;
//! this names them all.

use serde_json::Value;
use trust_tasks_rs::specs::trust_task_discovery::v0_3 as wire;
use trust_tasks_rs::validate::ValidatedPayload;
use trust_tasks_rs::{RejectReason, TrustTask};

use super::helpers::{TrustTaskOutcome, parse_payload, reject_with, success_response};
use super::{DISPATCHED_URIS, JoinAuthCtx, caller_is_identified};

/// `trust-task-discovery/0.3`.
pub(crate) const DISCOVERY_V0_3_TYPE: &str = vti_common::trust_task::discovery::DISCOVERY_V0_3;

/// Every Type URI this dispatcher routes.
pub(super) fn served_uris() -> Vec<&'static str> {
    DISPATCHED_URIS
        .iter()
        .copied()
        .chain(crate::rooms::handlers::served_uris())
        .chain(crate::git_ns::tasks::served_uris())
        .collect()
}

/// Answer a discovery 0.3 query.
pub(super) fn handle(ctx: &JoinAuthCtx, doc: TrustTask<Value>) -> TrustTaskOutcome {
    if !caller_is_identified(ctx) {
        return reject_with(
            &doc,
            RejectReason::PermissionDenied {
                reason: "this community lists the Trust Tasks it serves to callers it can \
                         identify — ask over DIDComm or TSP, or with a signed Trust Task document"
                    .to_string(),
            },
        );
    }
    if let Err(e) = wire::Payload::validate_value(&doc.payload) {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: format!("payload: {e}"),
            },
        );
    }
    let query: wire::Payload = match parse_payload(&doc) {
        Ok(q) => q,
        Err(reject) => return reject,
    };
    success_response(
        &doc,
        vti_common::trust_task::discovery::respond_v0_3(served_uris(), &query),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::join::JoinTransport;
    use vti_common::trust_task::acceptance::AcceptanceWindow;

    fn query(payload: Value) -> TrustTask<Value> {
        let mut doc = TrustTask::new(
            "urn:uuid:00000000-0000-4000-8000-000000000001".to_string(),
            DISCOVERY_V0_3_TYPE.parse().unwrap(),
            payload,
        );
        doc.issuer = Some("did:example:member".into());
        doc.recipient = Some("did:example:vtc".into());
        doc
    }

    fn identified() -> JoinAuthCtx {
        JoinAuthCtx {
            transport: JoinTransport::Rest,
            sender_did: None,
            verified_signer: Some("did:example:member".into()),
        }
    }

    fn answer(outcome: TrustTaskOutcome) -> Value {
        serde_json::from_slice(&outcome.body).expect("a JSON document")
    }

    /// What this VTC advertises is what its spine applies — neither wider
    /// (VTI-TRN-047's MUST NOT) nor narrower. Read back out of the answer the
    /// handler sends, and compared with `freshness_policy`, which the spine
    /// refuses documents with.
    #[test]
    fn vti_trn_047_the_advertised_window_is_the_applied_window() {
        let body = answer(handle(&identified(), query(serde_json::json!({}))));
        assert_eq!(
            body["type"],
            format!("{DISCOVERY_V0_3_TYPE}#response"),
            "{body}"
        );
        let window: wire::AcceptanceWindow =
            serde_json::from_value(body["payload"]["acceptanceWindow"].clone())
                .unwrap_or_else(|e| panic!("VTI-TRN-047: a response-level window ({e}): {body}"));
        let advertised = AcceptanceWindow::from_advertised(&window);
        let applied = super::super::freshness_policy();
        assert_eq!(Some(advertised.max_age), applied.max_age);
        assert_eq!(advertised.clock_skew, applied.skew);
    }

    /// The same property measured the way a producer meets it: a document at
    /// the advertised edge is accepted by the spine's policy, and one a second
    /// past it is refused.
    #[test]
    fn vti_trn_047_a_document_at_the_advertised_edge_is_accepted_and_one_past_it_refused() {
        let body = answer(handle(&identified(), query(serde_json::json!({}))));
        let window: wire::AcceptanceWindow =
            serde_json::from_value(body["payload"]["acceptanceWindow"].clone()).expect("window");
        let w = AcceptanceWindow::from_advertised(&window);
        let policy = super::super::freshness_policy();
        let now = chrono::SubsecRound::trunc_subsecs(chrono::Utc::now(), 0);
        let edge = now - w.max_age - w.clock_skew;
        let mut doc = query(serde_json::json!({}));
        doc.issued_at = Some(edge);
        assert!(doc.validate_freshness(now, &policy).is_ok());
        doc.issued_at = Some(edge - chrono::TimeDelta::seconds(1));
        assert!(doc.validate_freshness(now, &policy).is_err());
    }

    /// The answer is the routing table: it lists discovery itself, a task from
    /// each dispatcher, and every URI the table routes — and it is valid
    /// against the published 0.3 response schema.
    #[test]
    fn the_answer_lists_what_the_dispatcher_routes() {
        let body = answer(handle(&identified(), query(serde_json::json!({}))));
        wire::Response::validate_value(&body["payload"]).expect("schema-valid 0.3 response");
        let listed: Vec<&str> = body["payload"]["supportedTypes"]
            .as_array()
            .expect("an array")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for uri in served_uris() {
            assert!(listed.contains(&uri), "{uri} is routed but not listed");
        }
        assert!(listed.contains(&DISCOVERY_V0_3_TYPE));
        assert!(
            crate::rooms::handlers::served_uris()
                .iter()
                .any(|u| listed.contains(u))
        );
    }

    /// A caller the VTC cannot identify is refused, before anything is listed.
    #[test]
    fn an_unidentified_caller_is_refused() {
        let ctx = JoinAuthCtx {
            transport: JoinTransport::Rest,
            sender_did: None,
            verified_signer: None,
        };
        let body = answer(handle(&ctx, query(serde_json::json!({}))));
        assert_eq!(body["payload"]["code"], "permissionDenied", "{body}");
    }

    /// The pattern bound (16) is the schema's, and is enforced.
    #[test]
    fn a_query_over_the_pattern_bound_is_malformed() {
        let patterns: Vec<String> = (0..17).map(|i| format!("p{i}/*")).collect();
        let body = answer(handle(
            &identified(),
            query(serde_json::json!({ "patterns": patterns })),
        ));
        assert_eq!(body["payload"]["code"], "malformedRequest", "{body}");
    }
}
