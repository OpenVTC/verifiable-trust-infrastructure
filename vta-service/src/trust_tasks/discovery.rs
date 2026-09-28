//! Discovery slice. One URI family, one question: **which Trust Tasks does this
//! agent serve?**
//!
//! `spec/trust-task-discovery/0.1` and `/0.3` — the published canonical family
//! from the dtgwg-trust-tasks-tf registry, carried by `trust-tasks-rs`. Any
//! authenticated caller. This is what a client should ask before assuming a
//! task exists. Each version is answered in the version it was asked
//! (discovery 0.3, *Relationship to 0.2 and 0.1*).
//!
//! 0.3 adds the acceptance window this VTA applies to `issuedAt`, at response
//! level (VTI-TRN-047). It is built by
//! [`vti_common::trust_task::discovery::respond_v0_3`] from the same
//! [`VTI_ACCEPTANCE_WINDOW`](vti_common::trust_task::acceptance::VTI_ACCEPTANCE_WINDOW)
//! this VTA's spine applies (`super::freshness_policy`), so the advertised
//! window cannot be wider than the applied one; the tests below pin it.
//!
//! `vta/discovery/capabilities/1.0` and `GET /capabilities` used to live here
//! too. Both are retired (#1039, #1043) — see
//! `vta_sdk::protocols::discovery` for what each of their members turned out to
//! duplicate, and why a task named "capabilities" accumulated them.

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_common::trust_task::discovery;

use crate::auth::AuthClaims;
use crate::server::AppState;

use super::helpers::{parse_payload, success_response};

/// Handler for `spec/trust-task-discovery/0.1` — canonical capability
/// negotiation.
///
/// The answer is **derived from the dispatch table**, so it cannot claim a task
/// this service does not actually route. A hand-maintained list would be a
/// second source of truth, and an overstated discovery response is worse than
/// none: a client believes a task is available and finds out on a live call,
/// which on DIDComm is a 30-second timeout with no explanation.
pub(super) async fn handle_trust_task_discovery(
    _state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use trust_tasks_rs::specs::trust_task_discovery::v0_1 as wire;

    let req: wire::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    success_response(
        &doc,
        discovery::respond_v0_1(super::dispatched_uris(), &req),
    )
}

/// Handler for `spec/trust-task-discovery/0.3` — the 0.1 answer, with the
/// framework release in three parts and this VTA's acceptance window at
/// response level (VTI-TRN-047).
pub(super) async fn handle_trust_task_discovery_v0_3(
    _state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use trust_tasks_rs::specs::trust_task_discovery::v0_3 as wire;

    let req: wire::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    success_response(
        &doc,
        discovery::respond_v0_3(super::dispatched_uris(), &req),
    )
}

#[cfg(test)]
mod tests {
    use trust_tasks_rs::specs::trust_task_discovery::v0_3;
    use vti_common::trust_task::acceptance::AcceptanceWindow;

    /// What this VTA answers a discovery 0.3 query with, read back as a
    /// discoverer reads it.
    fn advertised() -> AcceptanceWindow {
        let response = vti_common::trust_task::discovery::respond_v0_3(
            crate::trust_tasks::dispatched_uris(),
            &v0_3::Payload::default(),
        );
        AcceptanceWindow::from_advertised(
            response
                .acceptance_window
                .as_ref()
                .expect("VTI-TRN-047: a VTA SHOULD advertise its window"),
        )
    }

    /// The window this VTA advertises in its discovery 0.3 answer is the window
    /// its spine applies — neither wider (VTI-TRN-047's MUST NOT) nor narrower.
    ///
    /// Compared against `freshness_policy`, the policy the spine refuses
    /// documents with: were either side to take its own constant again, this
    /// is where it would show.
    #[test]
    fn vti_trn_047_the_advertised_window_is_the_applied_window() {
        let advertised = advertised();
        let applied = super::super::freshness_policy();
        assert_eq!(Some(advertised.max_age), applied.max_age);
        assert_eq!(advertised.clock_skew, applied.skew);
    }

    /// The same property, measured the way a producer meets it: a document
    /// issued exactly the advertised window ago is still accepted, and one a
    /// second older is refused. An advertisement wider than the policy fails
    /// the second assertion; a narrower one fails the first.
    #[test]
    fn vti_trn_047_a_document_at_the_advertised_edge_is_accepted_and_one_past_it_refused() {
        let w = advertised();
        let now = chrono::SubsecRound::trunc_subsecs(chrono::Utc::now(), 0);
        let doc = |issued| {
            let mut d = trust_tasks_rs::TrustTask::new(
                "urn:uuid:00000000-0000-4000-8000-000000000000".to_string(),
                "https://trusttasks.org/spec/acl/list/0.1".parse().unwrap(),
                serde_json::json!({}),
            );
            d.issued_at = Some(issued);
            d
        };
        let policy = super::super::freshness_policy();
        let edge = now - w.max_age - w.clock_skew;
        assert!(doc(edge).validate_freshness(now, &policy).is_ok());
        assert!(
            doc(edge - chrono::TimeDelta::seconds(1))
                .validate_freshness(now, &policy)
                .is_err()
        );
    }

    /// Discovery answers from the dispatch table, and that table is non-trivial.
    ///
    /// The property under test is that the two are connected at all: if
    /// `dispatched_uris` were emptied by a refactor, the pattern tests in
    /// `vti_common::trust_task::discovery` would still pass while discovery
    /// answered "I support nothing".
    #[test]
    fn discovery_draws_on_the_real_dispatch_table() {
        let all = crate::trust_tasks::dispatched_uris();
        assert!(
            all.len() > 50,
            "only {} dispatched URIs — discovery would under-report; fix the \
             table rather than this floor",
            all.len()
        );
        for version in [
            vta_sdk::trust_tasks::TASK_TRUST_TASK_DISCOVERY_0_1,
            vta_sdk::trust_tasks::TASK_TRUST_TASK_DISCOVERY_0_3,
        ] {
            assert!(
                all.contains(&version),
                "discovery must advertise itself ({version}) — a client that \
                 cannot see it cannot know to ask again"
            );
        }
    }
}
