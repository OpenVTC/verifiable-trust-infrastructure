//! The applicant-facing poll (`vtc/join-requests/status/0.1`), served as a
//! signed document on every transport by the spine, which calls
//! [`status_inner`] / [`status_by_applicant`].
//!
//! The applicant polls their own request's lifecycle while it is in
//! flight (after a `refer` → `Pending`, or a `request_more` →
//! `Deferred`). It is the holder-authenticated counterpart to the
//! admin-only `show`: it returns only non-sensitive lifecycle fields
//! (never the stored VP), and — when `Deferred` — what the applicant
//! must present next, projected from the stored `request_more` verdict.
//!
//! ## Auth
//!
//! Holder-bound to the request's `applicantDid`: the spine has already bound
//! the document's sender before either function runs.

use chrono::{DateTime, Duration, Utc};
use tracing::{info, warn};
use uuid::Uuid;

use vta_sdk::protocols::join_requests::{CredentialResend, JoinRequestStatusResponseBody};
use vti_common::error::AppError;

use crate::ceremony::Verdict;
use crate::error::TaskError;
use crate::join::{
    CredentialResends, JoinStatus, get_credential_resends, get_join_request,
    store_credential_resends,
};
use crate::server::AppState;

/// Wait after the first honoured re-delivery before another is honoured. Each
/// later one doubles it, up to [`RESEND_BACKOFF_CAP`] (R1.4).
const RESEND_BACKOFF_BASE: Duration = Duration::minutes(10);
/// Longest wait between honoured re-deliveries.
const RESEND_BACKOFF_CAP: Duration = Duration::hours(6);
/// Re-deliveries honoured per request before the community stops and an
/// operator has to look. A persona that can receive nothing would otherwise be
/// sent the same credentials forever — and one whose acknowledgement cannot
/// reach us (it goes back over DIDComm only) looks exactly like that.
const RESEND_MAX: u32 = 5;
/// How long a queued re-delivery may take to reach the push outbox.
const RESEND_ENQUEUE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `vtc/join-requests/status:notFound` — no join request with that id, or one
/// that does not belong to the caller.
pub const STATUS_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::join_requests::status::v0_1::error_codes::NOT_FOUND.code;

/// The poll for a named request, answered only to its applicant.
pub async fn status_inner(
    state: &AppState,
    id: Uuid,
    applicant_did: String,
    resend_credentials: bool,
) -> Result<JoinRequestStatusResponseBody, TaskError> {
    // `vtc/join-requests/status:notFound` covers both "no such request" and
    // "not yours", and the two are answered with one message: telling them
    // apart would let any identified caller probe which request ids exist on
    // this community. A request belonging to somebody else used to be a
    // `malformedRequest` naming the mismatch — the oracle the spec closes.
    let not_found = || {
        TaskError::declared(
            STATUS_ERR_NOT_FOUND,
            AppError::NotFound(format!("join request not found: {id}")),
        )
    };
    let req = get_join_request(&state.join_requests_ks, id)
        .await?
        .ok_or_else(not_found)?;
    if req.applicant_did != applicant_did {
        return Err(not_found());
    }
    answer(state, id, req, resend_credentials, false).await
}

/// Resolve the applicant's **open** request without being told its id.
///
/// The id an applicant polls with is the community's, minted here on submit and
/// learned from the first correlated reply. An applicant whose reply was lost
/// therefore holds only the id of the document it sent — which this VTC has
/// never heard of — and cannot name its request at all. That made
/// [`status_inner`] unusable in precisely the situation it exists for: a join
/// whose answer went missing.
///
/// The applicant is already authenticated (authcrypt sender over DIDComm/TSP),
/// and the submit dedup allows at most one open request per applicant, so
/// "my open request" is both safe to ask and unambiguous to answer. The response
/// carries `request_id`, so one id-less poll also repairs the applicant's record
/// for every poll after it.
///
/// `NotFound` when nothing is open: either the applicant never reached us — in
/// which case re-submitting is the move, not polling — or the request already
/// settled and was retained past its window.
pub async fn status_by_applicant(
    state: &AppState,
    applicant_did: String,
    resend_credentials: bool,
) -> Result<JoinRequestStatusResponseBody, TaskError> {
    let id = find_pollable_request(state, &applicant_did)
        .await?
        .ok_or_else(|| {
            TaskError::declared(
                STATUS_ERR_NOT_FOUND,
                AppError::NotFound(format!(
                    "no open join request for applicant {applicant_did}"
                )),
            )
        })?;
    let req = get_join_request(&state.join_requests_ks, id)
        .await?
        .ok_or_else(|| {
            TaskError::declared(
                STATUS_ERR_NOT_FOUND,
                AppError::NotFound(format!("join request not found: {id}")),
            )
        })?;
    answer(state, id, req, resend_credentials, true).await
}

/// The request an id-less poll answers about: the applicant's open request,
/// or failing that their most recent **approved** one.
///
/// The approved case is the applicant whose every reply was lost — the one who
/// most needs the id-less form. Their request settled, so it is no longer
/// "open", and answering `notFound` would leave them no way to learn they were
/// admitted or to ask for the credentials that never came.
async fn find_pollable_request(
    state: &AppState,
    applicant_did: &str,
) -> Result<Option<Uuid>, AppError> {
    if let Some(id) =
        crate::join::orchestrate::find_open_request(&state.join_requests_ks, applicant_did).await?
    {
        return Ok(Some(id));
    }
    let approved = crate::join::list_join_requests(&state.join_requests_ks)
        .await?
        .into_iter()
        .filter(|r| r.applicant_did == applicant_did && r.status == JoinStatus::Approved)
        .max_by_key(|r| r.submitted_at);
    Ok(approved.map(|r| r.id))
}

/// [`answer_inner`], logged.
///
/// One `info` line per answered poll. Before it, an answered `status` poll
/// logged nothing at all — only the re-delivery paths warned — so a stuck join
/// whose applicant was polling steadily read in the logs exactly like one whose
/// polls never arrived. The line names only what the request row already
/// carries in the other join logs: the applicant's DID and the request id.
async fn answer(
    state: &AppState,
    id: Uuid,
    req: crate::join::JoinRequest,
    resend_credentials: bool,
    id_less: bool,
) -> Result<JoinRequestStatusResponseBody, TaskError> {
    let applicant = req.applicant_did.clone();
    let resp = answer_inner(state, id, req, resend_credentials).await?;
    info!(
        request = %id,
        applicant = %applicant,
        status = %resp.status,
        id_less,
        resend_asked = resend_credentials,
        credentials_delivered = ?resp.credentials_delivered,
        resend = ?resp.credential_resend,
        "join-requests/status poll answered"
    );
    Ok(resp)
}

/// The response for a request the caller owns, plus — for an `approved` one —
/// what the community knows about its credentials' delivery, and the answer to
/// `resend_credentials` when it was asked.
async fn answer_inner(
    state: &AppState,
    id: Uuid,
    req: crate::join::JoinRequest,
    resend_credentials: bool,
) -> Result<JoinRequestStatusResponseBody, TaskError> {
    let approved = req.status == JoinStatus::Approved;
    let applicant_did = req.applicant_did.clone();
    let mut resp = project_status(id, req)?;
    if !approved {
        return Ok(resp);
    }

    let member = crate::members::storage::get_member(&state.members_ks, &applicant_did).await?;
    let delivered = member
        .as_ref()
        .is_some_and(|m| m.member_vmc_received_at.is_some());
    resp.credentials_delivered = Some(delivered);
    if !resend_credentials {
        return Ok(resp);
    }

    // Only the credentials already issued are re-sent, and only to the
    // request's applicant. A member row without the bodies (issued before this
    // service kept them) has nothing to re-send: say nothing, which the spec
    // reads as "re-delivery not supported", and leave it to an operator.
    let credentials = member.as_ref().and_then(|m| {
        let vmc = m.current_vmc.clone()?;
        Some((vmc, m.current_role_vac.clone()))
    });
    let Some((vmc, role_vac)) = credentials else {
        warn!(
            request = %id, applicant = %applicant_did,
            "resendCredentials on an approved request whose member holds no issued credential \
             body to re-send"
        );
        return Ok(resp);
    };

    let now = Utc::now();
    let prior = get_credential_resends(&state.join_requests_ks, id).await?;
    match decide_resend(delivered, prior, now) {
        ResendDecision::NotNeeded => {
            resp.credential_resend = Some(CredentialResend::NotNeeded);
        }
        ResendDecision::RateLimited { retry_after } => {
            if retry_after.is_none() {
                warn!(
                    request = %id, applicant = %applicant_did, max = RESEND_MAX,
                    "credential re-delivery limit reached for an approved request whose \
                     credential is still unacknowledged; an operator needs to look"
                );
            }
            resp.credential_resend = Some(CredentialResend::RateLimited);
            resp.retry_after = retry_after;
        }
        ResendDecision::Queue => {
            // Recorded before the enqueue, so a burst of polls is rate-limited
            // by the first rather than each queueing its own.
            let resends = CredentialResends {
                count: prior.map_or(0, |p| p.count) + 1,
                last_at: now,
            };
            store_credential_resends(&state.join_requests_ks, id, &resends).await?;
            spawn_redelivery(state.clone(), id, applicant_did, vmc, role_vac);
            resp.credential_resend = Some(CredentialResend::Queued);
        }
    }
    Ok(resp)
}

/// What to do with a `resendCredentials` on an approved request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResendDecision {
    NotNeeded,
    Queue,
    /// `retry_after` is `None` once [`RESEND_MAX`] is reached.
    RateLimited {
        retry_after: Option<DateTime<Utc>>,
    },
}

/// The rate limit, kept pure so its arithmetic is tested directly.
fn decide_resend(
    delivered: bool,
    prior: Option<CredentialResends>,
    now: DateTime<Utc>,
) -> ResendDecision {
    if delivered {
        return ResendDecision::NotNeeded;
    }
    let Some(prior) = prior else {
        return ResendDecision::Queue;
    };
    if prior.count >= RESEND_MAX {
        return ResendDecision::RateLimited { retry_after: None };
    }
    let next = prior.last_at + resend_backoff(prior.count);
    if now >= next {
        ResendDecision::Queue
    } else {
        ResendDecision::RateLimited {
            retry_after: Some(next),
        }
    }
}

/// Wait after the `count`th honoured re-delivery: doubling from
/// [`RESEND_BACKOFF_BASE`], capped at [`RESEND_BACKOFF_CAP`].
fn resend_backoff(count: u32) -> Duration {
    let doublings = count.saturating_sub(1).min(16);
    (RESEND_BACKOFF_BASE * 2i32.pow(doublings)).min(RESEND_BACKOFF_CAP)
}

/// Push the stored credentials to the applicant again, off the poll's path:
/// the reply says `queued` and does not wait on the push.
///
/// The push is the same durable, escalating one admission used
/// ([`crate::credentials::delivery::deliver_credentials`]). Re-sending the same
/// bodies is safe to repeat — the holder replaces what it holds of each kind —
/// which is why this re-sends and never re-issues.
fn spawn_redelivery(
    state: AppState,
    request_id: Uuid,
    applicant_did: String,
    vmc: serde_json::Value,
    role_vac: Option<serde_json::Value>,
) {
    tokio::spawn(async move {
        let parse = |v: serde_json::Value| {
            serde_json::from_value::<affinidi_vc::VerifiableCredential>(v)
                .map_err(|e| AppError::Internal(format!("stored credential does not parse: {e}")))
        };
        let result = async {
            let mut credentials = vec![parse(vmc)?];
            if let Some(vac) = role_vac {
                credentials.push(parse(vac)?);
            }
            let refs: Vec<&affinidi_vc::VerifiableCredential> = credentials.iter().collect();
            match tokio::time::timeout(
                RESEND_ENQUEUE_TIMEOUT,
                crate::credentials::delivery::deliver_credentials(&state, &applicant_did, &refs),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => Err(AppError::Internal(format!(
                    "timed out after {}s queueing the re-delivery",
                    RESEND_ENQUEUE_TIMEOUT.as_secs()
                ))),
            }
        }
        .await;
        match result {
            Ok(()) => info!(
                request = %request_id, applicant = %applicant_did,
                "re-delivery of an approved request's credentials queued"
            ),
            Err(e) => warn!(
                request = %request_id, applicant = %applicant_did, error = %e,
                "could not queue the re-delivery of an approved request's credentials; \
                 the next honoured resendCredentials will try again"
            ),
        }
    });
}

/// Shared projection of a stored request into the applicant-facing response.
/// Only non-sensitive lifecycle fields (never the stored VP).
///
/// Two statuses carry more than the bare lifecycle word, for the same reason:
/// a `Deferred` applicant cannot act without knowing what is still missing,
/// and a `Rejected` one cannot act — or stop — without knowing why. Both are
/// projected here rather than only in the correlated ceremony reply, because
/// that reply is a **one-shot** delivery: an applicant whose socket was down,
/// whose reply was lost, or who was rejected by an admin long after the fact
/// never sees it. The poll is the recovery path, so it has to carry the
/// evidence the reply would have.
fn project_status(
    id: Uuid,
    req: crate::join::JoinRequest,
) -> Result<JoinRequestStatusResponseBody, AppError> {
    // Why the request was refused — `None` unless it was. Reconciles the two
    // rejection paths (policy auto-deny, admin reject) into one shape; see
    // `JoinRequest::decision_for_applicant`.
    let (code, reason, decided_at) = match req.decision_for_applicant() {
        Some((code, reason, at)) => (Some(code), reason, at),
        None => (None, None, None),
    };

    // Project the outstanding requirements only for a Deferred request
    // (a `request_more` verdict the daemon persisted on `policy_decision`).
    let (needs, presentation_definition) = if req.status == JoinStatus::Deferred {
        match req
            .policy_decision
            .and_then(|pd| serde_json::from_value::<Verdict>(pd).ok())
        {
            Some(Verdict::RequestMore(rm)) => (rm.needs, Some(rm.presentation_definition)),
            _ => (Vec::new(), None),
        }
    } else {
        (Vec::new(), None)
    };

    Ok(JoinRequestStatusResponseBody {
        request_id: id,
        status: req.status.to_string(),
        needs,
        presentation_definition,
        code,
        reason,
        decided_at,
        credentials_delivered: None,
        credential_resend: None,
        retry_after: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::join::{JoinRequest, store_join_request};
    use crate::members::Member;

    const APPLICANT: &str = "did:key:zApplicantResend";

    fn at(mins: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-02T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
            + Duration::minutes(mins)
    }

    fn resends(count: u32, last_at: DateTime<Utc>) -> Option<CredentialResends> {
        Some(CredentialResends { count, last_at })
    }

    /// Acknowledged delivery needs nothing; a first ask is honoured; later
    /// ones wait 10, 20, 40… minutes up to six hours; and after five the
    /// community stops and names no retry time.
    #[test]
    fn the_rate_limit_backs_off_and_stops() {
        assert_eq!(decide_resend(true, None, at(0)), ResendDecision::NotNeeded);
        assert_eq!(decide_resend(false, None, at(0)), ResendDecision::Queue);

        assert_eq!(
            decide_resend(false, resends(1, at(0)), at(5)),
            ResendDecision::RateLimited {
                retry_after: Some(at(10))
            }
        );
        assert_eq!(
            decide_resend(false, resends(1, at(0)), at(10)),
            ResendDecision::Queue
        );
        assert_eq!(
            decide_resend(false, resends(2, at(0)), at(15)),
            ResendDecision::RateLimited {
                retry_after: Some(at(20))
            }
        );
        assert_eq!(
            decide_resend(false, resends(RESEND_MAX, at(0)), at(100_000)),
            ResendDecision::RateLimited { retry_after: None }
        );

        assert_eq!(resend_backoff(1), Duration::minutes(10));
        assert_eq!(resend_backoff(3), Duration::minutes(40));
        assert_eq!(resend_backoff(10), RESEND_BACKOFF_CAP);
        assert_eq!(resend_backoff(u32::MAX), RESEND_BACKOFF_CAP);
    }

    async fn approved_member(state: &AppState, acknowledged: bool) -> Uuid {
        let mut req = JoinRequest::new(APPLICANT, serde_json::json!({"vp": "placeholder"}));
        req.status = JoinStatus::Approved;
        store_join_request(&state.join_requests_ks, &req)
            .await
            .unwrap();
        let member = Member {
            did: APPLICANT.into(),
            joined_at: Utc::now(),
            status_list_index: None,
            publish_consent: false,
            departure_preference: crate::members::Disposition::Historical,
            current_vmc_id: Some("vmc-1".into()),
            current_vmc: Some(serde_json::json!({ "id": "vmc-1" })),
            current_role_vac_id: None,
            current_role_vac: None,
            extensions: serde_json::Value::Null,
            removed_at: None,
            personhood: false,
            personhood_asserted_at: None,
            reciprocal_vc_id: None,
            accepted_at: None,
            joined_via_invitation: false,
            member_vmc: None,
            member_vmc_id: None,
            member_vmc_bound: false,
            member_vmc_received_at: acknowledged.then(Utc::now),
        };
        crate::members::storage::store_member(&state.members_ks, &member)
            .await
            .unwrap();
        req.id
    }

    /// An approved request reports delivery, queues a re-send when asked,
    /// rate-limits the next ask, and is found by the id-less poll — the only
    /// form an applicant whose replies were all lost can send.
    #[tokio::test]
    async fn an_approved_applicant_can_ask_for_its_credentials_again() {
        let tv = crate::test_support::build_test_vtc().await;
        let id = approved_member(&tv.state, false).await;

        let plain = status_inner(&tv.state, id, APPLICANT.into(), false)
            .await
            .unwrap();
        assert_eq!(plain.status, "approved");
        assert_eq!(plain.credentials_delivered, Some(false));
        assert_eq!(plain.credential_resend, None, "not asked, not answered");

        let first = status_by_applicant(&tv.state, APPLICANT.into(), true)
            .await
            .expect("the id-less poll finds the approved request");
        assert_eq!(first.request_id, id);
        assert_eq!(first.credential_resend, Some(CredentialResend::Queued));
        let recorded = get_credential_resends(&tv.state.join_requests_ks, id)
            .await
            .unwrap()
            .expect("the honoured ask is recorded for the rate limit");
        assert_eq!(recorded.count, 1);

        let second = status_inner(&tv.state, id, APPLICANT.into(), true)
            .await
            .unwrap();
        assert_eq!(
            second.credential_resend,
            Some(CredentialResend::RateLimited)
        );
        assert_eq!(
            second.retry_after,
            Some(recorded.last_at + RESEND_BACKOFF_BASE)
        );
    }

    /// Once the member's acknowledgement is held there is nothing to re-send.
    #[tokio::test]
    async fn an_acknowledged_delivery_needs_no_resend() {
        let tv = crate::test_support::build_test_vtc().await;
        let id = approved_member(&tv.state, true).await;
        let resp = status_inner(&tv.state, id, APPLICANT.into(), true)
            .await
            .unwrap();
        assert_eq!(resp.credentials_delivered, Some(true));
        assert_eq!(resp.credential_resend, Some(CredentialResend::NotNeeded));
        assert!(
            get_credential_resends(&tv.state.join_requests_ks, id)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The delivery members belong to an approved request only.
    #[tokio::test]
    async fn a_pending_request_carries_no_delivery_members() {
        let tv = crate::test_support::build_test_vtc().await;
        let req = JoinRequest::new(APPLICANT, serde_json::json!({"vp": "placeholder"}));
        store_join_request(&tv.state.join_requests_ks, &req)
            .await
            .unwrap();
        let resp = status_inner(&tv.state, req.id, APPLICANT.into(), true)
            .await
            .unwrap();
        assert_eq!(resp.status, "pending");
        assert_eq!(resp.credentials_delivered, None);
        assert_eq!(resp.credential_resend, None);
    }
}
