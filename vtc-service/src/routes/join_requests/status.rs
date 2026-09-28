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

use uuid::Uuid;

use vta_sdk::protocols::join_requests::JoinRequestStatusResponseBody;
use vti_common::error::AppError;

use crate::ceremony::Verdict;
use crate::error::TaskError;
use crate::join::{JoinStatus, get_join_request};
use crate::server::AppState;

/// `vtc/join-requests/status:notFound` — no join request with that id, or one
/// that does not belong to the caller.
pub const STATUS_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::join_requests::status::v0_1::error_codes::NOT_FOUND.code;

/// The poll for a named request, answered only to its applicant.
pub async fn status_inner(
    state: &AppState,
    id: Uuid,
    applicant_did: String,
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
    Ok(project_status(id, req)?)
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
) -> Result<JoinRequestStatusResponseBody, TaskError> {
    let id = crate::join::orchestrate::find_open_request(&state.join_requests_ks, &applicant_did)
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
    Ok(project_status(id, req)?)
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
    })
}
