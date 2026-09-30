//! `/v1/vetting/*` — the community-admin side of peer identity vetting.
//!
//! - `POST /v1/vetting/vetters` — name a member a vetter
//!   (`vtc/vetting/vetters/grant/0.1`). Auth: community Admin. The same task is
//!   dispatched as a Trust Task document for an admin on DIDComm or TSP; both
//!   go through [`crate::vetting::vetters::grant`]. A grant is withdrawn with
//!   `DELETE /v1/credentials/endorsements/{endorsementId}`.
//! - Resend (`vtc/vetting/vetters/resend/{0.1,0.2}`) is a signed document
//!   only: `0.1` for a vetter's own grant, `0.2` adding the `memberDid` an
//!   administrator names to resend on a vetter's behalf. The admin-only REST
//!   route had no caller once the spine dispatched `0.2` (tt-tf#689) and was
//!   removed.
//! - The grant listing (`vtc/vetting/vetters/grants/list/0.1`), automatic
//!   vetter grants (`vtc/vetting/auto-grant/{show,update}/0.1`) and vetting
//!   statement withdrawal notices (`vtc/vetting/revocations/list/0.1`) are
//!   signed documents only too (`trust_tasks::surface_tasks`) — their
//!   admin-only bearer REST mounts had no caller left once `vtc-client` and
//!   the admin console signed them instead.
//! - `POST /v1/vetting/vetters/list` — the public vetter listing
//!   (`vtc/vetting/vetters/list/0.1`) for an admin session, so the console can
//!   show what applicants see. Over `POST /v1/trust-tasks` the listing names its
//!   caller by the document proof, which a browser session cannot sign.

use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;
use vti_common::error::AppError;

use crate::join::{JoinStatus, get_vetting_facts, list_join_requests};
use crate::members::storage::get_member;
use crate::server::AppState;
use crate::vetting::revocation;

/// Whether a withdrawn statement touches a standing membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum RevocationReviewState {
    /// No current member was admitted on the statement.
    NoAdmission,
    /// A current member was admitted with the statement counted: their
    /// admission rested on evidence its vetter has taken back.
    NeedsReview,
}

/// One withdrawal notice, and the admissions it touches.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VettingRevocationRow {
    /// The vetter who withdrew the statement.
    pub issuer: String,
    /// The statement's `id`.
    pub statement_id: String,
    /// The statement's `digestMultibase`.
    pub statement_digest_multibase: String,
    /// The vetter's reason, when given (`mistake`, `newInformation`,
    /// `keyCompromise`, `other`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When the community recorded the notice.
    pub recorded_at: DateTime<Utc>,
    /// Whether a current membership rests on the statement.
    pub review_state: RevocationReviewState,
    /// Approved join requests that counted the statement.
    pub affected_join_requests: Vec<Uuid>,
    /// Of their applicants, those who are current members.
    pub affected_members: Vec<String>,
}

/// Every withdrawal notice, newest first, with the join requests and standing
/// members it touches — what `vtc/vetting/revocations/list/0.1` pages, on the
/// route and the spine alike.
pub(crate) async fn revocation_rows(
    state: &AppState,
) -> Result<Vec<VettingRevocationRow>, AppError> {
    // (issuer, statement id) → approved requests that counted it.
    let mut counted_by: HashMap<(String, String), Vec<(Uuid, String)>> = HashMap::new();
    for request in list_join_requests(&state.join_requests_ks).await? {
        if request.status != JoinStatus::Approved {
            continue;
        }
        let Some(stored) = get_vetting_facts(&state.join_requests_ks, request.id).await? else {
            continue;
        };
        for statement in stored.facts.statements.iter().filter(|s| s.counted) {
            if let (Some(issuer), Some(id)) = (&statement.issuer, &statement.id) {
                counted_by
                    .entry((issuer.clone(), id.clone()))
                    .or_default()
                    .push((request.id, request.applicant_did.clone()));
            }
        }
    }

    let mut rows = Vec::new();
    for notice in revocation::list_notices(&state.vetting_revocations_ks).await? {
        let affected = counted_by
            .get(&(notice.issuer.clone(), notice.statement_id.clone()))
            .cloned()
            .unwrap_or_default();
        let mut members = BTreeSet::new();
        for (_, applicant) in &affected {
            if get_member(&state.members_ks, applicant)
                .await?
                .is_some_and(|m| m.removed_at.is_none())
            {
                members.insert(applicant.clone());
            }
        }
        rows.push(VettingRevocationRow {
            review_state: if members.is_empty() {
                RevocationReviewState::NoAdmission
            } else {
                RevocationReviewState::NeedsReview
            },
            affected_join_requests: affected.iter().map(|(id, _)| *id).collect(),
            affected_members: members.into_iter().collect(),
            reason: notice.reason.map(|r| r.to_string()),
            issuer: notice.issuer,
            statement_id: notice.statement_id,
            statement_digest_multibase: notice.statement_digest_multibase,
            recorded_at: notice.recorded_at,
        });
    }
    Ok(rows)
}
