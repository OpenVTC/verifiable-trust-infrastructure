//! `POST /v1/invitations` — issue an **Invitation Credential** (VIC) to a
//! prospective member (the operator side of the VIC auto-join ceremony).
//!
//! The community admin enters an invitee DID; the VTC mints a short-lived,
//! revocable VIC bound to that DID and signed by the community key, and returns
//! the signed credential for **out-of-band delivery** (copy / QR) to the
//! invitee. The invitee later presents it inside a join VP and is auto-admitted
//! (`credentials::invitation_verify` + the default `join.rego`).
//!
//! Auth: Admin / Moderator / Issuer — the roles that grow + vouch for
//! membership. The issuance itself (slot allocation, signing, schema check)
//! lives in [`crate::credentials::invitation`]; this is the thin authenticated
//! REST surface over it.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::Duration;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::info;

use vti_common::auth::AuthClaims;
use vti_common::error::AppError;

use crate::acl::{VtcRole, get_acl_entry};
use crate::credentials::invitation::{DEFAULT_INVITATION_VALIDITY, issue_invitation};
use crate::members::get_member;
use crate::server::AppState;

/// Upper bound on a caller-requested validity — an invite is a short-lived
/// onboarding artifact, not a standing credential.
const MAX_VALIDITY_DAYS: i64 = 90;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssueInvitationBody {
    /// The DID to invite (a prospective, non-member holder).
    pub subject_did: String,
    /// Optional validity in days (1..=90); defaults to the 7-day VIC default.
    #[serde(default)]
    pub validity_days: Option<u32>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssueInvitationResponse {
    /// Echo of the invited DID.
    pub subject_did: String,
    /// The VIC's `validUntil` (RFC3339), for the operator UI to display.
    pub valid_until: Option<String>,
    /// The signed Invitation Credential — handed to the invitee out-of-band
    /// (copy / QR). The invitee presents it back in a join request.
    pub vic: JsonValue,
}

#[utoipa::path(
    post, path = "/invitations", tag = "invitations",
    security(("bearer_jwt" = [])),
    request_body = IssueInvitationBody,
    responses(
        (status = 201, description = "Invitation issued", body = IssueInvitationResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not Admin / Moderator / Issuer"),
        (status = 409, description = "Subject is already a member"),
    ),
)]
pub async fn issue(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(body): Json<IssueInvitationBody>,
) -> Result<(StatusCode, Json<IssueInvitationResponse>), AppError> {
    let signer = state
        .credential_signer
        .as_ref()
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;

    // Auth: Admin / Moderator / Issuer can invite (read the ACL row — the JWT
    // degrades non-Admin VTC roles to Reader, so it can't distinguish them).
    let acl = get_acl_entry(&state.acl_ks, &auth.did)
        .await?
        .ok_or_else(|| AppError::Forbidden("caller has no ACL row".into()))?;
    if !matches!(
        acl.role,
        VtcRole::Admin | VtcRole::Moderator | VtcRole::Issuer
    ) {
        return Err(AppError::Forbidden(
            "only Admin, Moderator, or Issuer members can issue invitations".into(),
        ));
    }

    // An invite is for a *prospective* member.
    if !body.subject_did.starts_with("did:") {
        return Err(AppError::Validation("subjectDid must be a DID".into()));
    }
    if get_member(&state.members_ks, &body.subject_did)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(format!(
            "{} is already a member — no invitation needed",
            body.subject_did
        )));
    }

    let validity = match body.validity_days {
        Some(d) if d == 0 || (d as i64) > MAX_VALIDITY_DAYS => {
            return Err(AppError::Validation(format!(
                "validityDays must be between 1 and {MAX_VALIDITY_DAYS}"
            )));
        }
        Some(d) => Duration::days(d as i64),
        None => DEFAULT_INVITATION_VALIDITY,
    };

    let vic = issue_invitation(
        signer,
        &state.status_lists_ks,
        &state.schemas_ks,
        &body.subject_did,
        validity,
    )
    .await?;
    let valid_until = vic
        .get("validUntil")
        .and_then(JsonValue::as_str)
        .map(str::to_string);

    info!(
        actor = %auth.did,
        subject = %body.subject_did,
        "issued an invitation credential (VIC)"
    );

    Ok((
        StatusCode::CREATED,
        Json(IssueInvitationResponse {
            subject_did: body.subject_did,
            valid_until,
            vic,
        }),
    ))
}
