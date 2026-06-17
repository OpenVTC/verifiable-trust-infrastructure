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
use axum::extract::Path;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::info;

use vti_common::auth::AuthClaims;
use vti_common::error::AppError;

use crate::acl::{VtcRole, get_acl_entry};
use crate::credentials::invitation::{DEFAULT_INVITATION_VALIDITY, issue_invitation};
use crate::credentials::invitation_registry::{
    InvitationRecord, get_invitation, list_invitations, store_invitation,
};
use crate::server::AppState;
use crate::status_list;

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
    /// Optional role to grant the invitee on join (e.g. `member`, `moderator`,
    /// `issuer`). Carried in the VIC's `credentialSubject.scopes` as
    /// `role:<name>` and honored by the join policy. `admin` is refused — the
    /// no-admin-via-join privilege ceiling would deny it anyway. Defaults to
    /// `member` (absent scope).
    #[serde(default)]
    pub role: Option<String>,
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
    // "Already a member" means a *current* (ACL-present) member — not a departed
    // one whose tombstone Member row lingers after a Tombstone/Historical
    // removal. A departed member can be re-invited (re-join overwrites the
    // tombstone with a fresh membership), so gate on the ACL, not the Member row.
    if get_acl_entry(&state.acl_ks, &body.subject_did)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(format!(
            "{} is already a current member — no invitation needed",
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

    // A role grant on the invite must parse to a known role and may never be
    // `admin` — a join can't grant admin (host privilege ceiling), so we refuse
    // it at issuance rather than mint an invite that would be denied on redeem.
    if let Some(role) = body.role.as_deref() {
        let parsed = role
            .parse::<VtcRole>()
            .map_err(|_| AppError::Validation(format!("unknown role `{role}`")))?;
        if matches!(parsed, VtcRole::Admin) {
            return Err(AppError::Validation(
                "an invitation may not grant `admin` (no admin via join)".into(),
            ));
        }
    }

    let vic = issue_invitation(
        signer,
        &state.status_lists_ks,
        &state.schemas_ks,
        &body.subject_did,
        validity,
        body.role.as_deref(),
    )
    .await?;
    let valid_until = vic
        .get("validUntil")
        .and_then(JsonValue::as_str)
        .map(str::to_string);

    // Record the issued VIC so it can be listed + revoked. The id + revocation
    // slot are read back from the freshly-signed credential.
    let id = vic
        .get("id")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| AppError::Internal("issued VIC has no `id`".into()))?
        .to_string();
    let slot = vic
        .pointer("/credentialStatus/statusListIndex")
        .and_then(JsonValue::as_str)
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| AppError::Internal("issued VIC has no usable statusListIndex".into()))?;
    store_invitation(
        &state.invitations_ks,
        &InvitationRecord {
            id: id.clone(),
            subject_did: body.subject_did.clone(),
            slot,
            role: body.role.clone(),
            issued_by: auth.did.clone(),
            issued_at: Utc::now(),
            valid_until: valid_until.clone(),
            revoked_at: None,
        },
    )
    .await?;

    info!(
        actor = %auth.did,
        subject = %body.subject_did,
        vic_id = %id,
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

// ── List + revoke ─────────────────────────────────────────────────────────

/// One row of the invitation list (the registry record, body-free).
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InvitationListItem {
    pub id: String,
    pub subject_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub issued_by: String,
    pub issued_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

impl From<InvitationRecord> for InvitationListItem {
    fn from(r: InvitationRecord) -> Self {
        Self {
            id: r.id,
            subject_did: r.subject_did,
            role: r.role,
            issued_by: r.issued_by,
            issued_at: r.issued_at.to_rfc3339(),
            valid_until: r.valid_until,
            revoked_at: r.revoked_at.map(|t| t.to_rfc3339()),
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InvitationListResponse {
    pub invitations: Vec<InvitationListItem>,
}

/// Auth gate shared by the invitation ops: Admin / Moderator / Issuer.
async fn require_inviter(state: &AppState, did: &str) -> Result<(), AppError> {
    let acl = get_acl_entry(&state.acl_ks, did)
        .await?
        .ok_or_else(|| AppError::Forbidden("caller has no ACL row".into()))?;
    if !matches!(
        acl.role,
        VtcRole::Admin | VtcRole::Moderator | VtcRole::Issuer
    ) {
        return Err(AppError::Forbidden(
            "only Admin, Moderator, or Issuer members can manage invitations".into(),
        ));
    }
    Ok(())
}

#[utoipa::path(
    get, path = "/invitations", tag = "invitations",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Issued invitations", body = InvitationListResponse),
        (status = 403, description = "Caller is not Admin / Moderator / Issuer"),
    ),
)]
pub async fn list(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<InvitationListResponse>, AppError> {
    require_inviter(&state, &auth.did).await?;
    let invitations = list_invitations(&state.invitations_ks)
        .await?
        .into_iter()
        .map(InvitationListItem::from)
        .collect();
    Ok(Json(InvitationListResponse { invitations }))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RevokeResponse {
    pub id: String,
    pub revoked_at: String,
    /// True if this call performed the revocation; false if it was already
    /// revoked (idempotent).
    pub newly_revoked: bool,
}

#[utoipa::path(
    delete, path = "/invitations/{id}", tag = "invitations",
    params(("id" = String, Path, description = "VIC id (urn:uuid)")),
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Invitation revoked", body = RevokeResponse),
        (status = 403, description = "Caller is not Admin / Moderator / Issuer"),
        (status = 404, description = "No such invitation"),
    ),
)]
pub async fn revoke(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<RevokeResponse>, AppError> {
    require_inviter(&state, &auth.did).await?;

    let mut record = get_invitation(&state.invitations_ks, &id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no invitation with id {id}")))?;

    // Idempotent: an already-revoked invite reports its prior revocation.
    if let Some(revoked_at) = record.revoked_at {
        return Ok(Json(RevokeResponse {
            id,
            revoked_at: revoked_at.to_rfc3339(),
            newly_revoked: false,
        }));
    }

    // Flip the revocation status-list bit at the VIC's slot — locked RMW so a
    // concurrent allocate/flip can't clobber it (P0.1).
    let slot = record.slot;
    status_list::with_locked(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        |sl| {
            status_list::flip(sl, slot, true)
                .map_err(|e| AppError::Internal(format!("flip revocation bit {slot}: {e}")))
        },
    )
    .await?;

    let now = Utc::now();
    record.revoked_at = Some(now);
    store_invitation(&state.invitations_ks, &record).await?;

    info!(actor = %auth.did, vic_id = %id, slot, "revoked an invitation credential (VIC)");

    Ok(Json(RevokeResponse {
        id,
        revoked_at: now.to_rfc3339(),
        newly_revoked: true,
    }))
}
