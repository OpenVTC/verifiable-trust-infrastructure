//! `PATCH /v1/members/{did}` — M1.5.1.
//!
//! Non-role fields (publish consent, departure preference, extensions)
//! are written directly. A **role change** is the role-change ceremony:
//! it runs through the decision pipeline ([`crate::ceremony`]) —
//! assemble Facts → decide the active `roleChange` policy → apply via
//! the `Remint` executor arm (which updates the ACL role in place,
//! re-mints the role VEC, and enforces no-last-admin on demotion).
//!
//! `role=admin` is still refused on this surface: admin promotion fires
//! the step-up UV ceremony on its own endpoint
//! (`POST /v1/members/{did}/promote-to-admin`, spec §10.4), so the
//! policy's admin branch is reached there, not here.

use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::Value as JsonValue;

use vti_common::audit::{AuditEvent, MemberUpdatedData, RoleChangedData};

use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry};
use crate::auth::AdminAuth;
use crate::error::AppError;
use crate::members::{Disposition, Member, get_member, store_member};
use crate::routes::members::read::MemberResponse;
use crate::server::AppState;

/// Body of the PATCH request. Every field is optional; a request
/// with no fields is a no-op (200 with the current row).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct UpdateMemberRequest {
    pub role: Option<VtcRole>,
    pub publish_consent: Option<bool>,
    pub departure_preference: Option<Disposition>,
    pub extensions: Option<JsonValue>,
}

/// PATCH /members/{did} — update member role + profile fields. Auth: Admin.
#[utoipa::path(
    patch, path = "/members/{did}", tag = "members",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Member DID")),
    request_body = UpdateMemberRequest,
    responses(
        (status = 200, description = "Updated member record", body = MemberResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin / role change denied by policy"),
        (status = 404, description = "Member not found"),
    ),
)]
pub async fn update_member(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<Json<MemberResponse>, AppError> {
    vti_common::identifier::validate_did("did", &did)?;
    // Role=Admin is forbidden on this surface — it routes to the
    // separate promote-to-admin endpoint (spec §10.4), where the
    // role-change policy's step-up branch is reached. Catch it early so
    // the response carries an operator-friendly hint.
    if matches!(req.role, Some(VtcRole::Admin)) {
        return Err(AppError::Validation(format!(
            "role=admin is not assignable via PATCH /v1/members/{{did}}; \
             use POST /v1/members/{did}/promote-to-admin (spec §10.4) \
             so the step-up UV ceremony fires."
        )));
    }

    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let acl = get_acl_entry(&state.acl_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;
    let mut member = get_member(&state.members_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;

    // Non-role field updates — written directly (not a ceremony).
    // Persisted *before* any role change so the Remint executor (which
    // re-reads the member to repoint its role VEC) sees them.
    let mut fields_changed: Vec<String> = Vec::new();
    if let Some(consent) = req.publish_consent
        && consent != member.publish_consent
    {
        member.publish_consent = consent;
        fields_changed.push("publishConsent".into());
    }
    if let Some(pref) = req.departure_preference
        && pref != member.departure_preference
    {
        member.departure_preference = pref;
        fields_changed.push("departurePreference".into());
    }
    if let Some(extensions) = req.extensions
        && extensions != member.extensions
    {
        member.extensions = extensions;
        fields_changed.push("extensions".into());
    }
    if !fields_changed.is_empty() {
        store_member(&state.members_ks, &member).await?;
    }

    // Role change → the role-change ceremony.
    let role_change = match req.role {
        Some(new_role) if new_role != acl.role => Some(new_role),
        _ => None,
    };
    if let Some(new_role) = role_change {
        let granted = crate::ceremony::role_change_via_pipeline(
            &state,
            &auth.0.did,
            &did,
            &acl.role.to_string(),
            &new_role.to_string(),
            // PATCH carries no reauth — the step-up path is the
            // promote-to-admin endpoint, which passes `true`.
            false,
        )
        .await?;
        audit_writer
            .write(
                &auth.0.did,
                Some(&did),
                AuditEvent::RoleChanged(RoleChangedData {
                    previous_role: granted.previous_role,
                    new_role: granted.new_role,
                }),
            )
            .await?;
    }

    if !fields_changed.is_empty() {
        audit_writer
            .write(
                &auth.0.did,
                Some(&did),
                AuditEvent::MemberUpdated(MemberUpdatedData {
                    fields_changed: fields_changed.clone(),
                }),
            )
            .await?;
    }

    // Re-read the authoritative state for the response — the Remint
    // executor may have changed the ACL role + the member's role-VEC
    // pointer.
    let acl = get_acl_entry(&state.acl_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;
    let member = get_member(&state.members_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;

    Ok(Json(MemberResponse::from_pair_for_route(acl, member)))
}

// Re-export `from_pair` under a route-only alias so this module
// doesn't have to make the constructor public on `MemberResponse`.
impl MemberResponse {
    pub(crate) fn from_pair_for_route(acl: VtcAclEntry, member: Member) -> Self {
        // Inline the same join the read endpoints do — duplicating
        // the body (~10 lines) is cheaper than exposing a public
        // constructor that's only used by route handlers.
        Self {
            did: member.did,
            role: acl.role,
            label: acl.label,
            joined_at: member.joined_at,
            publish_consent: member.publish_consent,
            departure_preference: member.departure_preference,
            status_list_index: member.status_list_index,
            current_vmc_id: member.current_vmc_id,
            current_role_vec_id: member.current_role_vec_id,
            extensions: member.extensions,
            personhood: member.personhood,
            personhood_asserted_at: member.personhood_asserted_at,
        }
    }
}
