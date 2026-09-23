//! `PATCH /v1/members/{did}` — M1.5.1.
//!
//! Non-role fields (publish consent, departure preference, extensions)
//! are written directly. A **role change** is the role-change ceremony:
//! it runs through the decision pipeline ([`crate::ceremony`]) —
//! assemble Facts → decide the active `roleChange` policy → apply via
//! the `Remint` executor arm (which updates the ACL role in place,
//! re-mints the role VEC, and enforces no-last-admin on demotion).
//!
//! `role = admin` is **refused here**, with the `adminRoleForbidden` code
//! `vtc/members/update/0.1` declares for it: promotion to admin is a separate,
//! gated flow, not a metadata update. `acl/change-role/0.1` is the task defined
//! for role transitions, and the refusal names it.
//!
//! ## Why it moved (#1645)
//!
//! Promotion landed here when the fused
//! `POST /v1/members/{did}/promote-to-admin/{start,finish}` endpoint was
//! retired, with the step-up it carried re-expressed as an in-handler
//! `require_fresh_step_up`. That was sound as far as this route went, and it
//! did not go far enough: `acl/change-role` and `acl/grant` assign the same
//! `admin` role to the same ACL row and asked for nothing at all, so an admin
//! session could confer admin with no second factor simply by using a
//! different door. The gate now sits on the transition rather than on the
//! route — as a host invariant in the role-change ceremony, which no policy
//! edit can disable — and this route refuses the field outright.
//!
//! Non-admin role changes are still made here, and still run the role-change
//! ceremony.

use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::Value as JsonValue;

use vti_common::audit::{AuditEvent, FieldChange, MemberUpdatedData, RoleChangedData};

use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry};
use crate::auth::{AdminAuth, session::now_epoch};
use crate::error::{AppError, TaskError};

/// `vtc/members/update:notFound` — no member with that DID.
pub const UPDATE_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::members::update::v0_1::error_codes::NOT_FOUND.code;
/// `vtc/members/update:adminRoleForbidden` — `role` was `admin`.
pub const UPDATE_ERR_ADMIN_ROLE_FORBIDDEN: &str =
    trust_tasks_rs::specs::vtc::members::update::v0_1::error_codes::ADMIN_ROLE_FORBIDDEN.code;
use crate::members::{Disposition, Member, get_member, store_member};
use crate::routes::members::read::{MemberEnvelope, MemberResponse};
use crate::server::AppState;

/// Body of the PATCH request. Every field is optional; a request
/// with no fields is a no-op (200 with the current row).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct UpdateMemberRequest {
    pub role: Option<VtcRole>,
    /// Human-readable name for this member, shown wherever their DID is
    /// rendered (admin UI, `vtc acl list`).
    ///
    /// The label lives on the ACL row, so until now it was writable only via
    /// `acl/grant` — a whole re-grant to correct a typo in a display name.
    /// An empty string clears it; omitting the field leaves it unchanged.
    pub label: Option<String>,
    pub publish_consent: Option<bool>,
    pub departure_preference: Option<Disposition>,
    pub extensions: Option<JsonValue>,
}

/// PATCH /members/{did} — update member role + profile fields. Auth: Admin.
///
/// **Transitional bearer-token path (#1641).** `vtc/members/update/0.1`
/// declares `proof` REQUIRED, and the authoritative binding is the signed
/// Trust Task document at `POST /v1/trust-tasks`, where the proof authenticates
/// the administrator and their authority is read from their ACL entry. This
/// route authenticates by bearer JWT and verifies no document proof; it is kept
/// only until the admin console can sign a Trust Task document, and is removed
/// in the same change that gives it that.
#[utoipa::path(
    patch, path = "/members/{did}", tag = "members",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Member DID")),
    request_body = UpdateMemberRequest,
    responses(
        (status = 200, description = "Updated member record", body = MemberEnvelope),
        (status = 400, description = "role was `admin` (adminRoleForbidden) — use acl/change-role"),
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
) -> Result<Json<MemberEnvelope>, TaskError> {
    Ok(Json(update_member_inner(&state, &auth.0, &did, req).await?))
}

/// Apply one `vtc/members/update/0.1` on behalf of `auth` — the whole of the
/// operation, with no transport in it.
///
/// Both doors call this: the bearer REST route above, and the signed-document
/// arm in [`crate::trust_tasks`] (#1641 phase 2). The signed path synthesises
/// `auth` from the verified signer's **ACL entry**, which is why nothing here
/// may read the caller's session: there is none. The one thing that would —
/// the promotion step-up in [`crate::ceremony::role_change_via_pipeline`] — is
/// unreachable, because `role: admin` is refused below before any of this runs,
/// and it fails closed (a session-less claim has no elevation) if that ever
/// changes.
pub(crate) async fn update_member_inner(
    state: &AppState,
    auth: &vti_common::auth::extractor::AuthClaims,
    did: &str,
    req: UpdateMemberRequest,
) -> Result<MemberEnvelope, TaskError> {
    vti_common::identifier::validate_did("did", did)?;

    // Declared, and refused before anything is read or written: the
    // specification's consumer conformance for this task is "if `role` is
    // `admin`, return `adminRoleForbidden` and change nothing". The message
    // names the replacement so an operator is not left to find it.
    if matches!(req.role, Some(VtcRole::Admin)) {
        return Err(TaskError::declared(
            UPDATE_ERR_ADMIN_ROLE_FORBIDDEN,
            AppError::Validation(format!(
                "`role: admin` is not a metadata update; promote with acl/change-role — \
                 PATCH /v1/acl/{did} {{\"fromRole\": \"<current role>\", \"toRole\": \"admin\"}}, \
                 which requires a fresh passkey step-up"
            )),
        ));
    }

    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let not_found = || {
        TaskError::declared(
            UPDATE_ERR_NOT_FOUND,
            AppError::NotFound(format!("member not found: {did}")),
        )
    };
    let acl = get_acl_entry(&state.acl_ks, did)
        .await?
        .ok_or_else(not_found)?;
    // Held across the read and the write of the member row, so a concurrent
    // edit of another field (a forge-account link, say) is not lost to this
    // whole-row write. Released before the role ceremony below, which does its
    // own writes.
    let edit_guard = crate::members::storage::edit_lock().await;
    let mut member = get_member(&state.members_ks, did)
        .await?
        .ok_or_else(not_found)?;

    // Non-role field updates — written directly (not a ceremony).
    // Persisted *before* any role change so the Remint executor (which
    // re-reads the member to repoint its role VEC) sees them.
    let mut fields_changed: Vec<String> = Vec::new();
    let mut changes: Vec<FieldChange> = Vec::new();
    if let Some(consent) = req.publish_consent
        && consent != member.publish_consent
    {
        changes.push(FieldChange {
            field: "publishConsent".into(),
            old: Some(JsonValue::Bool(member.publish_consent)),
            new: Some(JsonValue::Bool(consent)),
        });
        member.publish_consent = consent;
        fields_changed.push("publishConsent".into());
    }
    if let Some(pref) = req.departure_preference
        && pref != member.departure_preference
    {
        changes.push(FieldChange {
            field: "departurePreference".into(),
            old: serde_json::to_value(member.departure_preference).ok(),
            new: serde_json::to_value(pref).ok(),
            // (Disposition is Copy; values captured before the move below.)
        });
        member.departure_preference = pref;
        fields_changed.push("departurePreference".into());
    }
    if let Some(extensions) = req.extensions
        && extensions != member.extensions
    {
        changes.push(FieldChange {
            field: "extensions".into(),
            old: Some(member.extensions.clone()),
            new: Some(extensions.clone()),
        });
        member.extensions = extensions;
        fields_changed.push("extensions".into());
    }
    if !fields_changed.is_empty() {
        store_member(&state.members_ks, &member).await?;
    }
    drop(edit_guard);

    // The label lives on the ACL row, not the member row. Written before any
    // role change so the ceremony (which re-reads the ACL entry) picks it up
    // rather than overwriting it from a stale copy.
    if let Some(ref requested) = req.label {
        let trimmed = requested.trim();
        let new_label = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
        if new_label != acl.label {
            changes.push(FieldChange {
                field: "label".into(),
                old: acl.label.clone().map(JsonValue::String),
                new: new_label.clone().map(JsonValue::String),
            });
            let mut updated = acl.clone();
            updated.label = new_label;
            updated.updated_at = Some(now_epoch());
            updated.updated_by = Some(auth.did.clone());
            crate::acl::store_acl_entry(&state.acl_ks, &updated).await?;
            fields_changed.push("label".into());
        }
    }

    // Role change → the role-change ceremony.
    let role_change = match req.role {
        Some(new_role) if new_role != acl.role => Some(new_role),
        _ => None,
    };
    if let Some(new_role) = role_change {
        // `admin` was refused at the top, so this is always a lateral move or
        // a demotion — the serialisation and the elevation gate the promotion
        // path needs are the ceremony's, not this handler's.
        let granted = crate::ceremony::role_change_via_pipeline(
            state,
            auth,
            did,
            &acl.role.to_string(),
            &new_role.to_string(),
        )
        .await?;

        audit_writer
            .write(
                &auth.did,
                Some(did),
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
                &auth.did,
                Some(did),
                AuditEvent::MemberUpdated(MemberUpdatedData {
                    fields_changed: fields_changed.clone(),
                    changes,
                }),
            )
            .await?;
    }

    // Re-read the authoritative state for the response — the Remint
    // executor may have changed the ACL role + the member's role-VEC
    // pointer.
    let acl = get_acl_entry(&state.acl_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;
    let member = get_member(&state.members_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;

    // `{member: …}` — the shape `vtc/members/update/0.1` publishes, same as
    // its `show` sibling. The row was returned bare until #1094.
    Ok(MemberEnvelope {
        member: MemberResponse::from_pair_for_route(acl, member),
    })
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
            joined_via_invitation: member.joined_via_invitation,
            member_vmc_id: member.member_vmc_id,
            member_vmc_received_at: member.member_vmc_received_at,
        }
    }
}
