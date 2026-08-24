//! `PATCH /v1/members/{did}` — M1.5.1.
//!
//! Non-role fields (publish consent, departure preference, extensions)
//! are written directly. A **role change** is the role-change ceremony:
//! it runs through the decision pipeline ([`crate::ceremony`]) —
//! assemble Facts → decide the active `roleChange` policy → apply via
//! the `Remint` executor arm (which updates the ACL role in place,
//! re-mints the role VEC, and enforces no-last-admin on demotion).
//!
//! `role=admin` is assignable here, and is the one transition that
//! additionally demands a **live step-up elevation** on the caller's session
//! (`vti_common::auth::extractor::StepUpAuth`'s rule, applied in-handler
//! because it governs one field value, not the whole route).
//!
//! It used to live on its own fused endpoint,
//! `POST /v1/members/{did}/promote-to-admin/{start,finish}`, which ran a
//! WebAuthn UV ceremony and the role change in one pair of requests. That
//! fused the *authentication* ceremony into the *authorisation* operation:
//! two Trust Tasks' worth of semantics under one URI, and a second
//! implementation of passkey UV alongside `auth/passkey/login`. The API split
//! separates them — step the session up via
//! `auth/passkey/login/{start,finish}/0.2` with `purpose: stepUp`, then change
//! the role here — so each canonical task does one thing and the elevation is
//! reusable by any other privileged operation.
//!
//! The security properties the fused endpoint had are all preserved: user
//! verification is required (by the step-up ceremony), the promotion is
//! serialised against concurrent role writes, an already-admin target is
//! refused inside the critical section, and the change still flows through
//! `role_change_via_pipeline` with `step_up = true` so `role_change.rego`
//! governs it (P0.14). What changes is *when* the UV happens — recently, in a
//! separate request — which is exactly what makes the elevation window
//! meaningful.

use axum::Json;
use axum::extract::{Path, State};
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use tokio::sync::Mutex;

use vti_common::audit::{
    AdminPromotedData, AuditEvent, FieldChange, MemberUpdatedData, RoleChangedData,
};

use crate::acl::admin::{AdminEntry, get_admin_entry, store_admin_entry};
use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry};
use crate::auth::{AdminAuth, session::now_epoch};
use crate::error::AppError;
use crate::members::{Disposition, Member, get_member, store_member};
use crate::routes::members::read::{MemberEnvelope, MemberResponse};
use crate::server::AppState;

/// Serialises admin promotions per-process. Inherited from the retired
/// `promote-to-admin` endpoint, where it closed the window between the
/// already-admin check and the ACL write; the same window exists here.
static PROMOTE_LOCK: Mutex<()> = Mutex::const_new(());

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
#[utoipa::path(
    patch, path = "/members/{did}", tag = "members",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Member DID")),
    request_body = UpdateMemberRequest,
    responses(
        (status = 200, description = "Updated member record", body = MemberEnvelope),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin / role change denied by policy / step-up required for role=admin"),
        (status = 404, description = "Member not found"),
        (status = 409, description = "Target is already an admin"),
    ),
)]
pub async fn update_member(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<Json<MemberEnvelope>, AppError> {
    vti_common::identifier::validate_did("did", &did)?;

    let promoting = matches!(req.role, Some(VtcRole::Admin));
    if promoting {
        // Self-promotion was refused by the fused endpoint and stays refused:
        // admin elevation needs a second person, not just a second factor.
        if auth.0.did == did {
            return Err(AppError::Validation(
                "you cannot promote yourself; admin elevation requires a separate admin caller"
                    .into(),
            ));
        }
        // The gate that makes this safe. Checked before any work so a caller
        // without a live elevation gets the `step_up_required` signal — which
        // the admin UI turns into a passkey prompt — rather than a partial
        // update.
        auth.0.require_fresh_step_up(&state.sessions_ks).await?;
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
            updated.updated_by = Some(auth.0.did.clone());
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
        // Serialise promotions per-process so a concurrent PATCH racing this
        // one can't smuggle a role mutation in between the already-admin
        // re-check and the ACL write. Held across the ceremony because that is
        // what performs the write. fjall isn't multi-process safe, so a
        // process-wide lock is the right granularity.
        let _guard = if promoting {
            Some(PROMOTE_LOCK.lock().await)
        } else {
            None
        };

        // Re-read under the lock: the pre-flight `acl` above was fetched
        // before it was taken, so an interleaved promotion could have landed
        // since. Refusing here keeps admin promotion idempotent-or-conflict
        // rather than silently re-promoting.
        if promoting {
            let current = get_acl_entry(&state.acl_ks, &did)
                .await?
                .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;
            if current.role == VtcRole::Admin {
                return Err(AppError::Conflict(format!("{did} is already an admin")));
            }
        }

        let granted = crate::ceremony::role_change_via_pipeline(
            &state,
            &auth.0.did,
            &did,
            &acl.role.to_string(),
            &new_role.to_string(),
            // A verified reauth accompanies this change only when we gated on
            // one above. The policy's "admin with a verified step-up" branch
            // reads this; a tightened policy (quorum, tenure) can still deny.
            promoting,
        )
        .await?;

        if promoting {
            // The admin sister record lets the new admin enrol a device
            // through the existing passkey flow. Empty credential list until
            // `admin/passkeys/register` runs.
            if get_admin_entry(&state.passkey_ks, &did).await?.is_none() {
                store_admin_entry(
                    &state.passkey_ks,
                    &AdminEntry {
                        did: did.clone(),
                        passkeys: Vec::new(),
                        extensions: JsonValue::Null,
                        created_at: Utc::now(),
                    },
                )
                .await?;
            }
            // Its own variant, not `RoleChanged`: admin elevation is the
            // highest-privilege grant the community emits and SIEM rules
            // target it directly. `authorising_session_id` is the join key to
            // the `AuthSteppedUp` row that records which credential asserted
            // user verification.
            audit_writer
                .write(
                    &auth.0.did,
                    Some(&did),
                    AuditEvent::AdminPromoted(AdminPromotedData {
                        previous_role: granted.previous_role,
                        authorising_credential_id: String::new(),
                        authorising_session_id: auth.0.session_id.clone(),
                    }),
                )
                .await?;
        } else {
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
    }

    if !fields_changed.is_empty() {
        audit_writer
            .write(
                &auth.0.did,
                Some(&did),
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
    let acl = get_acl_entry(&state.acl_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;
    let member = get_member(&state.members_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;

    // `{member: …}` — the shape `vtc/members/update/0.1` publishes, same as
    // its `show` sibling. The row was returned bare until #1094.
    Ok(Json(MemberEnvelope {
        member: MemberResponse::from_pair_for_route(acl, member),
    }))
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
