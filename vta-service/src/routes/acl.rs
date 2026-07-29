use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;

use vta_sdk::protocols::acl_management::{
    create::{CreateAclResponseBody, CreateAclResultBody},
    get::GetAclResultBody,
    list::ListAclResultBody,
};

use crate::acl::{ApproveScope, ContextDirection, Role};
use crate::auth::{AdminAuth, AuthClaims, ManageAuth};
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;
use crate::trust_tasks::{AclChangeRoleOp, AclGrantOp, AclRevokeOp, AclSwapKeyOp, RequireStepUp};

#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListAclQuery {
    pub context: Option<String>,
    /// Which way `context` reads along the hierarchy: `acting-in` (default —
    /// entries that may act *in* the context, i.e. scoped to it or an
    /// ancestor), `subtree` (entries granted at or *beneath* it — the
    /// revocation-sweep direction), or `any` (the union).
    ///
    /// Taken as a string and parsed here rather than deserialized straight
    /// into the enum so a typo answers with the valid set instead of serde's
    /// "unknown variant" — the operator-errors-suggest-the-fix rule.
    pub direction: Option<String>,
}

/// GET /acl — list all ACL entries, optionally filtered by context. Auth: Admin or Initiator.
#[utoipa::path(
    get, path = "/acl", tag = "acl",
    security(("bearer_jwt" = [])),
    params(ListAclQuery),
    responses(
        (status = 200, description = "ACL entries", body = ListAclResultBody),
        (status = 400, description = "Unparseable `direction`, or a direction without a context"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller cannot manage ACL entries"),
    ),
)]
pub async fn list_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Query(query): Query<ListAclQuery>,
) -> Result<Json<ListAclResultBody>, AppError> {
    let direction = parse_direction(query.direction.as_deref())?;
    let result = operations::acl::list_entries(
        &state.acl_ks,
        &auth.0,
        query.context.as_deref(),
        direction,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// Parse the `direction` query parameter, defaulting to the historical
/// ancestor-or-self reading when it is absent and **refusing** anything it
/// cannot parse. Guessing which of the two opposite questions an operator
/// meant is how a confidently-wrong answer gets served.
fn parse_direction(raw: Option<&str>) -> Result<ContextDirection, AppError> {
    match raw {
        None => Ok(ContextDirection::default()),
        Some(s) => s.parse().map_err(AppError::Validation),
    }
}

/// REST body for `POST /acl`, identical to the canonical `acl/grant/0.1`
/// payload — the same interface the DIDComm and trust-task transports carry,
/// rather than a REST-shaped variant of it.
pub type CreateAclRequest = vta_sdk::protocols::acl_management::create::CreateAclBody;

/// POST /acl — create a new ACL entry for a DID. Auth: Admin or Initiator.
#[utoipa::path(
    post, path = "/acl", tag = "acl",
    security(("bearer_jwt" = [])),
    request_body = CreateAclRequest,
    responses(
        (status = 201, description = "ACL entry created", body = CreateAclResponseBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller cannot manage ACL entries"),
    ),
)]
pub async fn create_acl(
    auth: ManageAuth,
    // Role first, step-up second: a caller lacking the role gets a permission
    // error; an authorized AAL1 caller gets the step-up `403`. ACL mutations
    // require AAL2 (operator policy).
    _step_up: RequireStepUp<AclGrantOp>,
    State(state): State<AppState>,
    Json(req): Json<CreateAclRequest>,
) -> Result<(StatusCode, Json<CreateAclResponseBody>), AppError> {
    let result = operations::acl::grant_from_entry(
        &state.acl_ks,
        &state.audit_ks,
        &state.contexts_ks,
        &auth.0,
        req.entry,
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

/// GET /acl/{did} — retrieve a single ACL entry by DID. Auth: Admin or Initiator.
#[utoipa::path(
    get, path = "/acl/{did}", tag = "acl",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Subject DID")),
    responses(
        (status = 200, description = "ACL entry", body = GetAclResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller cannot manage ACL entries"),
        (status = 404, description = "ACL entry not found"),
    ),
)]
pub async fn get_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<GetAclResultBody>, AppError> {
    let result = operations::acl::show_by_subject(&state.acl_ks, &auth.0, &did, "rest").await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateAclRequest {
    pub role: Option<Role>,
    pub label: Option<String>,
    pub allowed_contexts: Option<Vec<String>>,
    /// Set the delegated step-up approver VID (`Some` sets; `None` leaves).
    #[serde(default)]
    pub step_up_approver: Option<String>,
    /// Set the per-entry step-up override (`"self"` | `"delegated"`; empty
    /// string clears; `None` leaves unchanged).
    #[serde(default)]
    pub step_up_require: Option<String>,
    /// Set the approve scope to exactly this value; omit to leave unchanged.
    ///
    /// Clearing is `{"kind":"none"}` — an explicit value, not absence. Unlike
    /// create, which takes `approve_all_contexts` + `approve_contexts` as two
    /// independent fields, the update path carries the enum itself: with two
    /// fields there is no way to distinguish "revoke this approver" from
    /// "leave it alone", and revoking is the case that matters most.
    #[serde(default)]
    pub approve_scope: Option<ApproveScope>,
}

/// PATCH /acl/{did} — update label, contexts, step-up or approve authority on
/// an ACL entry. Auth: Admin only (the operation layer also enforces this;
/// gating at the extractor fails earlier with a clearer error).
///
/// **Role changes are refused here.** They belong to
/// `POST /acl/{did}/change-role`, which carries the `fromRole`
/// compare-and-swap; applying one without that check is how a concurrent
/// demotion gets silently overwritten.
#[utoipa::path(
    patch, path = "/acl/{did}", tag = "acl",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Subject DID")),
    request_body = UpdateAclRequest,
    responses(
        (status = 200, description = "ACL entry updated", body = CreateAclResponseBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "ACL entry not found"),
    ),
)]
pub async fn update_acl(
    auth: AdminAuth,
    _step_up: RequireStepUp<AclChangeRoleOp>,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<UpdateAclRequest>,
) -> Result<Json<CreateAclResponseBody>, AppError> {
    // Refuse rather than ignore. Silently dropping a role from a patch
    // would report success while leaving the subject's privileges exactly
    // as they were — the caller believes they demoted someone who is still
    // an admin.
    if let Some(role) = &req.role {
        return Err(AppError::Validation(format!(
            "role changes are not part of `acl/update`; they need the compare-and-swap that \
             `acl/change-role` carries. Run: pnm acl change-role --did {did} --from \
             <current-role> --to {role}"
        )));
    }
    let result = operations::acl::update_from_params(
        &state.acl_ks,
        &state.audit_ks,
        &state.contexts_ks,
        &auth.0,
        &did,
        operations::acl::UpdateAclParams {
            role: None,
            label: req.label,
            allowed_contexts: req.allowed_contexts,
            step_up_approver: req.step_up_approver,
            step_up_require: req.step_up_require,
            approve_scope: req.approve_scope,
            // The REST body does not carry expiry or a rationale; the
            // canonical trust-task body does.
            expires_at: None,
            reason: None,
        },
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// Request body for `POST /acl/{did}/change-role`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChangeRoleRequest {
    /// The role the caller believes the subject currently holds. A
    /// mismatch against the stored role is refused rather than applied.
    pub from_role: String,
    pub to_role: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// POST /acl/{did}/change-role — transition a subject's role, guarded by a
/// compare-and-swap on `fromRole`. Auth: Admin only.
///
/// Split from `PATCH /acl/{did}` because role is the one attribute where a
/// lost update is a privilege change: without the check, two admins on the
/// same stale read silently overwrite one another and the loser's intent —
/// a demotion, say — disappears with no error.
#[utoipa::path(
    post, path = "/acl/{did}/change-role", tag = "acl",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Subject DID")),
    request_body = ChangeRoleRequest,
    responses(
        (status = 200, description = "Role changed", body = CreateAclResponseBody),
        (status = 400, description = "Role not recognized"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller may not confer the target role"),
        (status = 404, description = "ACL entry not found"),
        (status = 409, description = "Stored role does not match fromRole"),
    ),
)]
pub async fn change_role(
    auth: AdminAuth,
    _step_up: RequireStepUp<AclChangeRoleOp>,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<ChangeRoleRequest>,
) -> Result<Json<CreateAclResponseBody>, AppError> {
    let stored = operations::acl::change_role(
        &state.acl_ks,
        &state.audit_ks,
        &auth.0,
        &did,
        &req.from_role,
        &req.to_role,
        req.reason.as_deref(),
        "rest",
    )
    .await?;
    Ok(Json(CreateAclResponseBody {
        entry: vta_sdk::protocols::acl_management::entry::AclEntry::from_result(&stored),
    }))
}

/// DELETE /acl/{did} — remove an ACL entry. Auth: Admin or Initiator.
#[utoipa::path(
    delete, path = "/acl/{did}", tag = "acl",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Subject DID")),
    responses(
        (status = 204, description = "ACL entry removed"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller cannot manage ACL entries"),
        (status = 404, description = "ACL entry not found"),
    ),
)]
pub async fn delete_acl(
    auth: ManageAuth,
    _step_up: RequireStepUp<AclRevokeOp>,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    operations::acl::delete_acl(&state.acl_ks, &state.audit_ks, &auth.0, &did, "rest").await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Request body for `POST /acl/swap`. Accepts both the legacy `{ presentation }`
/// shape (FPN-private) and the canonical Trust Task `acl/swap-key/0.1` shape
/// `{ currentSubject, newSubject, linkProof, reason? }`. Distinguished by serde
/// `untagged` — the canonical variant has the discriminating `linkProof` field.
/// Field-name aliases let the canonical variant accept both `link_proof`
/// (snake_case from a Rust producer) and `linkProof` (camelCase from a TS
/// producer); the spec is camelCase.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[derive(utoipa::ToSchema)]
pub enum SwapAclRequest {
    /// Canonical Trust Task `acl/swap-key/0.1` body. Discriminated by the
    /// presence of `linkProof` (camelCase per spec, with snake_case alias).
    Canonical {
        #[serde(alias = "current_subject")]
        current_subject: String,
        #[serde(alias = "new_subject")]
        new_subject: String,
        #[serde(alias = "link_proof")]
        link_proof: String,
        /// Accepted per the spec but not currently surfaced to the audit
        /// log — will be wired through when the swap_acl operation signature
        /// grows a reason parameter. Tolerating the field now means existing
        /// clients can populate it without breaking on a subsequent migration.
        #[serde(default)]
        #[allow(dead_code)]
        reason: Option<String>,
    },
    /// Legacy FPN-private body.
    Legacy {
        /// Compact Ed25519 JWS (VP-JWT) proving control of the new DID.
        presentation: String,
    },
}

/// POST /acl/swap — atomically rotate the caller's own ACL entry onto a new
/// DID proven by the presentation. Auth: any authenticated caller (the swap is
/// self-service — it only moves the caller's own grant, copying role+contexts).
///
/// Accepts both the legacy `{ presentation }` body and the canonical Trust Task
/// `acl/swap-key/0.1` body during the deprecation window.
#[utoipa::path(
    post, path = "/acl/swap", tag = "acl",
    security(("bearer_jwt" = [])),
    request_body = SwapAclRequest,
    responses(
        (status = 200, description = "ACL entry swapped onto the new DID", body = CreateAclResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn swap_acl(
    auth: AuthClaims,
    _step_up: RequireStepUp<AclSwapKeyOp>,
    State(state): State<AppState>,
    Json(req): Json<SwapAclRequest>,
) -> Result<Json<CreateAclResultBody>, AppError> {
    let (presentation, claimed_new_subject) = match req {
        SwapAclRequest::Canonical {
            current_subject,
            new_subject,
            link_proof,
            reason: _,
        } => {
            if current_subject != auth.did {
                return Err(AppError::Validation(format!(
                    "acl/swap-key: currentSubject {} does not equal authenticated caller {}",
                    current_subject, auth.did
                )));
            }
            (link_proof, Some(new_subject))
        }
        SwapAclRequest::Legacy { presentation } => (presentation, None),
    };

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = {
        let config = state.config.read().await;
        config
            .vta_did
            .clone()
            .ok_or_else(|| AppError::Internal("VTA DID not configured".into()))?
    };
    let result = operations::acl::swap_acl(
        &state.acl_ks,
        &state.audit_ks,
        &auth,
        &presentation,
        did_resolver,
        &vta_did,
        "rest",
    )
    .await?;

    if let Some(claimed) = claimed_new_subject
        && claimed != result.did
    {
        return Err(AppError::Validation(format!(
            "acl/swap-key: newSubject {} does not match verified VP holder {}",
            claimed, result.did
        )));
    }

    Ok(Json(result))
}
