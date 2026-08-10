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
    State(state): State<AppState>,
    Json(req): Json<CreateAclRequest>,
) -> Result<(StatusCode, Json<CreateAclResponseBody>), AppError> {
    // The PDP gate, in-handler because the consent digest is taken over the
    // payload — an extractor cannot see the body.
    //
    // Gated on the whole body rather than on `req.entry`: the trust-task path
    // digests `doc.payload`, the entire `{entry: …}` object, and the two must
    // agree or an approval obtained over one transport could not be consumed
    // over the other.
    crate::trust_tasks::rest_gate(
        &state,
        &auth.0,
        vta_sdk::trust_tasks::TASK_ACL_GRANT_0_1,
        &serde_json::to_value(&req)?,
    )
    .await?;

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

// `Serialize` so the handler can hand the body to the PDP gate as JSON; the
// digest an approver signs must be taken over what the caller actually sent.
#[derive(Debug, Deserialize, serde::Serialize, utoipa::ToSchema)]
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
    /// Replace the signing-oracle key filter (#818). Omitted leaves it
    /// unchanged; explicit `null` clears it (privilege increase); an array
    /// sets it to exactly those ids — **the empty array means no keys at
    /// all**, never a wildcard. Wire name pinned to the canonical
    /// `allowedKeys` (the SDK's `UpdateAclRequest` serializes the same).
    #[serde(rename = "allowedKeys", default, deserialize_with = "double_option")]
    pub allowed_keys: Option<Option<Vec<String>>>,
}

/// Absent vs explicit-null, distinguishably: absent → `None` (leave alone),
/// `null` → `Some(None)` (clear), value → `Some(Some(v))`. A plain
/// `Option<Option<T>>` folds `null` into the outer `None` and loses the
/// clearing intent.
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(de).map(Some)
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

    // Gate after the shape check above, so a caller who sent an unsupported
    // patch is told that rather than being sent to find an approver for a
    // request that could never have executed.
    crate::trust_tasks::rest_gate(
        &state,
        &auth.0,
        vta_sdk::trust_tasks::TASK_ACL_UPDATE_0_1,
        &serde_json::to_value(&req)?,
    )
    .await?;

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
            allowed_keys: req
                .allowed_keys
                .map(|r| r.map(|keys| keys.into_iter().collect())),
        },
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// Request body for `POST /acl/{did}/change-role`.
// `Serialize` for the PDP gate — see `UpdateAclRequest`.
#[derive(Debug, Deserialize, serde::Serialize, utoipa::ToSchema)]
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
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<ChangeRoleRequest>,
) -> Result<Json<CreateAclResponseBody>, AppError> {
    crate::trust_tasks::rest_gate(
        &state,
        &auth.0,
        vta_sdk::trust_tasks::TASK_ACL_CHANGE_ROLE_0_1,
        &serde_json::to_value(&req)?,
    )
    .await?;

    let result = operations::acl::change_role_by_subject(
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
    Ok(Json(result))
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
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    // A DELETE carries no body, so the gated payload is the path parameter —
    // the same `{subject}` the `acl/revoke` trust task binds its digest to.
    crate::trust_tasks::rest_gate(
        &state,
        &auth.0,
        vta_sdk::trust_tasks::TASK_ACL_REVOKE_0_1,
        &serde_json::json!({ "subject": did }),
    )
    .await?;

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
///
/// `Serialize` so the handler can hand the body to the PDP gate. It serializes
/// **camelCase**, matching the canonical payload the trust-task path digests —
/// the snake_case spellings are read-aliases only. If this emitted
/// `current_subject`, the same rotation would digest differently depending on
/// which transport carried it, and an approval obtained over one could not be
/// consumed over the other.
#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(untagged)]
#[derive(utoipa::ToSchema)]
pub enum SwapAclRequest {
    /// Canonical Trust Task `acl/swap-key/0.1` body. Discriminated by the
    /// presence of `linkProof` (camelCase per spec, with snake_case alias).
    #[serde(rename_all = "camelCase")]
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
        ///
        /// Skipped when absent so the digest of a body that omitted it matches
        /// the trust-task payload that likewise omitted it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
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
    State(state): State<AppState>,
    Json(req): Json<SwapAclRequest>,
) -> Result<Json<CreateAclResultBody>, AppError> {
    // The PDP gate. This route carried the `RequireStepUp<AclSwapKeyOp>`
    // extractor instead — the one gated REST route #912 left on the old
    // trigger, because its floor had a non-escalation carve-out the shared gate
    // has no concept of. Retiring the floors takes the extractor with it, so the
    // gate has to be here, or self-service key rotation would be the one ACL
    // mutation a `requireConsent` rule bound over trust tasks and silently not
    // over REST.
    //
    // Digested over the canonical `acl/swap-key/0.1` payload so an approval is
    // interchangeable between the two transports. The legacy `{presentation}`
    // body has no canonical form; it is digested as it arrived, which is
    // consistent — a legacy caller can only re-submit the same legacy body.
    crate::trust_tasks::rest_gate(
        &state,
        &auth,
        vta_sdk::trust_tasks::TASK_ACL_SWAP_KEY_0_1,
        &serde_json::to_value(&req)?,
    )
    .await?;

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
