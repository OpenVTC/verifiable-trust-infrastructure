use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;

use vta_sdk::protocols::acl_management::{create::CreateAclResultBody, list::ListAclResultBody};

use crate::acl::Role;
use crate::auth::{AdminAuth, AuthClaims, ManageAuth};
use crate::error::AppError;
use crate::operations;
use crate::routes::trust_tasks::{
    AclChangeRoleOp, AclGrantOp, AclRevokeOp, AclSwapKeyOp, RequireStepUp,
};
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct ListAclQuery {
    pub context: Option<String>,
}

/// GET /acl — list all ACL entries, optionally filtered by context. Auth: Admin or Initiator.
pub async fn list_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Query(query): Query<ListAclQuery>,
) -> Result<Json<ListAclResultBody>, AppError> {
    let result =
        operations::acl::list_acl(&state.acl_ks, &auth.0, query.context.as_deref(), "rest").await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct CreateAclRequest {
    pub did: String,
    pub role: Role,
    pub label: Option<String>,
    #[serde(default)]
    pub allowed_contexts: Vec<String>,
    /// Unix-epoch seconds at which this entry auto-expires. Omit or set to
    /// `null` for a permanent entry.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// VID authorized to ratify a delegated AAL2 step-up for this subject
    /// (the approve-request `recipient`). Omit for no delegated approver.
    #[serde(default)]
    pub step_up_approver: Option<String>,
}

/// POST /acl — create a new ACL entry for a DID. Auth: Admin or Initiator.
pub async fn create_acl(
    auth: ManageAuth,
    // Role first, step-up second: a caller lacking the role gets a permission
    // error; an authorized AAL1 caller gets the step-up `403`. ACL mutations
    // require AAL2 (operator policy).
    _step_up: RequireStepUp<AclGrantOp>,
    State(state): State<AppState>,
    Json(req): Json<CreateAclRequest>,
) -> Result<(StatusCode, Json<CreateAclResultBody>), AppError> {
    let result = operations::acl::create_acl(
        &state.acl_ks,
        &state.audit_ks,
        &state.contexts_ks,
        &auth.0,
        &req.did,
        req.role,
        req.label,
        req.allowed_contexts,
        req.expires_at,
        req.step_up_approver,
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

/// GET /acl/{did} — retrieve a single ACL entry by DID. Auth: Admin or Initiator.
pub async fn get_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<CreateAclResultBody>, AppError> {
    let result = operations::acl::get_acl(&state.acl_ks, &auth.0, &did, "rest").await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct UpdateAclRequest {
    pub role: Option<Role>,
    pub label: Option<String>,
    pub allowed_contexts: Option<Vec<String>>,
}

/// PATCH /acl/{did} — update role, label, or allowed contexts for an ACL entry.
/// Auth: Admin only (the operation layer also enforces this; gating at the
/// extractor fails earlier with a clearer error).
pub async fn update_acl(
    auth: AdminAuth,
    _step_up: RequireStepUp<AclChangeRoleOp>,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<UpdateAclRequest>,
) -> Result<Json<CreateAclResultBody>, AppError> {
    let result = operations::acl::update_acl(
        &state.acl_ks,
        &state.audit_ks,
        &state.contexts_ks,
        &auth.0,
        &did,
        operations::acl::UpdateAclParams {
            role: req.role,
            label: req.label,
            allowed_contexts: req.allowed_contexts,
        },
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// DELETE /acl/{did} — remove an ACL entry. Auth: Admin or Initiator.
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
