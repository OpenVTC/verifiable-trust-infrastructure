use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use tracing::info;

use crate::acl::{
    VtcAclEntry, VtcRole, delete_acl_entry, get_acl_entry, is_acl_entry_visible, list_acl_entries,
    store_acl_entry, validate_acl_modification, validate_vtc_role_assignment,
};
use crate::auth::{AdminAuth, AuthClaims, ManageAuth, session::now_epoch};
use crate::error::AppError;
use crate::server::AppState;

// ---------- GET /acl ----------

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AclEntryResponse {
    pub did: String,
    pub role: VtcRole,
    pub label: Option<String>,
    pub allowed_contexts: Vec<String>,
    pub created_at: u64,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl From<VtcAclEntry> for AclEntryResponse {
    fn from(e: VtcAclEntry) -> Self {
        AclEntryResponse {
            did: e.did,
            role: e.role,
            label: e.label,
            allowed_contexts: e.allowed_contexts,
            created_at: e.created_at,
            created_by: e.created_by,
            expires_at: e.expires_at,
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListAclQuery {
    pub context: Option<String>,
}

/// GET /acl — list ACL entries visible to the caller. Auth: Manage.
#[utoipa::path(
    get, path = "/acl", tag = "acl",
    security(("bearer_jwt" = [])),
    params(ListAclQuery),
    responses(
        (status = 200, description = "Visible ACL entries", body = AclListResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks manage authority"),
    ),
)]
pub async fn list_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Query(query): Query<ListAclQuery>,
) -> Result<Json<AclListResponse>, AppError> {
    let acl = state.acl_ks.clone();
    let all_entries = list_acl_entries(&acl).await?;
    let entries: Vec<AclEntryResponse> = all_entries
        .into_iter()
        .filter(|e| is_acl_entry_visible(&auth.0, &as_vti_acl_entry(e)))
        // Hierarchy-aware: an entry scoped to an *ancestor* of `ctx` grants
        // access to `ctx`, so it's relevant to a query for `ctx`
        // (`docs/05-design-notes/hierarchical-contexts.md`). For flat ids this
        // is identical to an exact match.
        .filter(|e| match &query.context {
            Some(ctx) => e
                .allowed_contexts
                .iter()
                .any(|allowed| vti_common::context_path::is_ancestor_or_self(allowed, ctx)),
            None => true,
        })
        .map(AclEntryResponse::from)
        .collect();
    info!(caller = %auth.0.did, count = entries.len(), "ACL listed");
    Ok(Json(AclListResponse { entries }))
}

// ---------- POST /acl ----------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateAclRequest {
    pub did: String,
    pub role: VtcRole,
    pub label: Option<String>,
    #[serde(default)]
    pub allowed_contexts: Vec<String>,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

/// POST /acl — create a new ACL entry. Auth: Manage.
#[utoipa::path(
    post, path = "/acl", tag = "acl",
    security(("bearer_jwt" = [])),
    request_body = CreateAclRequest,
    responses(
        (status = 201, description = "ACL entry created", body = AclEntryResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks manage authority"),
    ),
)]
pub async fn create_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateAclRequest>,
) -> Result<(StatusCode, Json<AclEntryResponse>), AppError> {
    // Block non-admin callers from granting Admin — role + context
    // bound checks must run before we touch storage.
    validate_vtc_role_assignment(&auth.0, &req.role)?;
    validate_acl_modification(&auth.0, &req.allowed_contexts)?;

    let acl = state.acl_ks.clone();

    // Check if entry already exists
    if get_acl_entry(&acl, &req.did).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "ACL entry already exists for DID: {}",
            req.did
        )));
    }

    let entry = VtcAclEntry {
        did: req.did,
        role: req.role,
        label: req.label,
        allowed_contexts: req.allowed_contexts,
        created_at: now_epoch(),
        created_by: auth.0.did,
        expires_at: req.expires_at,
    };

    store_acl_entry(&acl, &entry).await?;

    info!(caller = %entry.created_by, did = %entry.did, role = %entry.role, "ACL entry created");
    Ok((StatusCode::CREATED, Json(AclEntryResponse::from(entry))))
}

// ---------- GET /acl/{did} ----------

/// GET /acl/{did} — retrieve a single ACL entry. Auth: Manage.
#[utoipa::path(
    get, path = "/acl/{did}", tag = "acl",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Subject DID")),
    responses(
        (status = 200, description = "ACL entry", body = AclEntryResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks manage authority"),
        (status = 404, description = "ACL entry not found"),
    ),
)]
pub async fn get_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<AclEntryResponse>, AppError> {
    let acl = state.acl_ks.clone();
    let entry = get_acl_entry(&acl, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    if !is_acl_entry_visible(&auth.0, &as_vti_acl_entry(&entry)) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }
    info!(did = %did, "ACL entry retrieved");
    Ok(Json(AclEntryResponse::from(entry)))
}

// ---------- PATCH /acl/{did} ----------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateAclRequest {
    pub role: Option<VtcRole>,
    pub label: Option<String>,
    pub allowed_contexts: Option<Vec<String>>,
}

/// PATCH /acl/{did} — modify an ACL entry. Auth: Admin.
#[utoipa::path(
    patch, path = "/acl/{did}", tag = "acl",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Subject DID")),
    request_body = UpdateAclRequest,
    responses(
        (status = 200, description = "Updated ACL entry", body = AclEntryResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "ACL entry not found"),
    ),
)]
pub async fn update_acl(
    // Modifying an ACL entry can downgrade an existing admin or shrink their
    // `allowed_contexts`. Gate on Admin so a non-admin can't tamper with
    // admin entries they happen to see (creation stays on `ManageAuth`).
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<UpdateAclRequest>,
) -> Result<Json<AclEntryResponse>, AppError> {
    let acl = state.acl_ks.clone();
    let mut entry = get_acl_entry(&acl, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;

    // Context admins can only modify entries they can see
    if !is_acl_entry_visible(&auth.0, &as_vti_acl_entry(&entry)) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }

    // Visibility (overlapping contexts) is enough to *see* an admin entry but
    // not to downgrade it: a context-admin of `ctx-a` must not be able to
    // demote a peer admin scoped to `[ctx-a, ctx-b]`, and can never touch a
    // super-admin. Only a super-admin, or an admin covering *every* context
    // the target holds, may modify an existing Admin entry.
    if entry.role == VtcRole::Admin && !caller_covers_admin_target(&auth.0, &entry) {
        return Err(AppError::Forbidden(
            "cannot modify an admin entry scoped outside your contexts".into(),
        ));
    }

    // Snapshot the pre-change authorization so we can detect a privilege
    // reduction after the patch is applied.
    let prev_role = entry.role.clone();
    let prev_contexts = entry.allowed_contexts.clone();

    if let Some(role) = req.role {
        validate_vtc_role_assignment(&auth.0, &role)?;
        entry.role = role;
    }
    if let Some(label) = req.label {
        entry.label = Some(label);
    }
    if let Some(allowed_contexts) = req.allowed_contexts {
        // Validate the new contexts before applying
        validate_acl_modification(&auth.0, &allowed_contexts)?;
        entry.allowed_contexts = allowed_contexts;
    }

    store_acl_entry(&acl, &entry).await?;

    // The `AuthClaims` extractor reads role/contexts straight from the
    // still-valid JWT (only `/auth/refresh` re-checks the ACL), so a demoted
    // admin would otherwise keep admin authority for the full access-token TTL.
    // Revoke the subject's live sessions on any privilege reduction so the
    // stale bearer is rejected on its next request.
    if is_privilege_reduction(
        &prev_role,
        &prev_contexts,
        &entry.role,
        &entry.allowed_contexts,
    ) {
        let sessions = state.sessions_ks.clone();
        let revoked = super::auth::revoke_sessions_for_did(&sessions, &did).await?;
        info!(did = %did, revoked, "subject sessions revoked after ACL privilege reduction");
    }

    info!(did = %did, "ACL entry updated");
    Ok(Json(AclEntryResponse::from(entry)))
}

// ---------- DELETE /acl/{did} ----------

/// DELETE /acl/{did} — remove an ACL entry. Auth: Admin.
#[utoipa::path(
    delete, path = "/acl/{did}", tag = "acl",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Subject DID")),
    responses(
        (status = 204, description = "ACL entry deleted"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "ACL entry not found"),
    ),
)]
pub async fn delete_acl(
    // Deletion is strictly more destructive than the `PATCH` edit, yet the
    // previous `ManageAuth` gate let an Initiator delete entries while `PATCH`
    // required Admin. Gate both on Admin so an Initiator can't delete admin
    // entries it happens to see.
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    // Prevent self-deletion
    if auth.0.did == did {
        return Err(AppError::Conflict(
            "cannot delete your own ACL entry".into(),
        ));
    }

    let acl = state.acl_ks.clone();

    // Verify entry exists and is visible to the caller
    let entry = get_acl_entry(&acl, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    if !is_acl_entry_visible(&auth.0, &as_vti_acl_entry(&entry)) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }

    // Same target-role guard as `update_acl`: overlapping contexts make an
    // admin entry *visible* but not *deletable* by a context-admin scoped
    // outside its full context set, and a super-admin can only be deleted by
    // another super-admin.
    if entry.role == VtcRole::Admin && !caller_covers_admin_target(&auth.0, &entry) {
        return Err(AppError::Forbidden(
            "cannot delete an admin entry scoped outside your contexts".into(),
        ));
    }

    delete_acl_entry(&acl, &did).await?;

    info!(caller = %auth.0.did, did = %did, "ACL entry deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// Translate a `VtcAclEntry` into the `vti_common::acl::AclEntry`
/// shape that the role-agnostic visibility helpers
/// (`is_acl_entry_visible`, `validate_acl_modification`) expect.
/// They only look at `allowed_contexts`, so the role mapping is
/// best-effort — `VtcRole::Admin` → `Role::Admin`, everything else
/// degrades to `Role::Reader` (lowest privilege; only the contexts
/// match), which is fine because these helpers ignore the role
/// field entirely.
pub(crate) fn as_vti_acl_entry(e: &VtcAclEntry) -> vti_common::acl::AclEntry {
    let role = match e.role {
        VtcRole::Admin => vti_common::acl::Role::Admin,
        _ => vti_common::acl::Role::Reader,
    };
    vti_common::acl::AclEntry::new(e.did.clone(), role, e.created_by.clone())
        .with_label(e.label.clone())
        .with_contexts(e.allowed_contexts.clone())
        .with_created_at(e.created_at)
        .with_expires_at(e.expires_at)
}

/// May `caller` delete or downgrade `target`, which is an **Admin** entry?
///
/// Mirrors [`vti_common::acl::delegated_any_approver_covers`]: a super-admin
/// covers any target; a context-admin covers only a context-scoped target
/// **all** of whose contexts fall within the caller's authority. A target with
/// no `allowed_contexts` is itself a super-admin and can only be acted on by a
/// super-admin (the empty-context branch below is `false` for a non-super
/// caller, so it is refused).
fn caller_covers_admin_target(caller: &AuthClaims, target: &VtcAclEntry) -> bool {
    if caller.is_super_admin() {
        return true;
    }
    !target.allowed_contexts.is_empty()
        && target
            .allowed_contexts
            .iter()
            .all(|ctx| caller.has_context_access(ctx))
}

/// Did an ACL update reduce the subject's authorization?
///
/// A reduction is either losing the `Admin` role, or narrowing the context
/// scope — going from unrestricted (empty `allowed_contexts`, i.e. super-admin)
/// to restricted, or dropping any previously-held context. Widening scope or a
/// lateral role change is not a reduction. Used to decide whether the subject's
/// live sessions must be revoked so the still-valid JWT can't outlive the
/// downgrade.
fn is_privilege_reduction(
    prev_role: &VtcRole,
    prev_contexts: &[String],
    new_role: &VtcRole,
    new_contexts: &[String],
) -> bool {
    let lost_admin = *prev_role == VtcRole::Admin && *new_role != VtcRole::Admin;
    let narrowed = if prev_contexts.is_empty() {
        // Previously unrestricted (super-admin scope); any restriction narrows.
        !new_contexts.is_empty()
    } else {
        // Previously restricted; dropping any held context narrows. (A move to
        // empty/unrestricted is a *widening*, handled by the `false` here.)
        !new_contexts.is_empty() && prev_contexts.iter().any(|c| !new_contexts.contains(c))
    };
    lost_admin || narrowed
}

#[cfg(test)]
mod tests {
    //! Wire-shape tests for the ACL route bodies. Full route integration
    //! (spawning the router with a real AppState) requires a test-support
    //! harness paralleling vta-service/src/test_support.rs; that's tracked
    //! separately. These tests catch serde regressions — e.g. someone
    //! renaming a field, changing a default, or breaking backward
    //! compatibility with the CLI clients that consume these types.
    use super::*;
    use serde_json::json;

    // ── P0.20: admin-target covering guard ─────────────────────────

    fn claims(super_admin: bool, contexts: &[&str]) -> AuthClaims {
        AuthClaims {
            role: vti_common::acl::Role::Admin,
            allowed_contexts: if super_admin {
                vec![]
            } else {
                contexts.iter().map(|c| c.to_string()).collect()
            },
            ..Default::default()
        }
    }

    fn admin_entry(contexts: &[&str]) -> VtcAclEntry {
        VtcAclEntry {
            did: "did:key:zTarget".into(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: contexts.iter().map(|c| c.to_string()).collect(),
            created_at: 0,
            created_by: "did:key:zCreator".into(),
            expires_at: None,
        }
    }

    #[test]
    fn super_admin_covers_any_admin_target() {
        let sa = claims(true, &[]);
        assert!(caller_covers_admin_target(
            &sa,
            &admin_entry(&["ctx-a", "ctx-b"])
        ));
        assert!(caller_covers_admin_target(&sa, &admin_entry(&[]))); // super-admin target
    }

    #[test]
    fn context_admin_covers_only_targets_fully_within_its_scope() {
        let ca = claims(false, &["ctx-a"]);
        // Target scoped exactly to ctx-a → covered.
        assert!(caller_covers_admin_target(&ca, &admin_entry(&["ctx-a"])));
        // Accept-criterion: ctx-a admin can't act on an admin scoped to
        // [ctx-a, ctx-b] — ctx-b is outside its authority.
        assert!(!caller_covers_admin_target(
            &ca,
            &admin_entry(&["ctx-a", "ctx-b"])
        ));
        // A context-admin can never act on a super-admin (empty-context) target.
        assert!(!caller_covers_admin_target(&ca, &admin_entry(&[])));
    }

    // ── P0.20: privilege-reduction detection ───────────────────────

    #[test]
    fn losing_admin_role_is_a_reduction() {
        assert!(is_privilege_reduction(
            &VtcRole::Admin,
            &["ctx-a".into()],
            &VtcRole::Member,
            &["ctx-a".into()],
        ));
    }

    #[test]
    fn narrowing_contexts_is_a_reduction() {
        // Drop a held context.
        assert!(is_privilege_reduction(
            &VtcRole::Admin,
            &["ctx-a".into(), "ctx-b".into()],
            &VtcRole::Admin,
            &["ctx-a".into()],
        ));
        // Unrestricted → restricted.
        assert!(is_privilege_reduction(
            &VtcRole::Admin,
            &[],
            &VtcRole::Admin,
            &["ctx-a".into()],
        ));
        // Swap a context (lose ctx-a, gain ctx-b).
        assert!(is_privilege_reduction(
            &VtcRole::Admin,
            &["ctx-a".into()],
            &VtcRole::Admin,
            &["ctx-b".into()],
        ));
    }

    #[test]
    fn widening_or_lateral_change_is_not_a_reduction() {
        // Add a context.
        assert!(!is_privilege_reduction(
            &VtcRole::Admin,
            &["ctx-a".into()],
            &VtcRole::Admin,
            &["ctx-a".into(), "ctx-b".into()],
        ));
        // Restricted → unrestricted (promotion to super-admin scope).
        assert!(!is_privilege_reduction(
            &VtcRole::Admin,
            &["ctx-a".into()],
            &VtcRole::Admin,
            &[],
        ));
        // No change (e.g. a label-only edit).
        assert!(!is_privilege_reduction(
            &VtcRole::Member,
            &["ctx-a".into()],
            &VtcRole::Member,
            &["ctx-a".into()],
        ));
    }

    // ── CreateAclRequest ────────────────────────────────────────────

    #[test]
    fn create_acl_request_parses_minimal_body() {
        let body = json!({ "did": "did:key:zABC", "role": "admin" });
        let req: CreateAclRequest = serde_json::from_value(body).expect("minimal body");
        assert_eq!(req.did, "did:key:zABC");
        assert_eq!(req.role, VtcRole::Admin);
        assert_eq!(req.label, None);
        assert!(req.allowed_contexts.is_empty(), "defaults to empty");
        assert_eq!(req.expires_at, None);
    }

    #[test]
    fn create_acl_request_parses_full_body() {
        let body = json!({
            "did": "did:key:zABC",
            "role": "moderator",
            "label": "ops lead",
            "allowed_contexts": ["ctx1", "ctx2"],
            "expires_at": 1_800_000_000u64,
        });
        let req: CreateAclRequest = serde_json::from_value(body).expect("full body");
        assert_eq!(req.role, VtcRole::Moderator);
        assert_eq!(req.label.as_deref(), Some("ops lead"));
        assert_eq!(req.allowed_contexts, vec!["ctx1", "ctx2"]);
        assert_eq!(req.expires_at, Some(1_800_000_000));
    }

    #[test]
    fn create_acl_request_rejects_unknown_role() {
        let body = json!({ "did": "did:key:zA", "role": "godmode" });
        let err = serde_json::from_value::<CreateAclRequest>(body)
            .expect_err("unknown role must not parse");
        let msg = format!("{err}");
        assert!(
            msg.contains("godmode") || msg.contains("unknown"),
            "got {msg}"
        );
    }

    #[test]
    fn create_acl_request_rejects_missing_required() {
        let body = json!({ "role": "admin" });
        serde_json::from_value::<CreateAclRequest>(body)
            .expect_err("missing `did` must be rejected");
    }

    // ── UpdateAclRequest ───────────────────────────────────────────

    #[test]
    fn update_acl_request_all_fields_optional() {
        let empty = json!({});
        let req: UpdateAclRequest = serde_json::from_value(empty).expect("empty body parses");
        assert!(req.role.is_none());
        assert!(req.label.is_none());
        assert!(req.allowed_contexts.is_none());
    }

    #[test]
    fn update_acl_request_parses_role_only() {
        let body = json!({ "role": "member" });
        let req: UpdateAclRequest = serde_json::from_value(body).unwrap();
        assert_eq!(req.role, Some(VtcRole::Member));
    }

    // ── ListAclQuery ───────────────────────────────────────────────

    #[test]
    fn list_acl_query_context_is_optional() {
        let q: ListAclQuery = serde_json::from_value(json!({})).unwrap();
        assert!(q.context.is_none());

        let q: ListAclQuery = serde_json::from_value(json!({ "context": "app1" })).unwrap();
        assert_eq!(q.context.as_deref(), Some("app1"));
    }

    // ── AclEntryResponse ───────────────────────────────────────────

    #[test]
    fn acl_entry_response_serializes_with_stable_field_names() {
        let entry = VtcAclEntry {
            did: "did:key:zABC".into(),
            role: VtcRole::Admin,
            label: Some("test".into()),
            allowed_contexts: vec!["ctx1".into()],
            created_at: 1_700_000_000,
            created_by: "did:key:zSetup".into(),
            expires_at: Some(1_800_000_000),
        };
        let resp = AclEntryResponse::from(entry);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["did"], "did:key:zABC");
        assert_eq!(json["role"], "admin");
        assert_eq!(json["label"], "test");
        assert_eq!(json["allowed_contexts"], json!(["ctx1"]));
        assert_eq!(json["created_at"], 1_700_000_000);
        assert_eq!(json["created_by"], "did:key:zSetup");
        assert_eq!(json["expires_at"], 1_800_000_000);
    }

    #[test]
    fn acl_entry_response_omits_expires_at_when_permanent() {
        let entry = VtcAclEntry {
            did: "did:key:zPerm".into(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: vec![],
            created_at: 1_700_000_000,
            created_by: "did:key:zSetup".into(),
            expires_at: None,
        };
        let resp = AclEntryResponse::from(entry);
        let json = serde_json::to_value(&resp).unwrap();
        assert!(
            json.get("expires_at").is_none(),
            "permanent entries must omit expires_at — got {json}"
        );
    }

    // ── AclListResponse round-trip ─────────────────────────────────

    #[test]
    fn acl_list_response_round_trips() {
        let entries = vec![AclEntryResponse {
            did: "did:key:zA".into(),
            role: VtcRole::Member,
            label: None,
            allowed_contexts: vec![],
            created_at: 0,
            created_by: "did:key:zS".into(),
            expires_at: None,
        }];
        let resp = AclListResponse { entries };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""entries":"#), "got {json}");
        assert!(json.contains(r#""role":"member""#));
    }

    #[test]
    fn custom_role_round_trip_through_request_body() {
        let body = json!({
            "did": "did:key:zEditor",
            "role": "custom:editor",
        });
        let req: CreateAclRequest = serde_json::from_value(body).expect("custom role parses");
        assert_eq!(req.role, VtcRole::Custom("editor".into()));
        // Round-trip via the response shape.
        let entry = VtcAclEntry {
            did: req.did,
            role: req.role,
            label: None,
            allowed_contexts: vec![],
            created_at: 0,
            created_by: "did:key:zS".into(),
            expires_at: None,
        };
        let resp = AclEntryResponse::from(entry);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["role"], "custom:editor");
    }
}
