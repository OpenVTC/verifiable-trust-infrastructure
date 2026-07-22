use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use tracing::info;

use crate::acl::{
    VtcAclEntry, VtcRole, delete_acl_entry, get_acl_entry, is_acl_entry_visible, list_acl_entries,
    store_acl_entry, validate_acl_modification, validate_vtc_role_assignment,
};
use crate::auth::{AdminAuth, AuthClaims, ManageAuth, session::now_epoch};
use crate::error::AppError;
use crate::server::AppState;
use vti_common::audit::{AclChangeData, AclRevokedData, AuditEvent};
use vti_common::pagination::{Cursor, MAX_LIMIT};

// ---------- GET /acl ----------

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
    /// True when more entries match beyond this page; `cursor` is then
    /// present. Required by canonical `acl/list`.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Canonical `acl/_shared` **AclEntry**.
///
/// Renames from VTC's storage shape: `did` → `subject`,
/// `allowed_contexts` → `scopes`. Timestamps are RFC3339 strings, not
/// unix epochs — canonical types them `format: date-time`, and an
/// integer there would be a silent contract break rather than a
/// cosmetic one.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AclEntryResponse {
    pub subject: String,
    pub role: VtcRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub scopes: Vec<String>,
    pub created_at: String,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Unix epoch seconds → RFC3339, for canonical `date-time` fields.
fn epoch_to_rfc3339(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .unwrap_or_default()
        .to_rfc3339()
}

impl From<VtcAclEntry> for AclEntryResponse {
    fn from(e: VtcAclEntry) -> Self {
        AclEntryResponse {
            subject: e.did,
            role: e.role,
            label: e.label,
            scopes: e.allowed_contexts,
            created_at: epoch_to_rfc3339(e.created_at),
            created_by: e.created_by,
            updated_at: e.updated_at.map(epoch_to_rfc3339),
            updated_by: e.updated_by,
            expires_at: e.expires_at.map(epoch_to_rfc3339),
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct ListAclQuery {
    /// Return only entries with this role.
    pub role: Option<String>,
    /// Return only entries carrying this scope (canonical name for
    /// what VTC stores as an allowed context).
    pub scope: Option<String>,
    /// Return only entries whose subject starts with this prefix.
    pub subject_prefix: Option<String>,
    /// Page size. Clamped to `1..=200`. Defaults to 50.
    pub page_size: Option<usize>,
    /// Opaque continuation token from a previous page's `cursor`.
    pub cursor: Option<String>,
}

impl ListAclQuery {
    /// Filters folded into the cursor's HMAC (see
    /// [`vti_common::pagination::Cursor::encode_bound`]) so a page
    /// cannot be resumed under a different filter set — on an ACL that
    /// would silently skip entries an operator believes they reviewed.
    fn cursor_binding(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut field = |v: Option<&str>| {
            let b = v.unwrap_or("").as_bytes();
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(b);
        };
        field(self.role.as_deref());
        field(self.scope.as_deref());
        field(self.subject_prefix.as_deref());
        out
    }

    fn matches(&self, e: &VtcAclEntry) -> bool {
        if let Some(role) = &self.role
            && e.role.to_string() != *role
        {
            return false;
        }
        // Hierarchy-aware, as the pre-migration `context` filter was: an
        // entry scoped to an *ancestor* of `scope` does grant `scope`
        // (`docs/05-design-notes/hierarchical-contexts.md`), so it
        // genuinely "carries" it. For flat ids this is exact match.
        if let Some(scope) = &self.scope
            && !e
                .allowed_contexts
                .iter()
                .any(|allowed| vti_common::context_path::is_ancestor_or_self(allowed, scope))
        {
            return false;
        }
        if let Some(prefix) = &self.subject_prefix
            && !e.did.starts_with(prefix.as_str())
        {
            return false;
        }
        true
    }
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
    let limit = query.page_size.unwrap_or(50).clamp(1, MAX_LIMIT);

    // Visibility first (a caller must never learn an entry exists by
    // watching it fall out of a filter), then the caller's filters.
    let mut matching: Vec<VtcAclEntry> = list_acl_entries(&acl)
        .await?
        .into_iter()
        .filter(|e| is_acl_entry_visible(&auth.0, &as_vti_acl_entry(e)))
        .filter(|e| query.matches(e))
        .collect();
    // Stable order so a cursor means the same thing across calls; the
    // subject is unique, so this is a total order.
    matching.sort_by(|a, b| a.did.cmp(&b.did));

    // Cursors are signed with the audit key, but the audit writer is
    // optional — listing the ACL is a core admin function and must not
    // stop working because audit is switched off. Without a key we
    // simply cannot mint or verify a cursor, so the whole visible set
    // is served as one page (which is what this endpoint did before it
    // paginated) and a supplied cursor is rejected rather than trusted
    // unverified.
    let audit_key = match state.audit_writer.as_ref() {
        Some(w) => Some(w.active_key().await?),
        None => None,
    };
    let binding = query.cursor_binding();

    let start = match (&query.cursor, &audit_key) {
        (Some(wire), Some(key)) => {
            let c = Cursor::decode_bound(wire, &key.key, &binding)?;
            matching
                .iter()
                .position(|e| e.did.as_bytes() > c.last_key.as_slice())
                .unwrap_or(matching.len())
        }
        // A cursor we cannot verify is not a cursor.
        (Some(_), None) => return Err(AppError::InvalidCursor),
        (None, _) => 0,
    };

    let take = if audit_key.is_some() {
        limit
    } else {
        matching.len()
    };
    let page: Vec<VtcAclEntry> = matching[start..].iter().take(take).cloned().collect();
    let truncated = start + page.len() < matching.len();
    let cursor = match (&audit_key, truncated) {
        (Some(key), true) => page.last().map(|e| {
            Cursor::new(e.did.as_bytes().to_vec(), matching.len() as u64)
                .encode_bound(&key.key, &binding)
        }),
        _ => None,
    };

    let entries: Vec<AclEntryResponse> = page.into_iter().map(AclEntryResponse::from).collect();
    info!(caller = %auth.0.did, count = entries.len(), truncated, "ACL listed");
    Ok(Json(AclListResponse {
        entries,
        truncated,
        cursor,
    }))
}

// ---------- POST /acl ----------

/// Canonical `acl/grant` request: the entry the maintainer should hold
/// for the subject, plus an optional operator rationale.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateAclRequest {
    pub entry: GrantEntry,
    /// Operator rationale. Emitted on the service log line for this
    /// change; the audit envelope's data types do not carry a free-text
    /// reason today, so this is deliberately not described as audited.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The writable subset of a canonical `AclEntry`. Server-owned fields
/// (`createdAt`/`createdBy`/`updatedAt`/`updatedBy`) are deliberately
/// absent — a caller must not be able to backdate provenance.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantEntry {
    pub subject: String,
    pub role: VtcRole,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// RFC3339, per canonical `AclEntry.expiresAt`.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
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
    let req_entry = req.entry;
    // Block non-admin callers from granting Admin — role + context
    // bound checks must run before we touch storage.
    validate_vtc_role_assignment(&auth.0, &req_entry.role)?;
    validate_acl_modification(&auth.0, &req_entry.scopes)?;

    let acl = state.acl_ks.clone();
    let expires_at = req_entry.expires_at.map(|t| t.timestamp() as u64);

    // Canonical `acl/grant` is "the entry the maintainer should hold":
    // re-granting the *same* role rewrites the entry's scopes/label,
    // but a role change is `acl/change-role`'s job and is refused here
    // — that task carries the `fromRole` compare-and-swap this one has
    // no way to express.
    let existing = get_acl_entry(&acl, &req_entry.subject).await?;
    let (created_at, created_by, status) = match existing {
        Some(prev) => {
            if !is_acl_entry_visible(&auth.0, &as_vti_acl_entry(&prev)) {
                return Err(AppError::NotFound(format!(
                    "ACL entry not found for DID: {}",
                    req_entry.subject
                )));
            }
            if prev.role != req_entry.role {
                return Err(AppError::Conflict(format!(
                    "ACL entry for {} already holds role {}; use acl/change-role \
                     (PATCH /v1/acl/{}) to move it to {}",
                    req_entry.subject, prev.role, req_entry.subject, req_entry.role
                )));
            }
            (prev.created_at, prev.created_by, StatusCode::OK)
        }
        None => (now_epoch(), auth.0.did.clone(), StatusCode::CREATED),
    };

    let entry = VtcAclEntry {
        did: req_entry.subject,
        role: req_entry.role,
        label: req_entry.label,
        allowed_contexts: req_entry.scopes,
        created_at,
        created_by,
        updated_at: (status == StatusCode::OK).then(now_epoch),
        updated_by: (status == StatusCode::OK).then(|| auth.0.did.clone()),
        expires_at,
    };

    store_acl_entry(&acl, &entry).await?;

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &entry.created_by,
                Some(&entry.did),
                AuditEvent::AclGranted(AclChangeData {
                    did: entry.did.clone(),
                    role: entry.role.to_string(),
                    contexts: entry.allowed_contexts.clone(),
                    expires_at: entry.expires_at.map(|e| e.to_string()),
                }),
            )
            .await?;
    }

    info!(
        caller = %auth.0.did,
        did = %entry.did,
        role = %entry.role,
        reason = req.reason.as_deref().unwrap_or(""),
        created = status == StatusCode::CREATED,
        "ACL entry granted",
    );
    Ok((status, Json(AclEntryResponse::from(entry))))
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

/// Canonical `acl/change-role` request.
///
/// Role-only, and `fromRole` is a **compare-and-swap guard**, not
/// decoration: the maintainer must confirm the subject's current role
/// equals it and refuse otherwise. That closes the read-modify-write
/// race the previous partial update had — two admins demoting the same
/// subject concurrently could each read `admin` and write a different
/// result, last-writer-wins, with no signal.
///
/// Label and scope edits are **not** here: they go to `acl/grant` with
/// the subject's existing role, which is what canonical means by "the
/// entry the maintainer should hold".
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateAclRequest {
    pub from_role: VtcRole,
    pub to_role: VtcRole,
    /// Operator rationale. Emitted on the service log line for this
    /// change; the audit envelope's data types do not carry a free-text
    /// reason today, so this is deliberately not described as audited.
    #[serde(default)]
    pub reason: Option<String>,
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

    // Compare-and-swap: the subject's current role MUST equal
    // `fromRole`, else the caller is acting on a stale read.
    if entry.role != req.from_role {
        return Err(AppError::Conflict(format!(
            "state mismatch: {did} currently holds role {}, not {}",
            entry.role, req.from_role
        )));
    }

    validate_vtc_role_assignment(&auth.0, &req.to_role)?;
    entry.role = req.to_role.clone();
    entry.updated_at = Some(now_epoch());
    entry.updated_by = Some(auth.0.did.clone());

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

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &auth.0.did,
                Some(&did),
                AuditEvent::AclUpdated(AclChangeData {
                    did: did.clone(),
                    role: entry.role.to_string(),
                    contexts: entry.allowed_contexts.clone(),
                    expires_at: entry.expires_at.map(|e| e.to_string()),
                }),
            )
            .await?;
    }

    info!(
        did = %did,
        from = %prev_role,
        to = %entry.role,
        reason = req.reason.as_deref().unwrap_or(""),
        "ACL role changed",
    );
    Ok(Json(AclEntryResponse::from(entry)))
}

// ---------- DELETE /acl/{did} ----------

/// Canonical `acl/revoke` parameters. `scopes` is a comma-separated
/// list; when present the entry is scope-reduced rather than removed.
#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct RevokeAclQuery {
    pub scopes: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

impl RevokeAclQuery {
    fn scopes_list(&self) -> Vec<String> {
        self.scopes
            .as_deref()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// DELETE /acl/{did} — revoke: remove the entry, or reduce its scopes
/// when `scopes` is supplied. Auth: Admin.
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
    Query(query): Query<RevokeAclQuery>,
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

    // Canonical `acl/revoke` has two modes. With `scopes`, this is a
    // *scope reduction*: the entry survives, minus those scopes. Only
    // an omitted `scopes` removes the entry outright. Treating a scope
    // reduction as a full removal would strip far more authority than
    // the operator asked for, so the two paths are kept distinct.
    let reduce = query.scopes_list();
    if !reduce.is_empty() {
        let mut entry = entry;
        let before = entry.allowed_contexts.len();
        entry.allowed_contexts.retain(|s| !reduce.contains(s));
        if entry.allowed_contexts.len() == before {
            return Err(AppError::NotFound(format!(
                "none of the requested scopes are held by {did}"
            )));
        }
        // Emptying an entry's scopes would silently promote it to
        // community-wide authority (an empty scope set is how a
        // super-admin is spelled), which is the opposite of revoking.
        if entry.allowed_contexts.is_empty() {
            return Err(AppError::Conflict(format!(
                "revoking every scope of {did} would leave an unscoped \
                 (community-wide) entry; omit `scopes` to remove it instead"
            )));
        }
        entry.updated_at = Some(now_epoch());
        entry.updated_by = Some(auth.0.did.clone());
        store_acl_entry(&acl, &entry).await?;

        // A shrunk scope set is a privilege reduction; the subject's
        // live tokens still carry the old scopes.
        let sessions = state.sessions_ks.clone();
        let revoked = super::auth::revoke_sessions_for_did(&sessions, &did).await?;

        if let Some(writer) = state.audit_writer.as_ref() {
            writer
                .write(
                    &auth.0.did,
                    Some(&did),
                    AuditEvent::AclUpdated(AclChangeData {
                        did: did.clone(),
                        role: entry.role.to_string(),
                        contexts: entry.allowed_contexts.clone(),
                        expires_at: entry.expires_at.map(|e| e.to_string()),
                    }),
                )
                .await?;
        }

        info!(
            caller = %auth.0.did, did = %did, revoked,
            remaining = entry.allowed_contexts.len(),
            reason = query.reason.as_deref().unwrap_or(""),
            "ACL scopes reduced",
        );
        return Ok(StatusCode::NO_CONTENT);
    }

    delete_acl_entry(&acl, &did).await?;

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &auth.0.did,
                Some(&did),
                AuditEvent::AclRevoked(AclRevokedData {
                    did: did.clone(),
                    prior_role: Some(entry.role.to_string()),
                }),
            )
            .await?;
    }

    info!(
        caller = %auth.0.did,
        did = %did,
        reason = query.reason.as_deref().unwrap_or(""),
        "ACL entry revoked",
    );
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
            updated_at: None,
            updated_by: None,
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
    fn grant_request_parses_minimal_body() {
        let body = json!({ "entry": { "subject": "did:key:zABC", "role": "admin" } });
        let req: CreateAclRequest = serde_json::from_value(body).expect("minimal body");
        assert_eq!(req.entry.subject, "did:key:zABC");
        assert_eq!(req.entry.role, VtcRole::Admin);
        assert_eq!(req.entry.label, None);
        assert!(req.entry.scopes.is_empty(), "defaults to empty");
        assert_eq!(req.entry.expires_at, None);
        assert_eq!(req.reason, None);
    }

    #[test]
    fn grant_request_parses_full_body() {
        let body = json!({
            "entry": {
                "subject": "did:key:zABC",
                "role": "moderator",
                "label": "ops lead",
                "scopes": ["ctx1", "ctx2"],
                "expiresAt": "2027-01-15T00:00:00Z",
            },
            "reason": "quarterly review",
        });
        let req: CreateAclRequest = serde_json::from_value(body).expect("full body");
        assert_eq!(req.entry.role, VtcRole::Moderator);
        assert_eq!(req.entry.label.as_deref(), Some("ops lead"));
        assert_eq!(req.entry.scopes, vec!["ctx1", "ctx2"]);
        assert!(req.entry.expires_at.is_some());
        assert_eq!(req.reason.as_deref(), Some("quarterly review"));
    }

    /// Server-owned provenance must not be settable by the caller, or a
    /// grant could backdate who added an entry and when.
    #[test]
    fn grant_request_rejects_caller_supplied_provenance() {
        for field in ["createdAt", "createdBy", "updatedAt", "updatedBy"] {
            let body = json!({
                "entry": { "subject": "did:key:zA", "role": "admin", field: "x" }
            });
            serde_json::from_value::<CreateAclRequest>(body)
                .expect_err(&format!("{field} must not be accepted"));
        }
    }

    #[test]
    fn grant_request_rejects_unknown_role() {
        let body = json!({ "entry": { "subject": "did:key:zA", "role": "godmode" } });
        let err = serde_json::from_value::<CreateAclRequest>(body)
            .expect_err("unknown role must not parse");
        let msg = format!("{err}");
        assert!(
            msg.contains("godmode") || msg.contains("unknown"),
            "got {msg}"
        );
    }

    /// `fromRole` is the compare-and-swap guard; omitting it would turn
    /// change-role back into a blind write.
    #[test]
    fn change_role_request_requires_both_roles() {
        let ok: UpdateAclRequest =
            serde_json::from_value(json!({ "fromRole": "member", "toRole": "moderator" }))
                .expect("both roles");
        assert_eq!(ok.from_role, VtcRole::Member);
        assert_eq!(ok.to_role, VtcRole::Moderator);

        serde_json::from_value::<UpdateAclRequest>(json!({ "toRole": "admin" }))
            .expect_err("fromRole is mandatory");
    }

    #[test]
    fn create_acl_request_rejects_missing_required() {
        let body = json!({ "role": "admin" });
        serde_json::from_value::<CreateAclRequest>(body)
            .expect_err("missing `did` must be rejected");
    }

    // ── UpdateAclRequest ───────────────────────────────────────────

    /// The pre-migration partial update (`role`/`label`/
    /// `allowed_contexts`, all optional) is gone: label and scope edits
    /// belong to `acl/grant`, and a role change now demands its CAS
    /// guard. An old client body must fail loudly rather than be read
    /// as some subset of the new one.
    #[test]
    fn change_role_request_rejects_the_pre_migration_body() {
        for body in [
            json!({}),
            json!({ "role": "member" }),
            json!({ "label": "ops", "allowed_contexts": ["ctx-a"] }),
        ] {
            serde_json::from_value::<UpdateAclRequest>(body.clone())
                .expect_err(&format!("legacy body must not parse: {body}"));
        }
    }

    // ── ListAclQuery ───────────────────────────────────────────────

    #[test]
    fn list_acl_query_filters_are_optional() {
        let q: ListAclQuery = serde_json::from_value(json!({})).unwrap();
        assert!(q.scope.is_none());
        assert!(q.role.is_none());
        assert!(q.subject_prefix.is_none());

        let q: ListAclQuery = serde_json::from_value(json!({ "scope": "app1" })).unwrap();
        assert_eq!(q.scope.as_deref(), Some("app1"));
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
            updated_at: None,
            updated_by: None,
            expires_at: Some(1_800_000_000),
        };
        let resp = AclEntryResponse::from(entry);
        let json = serde_json::to_value(&resp).unwrap();
        // Canonical `acl/_shared` AclEntry names.
        assert_eq!(json["subject"], "did:key:zABC");
        assert_eq!(json["role"], "admin");
        assert_eq!(json["label"], "test");
        assert_eq!(json["scopes"], json!(["ctx1"]));
        assert_eq!(json["createdBy"], "did:key:zSetup");
        // Timestamps are RFC3339 strings — canonical types them
        // `format: date-time`, so emitting the raw epoch would be a
        // silent contract break rather than a cosmetic one.
        assert_eq!(json["createdAt"], "2023-11-14T22:13:20+00:00");
        assert_eq!(json["expiresAt"], "2027-01-15T08:00:00+00:00");
        // The pre-migration names must be gone, not merely aliased.
        for old in [
            "did",
            "allowed_contexts",
            "created_at",
            "created_by",
            "expires_at",
        ] {
            assert!(
                json.get(old).is_none(),
                "{old} should not be emitted: {json}"
            );
        }
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
            updated_at: None,
            updated_by: None,
            expires_at: None,
        };
        let resp = AclEntryResponse::from(entry);
        let json = serde_json::to_value(&resp).unwrap();
        assert!(
            json.get("expiresAt").is_none() && json.get("expires_at").is_none(),
            "permanent entries must omit expiresAt — got {json}"
        );
        // Canonical names and RFC3339 timestamps, not the storage shape.
        assert_eq!(json["subject"], "did:key:zPerm");
        assert!(json.get("did").is_none(), "did renamed to subject: {json}");
        assert!(
            json["createdAt"].as_str().unwrap().contains('T'),
            "createdAt must be RFC3339, not an epoch int: {json}"
        );
    }

    // ── AclListResponse round-trip ─────────────────────────────────

    #[test]
    fn acl_list_response_round_trips() {
        let entries = vec![AclEntryResponse {
            subject: "did:key:zA".into(),
            role: VtcRole::Member,
            label: None,
            scopes: vec![],
            created_at: epoch_to_rfc3339(0),
            created_by: "did:key:zS".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        }];
        let resp = AclListResponse {
            entries,
            truncated: false,
            cursor: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""entries":"#), "got {json}");
        assert!(json.contains(r#""role":"member""#));
        // `truncated` is canonical-required and must always serialize.
        assert!(json.contains(r#""truncated":false"#), "got {json}");
    }

    #[test]
    fn custom_role_round_trip_through_request_body() {
        let body = json!({
            "entry": { "subject": "did:key:zEditor", "role": "custom:editor" },
        });
        let req: CreateAclRequest = serde_json::from_value(body).expect("custom role parses");
        assert_eq!(req.entry.role, VtcRole::Custom("editor".into()));
        // Round-trip via the response shape.
        let entry = VtcAclEntry {
            did: req.entry.subject,
            role: req.entry.role,
            label: None,
            allowed_contexts: vec![],
            created_at: 0,
            created_by: "did:key:zS".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        };
        let resp = AclEntryResponse::from(entry);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["role"], "custom:editor");
    }
}
