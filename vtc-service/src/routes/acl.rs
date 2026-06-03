use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use tracing::info;

use crate::acl::{
    VtcAclEntry, VtcRole, delete_acl_entry, get_acl_entry, is_acl_entry_visible, list_acl_entries,
    store_acl_entry, validate_acl_modification, validate_vtc_role_assignment,
};
use crate::auth::{AdminAuth, ManageAuth, session::now_epoch};
use crate::error::AppError;
use crate::server::AppState;

// ---------- GET /acl ----------

#[derive(Debug, Serialize)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Deserialize)]
pub struct ListAclQuery {
    pub context: Option<String>,
}

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

#[derive(Debug, Deserialize)]
pub struct CreateAclRequest {
    pub did: String,
    pub role: VtcRole,
    pub label: Option<String>,
    #[serde(default)]
    pub allowed_contexts: Vec<String>,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

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

#[derive(Debug, Deserialize)]
pub struct UpdateAclRequest {
    pub role: Option<VtcRole>,
    pub label: Option<String>,
    pub allowed_contexts: Option<Vec<String>>,
}

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

    info!(did = %did, "ACL entry updated");
    Ok(Json(AclEntryResponse::from(entry)))
}

// ---------- DELETE /acl/{did} ----------

pub async fn delete_acl(
    auth: ManageAuth,
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
fn as_vti_acl_entry(e: &VtcAclEntry) -> vti_common::acl::AclEntry {
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
