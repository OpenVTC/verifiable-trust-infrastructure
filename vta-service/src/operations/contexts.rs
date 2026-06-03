use chrono::Utc;
use tracing::info;

use vta_sdk::protocols::context_management::{
    create::CreateContextResultBody,
    delete::{DeleteContextPreviewResultBody, DeleteContextResultBody},
    list::ListContextsResultBody,
};

use crate::auth::AuthClaims;
use crate::contexts::{
    ContextRecord, allocate_context_index, delete_context as delete_context_store, get_context,
    list_contexts as list_contexts_store, store_context,
};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

pub struct UpdateContextParams {
    pub name: Option<String>,
    pub did: Option<String>,
    pub description: Option<String>,
}

fn validate_slug(id: &str) -> Result<(), AppError> {
    if id.is_empty() {
        return Err(AppError::Validation("context id cannot be empty".into()));
    }
    if id.len() > 64 {
        return Err(AppError::Validation(
            "context id must be 64 characters or fewer".into(),
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(AppError::Validation(
            "context id must contain only lowercase alphanumeric characters and hyphens".into(),
        ));
    }
    if id.starts_with('-') || id.ends_with('-') {
        return Err(AppError::Validation(
            "context id must not start or end with a hyphen".into(),
        ));
    }
    Ok(())
}

fn to_result_body(r: &ContextRecord) -> CreateContextResultBody {
    CreateContextResultBody {
        id: r.id.clone(),
        name: r.name.clone(),
        did: r.did.clone(),
        description: r.description.clone(),
        parent: r.parent.clone(),
        base_path: r.base_path.clone(),
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

/// Create a context — top-level, or a sub-context nested under `parent`.
///
/// `id` is the **leaf** segment; when `parent` is set the stored id is the full
/// path `<parent>/<id>` (`docs/05-design-notes/hierarchical-contexts.md`).
///
/// **Authorization:**
/// - **top-level** (`parent` is `None`) — super-admin only (unchanged).
/// - **sub-context** (`parent` is `Some`) — the parent must exist and the caller
///   must be **admin of it** (folder-level authority: `require_context(parent)`
///   passes for an admin scoped to the parent or any ancestor, and for a
///   super-admin). The route gates the admin *role*; this gates the *scope*.
///
/// The sub-context's BIP-32 base nests under the parent's, and the path depth is
/// bounded by [`vti_common::context_path::child_path`].
pub async fn create_context(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    name: String,
    description: Option<String>,
    parent: Option<String>,
    channel: &str,
) -> Result<CreateContextResultBody, AppError> {
    // The leaf id is always a single slug segment.
    validate_slug(id)?;

    let (full_id, parent_field, base_prefix, counter_key) = match &parent {
        None => {
            // Top-level context creation stays super-admin only.
            auth.require_super_admin()?;
            (
                id.to_string(),
                None,
                crate::contexts::CONTEXT_KEY_BASE.to_string(),
                "ctx_counter".to_string(),
            )
        }
        Some(parent_id) => {
            // Sub-context: the parent must exist and the caller must be admin of
            // it. `require_context` is the segment-aware ancestry gate; the route
            // already required the admin role.
            let parent_ctx = get_context(contexts_ks, parent_id).await?.ok_or_else(|| {
                AppError::NotFound(format!("parent context not found: {parent_id}"))
            })?;
            auth.require_context(parent_id)?;
            // Full path = `<parent>/<id>`; validates segment + total depth.
            let full = vti_common::context_path::child_path(parent_id, id)?;
            (
                full,
                Some(parent_id.clone()),
                parent_ctx.base_path.clone(),
                format!("ctx_counter:{parent_id}"),
            )
        }
    };

    if get_context(contexts_ks, &full_id).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "context already exists: {full_id}"
        )));
    }

    let (index, base_path) =
        allocate_context_index(contexts_ks, &base_prefix, &counter_key).await?;

    let now = Utc::now();
    let record = ContextRecord {
        id: full_id,
        name,
        did: None,
        description,
        parent: parent_field,
        base_path,
        index,
        created_at: now,
        updated_at: now,
    };

    store_context(contexts_ks, &record).await?;

    info!(channel, id = %record.id, parent = ?record.parent, index, "context created");
    Ok(to_result_body(&record))
}

pub async fn get_context_op(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    channel: &str,
) -> Result<CreateContextResultBody, AppError> {
    auth.require_context(id)?;
    let record = get_context(contexts_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;
    info!(channel, id = %id, "context retrieved");
    Ok(to_result_body(&record))
}

pub async fn list_contexts(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    channel: &str,
) -> Result<ListContextsResultBody, AppError> {
    let records = list_contexts_store(contexts_ks).await?;
    let contexts: Vec<CreateContextResultBody> = records
        .iter()
        .filter(|r| auth.has_context_access(&r.id))
        .map(to_result_body)
        .collect();
    info!(channel, caller = %auth.did, count = contexts.len(), "contexts listed");
    Ok(ListContextsResultBody { contexts })
}

pub async fn update_context(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    params: UpdateContextParams,
    channel: &str,
) -> Result<CreateContextResultBody, AppError> {
    auth.require_super_admin()?;

    let mut record = get_context(contexts_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;

    if let Some(name) = params.name {
        record.name = name;
    }
    if let Some(did) = params.did {
        record.did = Some(did);
    }
    if let Some(description) = params.description {
        record.description = Some(description);
    }
    record.updated_at = Utc::now();

    store_context(contexts_ks, &record).await?;

    info!(channel, id = %id, "context updated");
    Ok(to_result_body(&record))
}

/// Update the DID for a context. Requires Admin role with access to the context
/// (context-scoped admins can update DIDs on their own contexts).
pub async fn update_context_did(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    did: String,
    channel: &str,
) -> Result<CreateContextResultBody, AppError> {
    auth.require_admin()?;
    auth.require_context(id)?;

    let mut record = get_context(contexts_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;

    record.did = Some(did);
    record.updated_at = Utc::now();

    store_context(contexts_ks, &record).await?;

    info!(channel, id = %id, did = ?record.did, "context DID updated");
    Ok(to_result_body(&record))
}

/// Collect a preview of all resources associated with a context.
#[allow(clippy::too_many_arguments)]
pub async fn preview_delete_context(
    contexts_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    did_templates_ks: &KeyspaceHandle,
    #[cfg(feature = "webvh")] webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    channel: &str,
) -> Result<DeleteContextPreviewResultBody, AppError> {
    auth.require_super_admin()?;

    get_context(contexts_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;

    let preview = collect_context_resources(
        keys_ks,
        acl_ks,
        did_templates_ks,
        #[cfg(feature = "webvh")]
        webvh_ks,
        id,
    )
    .await?;

    info!(
        channel,
        id = %id,
        keys = preview.keys.len(),
        dids = preview.webvh_dids.len(),
        templates = preview.did_templates.len(),
        "context delete preview"
    );
    Ok(preview)
}

pub async fn delete_context(
    ks: &super::Keyspaces<'_>,
    auth: &AuthClaims,
    id: &str,
    force: bool,
    channel: &str,
) -> Result<DeleteContextResultBody, AppError> {
    let contexts_ks = ks.contexts;
    let keys_ks = ks.keys;
    let acl_ks = ks.acl;
    let did_templates_ks = ks.did_templates;
    #[cfg(feature = "webvh")]
    let webvh_ks = ks.webvh;
    auth.require_super_admin()?;

    get_context(contexts_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;

    let preview = collect_context_resources(
        keys_ks,
        acl_ks,
        did_templates_ks,
        #[cfg(feature = "webvh")]
        webvh_ks,
        id,
    )
    .await?;

    let has_resources = !preview.keys.is_empty()
        || !preview.webvh_dids.is_empty()
        || !preview.acl_entries_removed.is_empty()
        || !preview.acl_entries_updated.is_empty()
        || !preview.did_templates.is_empty();

    if has_resources && !force {
        return Err(AppError::Validation(
            "context has associated resources; use force=true to delete, or preview first".into(),
        ));
    }

    // Delete keys
    for key_id in &preview.keys {
        keys_ks.remove(crate::keys::store_key(key_id)).await?;
    }

    // Delete WebVH DIDs and their logs
    #[cfg(feature = "webvh")]
    for did in &preview.webvh_dids {
        crate::webvh_store::delete_did(webvh_ks, did).await?;
        // Remove the log entry (best-effort, may not exist for serverless DIDs)
        let _ = webvh_ks.remove(format!("log:{did}")).await;
    }

    // Remove or update ACL entries
    for did in &preview.acl_entries_removed {
        crate::acl::delete_acl_entry(acl_ks, did).await?;
    }
    for did in &preview.acl_entries_updated {
        if let Some(mut entry) = crate::acl::get_acl_entry(acl_ks, did).await? {
            entry.allowed_contexts.retain(|c| c != id);
            crate::acl::store_acl_entry(acl_ks, &entry).await?;
        }
    }

    // Delete any DID templates scoped to this context
    let templates_removed =
        crate::did_templates::delete_all_context_templates(did_templates_ks, id).await?;

    // Delete the context record itself
    delete_context_store(contexts_ks, id).await?;

    info!(
        channel,
        id = %id,
        keys_removed = preview.keys.len(),
        dids_removed = preview.webvh_dids.len(),
        acl_removed = preview.acl_entries_removed.len(),
        acl_updated = preview.acl_entries_updated.len(),
        templates_removed,
        "context deleted with cascade"
    );
    Ok(DeleteContextResultBody {
        id: id.to_string(),
        deleted: true,
    })
}

/// Scan all keyspaces and collect resources associated with a context.
async fn collect_context_resources(
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    did_templates_ks: &KeyspaceHandle,
    #[cfg(feature = "webvh")] webvh_ks: &KeyspaceHandle,
    context_id: &str,
) -> Result<DeleteContextPreviewResultBody, AppError> {
    use crate::keys::KeyRecord;

    let mut preview = DeleteContextPreviewResultBody {
        id: context_id.to_string(),
        ..Default::default()
    };

    // Keys
    let raw_keys = keys_ks.prefix_iter_raw("key:").await?;
    for (_key, value) in raw_keys {
        let record: KeyRecord = serde_json::from_slice(&value)?;
        if record.context_id.as_deref() == Some(context_id) {
            preview.keys.push(record.key_id);
        }
    }

    // WebVH DIDs
    #[cfg(feature = "webvh")]
    {
        use vta_sdk::webvh::WebvhDidRecord;
        let raw_dids = webvh_ks.prefix_iter_raw("did:").await?;
        for (_key, value) in raw_dids {
            let record: WebvhDidRecord = serde_json::from_slice(&value)?;
            if record.context_id == context_id {
                preview.webvh_dids.push(record.did);
            }
        }
    }

    // ACL entries
    let raw_acl = acl_ks.prefix_iter_raw("acl:").await?;
    for (_key, value) in raw_acl {
        let entry: crate::acl::AclEntry = serde_json::from_slice(&value)?;
        if entry.allowed_contexts.contains(&context_id.to_string()) {
            if entry.allowed_contexts.len() == 1 {
                // This entry only has this context — it will be deleted entirely
                preview.acl_entries_removed.push(entry.did);
            } else {
                // This entry has other contexts — just remove this one from the list
                preview.acl_entries_updated.push(entry.did);
            }
        }
    }

    // DID templates scoped to this context
    let templates =
        crate::did_templates::list_context_templates(did_templates_ks, context_id).await?;
    preview.did_templates = templates.into_iter().map(|r| r.template.name).collect();

    Ok(preview)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Role;
    use crate::auth::AuthClaims;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn fresh_contexts() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("contexts").unwrap();
        (dir, store, ks)
    }

    fn super_admin() -> AuthClaims {
        AuthClaims {
            role: Role::Admin,
            allowed_contexts: Vec::new(), // empty = super-admin
            ..Default::default()
        }
    }

    fn admin_of(context: &str) -> AuthClaims {
        AuthClaims {
            role: Role::Admin,
            allowed_contexts: vec![context.to_string()],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn creates_a_top_level_context() {
        let (_d, _s, ks) = fresh_contexts();
        let r = create_context(&ks, &super_admin(), "acme", "Acme".into(), None, None, "t")
            .await
            .expect("create top-level");
        assert_eq!(r.id, "acme");
        assert_eq!(r.parent, None);
        assert_eq!(r.base_path, "m/26'/2'/0'");
    }

    #[tokio::test]
    async fn top_level_creation_requires_super_admin() {
        let (_d, _s, ks) = fresh_contexts();
        // A context-admin (non-super) cannot create a top-level context.
        let err = create_context(&ks, &admin_of("acme"), "ops", "Ops".into(), None, None, "t")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    }

    #[tokio::test]
    async fn admin_of_parent_creates_a_nested_context_with_nested_base_path() {
        let (_d, _s, ks) = fresh_contexts();
        let parent = create_context(&ks, &super_admin(), "acme", "Acme".into(), None, None, "t")
            .await
            .unwrap();

        // An admin scoped to `acme` nests `eng` under it.
        let child = create_context(
            &ks,
            &admin_of("acme"),
            "eng",
            "Engineering".into(),
            None,
            Some("acme".into()),
            "t",
        )
        .await
        .expect("nest under acme");

        assert_eq!(child.id, "acme/eng");
        assert_eq!(child.parent.as_deref(), Some("acme"));
        // The child's BIP-32 base nests under the parent's.
        assert_eq!(child.base_path, format!("{}/0'", parent.base_path));
    }

    #[tokio::test]
    async fn nesting_requires_admin_of_the_parent() {
        let (_d, _s, ks) = fresh_contexts();
        create_context(&ks, &super_admin(), "acme", "Acme".into(), None, None, "t")
            .await
            .unwrap();
        create_context(
            &ks,
            &super_admin(),
            "other",
            "Other".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();

        // An admin of `acme` cannot nest under `other`.
        let err = create_context(
            &ks,
            &admin_of("acme"),
            "team",
            "Team".into(),
            None,
            Some("other".into()),
            "t",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    }

    #[tokio::test]
    async fn nesting_under_a_missing_parent_is_not_found() {
        let (_d, _s, ks) = fresh_contexts();
        let err = create_context(
            &ks,
            &super_admin(),
            "eng",
            "Engineering".into(),
            None,
            Some("ghost".into()),
            "t",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "{err:?}");
    }
}
