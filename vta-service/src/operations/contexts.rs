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
    /// Set this context's policy. `None` leaves it unchanged; `Some(policy)`
    /// replaces it (send [`ContextPolicy::unrestricted`] to clear constraints).
    /// Super-admin only (via [`update_context`]). Widening is impossible
    /// regardless: enforcement resolves the full ancestor chain.
    pub context_policy: Option<vta_sdk::context_policy::ContextPolicy>,
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
    crate::contexts::validate_slug(id)?;

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
        context_policy: None,
    };

    // Atomic claim: the early exists-check above is the friendly fast
    // path, but two concurrent creates with the same id both pass it.
    // The loser's counter slot stays as a gap — safe; record overwrite
    // would not be (it re-points the context's BIP-32 base path).
    if !crate::contexts::store_new_context(contexts_ks, &record).await? {
        return Err(AppError::Conflict(format!(
            "context already exists: {}",
            record.id
        )));
    }

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
    if let Some(context_policy) = params.context_policy {
        record.context_policy = Some(context_policy);
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
    // Admin role + access to the context (or an ancestor) — folder authority.
    auth.require_admin()?;
    auth.require_context(id)?;

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
    // Admin role + access to the context (or an ancestor) — folder authority: a
    // parent-admin may delete a sub-context and its subtree.
    auth.require_admin()?;
    auth.require_context(id)?;

    get_context(contexts_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;

    // The subtree below `id`, deepest first (so children are removed before
    // parents and ACL re-classification stays correct each step).
    let descendants = list_descendants(contexts_ks, id).await?;

    // Resources directly on `id`.
    let own = collect_context_resources(
        keys_ks,
        acl_ks,
        did_templates_ks,
        #[cfg(feature = "webvh")]
        webvh_ks,
        id,
    )
    .await?;
    let own_has_resources = !own.keys.is_empty()
        || !own.webvh_dids.is_empty()
        || !own.acl_entries_removed.is_empty()
        || !own.acl_entries_updated.is_empty()
        || !own.did_templates.is_empty();

    // Refuse a destructive delete (sub-contexts and/or resources) without force.
    if (own_has_resources || !descendants.is_empty()) && !force {
        let mut reasons = Vec::new();
        if !descendants.is_empty() {
            reasons.push(format!("{} sub-context(s)", descendants.len()));
        }
        if own_has_resources {
            reasons.push("associated resources".to_string());
        }
        return Err(AppError::Validation(format!(
            "context has {}; use force=true to delete the whole subtree, or preview first",
            reasons.join(" and "),
        )));
    }

    // Delete the subtree: each descendant (deepest first), then `id`.
    let mut to_delete = descendants;
    to_delete.push(id.to_string());

    let (mut keys, mut dids, mut acl_removed, mut acl_updated, mut templates) = (0, 0, 0, 0, 0);
    for ctx_id in &to_delete {
        let purged = purge_context_resources(
            keys_ks,
            acl_ks,
            did_templates_ks,
            #[cfg(feature = "webvh")]
            webvh_ks,
            ctx_id,
        )
        .await?;
        keys += purged.keys.len();
        dids += purged.webvh_dids.len();
        acl_removed += purged.acl_entries_removed.len();
        acl_updated += purged.acl_entries_updated.len();
        templates += purged.did_templates.len();
        delete_context_store(contexts_ks, ctx_id).await?;
    }

    info!(
        channel,
        id = %id,
        contexts_removed = to_delete.len(),
        keys_removed = keys,
        dids_removed = dids,
        acl_removed,
        acl_updated,
        templates_removed = templates,
        "context (and subtree) deleted"
    );
    Ok(DeleteContextResultBody {
        id: id.to_string(),
        deleted: true,
    })
}

/// Strict descendant contexts of `id` (the subtree below it, excluding `id`),
/// ordered **deepest first** so a cascade removes children before parents.
async fn list_descendants(contexts_ks: &KeyspaceHandle, id: &str) -> Result<Vec<String>, AppError> {
    use vti_common::context_path::{depth, is_ancestor_or_self};
    let mut descendants: Vec<String> = list_contexts_store(contexts_ks)
        .await?
        .into_iter()
        .map(|r| r.id)
        .filter(|cid| cid != id && is_ancestor_or_self(id, cid))
        .collect();
    // Deepest first.
    descendants.sort_by_key(|cid| std::cmp::Reverse(depth(cid)));
    Ok(descendants)
}

/// Collect **and delete** every resource (keys, WebVH DIDs, ACL refs, DID
/// templates) attached to a single `context_id`. Returns the collected preview
/// (for counts). Does NOT delete the context record itself.
async fn purge_context_resources(
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    did_templates_ks: &KeyspaceHandle,
    #[cfg(feature = "webvh")] webvh_ks: &KeyspaceHandle,
    context_id: &str,
) -> Result<DeleteContextPreviewResultBody, AppError> {
    let preview = collect_context_resources(
        keys_ks,
        acl_ks,
        did_templates_ks,
        #[cfg(feature = "webvh")]
        webvh_ks,
        context_id,
    )
    .await?;

    for key_id in &preview.keys {
        keys_ks.remove(crate::keys::store_key(key_id)).await?;
    }
    #[cfg(feature = "webvh")]
    for did in &preview.webvh_dids {
        crate::webvh_store::delete_did(webvh_ks, did).await?;
        // Best-effort: serverless DIDs have no log entry.
        let _ = webvh_ks.remove(format!("log:{did}")).await;
    }
    for did in &preview.acl_entries_removed {
        crate::acl::delete_acl_entry(acl_ks, did).await?;
    }
    for did in &preview.acl_entries_updated {
        if let Some(mut entry) = crate::acl::get_acl_entry(acl_ks, did).await? {
            entry.allowed_contexts.retain(|c| c != context_id);
            crate::acl::store_acl_entry(acl_ks, &entry).await?;
        }
    }
    crate::did_templates::delete_all_context_templates(did_templates_ks, context_id).await?;

    Ok(preview)
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
        let ks = store.keyspace(crate::keyspaces::CONTEXTS).unwrap();
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
    async fn update_sets_context_policy_and_chain_resolves() {
        use vta_sdk::context_policy::ContextPolicy;
        let (_d, _s, ks) = fresh_contexts();

        create_context(&ks, &super_admin(), "acme", "Acme".into(), None, None, "t")
            .await
            .unwrap();
        create_context(
            &ks,
            &admin_of("acme"),
            "eng",
            "Engineering".into(),
            None,
            Some("acme".into()),
            "t",
        )
        .await
        .unwrap();

        // Parent allows {a, b}; child allows {b, c} and disables export.
        update_context(
            &ks,
            &super_admin(),
            "acme",
            UpdateContextParams {
                name: None,
                did: None,
                description: None,
                context_policy: Some(ContextPolicy {
                    signable_keys: Some(["a".into(), "b".into()].into_iter().collect()),
                    ..ContextPolicy::unrestricted()
                }),
            },
            "t",
        )
        .await
        .expect("set parent policy");
        update_context(
            &ks,
            &super_admin(),
            "acme/eng",
            UpdateContextParams {
                name: None,
                did: None,
                description: None,
                context_policy: Some(ContextPolicy {
                    signable_keys: Some(["b".into(), "c".into()].into_iter().collect()),
                    export_allowed: false,
                    ..ContextPolicy::unrestricted()
                }),
            },
            "t",
        )
        .await
        .expect("set child policy");

        // The policy is persisted on the record …
        let rec = get_context(&ks, "acme/eng").await.unwrap().unwrap();
        assert!(rec.context_policy.is_some());

        // … and the effective policy intersects the whole chain: keys narrow to
        // {b}; export is off (child disabled it, can't be re-enabled).
        let eff = crate::contexts::effective_context_policy(&ks, "acme/eng")
            .await
            .unwrap();
        assert!(eff.allows_signing_key("b"));
        assert!(!eff.allows_signing_key("a"), "child narrowed 'a' away");
        assert!(!eff.allows_signing_key("c"), "parent never allowed 'c'");
        assert!(!eff.allows_export());
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

    // ── subtree delete (slice 3) ──

    struct OwnedKs {
        _dir: tempfile::TempDir,
        _store: Store,
        keys: KeyspaceHandle,
        acl: KeyspaceHandle,
        contexts: KeyspaceHandle,
        did_templates: KeyspaceHandle,
        audit: KeyspaceHandle,
        imported: KeyspaceHandle,
        #[cfg(feature = "webvh")]
        webvh: KeyspaceHandle,
    }

    impl OwnedKs {
        fn as_ks(&self) -> super::super::Keyspaces<'_> {
            super::super::Keyspaces {
                keys: &self.keys,
                acl: &self.acl,
                contexts: &self.contexts,
                did_templates: &self.did_templates,
                audit: &self.audit,
                imported: &self.imported,
                #[cfg(feature = "webvh")]
                webvh: &self.webvh,
            }
        }
    }

    fn fresh_keyspaces() -> OwnedKs {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let k = |n: &str| store.keyspace(n).unwrap();
        use crate::keyspaces as ks;
        OwnedKs {
            keys: k(ks::KEYS),
            acl: k(ks::ACL),
            contexts: k(ks::CONTEXTS),
            did_templates: k(ks::DID_TEMPLATES),
            audit: k(ks::AUDIT),
            imported: k(ks::IMPORTED_SECRETS),
            #[cfg(feature = "webvh")]
            webvh: k(ks::WEBVH),
            _dir: dir,
            _store: store,
        }
    }

    /// Seed a context (super-admin) by its full path; `parent` must already exist.
    async fn seed(ks: &KeyspaceHandle, id: &str, parent: Option<&str>) {
        create_context(
            ks,
            &super_admin(),
            id.rsplit('/').next().unwrap(),
            id.into(),
            None,
            parent.map(str::to_string),
            "seed",
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn delete_refuses_a_context_with_sub_contexts_without_force() {
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;
        seed(&ks.contexts, "acme/eng", Some("acme")).await;

        let err = delete_context(&ks.as_ks(), &super_admin(), "acme", false, "t")
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("sub-context")),
            "{err:?}"
        );
        // Nothing was deleted.
        assert!(get_context(&ks.contexts, "acme").await.unwrap().is_some());
        assert!(
            get_context(&ks.contexts, "acme/eng")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn force_delete_cascades_the_whole_subtree() {
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;
        seed(&ks.contexts, "acme/eng", Some("acme")).await;
        seed(&ks.contexts, "acme/eng/team", Some("acme/eng")).await;
        seed(&ks.contexts, "acme/ops", Some("acme")).await;

        delete_context(&ks.as_ks(), &super_admin(), "acme", true, "t")
            .await
            .expect("cascade delete");

        for id in ["acme", "acme/eng", "acme/eng/team", "acme/ops"] {
            assert!(
                get_context(&ks.contexts, id).await.unwrap().is_none(),
                "{id} should be gone"
            );
        }
    }

    #[tokio::test]
    async fn parent_admin_can_delete_a_sub_context() {
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;
        seed(&ks.contexts, "acme/eng", Some("acme")).await;

        // An admin scoped to `acme` deletes the leaf sub-context.
        delete_context(&ks.as_ks(), &admin_of("acme"), "acme/eng", false, "t")
            .await
            .expect("parent-admin deletes sub-context");
        assert!(
            get_context(&ks.contexts, "acme/eng")
                .await
                .unwrap()
                .is_none()
        );
        assert!(get_context(&ks.contexts, "acme").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn an_admin_cannot_delete_a_context_outside_its_subtree() {
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;
        seed(&ks.contexts, "other", None).await;

        let err = delete_context(&ks.as_ks(), &admin_of("acme"), "other", false, "t")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
        assert!(get_context(&ks.contexts, "other").await.unwrap().is_some());
    }
}
