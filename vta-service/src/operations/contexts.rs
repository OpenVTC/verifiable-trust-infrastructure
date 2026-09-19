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

    // The preview covers the whole subtree, because the deletion does.
    //
    // It used to collect `id` alone. A context whose own keyspaces were empty
    // but whose children held keys and DIDs previewed as holding nothing, so
    // every consumer that decides "does this need `force`?" from the preview
    // — the browser console does exactly that — decided it from the wrong
    // set: it either sent `force: false` and got an unexplained refusal, or,
    // when the parent happened to hold one key of its own, destroyed an entire
    // unlisted subtree under a confirmation that listed one key.
    //
    // Delete and preview must answer the same question. `subtree` is the list
    // the deletion iterates, built here the same way.
    let mut subtree = list_descendants(contexts_ks, id).await?;
    subtree.push(id.to_string());

    let mut preview = collect_subtree_resources(
        keys_ks,
        acl_ks,
        did_templates_ks,
        #[cfg(feature = "webvh")]
        webvh_ks,
        &subtree,
    )
    .await?;
    preview.id = id.to_string();
    // The contexts the arrays above are the union over. Measured already —
    // `subtree` is what `collect_subtree_resources` was handed — so the only
    // thing that was missing was saying so on the wire. `subtree` ends with
    // `id` itself, which is not a *sub*-context.
    preview.sub_contexts = subtree[..subtree.len() - 1].to_vec();

    info!(
        channel,
        id = %id,
        sub_contexts = preview.sub_contexts.len(),
        keys = preview.keys.len(),
        dids = preview.webvh_dids.len(),
        templates = preview.did_templates.len(),
        "context delete preview"
    );
    Ok(preview)
}

/// What a context deletion needs in order to take the `did:webvh` DIDs in its
/// subtree with it **properly** — off the hosting server, not merely out of
/// the local keyspace.
///
/// `None` is not "skip the DIDs". It means this caller cannot delete one, and
/// [`delete_context`] refuses rather than dropping the local records of DIDs
/// that would carry on resolving from their host forever after — the same
/// stance, for the same reason, that
/// [`WebvhDeps::delete_cascade`](crate::operations::did_webvh::WebvhDeps::delete_cascade)
/// takes on a DID deleted on its own.
#[cfg(feature = "webvh")]
pub struct ContextDidCleanup<'a> {
    pub deps: &'a crate::operations::did_webvh::WebvhDeps<'a>,
    /// This VTA's DID, which authenticates the delete to the hosting daemon.
    /// Absent, the host copy cannot be removed and the deletion says so.
    pub vta_did: Option<&'a str>,
}

/// Delete a context and, with `force`, everything below it.
///
/// ## Why the DIDs do not go through the local store
///
/// Every `did:webvh` DID in the subtree is deleted through
/// [`delete_did_webvh_with`](crate::operations::did_webvh::delete_did_webvh_with),
/// the same path `pnm did-mgmt dids delete` takes, rather than by dropping its
/// record here.
///
/// Dropping the record is what this function used to do, and it is not a
/// smaller version of deleting the DID — it is a different outcome. The log
/// stays published on the hosting server, so the DID keeps resolving for
/// everyone except the agent that owned it; the credentials the VTA issued
/// naming it stay valid with the only records that could revoke them
/// destroyed; and live sessions authenticated as it keep working. Deleting a
/// context is supposed to retire its identities, and a caller has no way to
/// tell from the result that it did not.
pub async fn delete_context(
    ks: &super::Keyspaces<'_>,
    auth: &AuthClaims,
    id: &str,
    force: bool,
    channel: &str,
    #[cfg(feature = "webvh")] webvh: Option<&ContextDidCleanup<'_>>,
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

    // ---- Refuse before destroying anything --------------------------------
    //
    // Every DID in the subtree is checked for blockers *first*, across the
    // whole subtree, and a single blocker refuses the whole deletion. Checking
    // per-DID inside the loop would delete the DIDs of the first three
    // contexts and then refuse on the fourth, which is the half-deletion the
    // task spec forbids in as many words ("either the context and its contents
    // go, or nothing does") and the state no operator can reason about.
    #[cfg(feature = "webvh")]
    let subtree_dids = subtree_webvh_dids(webvh_ks, &to_delete).await?;
    #[cfg(feature = "webvh")]
    if !subtree_dids.is_empty() {
        let cleanup = webvh.ok_or_else(|| {
            AppError::Internal(format!(
                "this code path cannot delete a context holding did:webvh DIDs: it has no way \
                 to reach their hosting servers, and dropping the local records would leave \
                 {} DID(s) resolving from their host with no means left to remove them",
                subtree_dids.len()
            ))
        })?;
        let options =
            crate::operations::did_webvh::DeleteDidOptions::within_context_deletion(&to_delete);
        let mut blockers = Vec::new();
        for did in &subtree_dids {
            let plan = crate::operations::did_webvh::plan_did_deletion_with(
                cleanup.deps,
                auth,
                did,
                cleanup.vta_did,
                options,
            )
            .await?;
            blockers.extend(plan.blockers.into_iter().map(|b| format!("{did}: {b}")));
        }
        if !blockers.is_empty() {
            return Err(AppError::Conflict(format!(
                "context `{id}` cannot be deleted — {} DID blocker{} to resolve first:\n{}",
                blockers.len(),
                if blockers.len() == 1 { "" } else { "s" },
                blockers
                    .iter()
                    .map(|b| format!("  - {b}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )));
        }
    }

    let (mut keys, mut acl_removed, mut acl_updated, mut templates) = (0, 0, 0, 0);
    #[allow(unused_mut)]
    let mut dids = 0usize;
    // Host copies the daemon would not remove. Deletion carries on — the
    // alternative is a subtree half gone — but the orphans are named rather
    // than counted, because an operator cleaning up out-of-band needs the
    // identifiers and a count tells them only that they have a problem.
    #[allow(unused_mut)]
    let mut orphans: Vec<String> = Vec::new();

    for ctx_id in &to_delete {
        // DIDs first, and remotely first within that: a local record removed
        // before its host copy is the one state from which the host copy can
        // never be removed at all (VTI R2.1).
        #[cfg(feature = "webvh")]
        if let Some(cleanup) = webvh {
            let options =
                crate::operations::did_webvh::DeleteDidOptions::within_context_deletion(&to_delete);
            for did in context_webvh_dids(webvh_ks, ctx_id).await? {
                let result = crate::operations::did_webvh::delete_did_webvh_with(
                    cleanup.deps,
                    auth,
                    &did,
                    cleanup.vta_did,
                    channel,
                    options,
                )
                .await?;
                if let Some(reason) = result.daemon_cleanup_error {
                    orphans.push(format!("{did}: {reason}"));
                }
                dids += 1;
            }
        }

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
        acl_removed += purged.acl_entries_removed.len();
        acl_updated += purged.acl_entries_updated.len();
        templates += purged.did_templates.len();
        delete_context_store(contexts_ks, ctx_id).await?;
    }

    // Said, never swallowed — the same partial success
    // `delete_did_webvh`'s `daemonCleanupError` reports for a single DID.
    // Logged *and* returned: the log is for whoever is watching the agent,
    // the response member is for the caller who asked for the deletion and is
    // otherwise told only that it succeeded.
    if !orphans.is_empty() {
        tracing::error!(
            channel,
            id = %id,
            orphans = orphans.len(),
            detail = %orphans.join("; "),
            "context deleted, but host copies of some DIDs were not removed and may still \
             resolve — clean them up out-of-band"
        );
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
        daemon_cleanup_errors: orphans,
    })
}

/// The `did:webvh` DIDs recorded against `context_id`.
#[cfg(feature = "webvh")]
async fn context_webvh_dids(
    webvh_ks: &KeyspaceHandle,
    context_id: &str,
) -> Result<Vec<String>, AppError> {
    use vta_sdk::webvh::WebvhDidRecord;
    let mut dids = Vec::new();
    for (_key, value) in webvh_ks.prefix_iter_raw("did:").await? {
        let record: WebvhDidRecord = serde_json::from_slice(&value)?;
        if record.context_id == context_id {
            dids.push(record.did);
        }
    }
    Ok(dids)
}

/// The `did:webvh` DIDs recorded against any of `context_ids`, in one pass.
///
/// One scan rather than one per context: the pre-flight runs over the whole
/// subtree, and a per-context scan makes a deep tree quadratic in the size of
/// the DID keyspace for no gain.
#[cfg(feature = "webvh")]
async fn subtree_webvh_dids(
    webvh_ks: &KeyspaceHandle,
    context_ids: &[String],
) -> Result<Vec<String>, AppError> {
    use vta_sdk::webvh::WebvhDidRecord;
    let mut dids = Vec::new();
    for (_key, value) in webvh_ks.prefix_iter_raw("did:").await? {
        let record: WebvhDidRecord = serde_json::from_slice(&value)?;
        if context_ids.contains(&record.context_id) {
            dids.push(record.did);
        }
    }
    Ok(dids)
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
    // No DID deletion here. The subtree's `did:webvh` DIDs are deleted by
    // `delete_context` through the full webvh path *before* this runs, so by
    // the time a context is purged it has none left. Deleting the record here
    // as well would be a second, weaker implementation of the same step — the
    // one that left host copies published.
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

/// Everything a deletion of `context_ids` (a context and its whole subtree)
/// would destroy, as one preview.
///
/// Not a loop over [`collect_context_resources`], and the difference is the
/// ACL classification. That function asks "does this entry hold *only* this
/// context?", which is the right question for one context and the wrong one
/// for a subtree: an entry scoped to both `acme` and `acme/eng` holds another
/// context by that test, so a per-context loop reports it twice as merely
/// *narrowed* — when deleting `acme` takes both of its scopes and the entry
/// goes entirely. An operator reading that preview is told a subject keeps
/// authority it is about to lose completely.
///
/// So the question is asked once against the whole delete set, which is also
/// the state the deletion's iterative, deepest-first cascade converges on.
async fn collect_subtree_resources(
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    did_templates_ks: &KeyspaceHandle,
    #[cfg(feature = "webvh")] webvh_ks: &KeyspaceHandle,
    context_ids: &[String],
) -> Result<DeleteContextPreviewResultBody, AppError> {
    use crate::keys::KeyRecord;

    // `id` is the caller's to set: this function answers for a set of
    // contexts and has no opinion about which of them the operator named.
    let mut preview = DeleteContextPreviewResultBody::default();

    // Keys. One scan for the whole subtree, not one per context.
    for (_key, value) in keys_ks.prefix_iter_raw("key:").await? {
        let record: KeyRecord = serde_json::from_slice(&value)?;
        if record
            .context_id
            .as_deref()
            .is_some_and(|c| context_ids.iter().any(|d| d == c))
        {
            preview.keys.push(record.key_id);
        }
    }

    // WebVH DIDs.
    #[cfg(feature = "webvh")]
    {
        use vta_sdk::webvh::WebvhDidRecord;
        for (_key, value) in webvh_ks.prefix_iter_raw("did:").await? {
            let record: WebvhDidRecord = serde_json::from_slice(&value)?;
            if context_ids.contains(&record.context_id) {
                preview.webvh_dids.push(record.did);
            }
        }
    }

    // ACL entries, classified against the whole delete set.
    for (_key, value) in acl_ks.prefix_iter_raw("acl:").await? {
        let entry: crate::acl::AclEntry = serde_json::from_slice(&value)?;
        let doomed = entry
            .allowed_contexts
            .iter()
            .filter(|c| context_ids.contains(c))
            .count();
        if doomed == 0 {
            continue;
        }
        if doomed == entry.allowed_contexts.len() {
            // Every scope it holds is going: the entry goes with them.
            preview.acl_entries_removed.push(entry.did);
        } else {
            preview.acl_entries_updated.push(entry.did);
        }
    }

    // DID templates. Duplicated names across contexts are kept, not deduped:
    // they are distinct templates, and collapsing them would under-report how
    // many are destroyed.
    for context_id in context_ids {
        let templates =
            crate::did_templates::list_context_templates(did_templates_ks, context_id).await?;
        preview
            .did_templates
            .extend(templates.into_iter().map(|r| r.template.name));
    }

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

    /// Store an ACL entry scoped to `contexts`.
    async fn seed_acl(ks: &KeyspaceHandle, did: &str, contexts: &[&str]) {
        let mut entry = crate::acl::AclEntry::new(did, Role::Admin, "seed");
        entry.allowed_contexts = contexts.iter().map(|c| (*c).to_string()).collect();
        crate::acl::store_acl_entry(ks, &entry).await.unwrap();
    }

    /// The preview answers for the subtree, because the deletion acts on it.
    ///
    /// The shape that mattered in the field: a parent holding nothing of its
    /// own, over children that hold everything. The old preview reported the
    /// parent's empty hands and consumers concluded the delete was harmless.
    #[tokio::test]
    async fn preview_reports_what_sub_contexts_hold() {
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;
        seed(&ks.contexts, "acme/eng", Some("acme")).await;
        // The resource is two levels down and belongs to neither `acme` nor
        // anything a per-context preview of `acme` would look at.
        seed(&ks.contexts, "acme/eng/ci", Some("acme/eng")).await;
        seed_acl(&ks.acl, "did:key:zBuildBot", &["acme/eng/ci"]).await;

        let preview = preview_delete_context(
            &ks.contexts,
            &ks.keys,
            &ks.acl,
            &ks.did_templates,
            #[cfg(feature = "webvh")]
            &ks.webvh,
            &super_admin(),
            "acme",
            "t",
        )
        .await
        .expect("preview");

        assert_eq!(
            preview.acl_entries_removed,
            vec!["did:key:zBuildBot".to_string()],
            "a grandchild's ACL entry is destroyed by this delete and must be previewed"
        );
    }

    /// An entry scoped to a parent *and* its child loses both scopes when the
    /// parent is deleted, so it is `removed`, not `updated`.
    ///
    /// A per-context preview gets this backwards twice over: asked about
    /// `acme` it sees the entry also holds `acme/eng` and calls it narrowed;
    /// asked about `acme/eng` it sees `acme` and says the same. Both scopes
    /// are in the delete set, so the entry goes — and "keeps some authority"
    /// is the one thing an operator must not be told about a subject that is
    /// about to have none.
    #[tokio::test]
    async fn an_acl_entry_scoped_wholly_inside_the_subtree_is_previewed_as_removed() {
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;
        seed(&ks.contexts, "acme/eng", Some("acme")).await;
        seed(&ks.contexts, "other", None).await;

        seed_acl(&ks.acl, "did:key:zInside", &["acme", "acme/eng"]).await;
        seed_acl(&ks.acl, "did:key:zStraddles", &["acme/eng", "other"]).await;
        seed_acl(&ks.acl, "did:key:zOutside", &["other"]).await;

        let preview = preview_delete_context(
            &ks.contexts,
            &ks.keys,
            &ks.acl,
            &ks.did_templates,
            #[cfg(feature = "webvh")]
            &ks.webvh,
            &super_admin(),
            "acme",
            "t",
        )
        .await
        .expect("preview");

        assert_eq!(
            preview.acl_entries_removed,
            vec!["did:key:zInside".to_string()],
            "both of its scopes are in the delete set"
        );
        assert_eq!(
            preview.acl_entries_updated,
            vec!["did:key:zStraddles".to_string()],
            "it keeps `other`"
        );
        assert!(
            !preview
                .acl_entries_removed
                .contains(&"did:key:zOutside".to_string())
                && !preview
                    .acl_entries_updated
                    .contains(&"did:key:zOutside".to_string()),
            "an entry with no scope in the subtree is untouched"
        );
    }

    /// The preview names the subtree, deepest first, and does not count the
    /// context itself among its own sub-contexts.
    ///
    /// Until trust-tasks 0.21.4 there was no member for this, and both CLIs
    /// plus the browser console each derived it from the context list. Three
    /// copies of the agent's cascade rule in front of a destructive prompt,
    /// none of them authoritative.
    #[tokio::test]
    async fn preview_names_the_sub_contexts_that_go_with_it() {
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;
        seed(&ks.contexts, "acme/eng", Some("acme")).await;
        seed(&ks.contexts, "acme/eng/ci", Some("acme/eng")).await;
        // Not under `acme` — a prefix match on the string alone would take it.
        seed(&ks.contexts, "acme-corp", None).await;

        let preview = preview_delete_context(
            &ks.contexts,
            &ks.keys,
            &ks.acl,
            &ks.did_templates,
            #[cfg(feature = "webvh")]
            &ks.webvh,
            &super_admin(),
            "acme",
            "t",
        )
        .await
        .expect("preview");

        assert_eq!(
            preview.sub_contexts,
            vec!["acme/eng/ci".to_string(), "acme/eng".to_string()],
            "deepest first, and `acme-corp` is not a child of `acme`"
        );
        assert!(
            !preview.sub_contexts.contains(&"acme".to_string()),
            "the context previewed is not one of its own sub-contexts"
        );
    }

    /// A leaf reports no sub-contexts rather than omitting the question.
    #[tokio::test]
    async fn a_leaf_previews_an_empty_sub_context_list() {
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;

        let preview = preview_delete_context(
            &ks.contexts,
            &ks.keys,
            &ks.acl,
            &ks.did_templates,
            #[cfg(feature = "webvh")]
            &ks.webvh,
            &super_admin(),
            "acme",
            "t",
        )
        .await
        .expect("preview");

        assert!(preview.sub_contexts.is_empty());
    }

    /// A deletion that destroyed nothing on a host reports no orphans — the
    /// control for the partial-success member, so a consumer reading it as
    /// "absent means clean" is reading something that was actually decided.
    #[tokio::test]
    async fn a_clean_delete_reports_no_daemon_cleanup_errors() {
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;

        let result = delete_context(
            &ks.as_ks(),
            &super_admin(),
            "acme",
            true,
            "t",
            #[cfg(feature = "webvh")]
            None,
        )
        .await
        .expect("delete");

        assert!(result.deleted);
        assert!(result.daemon_cleanup_errors.is_empty());
    }

    #[tokio::test]
    async fn delete_refuses_a_context_with_sub_contexts_without_force() {
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;
        seed(&ks.contexts, "acme/eng", Some("acme")).await;

        let err = delete_context(&ks.as_ks(), &super_admin(), "acme", false, "t", None)
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

        delete_context(&ks.as_ks(), &super_admin(), "acme", true, "t", None)
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
        delete_context(&ks.as_ks(), &admin_of("acme"), "acme/eng", false, "t", None)
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

        let err = delete_context(&ks.as_ks(), &admin_of("acme"), "other", false, "t", None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
        assert!(get_context(&ks.contexts, "other").await.unwrap().is_some());
    }
}
