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

/// Who is creating a context: an administrator, or a provisioner exercising
/// [`Capability::ContextCreate`](vti_common::acl::Capability::ContextCreate).
///
/// The difference outlives the create: a context a provisioner made is
/// recorded as its own, and that is the only kind of context whose unset DID it
/// may later fill ([`update_context_did`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateAuthority {
    Admin,
    Provisioner,
}

/// The create gate: the caller must be an admin **or** hold
/// [`Capability::ContextCreate`](vti_common::acl::Capability::ContextCreate).
///
/// Necessary and not sufficient on its own — [`create_context`] calls it and
/// then applies the finer rule: super-admin for a top-level context,
/// reach-the-parent for a sub-context (VTI-CTX-020). So a capability holder can
/// only branch under what it already reaches, which is what lets an automated
/// provisioner exist without being an admin of the context it provisions into.
///
/// An admin passes on its role without an ACL read, so the offline CLI (whose
/// synthesized `cli:` DID is in no ACL) is unaffected. Anyone else needs an
/// entry naming the capability; a failed read refuses
/// ([`caller_has_capability`](crate::operations::acl::caller_has_capability)).
pub async fn ensure_may_create_context(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
) -> Result<CreateAuthority, AppError> {
    if auth.require_admin().is_ok() {
        return Ok(CreateAuthority::Admin);
    }
    if crate::operations::acl::caller_has_capability(
        acl_ks,
        auth,
        vti_common::acl::Capability::ContextCreate,
    )
    .await
    {
        return Ok(CreateAuthority::Provisioner);
    }
    // Report the role failure: the role gate is the one every other caller
    // meets, and naming a capability the caller does not hold tells it what to
    // ask for.
    auth.require_admin().map(|()| CreateAuthority::Admin)
}

/// Create a context — top-level, or a sub-context nested under `parent`.
///
/// `id` is the **leaf** segment; when `parent` is set the stored id is the full
/// path `<parent>/<id>` (`docs/05-design-notes/hierarchical-contexts.md`).
///
/// **Authorization** — [`ensure_may_create_context`] first (admin role, or the
/// `context-create` capability), here rather than in a handler so that every
/// transport and in-process caller meets the same gate; then:
/// - **top-level** (`parent` is `None`) — super-admin only (unchanged).
/// - **sub-context** (`parent` is `Some`) — the parent must exist and the caller
///   must reach it (`require_context(parent)` passes for a caller scoped to the
///   parent or any ancestor, and for a super-admin) — VTI-CTX-020.
///
/// A context created under the capability is recorded as that provisioner's
/// ([`crate::contexts::store_new_provisioned_context`]).
///
/// The sub-context's BIP-32 base nests under the parent's, and the path depth is
/// bounded by [`vti_common::context_path::child_path`].
#[allow(clippy::too_many_arguments)]
pub async fn create_context(
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    name: String,
    description: Option<String>,
    parent: Option<String>,
    channel: &str,
) -> Result<CreateContextResultBody, ContextError> {
    let authority = ensure_may_create_context(acl_ks, auth).await?;

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
            // Sub-context: the parent must exist and the caller must reach it.
            // `require_context` is the segment-aware ancestry gate; the role or
            // capability was checked above.
            // Scope first, then existence, and one answer for both — the
            // specification requires the same treatment `vta/contexts/get`
            // sets out, and names it `create:parentNotFound`. This used to
            // look the parent up *before* checking scope and report the two
            // separately, so an unauthorised caller could learn which parent
            // ids are real by reading which refusal came back.
            if auth.require_context(parent_id).is_err() {
                return Err(ContextError::ParentUnreachable);
            }
            let parent_ctx = get_context(contexts_ks, parent_id)
                .await?
                .ok_or(ContextError::ParentUnreachable)?;
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
        return Err(ContextError::Other(AppError::Conflict(format!(
            "context already exists: {full_id}"
        ))));
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
    let stored = match authority {
        CreateAuthority::Admin => crate::contexts::store_new_context(contexts_ks, &record).await?,
        CreateAuthority::Provisioner => {
            crate::contexts::store_new_provisioned_context(contexts_ks, &record, &auth.did).await?
        }
    };
    if !stored {
        return Err(ContextError::Other(AppError::Conflict(format!(
            "context already exists: {}",
            record.id
        ))));
    }

    info!(channel, id = %record.id, parent = ?record.parent, index, "context created");
    Ok(to_result_body(&record))
}

pub async fn get_context_op(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    channel: &str,
) -> Result<CreateContextResultBody, ContextError> {
    let record = reach_context(contexts_ks, auth, id).await?;
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
) -> Result<CreateContextResultBody, ContextError> {
    auth.require_super_admin()?;

    // Super-admin reaches every context, so this only ever resolves the
    // existence half — but it resolves it to the same answer the rest of the
    // family gives, which is what `update:notFound` names.
    let mut record = reach_context(contexts_ks, auth, id).await?;

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

/// Whether `auth` is the provisioner of context `id`: it reaches the context,
/// still holds [`Capability::ContextCreate`](vti_common::acl::Capability::ContextCreate),
/// and is the DID recorded as having created it under that capability
/// ([`crate::contexts::context_provisioner`]).
///
/// The provisioning case: an automated caller creates a context and must then
/// make it usable — give it a DID. Only the context it created: reaching a
/// context is not enough, or a provisioner scoped to `gw` could set the
/// identity of `gw` itself, or of any context an administrator made beneath it.
///
/// Returning `false` is not a refusal; it means the ordinary admin gate decides.
async fn is_provisioner_of(
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
) -> Result<bool, AppError> {
    // Reach first, so this never reads anything in a subtree the caller was
    // not granted.
    if auth.require_context(id).is_err() {
        return Ok(false);
    }
    if crate::contexts::context_provisioner(contexts_ks, id)
        .await?
        .as_deref()
        != Some(&auth.did)
    {
        return Ok(false);
    }
    Ok(crate::operations::acl::caller_has_capability(
        acl_ks,
        auth,
        vti_common::acl::Capability::ContextCreate,
    )
    .await)
}

/// A provisioner may name only the `did:key` of an active Ed25519 key that lives
/// in `context_id` itself.
///
/// A `did:key` resolves to exactly the key it is derived from, under every
/// verification relationship, with no document to publish — so naming one the
/// context holds is the only identity a provisioner can give it that the context
/// is certain to control. Anything else (another DID method, or a `did:key` of a
/// key held elsewhere) is an administrator's decision.
async fn require_did_is_a_context_key(
    keys_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    context_id: &str,
    did: &str,
) -> Result<(), ContextError> {
    let refuse = |why: String| refuse_provisioning(auth, context_id, why);
    let Some(public_key) = did.strip_prefix("did:key:") else {
        return Err(refuse(format!(
            "a provisioner may name only a `did:key` for context `{context_id}`; any other DID \
             is an administrator's act"
        )));
    };
    let held = crate::operations::keys::find_key_by_public_multibase_in_context(
        keys_ks, public_key, context_id,
    )
    .await?;
    if held.is_some_and(|k| k.key_type == vta_sdk::keys::KeyType::Ed25519) {
        return Ok(());
    }
    Err(refuse(format!(
        "`{did}` is not the did:key of an active Ed25519 key held in context `{context_id}`, so a \
         provisioner may not name it"
    )))
}

/// Refuse a provisioning attempt, logged as a security alert: this path is
/// reachable without administrative authority.
fn refuse_provisioning(auth: &AuthClaims, id: &str, why: String) -> ContextError {
    tracing::warn!(
        security_alert = true,
        caller = %auth.did,
        context = %id,
        reason = %why,
        "context DID provisioning refused"
    );
    ContextError::Other(AppError::Forbidden(why))
}

/// Update the DID for a context. Requires Admin role with access to the context
/// (context-scoped admins can update DIDs on their own contexts).
///
/// A caller holding `context-create` may instead set the DID of a context **it
/// created**, **while that DID is unset**, to the `did:key` of a key the context
/// holds — which is what lets it finish provisioning. See [`is_provisioner_of`].
///
/// **Write-once, deliberately.** A provisioner may fill a blank field; it may
/// never change or clear an established one. Re-pointing a context's identity
/// is how an automated process would quietly become something else, and it is
/// an administrator's act. The bound is applied to the record as read and the
/// write is a compare-and-swap on those bytes, so a DID set by anyone in
/// between makes the provisioner's write fail rather than overwrite it.
///
/// An administrator is never treated as provisioning: the bound would stop it
/// re-pointing a DID, which is exactly the act the bound reserves for it.
pub async fn update_context_did(
    contexts_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    did: Option<String>,
    channel: &str,
) -> Result<CreateContextResultBody, ContextError> {
    if auth.require_admin().is_err() {
        if !is_provisioner_of(contexts_ks, acl_ks, auth, id).await? {
            // Not an admin, and not this context's provisioner: the ordinary
            // refusal, which names the role.
            auth.require_admin()?;
        }
        return provision_context_did(contexts_ks, keys_ks, auth, id, did, channel).await;
    }

    let mut record = reach_context(contexts_ks, auth, id).await?;

    // `None` clears (`update-did/1.1`, `did: null`). Clearing a context that
    // has no DID is not an error — the requested state already holds. The DID
    // itself is untouched: it can be assigned again, or now deleted.
    let previous = std::mem::replace(&mut record.did, did);
    record.updated_at = Utc::now();

    store_context(contexts_ks, &record).await?;

    match &record.did {
        Some(did) => {
            info!(channel, id = %id, did = %did, previous = ?previous, "context DID updated")
        }
        None => info!(channel, id = %id, previous = ?previous, "context DID cleared"),
    }
    Ok(to_result_body(&record))
}

/// The provisioner's half of [`update_context_did`]: write-once, bound to a key
/// the context holds, and a compare-and-swap against the record the bound was
/// checked on.
async fn provision_context_did(
    contexts_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    did: Option<String>,
    channel: &str,
) -> Result<CreateContextResultBody, ContextError> {
    let raw = crate::contexts::get_context_raw(contexts_ks, id)
        .await?
        .ok_or(ContextError::Unreachable)?;
    let mut record: ContextRecord = serde_json::from_slice(&raw)
        .map_err(|e| AppError::Internal(format!("context `{id}` is unreadable: {e}")))?;

    if record.did.is_some() {
        return Err(refuse_provisioning(
            auth,
            id,
            format!(
                "context `{id}` already has a DID; changing it is an administrator's act, not a \
                 provisioning one"
            ),
        ));
    }
    let Some(did) = did else {
        return Err(refuse_provisioning(
            auth,
            id,
            format!("clearing the DID on context `{id}` is an administrator's act"),
        ));
    };
    require_did_is_a_context_key(keys_ks, auth, id, &did).await?;

    record.did = Some(did);
    record.updated_at = Utc::now();
    if !crate::contexts::store_context_if_unchanged(contexts_ks, &record, raw).await? {
        // Someone wrote the record after it was read. Not necessarily its DID —
        // a rename also counts — so this is a conflict to re-read and retry,
        // and the retry meets the write-once bound against what is there now.
        return Err(ContextError::Other(AppError::Conflict(format!(
            "context `{id}` changed while its DID was being provisioned; read it again and retry"
        ))));
    }

    info!(channel, id = %id, did = ?record.did, provisioner = %auth.did, "context DID provisioned");
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
) -> Result<DeleteContextPreviewResultBody, ContextError> {
    // Admin role + access to the context (or an ancestor) — folder authority.
    auth.require_admin()?;
    reach_context(contexts_ks, auth, id).await?;

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

/// What the subtree holds, when that is why a deletion was refused.
///
/// Counts rather than lists: the operator who wants the identifiers has
/// `vta/contexts/preview-delete/1.0`, which returns them, and duplicating that
/// here would be a second answer to the same question — the divergence this
/// module spent #1576 removing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NotEmpty {
    pub sub_contexts: usize,
    pub keys: usize,
    pub webvh_dids: usize,
    /// ACL entries the deletion would remove outright or narrow.
    pub acl_entries: usize,
    pub did_templates: usize,
}

impl NotEmpty {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sub_contexts == 0
            && self.keys == 0
            && self.webvh_dids == 0
            && self.acl_entries == 0
            && self.did_templates == 0
    }

    /// An operator-facing summary naming only what is actually there.
    #[must_use]
    pub fn summary(&self) -> String {
        let plural =
            |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
        let mut parts = Vec::new();
        if self.sub_contexts > 0 {
            parts.push(plural(self.sub_contexts, "sub-context", "sub-contexts"));
        }
        if self.keys > 0 {
            parts.push(plural(self.keys, "key", "keys"));
        }
        if self.webvh_dids > 0 {
            parts.push(plural(self.webvh_dids, "published DID", "published DIDs"));
        }
        if self.acl_entries > 0 {
            parts.push(plural(self.acl_entries, "ACL entry", "ACL entries"));
        }
        if self.did_templates > 0 {
            parts.push(plural(self.did_templates, "DID template", "DID templates"));
        }
        match parts.len() {
            0 => "nothing".to_string(),
            1 => parts.remove(0),
            _ => {
                let last = parts.pop().unwrap_or_default();
                format!("{} and {last}", parts.join(", "))
            }
        }
    }
}

/// Why a context operation refused, when the reason is one the family's
/// specifications name as an error code of their own.
///
/// A distinct type, rather than more [`AppError`] variants, because exactly
/// one caller needs to tell these apart: the Trust-Task handlers, which owe
/// `<task>:notFound`, `vta/contexts/delete:notEmpty` and
/// `vta/contexts/create:parentNotFound` on the wire. `AppError` is shared by
/// the whole workspace and every match on it would have to grow arms for
/// codes belonging to one family.
///
/// Typed rather than matched on `AppError::NotFound`, which was the cheaper
/// option and is wrong: `delete_context` also drives
/// `delete_did_webvh_with`, whose own `NotFound` means a DID record is
/// missing. Mapping every `NotFound` in the handler to `delete:notFound`
/// would answer "no such context" for a DID that vanished mid-cascade.
///
/// `From<AppError>` keeps `?` working inside these functions, and
/// `From<ContextError>` converts back for the transports that carry a status
/// rather than a Trust-Task code — so a caller that does not care is
/// unchanged.
#[derive(Debug)]
#[non_exhaustive]
pub enum ContextError {
    /// No context with this id is reachable by this caller — **whether or not
    /// it exists**. The family's `<task>:notFound`.
    ///
    /// One variant for both because the specifications require one answer:
    /// `vta/contexts/get` puts it plainly ("deliberately does not distinguish
    /// 'does not exist' from 'exists but not yours'"), and `update`,
    /// `update-did` and `delete` each repeat it as "whether or not it
    /// exists". Distinguishing them tells an unauthorised caller which ids
    /// are real.
    Unreachable,
    /// The `parent` of a create is unreachable — `create:parentNotFound`. The
    /// same question as [`Self::Unreachable`] asked about a different id, and
    /// a separate variant only because the code the specification declares
    /// for it is named differently.
    ParentUnreachable,
    /// Refused because the subtree holds something and `force` was absent —
    /// `vta/contexts/delete:notEmpty`.
    NotEmpty(NotEmpty),
    /// Refused because the published log of at least one `did:webvh` DID in
    /// the subtree could not be confirmed removed from its host, and the
    /// caller did not choose to abandon it — `vta/contexts/delete:hostCleanupFailed`.
    /// Nothing local was deleted.
    HostCleanupFailed(Vec<HostCleanupFailure>),
    Other(AppError),
}

/// One host copy a context deletion could not confirm removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCleanupFailure {
    pub did: String,
    /// The hosting server's id here, when the record names one.
    pub server: Option<String>,
    pub reason: String,
}

impl std::fmt::Display for HostCleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.did, self.reason)
    }
}

/// Says how many host copies were left, for a refusal's message.
pub(crate) fn host_cleanup_summary(failures: &[HostCleanupFailure]) -> String {
    let n = failures.len();
    format!(
        "{n} published DID{} could not be removed from {} hosting server; nothing was \
         deleted. Retry once the host is reachable, or retry abandoning the host \
         cop{} — they may then keep resolving, and removing them is yours to do",
        if n == 1 { "" } else { "s" },
        if n == 1 { "its" } else { "their" },
        if n == 1 { "y" } else { "ies" },
    )
}

impl From<AppError> for ContextError {
    fn from(e: AppError) -> Self {
        Self::Other(e)
    }
}

impl From<ContextError> for AppError {
    fn from(e: ContextError) -> Self {
        match e {
            // 404 on both, which is the enumeration-safe status and already
            // what REST answered for the missing half.
            ContextError::Unreachable => AppError::NotFound("context not found".into()),
            ContextError::ParentUnreachable => {
                AppError::NotFound("parent context not found".into())
            }
            // Conflict, not Validation: the request is well-formed and the
            // refusal is about the state of the context, which is what 409
            // says and 400 does not.
            ContextError::NotEmpty(n) => AppError::Conflict(format!(
                "context holds {}; use force=true to delete the whole subtree, or preview first",
                n.summary()
            )),
            // Bad gateway, not Conflict: the request is fine and the state is
            // fine — a host this VTA does not control did not do its part, and
            // retrying later is a legitimate fix.
            ContextError::HostCleanupFailed(failures) => crate::error::bad_gateway_error(format!(
                "{}:\n{}",
                host_cleanup_summary(&failures),
                failures
                    .iter()
                    .map(|f| format!("  - {f}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )),
            ContextError::Other(e) => e,
        }
    }
}

impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable => write!(f, "context not found"),
            Self::ParentUnreachable => write!(f, "parent context not found"),
            Self::NotEmpty(n) => write!(f, "context holds {}", n.summary()),
            Self::HostCleanupFailed(failures) => f.write_str(&host_cleanup_summary(failures)),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ContextError {}

/// The context `id`, if this caller can reach it.
///
/// The family's single answer to "does this caller get to act on this id",
/// and the reason it is one function: the check is two steps — scope, then
/// existence — and performing them in the wrong order, or reporting them
/// separately, is what tells an unauthorised caller which ids are real. Every
/// id-taking task in the family had them separate, and `create_context` had
/// them in the opposite order to everything else.
///
/// **Not for `vta/contexts/secrets`.** That task's specification takes the
/// opposite position deliberately and argues it: entitlement is checked
/// *before* existence, so "not found" is only ever said to a caller already
/// entitled to hear it, and the pair leaks nothing. `operations::export`
/// keeps that order, and `entitlement_is_checked_before_existence` pins it.
async fn reach_context(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
) -> Result<ContextRecord, ContextError> {
    if auth.require_context(id).is_err() {
        return Err(ContextError::Unreachable);
    }
    get_context(contexts_ks, id)
        .await?
        .ok_or(ContextError::Unreachable)
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
    /// What to do about a host copy that cannot be confirmed removed.
    pub host_copies: HostCopies,
}

/// What a context deletion does about a `did:webvh` log whose hosting server
/// does not confirm removing it.
///
/// Every policy removes host copies **first**, all at once and within
/// [`HOST_SETTLE_BUDGET`], before any local record goes: the records are the
/// only means of removing a host copy later (VTI R2.1), and a host that never
/// answers must not hold the deletion past the caller's patience — it used to
/// cost a full reply timeout per DID, one after another, which outlasted the
/// client's own timeout and left the operator unable to finish the deletion.
#[cfg(feature = "webvh")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCopies {
    /// The offline break-glass `vta contexts delete` (the contract of the
    /// retired `vta/contexts/delete/1.0`): a DID whose hosting server is no
    /// longer registered refuses the deletion; any other unconfirmed copy is
    /// reported in `daemonCleanupErrors` and the deletion completes.
    ReportAfter,
    /// `vta/contexts/delete/1.1` without `abandonHostCopies`: any unconfirmed
    /// copy refuses with `hostCleanupFailed`, and nothing local is deleted.
    RequireRemoved,
    /// `vta/contexts/delete/1.1` with `abandonHostCopies`: the deletion
    /// completes, and each unconfirmed copy is reported.
    Abandon,
}

/// The whole time a context deletion spends on hosting servers, however many
/// DIDs it holds. Under the 30 seconds a client may wait (the SDK waits 60),
/// with room for the local work after it; a host that has not answered by then
/// is unconfirmed.
#[cfg(feature = "webvh")]
pub const HOST_SETTLE_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// How many hosts a deletion talks to at once.
#[cfg(feature = "webvh")]
const HOST_SETTLE_CONCURRENCY: usize = 8;

/// Remove the host copy of every DID in `dids`, at most
/// [`HOST_SETTLE_CONCURRENCY`] at a time and all within
/// [`HOST_SETTLE_BUDGET`], returning the ones not confirmed removed.
#[cfg(feature = "webvh")]
async fn settle_host_copies(
    cleanup: &ContextDidCleanup<'_>,
    dids: &[String],
) -> Result<Vec<HostCleanupFailure>, AppError> {
    use crate::operations::did_webvh::HostCopy;

    let deadline = tokio::time::Instant::now() + HOST_SETTLE_BUDGET;
    let mut failures = Vec::new();
    // A chunk at a time under one deadline: a later chunk gets whatever the
    // budget has left, and a host reached after it is unconfirmed, not waited on.
    for chunk in dids.chunks(HOST_SETTLE_CONCURRENCY) {
        let outcomes = futures_util::future::join_all(
            chunk
                .iter()
                .map(|did| settle_host_copy(cleanup, did, deadline)),
        )
        .await;
        for (did, outcome) in chunk.iter().zip(outcomes) {
            if let HostCopy::Unconfirmed { server, reason } = outcome? {
                failures.push(HostCleanupFailure {
                    did: did.clone(),
                    server,
                    reason,
                });
            }
        }
    }
    Ok(failures)
}

/// One DID's host copy, given up on at `deadline`.
#[cfg(feature = "webvh")]
async fn settle_host_copy(
    cleanup: &ContextDidCleanup<'_>,
    did: &str,
    deadline: tokio::time::Instant,
) -> Result<crate::operations::did_webvh::HostCopy, AppError> {
    use crate::operations::did_webvh::{HostCopy, remove_host_copy};

    match tokio::time::timeout_at(
        deadline,
        remove_host_copy(cleanup.deps, did, cleanup.vta_did),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => Ok(HostCopy::Unconfirmed {
            server: crate::webvh_store::get_did(cleanup.deps.webvh_ks, did)
                .await?
                .map(|r| r.server_id),
            reason: format!(
                "the hosting server did not answer within {}s",
                HOST_SETTLE_BUDGET.as_secs()
            ),
        }),
    }
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
) -> Result<DeleteContextResultBody, ContextError> {
    let contexts_ks = ks.contexts;
    let keys_ks = ks.keys;
    let acl_ks = ks.acl;
    let did_templates_ks = ks.did_templates;
    #[cfg(feature = "webvh")]
    let webvh_ks = ks.webvh;
    // Admin role + access to the context (or an ancestor) — folder authority: a
    // parent-admin may delete a sub-context and its subtree.
    auth.require_admin()?;
    reach_context(contexts_ks, auth, id).await?;

    // The subtree below `id`, deepest first (so children are removed before
    // parents and ACL re-classification stays correct each step).
    let descendants = list_descendants(contexts_ks, id).await?;

    // Delete the subtree: each descendant (deepest first), then `id`.
    let mut to_delete = descendants;
    to_delete.push(id.to_string());

    // What the deletion would destroy, measured over the whole subtree and
    // measured once — the same scan the force gate and the refusal message
    // both read. This used to count the named context's own resources and
    // separately test "are there descendants", which reached the right
    // verdict and then described it as "associated resources": true of a
    // context holding one key and of a subtree holding forty.
    let contents = collect_subtree_resources(
        keys_ks,
        acl_ks,
        did_templates_ks,
        #[cfg(feature = "webvh")]
        webvh_ks,
        &to_delete,
    )
    .await?;
    let holds = NotEmpty {
        sub_contexts: to_delete.len() - 1,
        keys: contents.keys.len(),
        webvh_dids: contents.webvh_dids.len(),
        acl_entries: contents.acl_entries_removed.len() + contents.acl_entries_updated.len(),
        did_templates: contents.did_templates.len(),
    };

    // `force` is an explicitness flag, not a privilege: the specification is
    // explicit that a consumer MUST NOT require a different role for it, and
    // MUST NOT treat its absence as permission to delete contents anyway.
    if !holds.is_empty() && !force {
        return Err(ContextError::NotEmpty(holds));
    }

    // Host copies the deletion did not get confirmed removed. Deletion carries
    // on only where the caller's policy says so — the alternative is a subtree
    // half gone — and the orphans are named rather than counted, because an
    // operator cleaning up out-of-band needs the identifiers and a count tells
    // them only that they have a problem.
    #[allow(unused_mut)]
    let mut orphans: Vec<String> = Vec::new();

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
        // The break-glass CLI keeps its refusal for a server no longer
        // registered; 1.1 counts that as one more unconfirmed host copy,
        // settled below.
        let options =
            crate::operations::did_webvh::DeleteDidOptions::within_context_deletion(&to_delete);
        let options = if cleanup.host_copies == HostCopies::ReportAfter {
            options
        } else {
            options.with_host_copy_settled()
        };
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
            return Err(ContextError::Other(AppError::Conflict(format!(
                "context `{id}` cannot be deleted — {} DID blocker{} to resolve first:\n{}",
                blockers.len(),
                if blockers.len() == 1 { "" } else { "s" },
                blockers
                    .iter()
                    .map(|b| format!("  - {b}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))));
        }

        // ---- Host copies, before anything local ----------------------------
        //
        // Every one at once, within one budget. A local record removed before
        // its host copy is the one state from which the host copy can never be
        // removed at all (VTI R2.1), so a refusal here must come while every
        // record is still in place — a retry then completes the deletion, and
        // finds the copies that did go already gone.
        let failures = settle_host_copies(cleanup, &subtree_dids).await?;
        if !failures.is_empty() {
            if cleanup.host_copies == HostCopies::RequireRemoved {
                tracing::warn!(
                    channel,
                    id = %id,
                    unconfirmed = failures.len(),
                    detail = %failures.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "),
                    "context deletion refused: host copies not confirmed removed; nothing deleted"
                );
                return Err(ContextError::HostCleanupFailed(failures));
            }
            orphans = failures.iter().map(ToString::to_string).collect();
        }
    }

    let (mut keys, mut acl_removed, mut acl_updated, mut templates) = (0, 0, 0, 0);
    let mut rows = PurgedRows::default();
    #[allow(unused_mut)]
    let mut dids = 0usize;

    for ctx_id in &to_delete {
        // DIDs first. Their host copies were settled above, so each deletion
        // goes straight to the local cascade: credentials, records, keys,
        // authority and sessions.
        #[cfg(feature = "webvh")]
        if let Some(cleanup) = webvh {
            let options =
                crate::operations::did_webvh::DeleteDidOptions::within_context_deletion(&to_delete)
                    .with_host_copy_settled();
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

        let purged = purge_context_resources(ks, ctx_id).await?;
        keys += purged.keys.len();
        acl_removed += purged.acl_entries_removed.len();
        acl_updated += purged.acl_entries_updated.len();
        templates += purged.did_templates.len();
        // Everything held *for* the context, keyed by its id: left behind, a
        // context later created under the same id inherits it.
        rows += purge_context_rows(ks, ctx_id).await?;
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
        app_state_records_removed = rows.app_state,
        memory_entries_removed = rows.memory,
        persona_records_removed = rows.persona,
        credentials_removed = rows.credentials,
        vault_entries_removed = rows.vault_entries,
        consent_records_removed = rows.consent,
        consent_approvers_removed = rows.consent_approvers,
        notifications_removed = rows.notifications,
        pcs_engine_records_removed = rows.pcs_engine,
        external_accounts_removed = rows.external_accounts,
        quota_counters_removed = rows.quota_counters,
        collection_records_removed = rows.collection,
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

/// Collect **and delete** every resource (keys and their secret material, ACL
/// refs, DID templates) attached to a single `context_id`. Returns the
/// collected preview (for counts). Does NOT delete the context record itself.
async fn purge_context_resources(
    ks: &super::Keyspaces<'_>,
    context_id: &str,
) -> Result<DeleteContextPreviewResultBody, AppError> {
    let preview = collect_context_resources(
        ks.keys,
        ks.acl,
        ks.did_templates,
        #[cfg(feature = "webvh")]
        ks.webvh,
        context_id,
    )
    .await?;

    for key_id in &preview.keys {
        // The material first, then the record that names it. An imported
        // key's wrapped secret and an internal key's material are stored
        // under the key id; left behind, they outlive the only record that
        // says what they are. `revoke_key` destroys an imported secret the same
        // way. Both removals are no-ops for a key of the other origins.
        vta_keys::imported::delete_secret(ks.imported, key_id).await?;
        vta_keys::internal::delete(ks.internal, key_id).await?;
        ks.keys.remove(crate::keys::store_key(key_id)).await?;
    }
    // No DID deletion here. The subtree's `did:webvh` DIDs are deleted by
    // `delete_context` through the full webvh path *before* this runs, so by
    // the time a context is purged it has none left. Deleting the record here
    // as well would be a second, weaker implementation of the same step — the
    // one that left host copies published.
    for did in &preview.acl_entries_removed {
        crate::acl::delete_acl_entry(ks.acl, did).await?;
    }
    for did in &preview.acl_entries_updated {
        if let Some(mut entry) = crate::acl::get_acl_entry(ks.acl, did).await? {
            entry.allowed_contexts.retain(|c| c != context_id);
            crate::acl::store_acl_entry(ks.acl, &entry).await?;
        }
    }
    crate::did_templates::delete_all_context_templates(ks.did_templates, context_id).await?;

    Ok(preview)
}

/// The keyspaces [`delete_context`] purges a deleted context's rows from — the
/// cascade's own statement of what it reaches.
///
/// `context_delete_labels_match_the_cascade` holds
/// [`vta_keyspaces::context_delete_effect`]'s `Purged` set to exactly this
/// list, so a keyspace cannot be labelled purged without being added here, and
/// one added here has to be labelled. Keep it in step with [`purge_context_rows`]
/// and [`purge_context_resources`].
#[cfg(test)]
const PURGED_ON_CONTEXT_DELETE: &[&str] = &[
    crate::keyspaces::CONTEXTS,
    crate::keyspaces::KEYS,
    crate::keyspaces::IMPORTED_SECRETS,
    crate::keyspaces::INTERNAL_KEYS,
    crate::keyspaces::WEBVH,
    crate::keyspaces::ACL,
    crate::keyspaces::DID_TEMPLATES,
    crate::keyspaces::APP_STATE,
    crate::keyspaces::MEMORY,
    crate::keyspaces::PERSONA,
    crate::keyspaces::VAULT,
    crate::keyspaces::CONSENT,
    crate::keyspaces::CONSENT_APPROVERS,
    crate::keyspaces::NOTIFICATIONS,
    crate::keyspaces::PCS_ENGINE,
    crate::keyspaces::EXTERNAL_ACCOUNTS,
    crate::keyspaces::EXTERNAL_SECRETS,
    crate::keyspaces::COLLECTION,
];

/// How many rows [`purge_context_rows`] removed, by store, for the log line.
#[derive(Debug, Default)]
struct PurgedRows {
    app_state: usize,
    memory: usize,
    persona: usize,
    credentials: usize,
    vault_entries: usize,
    consent: usize,
    consent_approvers: usize,
    notifications: usize,
    pcs_engine: usize,
    external_accounts: usize,
    quota_counters: usize,
    collection: usize,
}

impl std::ops::AddAssign for PurgedRows {
    fn add_assign(&mut self, o: Self) {
        self.app_state += o.app_state;
        self.memory += o.memory;
        self.persona += o.persona;
        self.credentials += o.credentials;
        self.vault_entries += o.vault_entries;
        self.consent += o.consent;
        self.consent_approvers += o.consent_approvers;
        self.notifications += o.notifications;
        self.pcs_engine += o.pcs_engine;
        self.external_accounts += o.external_accounts;
        self.collection += o.collection;
        self.quota_counters += o.quota_counters;
    }
}

/// Remove every record keyed by, or carrying, `context_id` in the stores that
/// hold data *for* the context — everything but its keys, ACL scope, DID
/// templates and DIDs, which [`purge_context_resources`] and the DID deletion
/// take.
///
/// A context can be created again under the same id, and whatever survives
/// here is inherited by it: application state syncing a deleted profile's
/// personas back (#2415), a vetter engine pinned to the old member DID so the
/// new context's `vta/pcs/root-request` fails with `memberMismatch`. Each store
/// purges itself, next to the code that writes it.
///
/// Not part of the not-empty gate: the gate must agree with `preview-delete`,
/// whose wire shape has no member for any of these, and a refusal the preview
/// cannot explain is the failure that function's comment describes. Counted in
/// the log line instead.
async fn purge_context_rows(
    ks: &super::Keyspaces<'_>,
    context_id: &str,
) -> Result<PurgedRows, AppError> {
    Ok(PurgedRows {
        app_state: super::app_state::purge_context(ks.app_state, context_id).await?,
        memory: super::memory::purge_context(ks.memory, context_id).await?,
        persona: vta_persona::storage::purge_context(ks.persona, context_id).await?,
        credentials: vta_vault::storage::purge_context(ks.vault, context_id).await?,
        vault_entries: vti_common::vault::purge_context(ks.vault, context_id).await?,
        consent: vti_common::consent::purge_context_consent(ks.consent, context_id).await?,
        consent_approvers: vti_common::consent::purge_context_approvers(
            ks.consent_approvers,
            context_id,
        )
        .await?,
        notifications: super::notifications::purge_context(ks.notifications, context_id).await?,
        pcs_engine: super::pcs::purge_context(ks.pcs_engine, context_id).await?,
        external_accounts: vta_external::store::purge_context(
            ks.external_accounts,
            ks.external_secrets,
            context_id,
        )
        .await?,
        quota_counters: crate::contexts::purge_quota_counters(ks.contexts, context_id).await?,
        // Every collection claim for the context's identifiers ends with it
        // (VTI-NTF-090); the collector stops on its next pass.
        collection: super::collection::purge_context(ks.collection, context_id).await?,
    })
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

    /// `update-did/1.1`'s `did: null`: the context is left with no DID, the
    /// record comes back without one, and a second clear is not an error.
    #[tokio::test]
    async fn clearing_a_context_did_removes_it_and_is_idempotent() {
        let (_d, _s, ks, acl) = fresh_contexts_and_acl();
        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "acme",
            "Acme".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        let keys_ks = _s.keyspace(crate::keyspaces::KEYS).unwrap();
        let set = update_context_did(
            &ks,
            &keys_ks,
            &acl,
            &admin_of("acme"),
            "acme",
            Some("did:web:a.example".into()),
            "t",
        )
        .await
        .expect("assign");
        assert_eq!(set.did.as_deref(), Some("did:web:a.example"));

        let cleared = update_context_did(&ks, &keys_ks, &acl, &admin_of("acme"), "acme", None, "t")
            .await
            .expect("clear");
        assert_eq!(cleared.did, None);
        assert_eq!(
            get_context_op(&ks, &super_admin(), "acme", "t")
                .await
                .unwrap()
                .did,
            None,
            "the clear was not stored"
        );

        let again = update_context_did(&ks, &keys_ks, &acl, &admin_of("acme"), "acme", None, "t")
            .await
            .expect("clearing a context with no DID is not an error");
        assert_eq!(again.did, None);
    }

    #[tokio::test]
    async fn creates_a_top_level_context() {
        let (_d, _s, ks) = fresh_contexts();
        let r = create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "acme",
            "Acme".into(),
            None,
            None,
            "t",
        )
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
        let err = create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &admin_of("acme"),
            "ops",
            "Ops".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ContextError::Other(AppError::Forbidden(_))),
            "creating a top-level context is a role question, not an id one: {err:?}"
        );
    }

    #[tokio::test]
    async fn admin_of_parent_creates_a_nested_context_with_nested_base_path() {
        let (_d, _s, ks) = fresh_contexts();
        let parent = create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "acme",
            "Acme".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();

        // An admin scoped to `acme` nests `eng` under it.
        let child = create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
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

        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "acme",
            "Acme".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
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
        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "acme",
            "Acme".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
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
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &admin_of("acme"),
            "team",
            "Team".into(),
            None,
            Some("other".into()),
            "t",
        )
        .await
        .unwrap_err();
        // ...and is told the same thing it would be told about a parent that
        // does not exist. The specification requires that answer in as many
        // words: "the same answer it gives for a parent that does not exist,
        // for the reason set out in `vta/contexts/get`". Told apart, the pair
        // is an oracle for which context ids are real.
        let absent = create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &admin_of("acme"),
            "team",
            "Team".into(),
            None,
            Some("ghost".into()),
            "t",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ContextError::ParentUnreachable), "{err:?}");
        assert!(
            matches!(absent, ContextError::ParentUnreachable),
            "{absent:?}"
        );
        // Indistinguishable on the way out, not merely the same variant: a
        // message naming one of them would hand back what the variant hides.
        assert_eq!(err.to_string(), absent.to_string());
    }

    #[tokio::test]
    async fn nesting_under_a_missing_parent_is_not_found() {
        let (_d, _s, ks) = fresh_contexts();
        let err = create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "eng",
            "Engineering".into(),
            None,
            Some("ghost".into()),
            "t",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ContextError::ParentUnreachable), "{err:?}");
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
        memory: KeyspaceHandle,
        app_state: KeyspaceHandle,
        internal: KeyspaceHandle,
        vault: KeyspaceHandle,
        consent: KeyspaceHandle,
        consent_approvers: KeyspaceHandle,
        persona: KeyspaceHandle,
        pcs_engine: KeyspaceHandle,
        notifications: KeyspaceHandle,
        external_accounts: KeyspaceHandle,
        external_secrets: KeyspaceHandle,
        collection: KeyspaceHandle,
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
                memory: &self.memory,
                app_state: &self.app_state,
                internal: &self.internal,
                vault: &self.vault,
                consent: &self.consent,
                consent_approvers: &self.consent_approvers,
                persona: &self.persona,
                pcs_engine: &self.pcs_engine,
                notifications: &self.notifications,
                external_accounts: &self.external_accounts,
                external_secrets: &self.external_secrets,
                collection: &self.collection,
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
            memory: k(ks::MEMORY),
            app_state: k(ks::APP_STATE),
            internal: k(ks::INTERNAL_KEYS),
            vault: k(ks::VAULT),
            consent: k(ks::CONSENT),
            consent_approvers: k(ks::CONSENT_APPROVERS),
            persona: k(ks::PERSONA),
            pcs_engine: k(ks::PCS_ENGINE),
            notifications: k(ks::NOTIFICATIONS),
            external_accounts: k(ks::EXTERNAL_ACCOUNTS),
            external_secrets: k(ks::EXTERNAL_SECRETS),
            collection: k(ks::COLLECTION),
            #[cfg(feature = "webvh")]
            webvh: k(ks::WEBVH),
            _dir: dir,
            _store: store,
        }
    }

    /// Seed a context (super-admin) by its full path; `parent` must already exist.
    async fn seed(ks: &KeyspaceHandle, id: &str, parent: Option<&str>) {
        // A super-admin passes the create gate on its role without reading the
        // ACL, so any keyspace stands in for it here.
        create_context(
            ks,
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
        // The typed refusal, not a string: this is what the Trust-Task handler
        // reads to emit `vta/contexts/delete:notEmpty`, and asserting on prose
        // is how the old check managed to pass while the wire carried
        // `malformedRequest`.
        let ContextError::NotEmpty(holds) = &err else {
            panic!("expected a notEmpty refusal, got {err:?}");
        };
        assert_eq!(holds.sub_contexts, 1);
        assert_eq!(holds.summary(), "1 sub-context");
        // Nothing was deleted.
        assert!(get_context(&ks.contexts, "acme").await.unwrap().is_some());
        assert!(
            get_context(&ks.contexts, "acme/eng")
                .await
                .unwrap()
                .is_some()
        );
    }

    /// The refusal counts the whole subtree, and names what is there.
    ///
    /// The old message said "associated resources" — as true of one key as of
    /// forty, and of a leaf as of a deep tree. An operator deciding whether to
    /// pass `force` is deciding about the difference.
    #[tokio::test]
    async fn the_refusal_counts_the_whole_subtree() {
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;
        seed(&ks.contexts, "acme/eng", Some("acme")).await;
        seed(&ks.contexts, "acme/eng/ci", Some("acme/eng")).await;
        // A grant two levels down: the named context holds nothing itself.
        seed_acl(&ks.acl, "did:key:zBuildBot", &["acme/eng/ci"]).await;

        let err = delete_context(&ks.as_ks(), &super_admin(), "acme", false, "t", None)
            .await
            .unwrap_err();
        let ContextError::NotEmpty(holds) = &err else {
            panic!("expected a notEmpty refusal, got {err:?}");
        };
        assert_eq!(holds.sub_contexts, 2);
        assert_eq!(holds.acl_entries, 1);
        assert_eq!(holds.summary(), "2 sub-contexts and 1 ACL entry");
    }

    /// An empty leaf is deletable without `force` — the control, so the
    /// refusal above is not simply "always refuses".
    #[tokio::test]
    async fn an_empty_leaf_needs_no_force() {
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;

        delete_context(&ks.as_ks(), &super_admin(), "acme", false, "t", None)
            .await
            .expect("an empty leaf deletes without force");
        assert!(get_context(&ks.contexts, "acme").await.unwrap().is_none());
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

    /// Application state and agent memory go with the context.
    ///
    /// Both are keyed by context id alone. Left behind, a context recreated
    /// under the same id inherited them: an OpenVTC profile wiped locally and
    /// re-provisioned into a fresh `openvtc-bob` synced the deleted profile's
    /// personas and communities straight back from `vta/app-state`.
    #[tokio::test]
    async fn delete_purges_app_state_and_memory_across_the_subtree() {
        use crate::operations::{app_state, memory};
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;
        seed(&ks.contexts, "acme/eng", Some("acme")).await;
        // A sibling sharing the prefix, which must survive.
        seed(&ks.contexts, "acme2", None).await;

        let locks = app_state::NamespaceLocks::default();
        let v = serde_json::json!({"n": 1});
        for ctx in ["acme", "acme/eng", "acme2"] {
            app_state::put(
                &ks.app_state,
                &locks,
                ctx,
                "openvtc",
                "persona",
                Some(&v),
                None,
                None,
            )
            .await
            .unwrap();
            memory::put(&ks.memory, ctx, "note", "x").await.unwrap();
        }
        // A tombstone and its version index, so every record family is present.
        app_state::put(
            &ks.app_state,
            &locks,
            "acme",
            "openvtc",
            "gone",
            Some(&v),
            None,
            None,
        )
        .await
        .unwrap();
        app_state::delete(&ks.app_state, &locks, "acme", "openvtc", "gone", None)
            .await
            .unwrap();

        delete_context(&ks.as_ks(), &super_admin(), "acme", true, "t", None)
            .await
            .expect("cascade delete");

        for ctx in ["acme", "acme/eng"] {
            for family in ["app", "appv", "appc", "appt"] {
                let left = ks
                    .app_state
                    .prefix_keys(format!("{family}:{ctx}:"))
                    .await
                    .unwrap();
                assert!(left.is_empty(), "{family} records left for {ctx}: {left:?}");
            }
            assert!(memory::list(&ks.memory, ctx).await.unwrap().is_empty());
        }

        // Recreated under the same id, the context starts empty.
        seed(&ks.contexts, "acme", None).await;
        assert!(matches!(
            app_state::get(&ks.app_state, "acme", "openvtc", "persona", true).await,
            Err(app_state::AppStateError::NotFound)
        ));

        // The prefix-sharing sibling is untouched.
        assert!(
            app_state::get(&ks.app_state, "acme2", "openvtc", "persona", false)
                .await
                .is_ok()
        );
        assert_eq!(memory::list(&ks.memory, "acme2").await.unwrap().len(), 1);
    }

    /// The `Purged` labels in `vta_keyspaces::context_delete_effect` are a
    /// claim about this cascade, held to the cascade's own list: a keyspace
    /// cannot be labelled purged without being purged here, nor purged here
    /// without being labelled.
    #[test]
    fn context_delete_labels_match_the_cascade() {
        use vta_keyspaces::{ContextDeleteEffect, context_delete_effect};
        for ks in crate::keyspaces::ALL {
            let labelled = context_delete_effect(ks) == Some(ContextDeleteEffect::Purged);
            let purged = PURGED_ON_CONTEXT_DELETE.contains(ks);
            assert_eq!(
                labelled, purged,
                "{ks}: labelled purged = {labelled}, purged by delete_context = {purged}"
            );
        }
    }

    const COMMUNITY: &str = "did:webvh:QmCommunity:vtc.example.org";

    /// One record of every kind a context's deletion must take, written into
    /// `ctx` through each store's own writer where it has one.
    async fn seed_context_rows(ks: &OwnedKs, ctx: &str) {
        use vta_persona::storage as ps;
        let tag = ctx.replace('/', "-");
        let now = Utc::now();

        // A key record, with material in both secret stores under its id —
        // an imported key's wrapped secret, an internal key's material.
        let key_id = format!("did:key:z{tag}#k");
        let record = crate::keys::KeyRecord {
            key_id: key_id.clone(),
            derivation_path: "m/26'/0'".into(),
            key_type: vta_sdk::keys::KeyType::Ed25519,
            status: vta_sdk::keys::KeyStatus::Active,
            public_key: "z".into(),
            label: None,
            context_id: Some(ctx.into()),
            seed_id: None,
            exportable: None,
            origin: vta_sdk::keys::KeyOrigin::Imported,
            created_at: now,
            updated_at: now,
        };
        ks.keys
            .insert(crate::keys::store_key(&key_id), &record)
            .await
            .unwrap();
        ks.imported
            .insert_raw(format!("secret:{key_id}"), b"wrapped".to_vec())
            .await
            .unwrap();
        ks.internal
            .insert_raw(format!("internal:{key_id}"), b"material".to_vec())
            .await
            .unwrap();

        // Persona: every context-scoped prefix, and a face-value edge naming
        // one of the context's local profiles.
        for key in [
            ps::binding_key(ctx, "did:key:zPersona"),
            ps::contact_key(ctx, "c1"),
            ps::contact_revision_key(ctx, "c1", 1),
            ps::disclosure_key(ctx, 1),
            ps::local_profile_key(ctx, "p1"),
            ps::local_binding_key(ctx, "did:key:zPersona"),
            format!("pca:{ctx}:c1"),
            format!("pcl:{ctx}:l1"),
            ps::face_value_key("abcd", &ps::face_carrier(Some(ctx), "p1")),
        ] {
            ks.persona.insert_raw(key, b"{}".to_vec()).await.unwrap();
        }

        // Vault: a credential in the context's custody, and a vault entry.
        let cred = vta_vault::StoredCredential {
            id: format!("cred-{tag}"),
            format: vta_vault::CredentialFormat::SdJwtVc,
            types: vec!["MembershipCredential".into()],
            schema_id: None,
            community_did: Some(COMMUNITY.into()),
            context_id: Some(ctx.into()),
            subject_did: None,
            issuer_did: Some(COMMUNITY.into()),
            purpose: None,
            status: vta_vault::CredentialStatus::Valid,
            valid_from: None,
            valid_until: None,
            received_at: now.to_rfc3339(),
            source: None,
            tags: Default::default(),
            body: b"opaque".to_vec(),
            lifecycle: vti_common::vault::VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        };
        vta_vault::storage::put(&ks.vault, &cred).await.unwrap();
        let entry: vti_common::vault::StoredVaultEntry =
            serde_json::from_value(serde_json::json!({
                "entry": {
                    "id": format!("entry-{tag}"), "contextId": ctx,
                    "targets": [{"kind": "web-origin", "origin": "https://example.org"}],
                    "label": "login", "secretKind": "password",
                    "createdAt": now.to_rfc3339(), "updatedAt": now.to_rfc3339(),
                    "version": 1, "status": "active"
                },
                "secret": {"kind": "password", "password": "hunter2"}
            }))
            .unwrap();
        vti_common::vault::put_stored_vault_entry(&ks.vault, &entry)
            .await
            .unwrap();

        // Inbound-messaging consent: a grant and a pending request decided in
        // the context, and its approver binding.
        use vti_common::consent as c;
        let subject = c::ConsentSubject {
            platform: "slack".into(),
            conversation_ref: format!("conv-{tag}"),
            kind: c::ConsentKind::Dm,
            agent: "did:key:zAgent".into(),
        };
        c::store_consent_grant(
            &ks.consent,
            &c::ConsentGrant {
                subject: subject.clone(),
                effect: c::ConsentEffect::Allow,
                scope: Some(c::ConsentScope::Receive),
                granted_by: "did:key:zApprover".into(),
                granted_at: 0,
                expires_at: None,
                evidence: "did-signed".into(),
                context: Some(ctx.into()),
            },
        )
        .await
        .unwrap();
        let pending = c::new_pending_consent(
            subject,
            c::ConsentScope::Receive,
            format!("ch-{tag}"),
            "did:key:zBridge",
            Some(ctx.into()),
            3600,
        );
        c::store_pending_consent(&ks.consent, &pending)
            .await
            .unwrap();
        c::store_approver(
            &ks.consent_approvers,
            &c::ApproverBinding {
                platform: "slack".into(),
                context: ctx.into(),
                approver: "did:key:zApprover".into(),
                route: None,
                route_hint: None,
            },
        )
        .await
        .unwrap();

        // A held notification.
        let held = crate::operations::notifications::HeldRecord {
            record_id: format!("rec-{tag}"),
            context_id: ctx.into(),
            addressee: "did:key:zAddressee".into(),
            originator: COMMUNITY.into(),
            relayed_by: vec![],
            delivered_by: COMMUNITY.into(),
            notification: serde_json::json!({"notificationId": format!("n-{tag}")}),
            revision: 1,
            kind: "election".into(),
            held_by: "did:key:zAddressee".into(),
            withdrawn: false,
            valid_until: None,
            state: crate::operations::notifications::HeldState::Active,
            received_at: now,
            dismissed_at: None,
            lapsed_at: None,
            document: serde_json::json!({}),
        };
        ks.notifications
            .insert(format!("held:{ctx}\0rec-{tag}"), &held)
            .await
            .unwrap();

        // PCS engine records of every kind, each with its wrapped state.
        let vetter = crate::operations::pcs::vetter_key(ctx, COMMUNITY);
        for (key, extra) in [
            (vetter.clone(), None),
            (format!("app:app-{tag}"), None),
            (format!("voter:{tag}"), Some(format!("voter-casts:{tag}"))),
            (format!("trustee:{tag}"), None),
        ] {
            ks.pcs_engine
                .insert(
                    key.clone(),
                    &serde_json::json!({"contextId": ctx, "memberDid": "did:key:zOld", "path": "m/1"}),
                )
                .await
                .unwrap();
            ks.pcs_engine
                .insert_raw(format!("secret:{key}"), b"wrapped".to_vec())
                .await
                .unwrap();
            if let Some(extra) = extra {
                ks.pcs_engine
                    .insert_raw(format!("secret:{extra}"), b"wrapped".to_vec())
                    .await
                    .unwrap();
            }
        }

        // An external account with its secret.
        let account = vta_external::model::AccountRecord {
            id: "acct1".into(),
            label: "storage".into(),
            context: ctx.into(),
            settings: serde_json::json!({"model": "static-secret"}),
            state: vta_external::model::AccountState::Active,
            public_material: None,
            secret: None,
            bindings: vec![],
            provider_setup_required: false,
            last_probe: None,
            created_at: now,
            updated_at: now,
        };
        assert!(
            vta_external::store::insert_new(&ks.external_accounts, &account)
                .await
                .unwrap()
        );
        ks.external_secrets
            .insert_raw(format!("secret:external:{ctx}:acct1"), b"wrapped".to_vec())
            .await
            .unwrap();

        // Today's quota counter.
        crate::contexts::enforce_daily_quota(&ks.contexts, ctx, "sign", 10)
            .await
            .unwrap();
    }

    /// Which of [`seed_context_rows`]'s kinds `ctx` still holds, by name.
    async fn context_rows(ks: &OwnedKs, ctx: &str) -> Vec<&'static str> {
        use vta_persona::storage as ps;
        let tag = ctx.replace('/', "-");
        let key_id = format!("did:key:z{tag}#k");
        let mut found = Vec::new();
        let mut check = |name: &'static str, present: bool| {
            if present {
                found.push(name);
            }
        };
        let raw = |ks: &KeyspaceHandle, key: String| {
            let ks = ks.clone();
            async move { ks.get_raw(key).await.unwrap().is_some() }
        };
        let prefixed = |ks: &KeyspaceHandle, prefix: String| {
            let ks = ks.clone();
            async move { !ks.prefix_keys(prefix).await.unwrap().is_empty() }
        };

        check(
            "key record",
            raw(&ks.keys, crate::keys::store_key(&key_id)).await,
        );
        check(
            "imported secret",
            raw(&ks.imported, format!("secret:{key_id}")).await,
        );
        check(
            "internal key",
            raw(&ks.internal, format!("internal:{key_id}")).await,
        );
        for p in ["pb", "pc", "pcr", "pca", "pcl", "pd", "plp", "plb"] {
            check(
                "persona",
                prefixed(&ks.persona, format!("{p}:{ctx}:")).await,
            );
        }
        check(
            "persona face edge",
            raw(
                &ks.persona,
                ps::face_value_key("abcd", &ps::face_carrier(Some(ctx), "p1")),
            )
            .await,
        );
        check(
            "credential",
            vta_vault::storage::get(&ks.vault, &format!("cred-{tag}"))
                .await
                .unwrap()
                .is_some(),
        );
        // The credential's index rows go with it: a search by its type finds
        // nothing of this context's.
        check(
            "credential index",
            vta_vault::storage::find_by_index(
                &ks.vault,
                vta_vault::IndexField::Type,
                "MembershipCredential",
            )
            .await
            .unwrap()
            .iter()
            .any(|c| c.id == format!("cred-{tag}")),
        );
        check(
            "vault entry",
            vti_common::vault::get_vault_entry(&ks.vault, &format!("entry-{tag}"))
                .await
                .unwrap()
                .is_some(),
        );
        check(
            "consent grant",
            vti_common::consent::list_consent_grants(&ks.consent)
                .await
                .unwrap()
                .iter()
                .any(|g| g.context.as_deref() == Some(ctx)),
        );
        check(
            "pending consent",
            raw(&ks.consent, format!("consent_pending:ch-{tag}")).await,
        );
        check(
            "consent approver",
            vti_common::consent::get_approver(&ks.consent_approvers, "slack", ctx)
                .await
                .unwrap()
                .is_some(),
        );
        check(
            "notification",
            prefixed(&ks.notifications, format!("held:{ctx}\0")).await,
        );
        let vetter = crate::operations::pcs::vetter_key(ctx, COMMUNITY);
        for key in [
            vetter,
            format!("app:app-{tag}"),
            format!("voter:{tag}"),
            format!("trustee:{tag}"),
        ] {
            check("pcs record", raw(&ks.pcs_engine, key.clone()).await);
            check(
                "pcs secret",
                raw(&ks.pcs_engine, format!("secret:{key}")).await,
            );
        }
        check(
            "pcs voter casts",
            raw(&ks.pcs_engine, format!("secret:voter-casts:{tag}")).await,
        );
        check(
            "external account",
            vta_external::store::get(&ks.external_accounts, ctx, "acct1")
                .await
                .unwrap()
                .is_some(),
        );
        check(
            "external secret",
            raw(&ks.external_secrets, format!("secret:external:{ctx}:acct1")).await,
        );
        check(
            "quota counter",
            prefixed(&ks.contexts, format!("quota:{ctx}:")).await,
        );
        found
    }

    /// Everything held for a context goes with it, so a context created again
    /// under the same id starts empty.
    ///
    /// Each kind here survived the deletion before, and each was inherited by
    /// the recreated context — most visibly a vetter engine record pinned to
    /// the old member DID, which made the new context's `vta/pcs/root-request`
    /// fail with `memberMismatch`.
    #[tokio::test]
    async fn delete_purges_every_context_scoped_store_and_a_recreated_context_inherits_nothing() {
        let ks = fresh_keyspaces();
        seed(&ks.contexts, "acme", None).await;
        seed(&ks.contexts, "acme/eng", Some("acme")).await;
        // A sibling sharing the prefix, which must survive.
        seed(&ks.contexts, "acme2", None).await;
        for ctx in ["acme", "acme/eng", "acme2"] {
            seed_context_rows(&ks, ctx).await;
        }
        let everything = context_rows(&ks, "acme2").await;

        delete_context(&ks.as_ks(), &super_admin(), "acme", true, "t", None)
            .await
            .expect("cascade delete");

        // Recreated under the same ids, the contexts inherit nothing.
        seed(&ks.contexts, "acme", None).await;
        seed(&ks.contexts, "acme/eng", Some("acme")).await;
        for ctx in ["acme", "acme/eng"] {
            assert_eq!(
                context_rows(&ks, ctx).await,
                Vec::<&str>::new(),
                "{ctx} inherited records from the deleted context"
            );
            // The external account's id stays retired: a provider-side trust
            // policy may still name it, so the recreated context cannot reuse it.
            assert!(
                vta_external::store::is_retired(&ks.external_accounts, ctx, "acct1")
                    .await
                    .unwrap()
            );
        }

        // The prefix-sharing sibling keeps every kind.
        assert_eq!(context_rows(&ks, "acme2").await, everything);
        assert!(everything.contains(&"quota counter"), "{everything:?}");
        assert!(everything.contains(&"pcs voter casts"), "{everything:?}");
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
        // `notFound`, not `forbidden`: `vta/contexts/delete` requires this
        // answer "for an id the caller cannot reach, whether or not it
        // exists". `other` does exist — and saying so to a caller who may not
        // touch it is the leak the code exists to close.
        assert!(matches!(&err, ContextError::Unreachable), "{err:?}");
        let absent = delete_context(&ks.as_ks(), &admin_of("acme"), "ghost", false, "t", None)
            .await
            .unwrap_err();
        assert!(matches!(&absent, ContextError::Unreachable), "{absent:?}");
        // Indistinguishable on the way out, not merely the same variant: a
        // message naming one of them would hand back what the variant hides.
        assert_eq!(err.to_string(), absent.to_string());

        assert!(get_context(&ks.contexts, "other").await.unwrap().is_some());
    }

    // ─── `context-create` capability ─────────────────────────────────────
    //
    // The power under test: an automated provisioner can branch under a
    // context it already reaches, without being an admin of it.

    /// One store, both keyspaces: opening the same directory twice is a
    /// `Store(Locked)`.
    fn fresh_contexts_and_acl() -> (tempfile::TempDir, Store, KeyspaceHandle, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let contexts = store.keyspace(crate::keyspaces::CONTEXTS).unwrap();
        let acl = store.keyspace(crate::keyspaces::ACL).unwrap();
        (dir, store, contexts, acl)
    }

    /// A non-admin scoped to one context, carrying only `context-create` —
    /// exactly the grant an agent gateway is paired with.
    async fn provisioner(acl_ks: &KeyspaceHandle, did: &str, context: &str) -> AuthClaims {
        let entry = vti_common::acl::AclEntry {
            did: did.to_string(),
            role: Role::Initiator,
            label: None,
            allowed_contexts: vec![context.to_string()],
            created_at: 0,
            created_by: "test".to_string(),
            expires_at: None,
            kind: Default::default(),
            capabilities: vec![vti_common::acl::Capability::ContextCreate],
            device: None,
            version: 1,
            step_up_approver: None,
            step_up_require: None,
            approve_scope: Default::default(),
            allowed_keys: None,
            handoff: None,
        };
        vti_common::acl::store_acl_entry(acl_ks, &entry)
            .await
            .expect("store the provisioner entry");
        AuthClaims {
            did: did.to_string(),
            role: Role::Initiator,
            allowed_contexts: vec![context.to_string()],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_capability_holder_may_create_a_sub_context_without_being_an_admin() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();

        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "gw",
            "Gateway".into(),
            None,
            None,
            "t",
        )
        .await
        .expect("super-admin seeds the top-level context");

        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;
        ensure_may_create_context(&acl_ks, &caller)
            .await
            .expect("the capability satisfies the create gate without an admin role");

        let created = create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &caller,
            "agent-1",
            "Agent 1".into(),
            None,
            Some("gw".to_string()),
            "t",
        )
        .await
        .expect("a sub-context under a reachable parent");
        assert_eq!(created.id, "gw/agent-1");
    }

    /// The bound that makes the capability safe: it confers "branch under what
    /// I already reach", never "create anywhere".
    #[tokio::test]
    async fn the_capability_cannot_create_a_top_level_context() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();

        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;
        ensure_may_create_context(&acl_ks, &caller)
            .await
            .expect("the gate passes; the finer rule is enforced below it");

        let err = match create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &caller,
            "rogue",
            "Rogue".into(),
            None,
            None,
            "t",
        )
        .await
        {
            Ok(created) => {
                panic!("a top-level context must still require super-admin: {created:?}")
            }
            Err(e) => e,
        };
        assert!(
            format!("{err:?}").contains("super") || matches!(err, ContextError::Other(_)),
            "{err:?}"
        );
    }

    /// Reaching the parent is required as well as the capability, so the
    /// capability cannot be used to grow somebody else's subtree.
    #[tokio::test]
    async fn the_capability_cannot_reach_another_contexts_subtree() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();

        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "gw",
            "Gateway".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "other",
            "Other".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();

        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;
        let err = match create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &caller,
            "agent-1",
            "Agent 1".into(),
            None,
            Some("other".to_string()),
            "t",
        )
        .await
        {
            Ok(created) => {
                panic!("a parent the caller does not reach must be refused: {created:?}")
            }
            Err(e) => e,
        };
        assert!(matches!(err, ContextError::ParentUnreachable), "{err:?}");
    }

    /// Without the capability a non-admin is refused by the role gate, which is
    /// the behaviour every caller had before the capability existed.
    #[tokio::test]
    async fn a_non_admin_without_the_capability_is_still_refused() {
        let (_d, _s, _ks, acl_ks) = fresh_contexts_and_acl();
        let caller = AuthClaims {
            did: "did:key:zPlain".to_string(),
            role: Role::Initiator,
            allowed_contexts: vec!["gw".to_string()],
            ..Default::default()
        };
        assert!(
            ensure_may_create_context(&acl_ks, &caller).await.is_err(),
            "a non-admin with no capability must not pass the create gate"
        );
    }

    /// An admin keeps working through the role, with no entry and no capability
    /// — the capability adds a path, it does not replace one.
    #[tokio::test]
    async fn an_admin_still_passes_the_gate_without_the_capability() {
        let (_d, _s, _ks, acl_ks) = fresh_contexts_and_acl();
        ensure_may_create_context(&acl_ks, &admin_of("gw"))
            .await
            .expect("an admin passes the gate as it always did");
    }

    // ─── Write-once provisioning ─────────────────────────────────────────
    //
    // The property: a provisioner may make a context it created *usable*, and
    // may never reconfigure one. Filling a blank field is provisioning;
    // changing an established one is an administrator's act.

    /// A provisioner names the DID of a key the context holds, then is refused
    /// when it tries to change or clear it.
    #[tokio::test]
    async fn a_provisioner_configures_a_fresh_context_once_and_no_more() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();
        let keys_ks = _s.keyspace(crate::keyspaces::KEYS).unwrap();
        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "gw",
            "Gateway".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;
        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &caller,
            "agent-1",
            "Agent 1".into(),
            None,
            Some("gw".to_string()),
            "t",
        )
        .await
        .expect("provision the context");
        seed_key(&keys_ks, "agent-1-key", Some("gw/agent-1")).await;
        let own_did = format!("did:key:{SEEDED_PUBLIC_KEY}");

        let set = update_context_did(
            &ks,
            &keys_ks,
            &acl_ks,
            &caller,
            "gw/agent-1",
            Some(own_did.clone()),
            "t",
        )
        .await
        .expect("a provisioner may name a context that has no DID");
        assert_eq!(set.did.as_deref(), Some(own_did.as_str()));

        let err = match update_context_did(
            &ks,
            &keys_ks,
            &acl_ks,
            &caller,
            "gw/agent-1",
            Some("did:key:zSomethingElse".into()),
            "t",
        )
        .await
        {
            Ok(r) => panic!("re-pointing an established DID must be refused: {r:?}"),
            Err(e) => format!("{e:?}"),
        };
        assert!(err.contains("administrator"), "{err}");

        let cleared =
            update_context_did(&ks, &keys_ks, &acl_ks, &caller, "gw/agent-1", None, "t").await;
        assert!(cleared.is_err(), "a provisioner must not clear a DID");
    }

    /// A provisioner may name only the `did:key` of a key the context holds.
    /// Anything else is an administrator's decision, however blank the field.
    #[tokio::test]
    async fn a_provisioner_may_name_only_a_did_the_context_controls() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();
        let keys_ks = _s.keyspace(crate::keyspaces::KEYS).unwrap();
        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "gw",
            "Gateway".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;
        for leaf in ["agent-1", "agent-2"] {
            create_context(
                &ks,
                &_s.keyspace(crate::keyspaces::ACL).unwrap(),
                &caller,
                leaf,
                leaf.into(),
                None,
                Some("gw".to_string()),
                "t",
            )
            .await
            .unwrap();
        }
        seed_key(&keys_ks, "agent-1-key", Some("gw/agent-1")).await;
        let held_by_agent_1 = format!("did:key:{SEEDED_PUBLIC_KEY}");

        for (what, did) in [
            (
                "a did:key nothing in the context holds",
                "did:key:z6MkNobodyHoldsThis",
            ),
            ("a different DID method", "did:web:example.com"),
            ("a key held by another context", held_by_agent_1.as_str()),
        ] {
            let refused = update_context_did(
                &ks,
                &keys_ks,
                &acl_ks,
                &caller,
                "gw/agent-2",
                Some(did.to_string()),
                "t",
            )
            .await;
            assert!(refused.is_err(), "{what} must be refused");
            assert_eq!(
                get_context_op(&ks, &super_admin(), "gw/agent-2", "t")
                    .await
                    .unwrap()
                    .did,
                None,
                "{what}: a refused write left a DID behind"
            );
        }
    }

    /// A revoked key, or one that cannot sign `eddsa-jcs-2022`, is not a key the
    /// context can use as an identity.
    #[tokio::test]
    async fn a_provisioner_cannot_name_a_revoked_or_non_ed25519_key() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();
        let keys_ks = _s.keyspace(crate::keyspaces::KEYS).unwrap();
        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "gw",
            "Gateway".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;
        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &caller,
            "agent-1",
            "Agent 1".into(),
            None,
            Some("gw".to_string()),
            "t",
        )
        .await
        .unwrap();
        let did = format!("did:key:{SEEDED_PUBLIC_KEY}");

        seed_key_with(
            &keys_ks,
            "revoked",
            Some("gw/agent-1"),
            vta_sdk::keys::KeyType::Ed25519,
            vta_sdk::keys::KeyStatus::Revoked,
        )
        .await;
        assert!(
            update_context_did(
                &ks,
                &keys_ks,
                &acl_ks,
                &caller,
                "gw/agent-1",
                Some(did.clone()),
                "t"
            )
            .await
            .is_err(),
            "a revoked key must not become the context's identity"
        );

        seed_key_with(
            &keys_ks,
            "revoked",
            Some("gw/agent-1"),
            vta_sdk::keys::KeyType::P256,
            vta_sdk::keys::KeyStatus::Active,
        )
        .await;
        assert!(
            update_context_did(
                &ks,
                &keys_ks,
                &acl_ks,
                &caller,
                "gw/agent-1",
                Some(did),
                "t"
            )
            .await
            .is_err(),
            "a P-256 key cannot be the did:key of an eddsa-jcs-2022 signer"
        );
    }

    /// Write-once does not widen reach: a provisioner still cannot configure a
    /// context outside its own subtree, blank or not.
    #[tokio::test]
    async fn a_provisioner_cannot_configure_a_context_it_does_not_reach() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();
        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "gw",
            "Gateway".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "other",
            "Other".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;

        let keys_ks = _s.keyspace(crate::keyspaces::KEYS).unwrap();
        let outcome = update_context_did(
            &ks,
            &keys_ks,
            &acl_ks,
            &caller,
            "other",
            Some("did:key:zNotYours".into()),
            "t",
        )
        .await;
        assert!(
            outcome.is_err(),
            "a context outside the granted subtree must stay out of reach"
        );
    }

    /// A super-admin is unaffected: it may still re-point an established DID,
    /// which is the whole reason the provisioning path is narrow.
    #[tokio::test]
    async fn an_administrator_may_still_reconfigure_an_established_context() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();
        create_context(
            &ks,
            &_s.keyspace(crate::keyspaces::ACL).unwrap(),
            &super_admin(),
            "gw",
            "Gateway".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        let keys_ks = _s.keyspace(crate::keyspaces::KEYS).unwrap();
        update_context_did(
            &ks,
            &keys_ks,
            &acl_ks,
            &super_admin(),
            "gw",
            Some("did:key:zFirst".into()),
            "t",
        )
        .await
        .unwrap();
        let changed = update_context_did(
            &ks,
            &keys_ks,
            &acl_ks,
            &super_admin(),
            "gw",
            Some("did:key:zSecond".into()),
            "t",
        )
        .await
        .expect("an administrator may re-point a DID");
        assert_eq!(changed.did.as_deref(), Some("did:key:zSecond"));
    }

    /// A provisioner may finish only a context **it created**. Reaching one is
    /// not enough: its own root, a context an administrator made beneath it,
    /// and a context another provisioner made are all refused, blank DID or not.
    #[tokio::test]
    async fn a_provisioner_may_set_the_did_only_of_a_context_it_created() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();
        let keys_ks = _s.keyspace(crate::keyspaces::KEYS).unwrap();
        create_context(
            &ks,
            &acl_ks,
            &super_admin(),
            "gw",
            "Gateway".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        create_context(
            &ks,
            &acl_ks,
            &super_admin(),
            "by-admin",
            "By admin".into(),
            None,
            Some("gw".to_string()),
            "t",
        )
        .await
        .unwrap();
        let first = provisioner(&acl_ks, "did:key:zFirst", "gw").await;
        let second = provisioner(&acl_ks, "did:key:zSecond", "gw").await;
        create_context(
            &ks,
            &acl_ks,
            &first,
            "by-first",
            "By first".into(),
            None,
            Some("gw".to_string()),
            "t",
        )
        .await
        .unwrap();

        for (what, caller, id) in [
            ("its own root context", &first, "gw"),
            ("a context an administrator created", &first, "gw/by-admin"),
            (
                "a context another provisioner created",
                &second,
                "gw/by-first",
            ),
        ] {
            seed_key(&keys_ks, "k", Some(id)).await;
            let refused = update_context_did(
                &ks,
                &keys_ks,
                &acl_ks,
                caller,
                id,
                Some(format!("did:key:{SEEDED_PUBLIC_KEY}")),
                "t",
            )
            .await;
            assert!(refused.is_err(), "{what} must be refused");
            assert_eq!(
                get_context_op(&ks, &super_admin(), id, "t")
                    .await
                    .unwrap()
                    .did,
                None,
                "{what}: a refused write left a DID behind"
            );
        }
    }

    /// The capability is read at the time of the write, not at creation: an
    /// entry narrowed after it created a context can no longer finish it.
    #[tokio::test]
    async fn a_provisioner_that_lost_the_capability_cannot_finish_its_context() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();
        let keys_ks = _s.keyspace(crate::keyspaces::KEYS).unwrap();
        create_context(
            &ks,
            &acl_ks,
            &super_admin(),
            "gw",
            "Gateway".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;
        create_context(
            &ks,
            &acl_ks,
            &caller,
            "agent-1",
            "Agent 1".into(),
            None,
            Some("gw".to_string()),
            "t",
        )
        .await
        .unwrap();
        seed_key(&keys_ks, "agent-1-key", Some("gw/agent-1")).await;

        let mut entry = vti_common::acl::get_acl_entry(&acl_ks, &caller.did)
            .await
            .unwrap()
            .unwrap();
        entry.capabilities = vec![vti_common::acl::Capability::KeyMint];
        vti_common::acl::store_acl_entry(&acl_ks, &entry)
            .await
            .unwrap();

        let refused = update_context_did(
            &ks,
            &keys_ks,
            &acl_ks,
            &caller,
            "gw/agent-1",
            Some(format!("did:key:{SEEDED_PUBLIC_KEY}")),
            "t",
        )
        .await;
        assert!(
            refused.is_err(),
            "the capability must still be held at the write"
        );
    }

    /// The role/capability gate is in the operation, not only in the Trust
    /// Task handler: an in-process caller that skips the handler meets it too.
    #[tokio::test]
    async fn create_context_itself_refuses_a_non_admin_without_the_capability() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();
        create_context(
            &ks,
            &acl_ks,
            &super_admin(),
            "gw",
            "Gateway".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        let reader = AuthClaims {
            did: "did:key:zReader".to_string(),
            role: Role::Reader,
            allowed_contexts: vec!["gw".to_string()],
            ..Default::default()
        };
        let err = match create_context(
            &ks,
            &acl_ks,
            &reader,
            "sneaky",
            "Sneaky".into(),
            None,
            Some("gw".to_string()),
            "t",
        )
        .await
        {
            Ok(created) => panic!("a reader of the parent must not create under it: {created:?}"),
            Err(e) => e,
        };
        assert!(
            matches!(err, ContextError::Other(AppError::Forbidden(_))),
            "{err:?}"
        );
        assert!(get_context(&ks, "gw/sneaky").await.unwrap().is_none());
    }

    /// A context an administrator creates records no provisioner, and deleting
    /// a provisioned context removes its provisioner record — so an id reused
    /// later does not inherit the old provisioner's right to finish it.
    #[tokio::test]
    async fn the_provisioner_record_follows_the_context() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();
        create_context(
            &ks,
            &acl_ks,
            &super_admin(),
            "gw",
            "Gateway".into(),
            None,
            None,
            "t",
        )
        .await
        .unwrap();
        assert_eq!(
            crate::contexts::context_provisioner(&ks, "gw")
                .await
                .unwrap(),
            None
        );
        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;
        create_context(
            &ks,
            &acl_ks,
            &caller,
            "agent-1",
            "Agent 1".into(),
            None,
            Some("gw".to_string()),
            "t",
        )
        .await
        .unwrap();
        assert_eq!(
            crate::contexts::context_provisioner(&ks, "gw/agent-1")
                .await
                .unwrap()
                .as_deref(),
            Some("did:key:zProvisioner")
        );
        crate::contexts::delete_context(&ks, "gw/agent-1")
            .await
            .unwrap();
        assert_eq!(
            crate::contexts::context_provisioner(&ks, "gw/agent-1")
                .await
                .unwrap(),
            None
        );
    }

    const SEEDED_PUBLIC_KEY: &str = "z6MkTestPublicKey";

    /// Store a minimal active Ed25519 key record in `context_id`.
    async fn seed_key(keys_ks: &KeyspaceHandle, key_id: &str, context_id: Option<&str>) {
        seed_key_with(
            keys_ks,
            key_id,
            context_id,
            vta_sdk::keys::KeyType::Ed25519,
            vta_sdk::keys::KeyStatus::Active,
        )
        .await;
    }

    async fn seed_key_with(
        keys_ks: &KeyspaceHandle,
        key_id: &str,
        context_id: Option<&str>,
        key_type: vta_sdk::keys::KeyType,
        status: vta_sdk::keys::KeyStatus,
    ) {
        let record = vta_sdk::keys::KeyRecord {
            key_id: key_id.to_string(),
            derivation_path: "m/26'/2'/1'/0".to_string(),
            key_type,
            status,
            public_key: SEEDED_PUBLIC_KEY.to_string(),
            label: None,
            context_id: context_id.map(str::to_string),
            seed_id: None,
            exportable: Some(false),
            origin: vta_sdk::keys::KeyOrigin::Derived,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        keys_ks
            .insert(crate::keys::store_key(key_id), &record)
            .await
            .expect("seed the key record");
    }
}
