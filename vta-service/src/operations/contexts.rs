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
    /// Designate this context's credential-issuing key. `None` leaves the
    /// designation unchanged. Super-admin only (via [`update_context`]), and
    /// the key must already live in this context.
    pub issuer_key_id: Option<String>,
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
        issuer_key_id: r.issuer_key_id.clone(),
        proof_key_ids: r.proof_key_ids.clone(),
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
/// The create gate: the caller must be an admin **or** hold
/// [`Capability::ContextCreate`](vti_common::acl::Capability::ContextCreate).
///
/// Necessary and not sufficient on its own — [`create_context`] then applies
/// the finer rule: super-admin for a top-level context, reach-the-parent for a
/// sub-context. So a capability holder can only branch under what it already
/// administers, which is what lets an automated provisioner exist without being
/// an admin of the context it provisions into.
///
/// Lives here rather than in the handler because the create surface is
/// reachable over more than one transport, and a gate written per transport is
/// a gate that eventually differs between them.
///
/// A failed ACL read refuses rather than falling through to the role check: not
/// being able to confirm a capability is not the same as the caller not having
/// one, and the safe reading of "I cannot tell" is no.
pub async fn ensure_may_create_context(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
) -> Result<(), AppError> {
    use vti_common::acl::Capability;

    let entry = vti_common::acl::get_acl_entry(acl_ks, &auth.did)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e, did = %auth.did,
                "could not read the ACL entry for a context-create capability check; refusing"
            );
            AppError::Forbidden(format!(
                "contexts/create denied: could not confirm that {} carries the context-create \
                 capability",
                auth.did
            ))
        })?;

    let has_capability = match entry {
        Some(ref entry) => vti_common::acl::entry_has_capability(entry, Capability::ContextCreate),
        None => vti_common::acl::role_has_capability(&auth.role, Capability::ContextCreate),
    };
    if has_capability {
        return Ok(());
    }

    // Report the role failure when both fail: naming a capability the caller
    // does not hold tells it what to ask for, and the role gate is the one
    // every other caller meets.
    auth.require_admin()
}

pub async fn create_context(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    name: String,
    description: Option<String>,
    parent: Option<String>,
    channel: &str,
) -> Result<CreateContextResultBody, ContextError> {
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
        issuer_key_id: None,
        proof_key_ids: Default::default(),
    };

    // Atomic claim: the early exists-check above is the friendly fast
    // path, but two concurrent creates with the same id both pass it.
    // The loser's counter slot stays as a gap — safe; record overwrite
    // would not be (it re-points the context's BIP-32 base path).
    if !crate::contexts::store_new_context(contexts_ks, &record).await? {
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
    if let Some(issuer_key_id) = params.issuer_key_id {
        // Residency is *not* checked here. Issuance re-derives the key from
        // the context and refuses one that does not live in it, so that check
        // is the boundary and it holds however the designation was written —
        // including a record restored from a backup or edited out of band.
        // Checking here as well would need the key keyspace threaded through
        // every caller of this function to re-state a guarantee issuance
        // already makes unconditionally.
        record.issuer_key_id = Some(issuer_key_id);
    }
    record.updated_at = Utc::now();

    store_context(contexts_ks, &record).await?;

    info!(channel, id = %id, "context updated");
    Ok(to_result_body(&record))
}

/// The `proofPurpose` values a context may designate a key for, and that
/// `proofs/attach` will sign under.
///
/// An allow-list rather than any string — the DI analogue of the `typ`
/// allow-list on `keys/sign-jws`. A proof purpose is a *claim about what the
/// signature means*, so an unrecognised one would let a caller mint a signature
/// whose meaning the VTA never agreed to.
pub const ALLOWED_PROOF_PURPOSES: &[&str] = &["authentication", "assertionMethod"];

/// Resolve the key a context signs with for `proof_purpose`.
///
/// `assertionMethod` falls back to the context's issuer key when no explicit
/// proof key is designated: that *is* the context's assertion key, and
/// requiring it to be named twice would let the two disagree.
///
/// Returns `None` when the context has designated nothing for this purpose —
/// callers must fail closed rather than reach for any other key.
pub fn resolve_proof_key<'a>(
    context: &'a vta_sdk::contexts::ContextRecord,
    proof_purpose: &str,
) -> Option<&'a str> {
    context
        .proof_key_ids
        .get(proof_purpose)
        .map(String::as_str)
        .or_else(|| {
            (proof_purpose == "assertionMethod")
                .then_some(context.issuer_key_id.as_deref())
                .flatten()
        })
}

/// Designate (or clear) the key that signs credentials issued as `id`'s DID.
///
/// Super-admin, like every other context mutation: the designation decides
/// which key a *context-scoped* caller can reach through
/// `credentials/issue-in-context`, so a caller who could set it could widen
/// their own authority.
///
/// The key must live in this context. Issuance re-checks that and refuses
/// regardless of how the designation was written, so this check exists to fail
/// the operator's mistake at the point they make it rather than at the first
/// issuance.
///
/// `proof_purpose` selects which designation is written: `None` sets the
/// credential issuer key, `Some(purpose)` sets the Data-Integrity proof key for
/// that purpose.
pub async fn set_context_issuer_key(
    contexts_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    key_id: Option<String>,
    proof_purpose: Option<&str>,
    channel: &str,
) -> Result<CreateContextResultBody, ContextError> {
    // Provisioning may fill a designation that is unset; changing an
    // established one stays super-admin. The super-admin gate is checked
    // first, so an administrator is never held to the write-once bound.
    let provisioning =
        auth.require_super_admin().is_err() && may_configure_unset(acl_ks, auth, id).await;
    if !provisioning {
        auth.require_super_admin()?;
    }

    if let Some(purpose) = proof_purpose
        && !ALLOWED_PROOF_PURPOSES.contains(&purpose)
    {
        return Err(ContextError::Other(AppError::Validation(format!(
            "proof purpose `{purpose}` is not one of {ALLOWED_PROOF_PURPOSES:?}"
        ))));
    }

    let mut record = reach_context(contexts_ks, auth, id).await?;

    // The write-once bound for a provisioning caller: it may name a key for a
    // purpose that has none, never re-point one already designated.
    if provisioning {
        let already = match proof_purpose {
            Some(purpose) => record.proof_key_ids.contains_key(purpose),
            None => record.issuer_key_id.is_some(),
        };
        if already {
            return Err(ContextError::Other(AppError::Forbidden(format!(
                "context `{id}` already designates a signing key for this purpose; changing it \
                 is an administrator's act, not a provisioning one"
            ))));
        }
        if key_id.is_none() {
            return Err(ContextError::Other(AppError::Forbidden(format!(
                "clearing a signing-key designation on context `{id}` is an administrator's act"
            ))));
        }
    }

    if let Some(ref key_id) = key_id {
        let key: vta_sdk::keys::KeyRecord = keys_ks
            .get(crate::keys::store_key(key_id))
            .await?
            .ok_or_else(|| AppError::NotFound(format!("key `{key_id}` not found")))?;
        if key.context_id.as_deref() != Some(id) {
            return Err(ContextError::Other(AppError::Validation(format!(
                "key `{key_id}` does not belong to context `{id}`, so it cannot be its signing key"
            ))));
        }
    }

    match proof_purpose {
        Some(purpose) => match key_id {
            Some(key_id) => {
                record.proof_key_ids.insert(purpose.to_string(), key_id);
            }
            None => {
                record.proof_key_ids.remove(purpose);
            }
        },
        None => record.issuer_key_id = key_id,
    }
    record.updated_at = Utc::now();
    store_context(contexts_ks, &record).await?;

    info!(
        channel,
        id = %id,
        proof_purpose = ?proof_purpose,
        issuer_key_id = ?record.issuer_key_id,
        "context signing key designated"
    );
    Ok(to_result_body(&record))
}

/// Whether `auth` may configure `record`'s **unset** signing fields without
/// being an admin of it.
///
/// The provisioning case: an automated caller holding
/// [`Capability::ContextCreate`](vti_common::acl::Capability::ContextCreate)
/// creates a context and must then make it usable — give it a DID, name its
/// issuer key. Both are one-time acts at the context's birth.
///
/// **Write-once, deliberately.** The caller may fill a blank field; it may never
/// change an established one. Re-pointing a context's identity or its signing
/// key is how an automated process would quietly become something else, and it
/// is rare enough to be an operator's act. The alternative considered — making
/// the creator an *admin* of what it created — was rejected: a context admin can
/// write ACL entries scoped to that context, so the authority would accumulate
/// one context at a time for as long as the process ran.
///
/// Returning `false` is not a refusal; it means the ordinary admin gate decides.
///
/// Callers must check their own admin gate **first** and only consult this when
/// it fails. An administrator is not provisioning — applying the write-once
/// bound to one would stop it re-pointing a DID, which is exactly the act the
/// bound exists to reserve *for* administrators.
async fn may_configure_unset(acl_ks: &KeyspaceHandle, auth: &AuthClaims, context_id: &str) -> bool {
    // Reaching the context is required as well as the capability, so this can
    // never touch a subtree the caller was not granted.
    if auth.require_context(context_id).is_err() {
        return false;
    }
    ensure_may_create_context(acl_ks, auth).await.is_ok()
}

/// Update the DID for a context. Requires Admin role with access to the context
/// (context-scoped admins can update DIDs on their own contexts).
///
/// A caller holding `context-create` may instead set the DID **while it is
/// unset**, which is what lets it finish provisioning a context it just
/// created. See [`may_configure_unset`].
pub async fn update_context_did(
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    did: Option<String>,
    channel: &str,
) -> Result<CreateContextResultBody, ContextError> {
    // The admin gate first: an administrator takes the ordinary path with no
    // write-once bound. Only a caller it refuses may be provisioning.
    let provisioning = auth.require_admin().is_err() && may_configure_unset(acl_ks, auth, id).await;
    if !provisioning {
        auth.require_admin()?;
    }
    let mut record = reach_context(contexts_ks, auth, id).await?;

    // The write-once bound. Checked against the record just read, and the
    // store write below is what settles a race: two concurrent provisions both
    // see `None`, both write, and the loser's value is overwritten rather than
    // compounded — the field still ends up set exactly once, to one of the two
    // DIDs the same caller asked for.
    if provisioning && record.did.is_some() {
        return Err(ContextError::Other(AppError::Forbidden(format!(
            "context `{id}` already has a DID; changing it is an administrator's act, not a \
             provisioning one"
        ))));
    }
    if provisioning && did.is_none() {
        return Err(ContextError::Other(AppError::Forbidden(format!(
            "clearing the DID on context `{id}` is an administrator's act"
        ))));
    }

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
    Other(AppError),
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

    /// `update-did/1.1`'s `did: null`: the context is left with no DID, the
    /// record comes back without one, and a second clear is not an error.
    #[tokio::test]
    async fn clearing_a_context_did_removes_it_and_is_idempotent() {
        let (_d, _s, ks, acl) = fresh_contexts_and_acl();
        create_context(&ks, &super_admin(), "acme", "Acme".into(), None, None, "t")
            .await
            .unwrap();
        let set = update_context_did(
            &ks,
            &acl,
            &admin_of("acme"),
            "acme",
            Some("did:web:a.example".into()),
            "t",
        )
        .await
        .expect("assign");
        assert_eq!(set.did.as_deref(), Some("did:web:a.example"));

        let cleared = update_context_did(&ks, &acl, &admin_of("acme"), "acme", None, "t")
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

        let again = update_context_did(&ks, &acl, &admin_of("acme"), "acme", None, "t")
            .await
            .expect("clearing a context with no DID is not an error");
        assert_eq!(again.did, None);
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
        assert!(
            matches!(err, ContextError::Other(AppError::Forbidden(_))),
            "creating a top-level context is a role question, not an id one: {err:?}"
        );
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
                issuer_key_id: None,
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
                issuer_key_id: None,
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
        // ...and is told the same thing it would be told about a parent that
        // does not exist. The specification requires that answer in as many
        // words: "the same answer it gives for a parent that does not exist,
        // for the reason set out in `vta/contexts/get`". Told apart, the pair
        // is an oracle for which context ids are real.
        let absent = create_context(
            &ks,
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

        create_context(&ks, &super_admin(), "gw", "Gateway".into(), None, None, "t")
            .await
            .expect("super-admin seeds the top-level context");

        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;
        ensure_may_create_context(&acl_ks, &caller)
            .await
            .expect("the capability satisfies the create gate without an admin role");

        let created = create_context(
            &ks,
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

        let err = match create_context(&ks, &caller, "rogue", "Rogue".into(), None, None, "t").await
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

        create_context(&ks, &super_admin(), "gw", "Gateway".into(), None, None, "t")
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

        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;
        let err = match create_context(
            &ks,
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

    /// A provisioner sets the DID and the issuer key on a fresh context, then
    /// is refused when it tries to change either.
    #[tokio::test]
    async fn a_provisioner_configures_a_fresh_context_once_and_no_more() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();
        create_context(&ks, &super_admin(), "gw", "Gateway".into(), None, None, "t")
            .await
            .unwrap();
        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;
        create_context(
            &ks,
            &caller,
            "agent-1",
            "Agent 1".into(),
            None,
            Some("gw".to_string()),
            "t",
        )
        .await
        .expect("provision the context");

        // Fill the DID while unset — allowed.
        let set = update_context_did(
            &ks,
            &acl_ks,
            &caller,
            "gw/agent-1",
            Some("did:key:zAgentOne".into()),
            "t",
        )
        .await
        .expect("a provisioner may name a context that has no DID");
        assert_eq!(set.did.as_deref(), Some("did:key:zAgentOne"));

        // Change it — refused.
        let err = match update_context_did(
            &ks,
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

        // Clearing it — also refused: that is a reconfiguration, not a birth.
        let cleared = update_context_did(&ks, &acl_ks, &caller, "gw/agent-1", None, "t").await;
        assert!(cleared.is_err(), "a provisioner must not clear a DID");
    }

    /// The same rule for the issuer-key designation.
    #[tokio::test]
    async fn a_provisioner_designates_an_issuer_key_once_and_no_more() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();
        create_context(&ks, &super_admin(), "gw", "Gateway".into(), None, None, "t")
            .await
            .unwrap();
        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;
        create_context(
            &ks,
            &caller,
            "agent-1",
            "Agent 1".into(),
            None,
            Some("gw".to_string()),
            "t",
        )
        .await
        .unwrap();

        // The designation is checked for residency, so the key must be real
        // and live in the context it is designated for.
        let keys_ks = _s.keyspace(crate::keyspaces::KEYS).unwrap();
        seed_key(&keys_ks, "agent-1-key", Some("gw/agent-1")).await;

        set_context_issuer_key(
            &ks,
            &keys_ks,
            &acl_ks,
            &caller,
            "gw/agent-1",
            Some("agent-1-key".to_string()),
            None,
            "t",
        )
        .await
        .expect("a provisioner may designate a key for a context that has none");

        seed_key(&keys_ks, "agent-1-other", Some("gw/agent-1")).await;
        let err = match set_context_issuer_key(
            &ks,
            &keys_ks,
            &acl_ks,
            &caller,
            "gw/agent-1",
            Some("agent-1-other".to_string()),
            None,
            "t",
        )
        .await
        {
            Ok(r) => panic!("re-pointing an established designation must be refused: {r:?}"),
            Err(e) => format!("{e:?}"),
        };
        assert!(err.contains("administrator"), "{err}");
    }

    /// Write-once does not widen reach: a provisioner still cannot configure a
    /// context outside its own subtree, blank or not.
    #[tokio::test]
    async fn a_provisioner_cannot_configure_a_context_it_does_not_reach() {
        let (_d, _s, ks, acl_ks) = fresh_contexts_and_acl();
        create_context(&ks, &super_admin(), "gw", "Gateway".into(), None, None, "t")
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
        let caller = provisioner(&acl_ks, "did:key:zProvisioner", "gw").await;

        let outcome = update_context_did(
            &ks,
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
        create_context(&ks, &super_admin(), "gw", "Gateway".into(), None, None, "t")
            .await
            .unwrap();
        update_context_did(
            &ks,
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

    /// Store a minimal key record so a designation has something real to point
    /// at — `set_context_issuer_key` checks the key exists and lives in the
    /// context.
    async fn seed_key(keys_ks: &KeyspaceHandle, key_id: &str, context_id: Option<&str>) {
        let record = vta_sdk::keys::KeyRecord {
            key_id: key_id.to_string(),
            derivation_path: "m/26'/2'/1'/0".to_string(),
            key_type: vta_sdk::keys::KeyType::Ed25519,
            status: vta_sdk::keys::KeyStatus::Active,
            public_key: "z6MkTestPublicKey".to_string(),
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
