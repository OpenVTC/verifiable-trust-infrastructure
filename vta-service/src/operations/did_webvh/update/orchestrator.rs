//! End-to-end orchestration of [`update_did_webvh`].
//!
//! Stages: SCID lookup → auth gate → input validation → load chain →
//! optimistic-concurrency precondition → derive new keys → resolve
//! signing key (pre-rotation aware) → call `didwebvh_rs::update_did`
//! → CAS check → persist log + handles → publish to host → audit.

use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::Utc;
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::multibase_type::Multibase;
use didwebvh_rs::update::{UpdateDIDConfig, update_did};

use super::errors::UpdateDidWebvhError;
use super::keys::{
    derive_secret_for_handle, install_derived_webvh_keys, load_active_update_key,
    load_pre_rotation_signing_key, peek_webvh_keys,
};
use super::options::{UpdateDidWebvhOptions, UpdateDidWebvhResult};
use super::plan::UpdatePlan;
use super::state::{find_record_by_scid, state_from_jsonl, state_to_jsonl};
use super::validate::{validate_document_for_update, validate_watchers, validate_witnesses};
use crate::audit;
use crate::auth::AuthClaims;
use crate::keys::paths::peek_path_counter;
use crate::operations::did_webvh::concurrency::RecordSnapshot;
use crate::operations::did_webvh::webvh_keys::{self, WebvhKeyHandle, WebvhKeyRole};
use crate::webvh_store;

/// Plan an update without performing it: run the real path up to — and not
/// through — its first write, and report what it *would* do.
///
/// This exists so a human can be shown the consequences of an update before
/// authorizing it. It must be the same code as the update itself: a separate
/// implementation that described the update would drift, and a drifted
/// description is worse than none, because it misinforms with a straight face.
///
/// Read-only. In particular the key derivation *peeks* the BIP-32 path counter
/// rather than allocating from it — allocating here would both burn an index
/// and, far worse, cause the subsequent real run to derive a **different** key
/// than the one reported, which is exactly the deception the plan exists to
/// prevent. Because a peek reserves nothing, the plan carries
/// [`UpdatePlan::path_counter_pin`], and a caller that acts on the plan must
/// re-check it.
pub async fn plan_did_webvh_update(
    deps: &super::super::WebvhDeps<'_>,
    auth: &AuthClaims,
    scid: &str,
    opts: UpdateDidWebvhOptions,
) -> Result<UpdatePlan, UpdateDidWebvhError> {
    match run_update(
        deps,
        auth,
        scid,
        opts,
        None,
        "plan",
        Mode::Plan,
        PublishTarget::DidLog,
    )
    .await?
    {
        Outcome::Planned(plan) => Ok(plan),
        Outcome::Executed(_) => Err(UpdateDidWebvhError::Library(
            "plan mode committed an update".into(),
        )),
    }
}

/// Drive a webvh DID update end-to-end. See module docs.
///
/// - `vta_did` — the running VTA's DID (read from `AppConfig::vta_did` at the
///   call site). `None` means "no VTA identity configured" — server-managed DID
///   publishes fail loudly with `Publish("…")` rather than silently 401.
pub async fn update_did_webvh(
    deps: &super::super::WebvhDeps<'_>,
    auth: &AuthClaims,
    scid: &str,
    opts: UpdateDidWebvhOptions,
    vta_did: Option<&str>,
    channel: &str,
) -> Result<UpdateDidWebvhResult, UpdateDidWebvhError> {
    match run_update(
        deps,
        auth,
        scid,
        opts,
        vta_did,
        channel,
        Mode::Execute,
        PublishTarget::DidLog,
    )
    .await?
    {
        Outcome::Executed(result) => Ok(result),
        Outcome::Planned(_) => Err(UpdateDidWebvhError::Library(
            "execute mode returned a plan".into(),
        )),
    }
}

/// Which agent-name operation [`agent_name_op`] performs.
///
/// The four verbs share one document-level behaviour — claim the name in
/// `alsoKnownAs` or drop it — and differ in the registry effect the host
/// applies. `claims_name` mirrors did-hosting's own
/// `AgentNameOp::requires_claim` exactly; if the two ever disagree the host
/// rejects the submitted document with `also_known_as_mismatch`, which is the
/// invariant keeping the served state and the signed document from diverging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentNameVerb {
    /// Bind the name to this DID.
    Set,
    /// Release the name for anyone to reclaim.
    Remove,
    /// Resume serving a parked name.
    Enable,
    /// Park the name: stops resolving, stays reserved to this DID.
    Disable,
}

impl AgentNameVerb {
    /// The host endpoint segment — `POST /api/agent-names/{op}`.
    pub fn endpoint(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Remove => "remove",
            Self::Enable => "enable",
            Self::Disable => "disable",
        }
    }

    /// Whether the published document must claim the name.
    pub fn claims_name(self) -> bool {
        matches!(self, Self::Set | Self::Enable)
    }
}

/// Resolve a hosted DID to `(record, server, domain)` for the read-only
/// agent-name operations. Shares `agent_name_op`'s preconditions — the DID
/// must exist, must not be serverless, and must have a resolvable host — so
/// the read and write paths agree about which DIDs have agent names at all.
///
/// Enforces `require_context` like every other per-DID read
/// (`get_did_webvh`, `get_did_webvh_log`). These reads are not public: the
/// registry exposes *parked* names, which are deliberately absent from the
/// published document, and `check` is a probe against the host. Neither is
/// inferable from the DID log, so neither may be readable across contexts.
async fn hosted_agent_name_context(
    deps: &super::super::WebvhDeps<'_>,
    auth: &AuthClaims,
    did: &str,
) -> Result<
    (
        vta_sdk::webvh::WebvhDidRecord,
        vta_sdk::webvh::WebvhServerRecord,
        String,
    ),
    UpdateDidWebvhError,
> {
    let record = find_record_by_scid(deps.webvh_ks, did)
        .await?
        .ok_or_else(|| UpdateDidWebvhError::NotFound(format!("DID {did} not found")))?;

    // Forbidden and NotFound both surface as 404, so this does not tell an
    // unauthorized caller that the DID exists.
    auth.require_context(&record.context_id)
        .map_err(|e| UpdateDidWebvhError::Forbidden(e.to_string()))?;

    if record.server_id == "serverless" {
        return Err(UpdateDidWebvhError::Publish(
            "agent names require a hosted DID; this DID is serverless \
             (register it with a server first)"
                .to_string(),
        ));
    }

    let server = webvh_store::get_server(deps.webvh_ks, &record.server_id)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_server: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::Publish(format!(
                "webvh server `{}` referenced by DID is missing",
                record.server_id
            ))
        })?;

    let domain = domain_from_webvh_did(&record.did).ok_or_else(|| {
        UpdateDidWebvhError::Library(format!("cannot derive domain from DID {}", record.did))
    })?;

    Ok((record, server, domain))
}

/// Read a hosted DID's agent-name registry from the control plane.
///
/// The control plane is the source of record for agent names, and this is a
/// live read of it — not a projection of the local DID record. That matters
/// for one case in particular: a **parked** name is deliberately absent from
/// the DID document (dropping the `alsoKnownAs` claim is *how* parking stops
/// it resolving), so nothing derived from the document can show one. Without
/// this call a client cannot offer "resume" without making the user retype
/// the name from memory.
pub async fn list_agent_names(
    deps: &super::super::WebvhDeps<'_>,
    auth: &AuthClaims,
    did: &str,
    vta_did: Option<&str>,
) -> Result<(String, Vec<crate::webvh_client::AgentNameEntryWire>), UpdateDidWebvhError> {
    let (record, server, domain) = hosted_agent_name_context(deps, auth, did).await?;
    let vta_did = vta_did.ok_or_else(|| {
        UpdateDidWebvhError::Library("no VTA DID configured for hosting auth".to_string())
    })?;

    let names = super::super::list_agent_names_on_server(
        deps,
        vta_did,
        &server,
        &record.mnemonic,
        Some(&domain),
    )
    .await
    .map_err(|e| UpdateDidWebvhError::Publish(format!("list_agent_names: {e}")))?;

    Ok((record.did, names))
}

/// Ask the host whether `name` is free on this DID's domain.
///
/// Availability is domain-scoped, and the domain is the DID's own host — the
/// same rule the mutating verbs follow. Answering this *before* the caller
/// signs a new DID version is the point: otherwise the only way to discover a
/// collision is to publish and have the bind rejected.
pub async fn check_agent_name(
    deps: &super::super::WebvhDeps<'_>,
    auth: &AuthClaims,
    did: &str,
    name: &str,
    vta_did: Option<&str>,
) -> Result<crate::webvh_client::AgentNameAvailabilityWire, UpdateDidWebvhError> {
    let (_record, server, domain) = hosted_agent_name_context(deps, auth, did).await?;
    let vta_did = vta_did.ok_or_else(|| {
        UpdateDidWebvhError::Library("no VTA DID configured for hosting auth".to_string())
    })?;

    super::super::check_agent_name_on_server(deps, vta_did, &server, name, Some(&domain))
        .await
        .map_err(|e| UpdateDidWebvhError::Publish(format!("check_agent_name: {e}")))
}

/// Bind, release, park or resume an agent name (`/@alice`) on a hosted webvh
/// DID.
///
/// Reads the DID's current document, edits its `alsoKnownAs` to claim
/// (`set`/`enable`) or no-longer-claim (`remove`/`disable`)
/// `https://<domain>/@<name>`, then runs the *same* signing path as an update
/// and submits the new version to the host's `agent-name/{op}` endpoint —
/// which republishes it AND applies the registry change atomically.
///
/// Binding through `set` rather than a plain `dids/update` with an edited
/// `alsoKnownAs` is deliberate: the host's `set` endpoint enforces the
/// reserved-name and already-taken checks, so a collision comes back as
/// `name_taken` / `name_reserved` instead of a bind that appears to succeed.
///
/// `did` may be a full `did:webvh:…` or a bare SCID. Refused for serverless
/// DIDs (no host serves their names).
pub async fn agent_name_op(
    deps: &super::super::WebvhDeps<'_>,
    auth: &AuthClaims,
    did: &str,
    name: &str,
    verb: AgentNameVerb,
    vta_did: Option<&str>,
    channel: &str,
) -> Result<UpdateDidWebvhResult, UpdateDidWebvhError> {
    let record = find_record_by_scid(deps.webvh_ks, did)
        .await?
        .ok_or_else(|| UpdateDidWebvhError::NotFound(format!("DID {did} not found")))?;

    if record.server_id == "serverless" {
        return Err(UpdateDidWebvhError::Publish(
            "agent names require a hosted DID; this DID is serverless \
             (register it with a server first)"
                .to_string(),
        ));
    }

    let did_log = webvh_store::get_did_log(deps.webvh_ks, &record.did)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_did_log: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::NotFound(format!("no did.jsonl stored for {}", record.did))
        })?;
    let mut document =
        crate::operations::protocol::document::current_document_from_log(&did_log)
            .map_err(|e| UpdateDidWebvhError::Library(format!("read current document: {e}")))?;

    let domain = domain_from_webvh_did(&record.did).ok_or_else(|| {
        UpdateDidWebvhError::Library(format!("cannot derive domain from DID {}", record.did))
    })?;
    edit_agent_name(&mut document, &domain, name, verb.claims_name());

    let opts = UpdateDidWebvhOptions {
        document: Some(document),
        label: Some(format!("agent-name/{}", verb.endpoint())),
        ..Default::default()
    };

    match run_update(
        deps,
        auth,
        &record.scid,
        opts,
        vta_did,
        channel,
        Mode::Execute,
        PublishTarget::AgentName {
            name: name.to_string(),
            verb,
        },
    )
    .await?
    {
        Outcome::Executed(result) => Ok(result),
        Outcome::Planned(_) => Err(UpdateDidWebvhError::Library(
            "execute mode returned a plan".into(),
        )),
    }
}

/// Extract the hosting domain (host authority) from a
/// `did:webvh:{scid}:{host}:…` identifier, percent-decoding an encoded port
/// (`localhost%3A8534` → `localhost:8534`). `None` if the shape is unexpected.
fn domain_from_webvh_did(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:webvh:")?;
    let host = rest.split(':').nth(1)?;
    if host.is_empty() {
        return None;
    }
    Some(host.replace("%3A", ":").replace("%3a", ":"))
}

/// Edit a DID document's `alsoKnownAs` to claim (`claim`) or drop (`!claim`)
/// the agent name `https://<domain>/@<name>`. Idempotent.
fn edit_agent_name(document: &mut serde_json::Value, domain: &str, name: &str, claim: bool) {
    let entry = format!("https://{domain}/@{name}");
    let Some(obj) = document.as_object_mut() else {
        return;
    };
    if claim {
        let arr = obj
            .entry("alsoKnownAs")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let Some(list) = arr.as_array_mut()
            && !list.iter().any(|v| is_agent_name(v, domain, name))
        {
            list.push(serde_json::Value::String(entry));
        }
    } else if let Some(serde_json::Value::Array(list)) = obj.get_mut("alsoKnownAs") {
        list.retain(|v| !is_agent_name(v, domain, name));
        if list.is_empty() {
            obj.remove("alsoKnownAs");
        }
    }
}

/// Whether a JSON value is the agent name `<name>` on `<domain>` (host match
/// case-insensitive; local part exact, per the spec's case-sensitive rule).
fn is_agent_name(v: &serde_json::Value, domain: &str, name: &str) -> bool {
    let Some(s) = v.as_str() else {
        return false;
    };
    let no_scheme = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let Some((host, rest)) = no_scheme.split_once("/@") else {
        return false;
    };
    let local = rest.split('/').next().unwrap_or("");
    host.eq_ignore_ascii_case(domain) && local == name
}

/// Whether [`run_update`] stops at the last read or goes on to commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Plan,
    Execute,
}

enum Outcome {
    Planned(UpdatePlan),
    Executed(UpdateDidWebvhResult),
}

/// Where [`run_update`]'s freshly-signed log gets published (Execute mode).
///
/// Both variants publish the *same* signed `did.jsonl` a normal update
/// produces; they differ only in which host endpoint receives it. Agent-name
/// ops build the mutated document (`alsoKnownAs` edited) and pass it as
/// `opts.document`, so the signing path is byte-for-byte the update path.
enum PublishTarget {
    /// `PUT /api/dids/{mnemonic}` — every plain document update.
    DidLog,
    /// `POST /api/agent-names/{set,remove,enable,disable}` — the host
    /// republishes the log AND applies the registry change in one commit.
    AgentName { name: String, verb: AgentNameVerb },
}

async fn run_update(
    deps: &super::super::WebvhDeps<'_>,
    auth: &AuthClaims,
    scid: &str,
    opts: UpdateDidWebvhOptions,
    vta_did: Option<&str>,
    channel: &str,
    mode: Mode,
    publish: PublishTarget,
) -> Result<Outcome, UpdateDidWebvhError> {
    // Re-bind the bundled deps to the historical local names so the (large) body
    // below is unchanged. All fields are `Copy` references — this copies the
    // borrows out of `*deps`; `deps` itself stays usable (the publish step below
    // forwards it to `publish_log_to_server`).
    let super::super::WebvhDeps {
        keys_ks,
        contexts_ks,
        webvh_ks,
        audit_ks,
        seed_store,
        did_resolver,
        ..
    } = *deps;
    // 1. Resolve SCID → record. Snapshot the version-vector fields
    //    immediately. The snapshot is consulted just before the
    //    final store (step 11) to catch any concurrent record
    //    mutation — not just log_entry_count changes (which this
    //    op makes itself) but `server_id` / `updated_at` changes
    //    too, since a concurrent `register_did_with_server` flipping
    //    `server_id` from `serverless` → `webvh-prod` is a real
    //    race that the previous ad-hoc `log_entry_count` check
    //    silently missed.
    let mut record = find_record_by_scid(webvh_ks, scid)
        .await?
        .ok_or_else(|| UpdateDidWebvhError::NotFound(format!("SCID {scid} not found")))?;
    // `scid` may arrive as a full `did:webvh:…` (the delegated-update path,
    // `trust_tasks/webvh.rs`) or as a bare SCID (the CLI path). `find_record_by_scid`
    // accepts either form for lookup, but the `webvh_keys` handle keyspace is
    // ALWAYS keyed by the canonical bare SCID (`record.scid`). Keying it off the
    // raw argument bifurcates the keyspace — a DID updated via one path installs
    // its handles under a prefix the other path can't find, so the DID becomes
    // un-updatable that way (#659 regression). Canonicalize the identifier here so
    // every `webvh_keys` op below (load/install/supersede) and every derived DID
    // string uses the SCID, whichever caller we came from.
    let canonical_scid = record.scid.clone();
    let scid = canonical_scid.as_str();
    let initial_log_entry_count = record.log_entry_count;
    let snapshot = RecordSnapshot::capture(&record);

    // 2. Auth gate. Forbidden + NotFound both surface as 404 at the
    //    wire boundary — see `From<UpdateDidWebvhError> for AppError`.
    //
    // `require_admin` always holds: only an admin (of *some* context) may
    // propose an update at all. `require_context` is the per-DID authority. In
    // Execute mode it is mandatory — but note the caller may have widened `auth`
    // for this one dispatch via a consented delegation
    // (`AuthClaims::with_delegated_contexts`), so a requester who lacked the
    // context on their own token passes here iff an approver conferred it.
    //
    // In Plan mode the check is *recorded, not enforced*: the plan is a
    // read-only dry-run whose only outputs are the DID-document diff (public —
    // webvh logs resolve for anyone) and a reserving-nothing key-counter peek.
    // Letting it run for a context the requester can't self-authorize is what
    // lets the consent gate show an approver the effects of a delegated update
    // *before* anyone holds the authority to commit it. Whether the requester
    // self-authorized rides out on `UpdatePlan.requester_authorized` so the gate
    // knows to demand a context-admin approver.
    // Whether the caller can authorize this update on its **own standing** —
    // admin role AND access to the DID's context. In Execute mode `auth` may
    // already have been widened for this one dispatch by a consented delegation
    // (`AuthClaims::with_delegated_authority`, which confers *both* admin and the
    // context), so a requester that held neither on its own token passes here iff
    // an approver conferred them. This is what lets a purely unprivileged agent
    // execute a task an approver blessed.
    let requester_authorized =
        auth.require_admin().is_ok() && auth.has_context_access(&record.context_id);
    match mode {
        // A dry-run reveals only the public DID-document diff and reserves
        // nothing, so any known (Reader+) principal may run it to surface the
        // effects a consent surface must show — including for a context the
        // caller cannot self-authorize. That is precisely how the consent gate
        // shows an approver a delegated update before anyone holds the authority
        // to commit it. `requester_authorized` still rides out on
        // `UpdatePlan.requester_authorized` so the gate knows to demand a
        // conferring approver.
        Mode::Plan => auth.require_read().map_err(|e| {
            UpdateDidWebvhError::Forbidden(format!("read access required to plan an update: {e}"))
        })?,
        Mode::Execute if !requester_authorized => {
            return Err(UpdateDidWebvhError::Forbidden(format!(
                "caller is not authorized to update DIDs in context `{}`, and no consented delegation conferred it",
                record.context_id
            )));
        }
        Mode::Execute => {}
    }

    // 3. Validate caller-supplied inputs (cheap; do before key derivation).
    let new_doc = match opts.document {
        Some(doc) => Some(validate_document_for_update(doc, &record.did)?),
        None => None,
    };
    if let Some(ref w) = opts.witnesses {
        validate_witnesses(w, did_resolver).await?;
    }
    if let Some(ref watch) = opts.watchers {
        validate_watchers(watch)?;
    }

    // 4. Load DID log → DIDWebVHState; validate the chain.
    let did_log = webvh_store::get_did_log(webvh_ks, &record.did)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_did_log: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::Library(format!("DID log missing for {}", record.did))
        })?;
    let state = state_from_jsonl(&did_log)?;
    let last_state = state.log_entries().last().ok_or_else(|| {
        UpdateDidWebvhError::Library(format!("DID {} has no log entries", record.did))
    })?;
    // Index for the new entry's backdated versionTime (count already in the chain).
    let new_entry_index = state.log_entries().len();

    // 4a. Optimistic-concurrency precondition. Check BEFORE key
    //     derivation / signing so a stale `get → edit → save` cycle
    //     fails fast and cheap, with a message the operator can act
    //     on. This catches the lost-update race the within-operation
    //     `log_entry_count` check at the end does NOT — that one only
    //     covers two server calls racing each other; this one covers
    //     a client call that was authored against a stale view.
    if let Some(expected) = opts.expected_version_id.as_deref() {
        let latest = last_state.get_version_id();
        if latest != expected {
            return Err(UpdateDidWebvhError::Conflict(format!(
                "DID {} has been updated since you read it (expected versionId `{expected}`, \
                 current is `{latest}`). Re-fetch the document and re-apply your edits.",
                record.did
            )));
        }
    }

    let last_params = last_state.validated_parameters.clone();
    let last_update_keys: Vec<Multibase> = last_params
        .update_keys
        .as_ref()
        .map(|arc| (**arc).clone())
        .unwrap_or_default();
    // Owned snapshot of the prior state. Taken here because `state` is moved
    // into the update config below, which ends `last_state`'s borrow — and a
    // plan needs the before-picture after that point.
    let prior_version_id = last_state.get_version_id().to_string();
    let prior_document = last_state.log_entry.get_state().clone();
    // Pre-rotation is "active" when the previous entry committed
    // `next_key_hashes`. The library's `check_signing_key` consults
    // `previous.next_key_hashes` (not `previous.update_keys`) for the
    // signing-key authorization check in that case, so the next entry
    // MUST be signed by a key whose hash was in that commitment.
    // See didwebvh-rs::lib::DIDWebVHState::check_signing_key.
    let last_next_key_hashes: Vec<String> = last_params
        .next_key_hashes
        .as_ref()
        .map(|arc| arc.iter().map(|m| m.as_ref().to_string()).collect())
        .unwrap_or_default();
    let pre_rotation_active = !last_next_key_hashes.is_empty();

    // 5. Resolve effective pre-rotation count.
    let pre_rotation_count = opts.pre_rotation_count.unwrap_or(record.pre_rotation_count);

    // 6. Resolve context base path for BIP-32 derivation.
    let context = crate::contexts::get_context(contexts_ks, &record.context_id)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_context: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::Library(format!(
                "context `{}` referenced by DID is missing",
                record.context_id
            ))
        })?;

    // 7. Derive new keys (no persist yet — version_id unknown).
    //    With pre-rotation active, the "auth" key for the new entry is
    //    the *revealed* pre-rotation candidate from the previous entry,
    //    not a freshly-minted key. We pick that handle in step 8 below.
    //
    //    In Plan mode we *peek* the derivation-path counter instead of
    //    allocating from it. Allocating would make the plan a mutation —
    //    and would mean the real run derived a different key than the one
    //    the plan reported, since it would allocate the *next* index. The
    //    peeked counter is pinned into the plan so the caller can detect a
    //    concurrent allocation before acting on it.
    let path_counter_pin = peek_path_counter(keys_ks, &context.base_path)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("peek_path_counter: {e}")))?;
    let auth_count: u32 = u32::from(new_doc.is_some() && !pre_rotation_active);
    let total_keys = auth_count + pre_rotation_count;

    // Plan and execute derive the *same contiguous block* and split it the same
    // way — that symmetry is what makes the prediction sound.
    //
    // Plan peeks the block (read-only); execute allocates it in one atomic step,
    // pinned to the counter the plan peeked. If anything advanced the counter in
    // between — a concurrent update in the same context, minutes later, while a
    // human was deciding — the allocation fails rather than installing keys the
    // approver never saw. Allocating the auth and pre-rotation keys separately, as
    // this once did, left a window for exactly that between the two calls.
    let derived_all = match mode {
        Mode::Plan => peek_webvh_keys(keys_ks, seed_store, &context.base_path, total_keys).await?,
        Mode::Execute => {
            super::keys::derive_webvh_keys_block(
                keys_ks,
                seed_store,
                &context.base_path,
                total_keys,
                Some(path_counter_pin),
            )
            .await?
        }
    };
    let (auth_slice, pre_slice) = derived_all.split_at(auth_count as usize);
    let (derived_auth, derived_pre_rotation) = (auth_slice.to_vec(), pre_slice.to_vec());

    // 8. Resolve the signing key.
    //
    //    With pre-rotation active, find a handle whose hash is in
    //    `last.next_key_hashes` — that's the only key webvh will accept
    //    as a signer for the next log entry. Without pre-rotation, fall
    //    back to the pre-existing `load_active_update_key` lookup over
    //    `last.update_keys`.
    tracing::info!(
        scid,
        did = %record.did,
        pre_rotation_active,
        next_key_hashes_count = last_next_key_hashes.len(),
        update_keys_count = last_update_keys.len(),
        "update_did_webvh: resolving signing key"
    );
    let signing_handle = if pre_rotation_active {
        load_pre_rotation_signing_key(keys_ks, scid, &last_next_key_hashes).await?
    } else {
        load_active_update_key(keys_ks, scid, &last_update_keys).await?
    };
    tracing::info!(
        scid,
        signing_pubkey = %signing_handle.public_key,
        signing_hash = %signing_handle.hash,
        signing_role = ?signing_handle.role,
        signing_version = %signing_handle.version_id,
        "update_did_webvh: signing key resolved"
    );
    let signing_secret = derive_secret_for_handle(keys_ks, seed_store, &signing_handle).await?;

    // 9. Build the library config.
    let mut builder = UpdateDIDConfig::<Secret, Secret>::builder_generic()
        .state(state)
        .signing_key(signing_secret)
        // Backdated, index-spaced timestamp so a back-to-back update doesn't
        // collide with the previous entry's second — see `backdated_version_time`.
        .version_time(super::super::backdated_version_time(new_entry_index));
    // The update_keys this entry sets, or `None` to leave the previous entry's
    // in force — webvh parameters are a delta, so "not restated" means
    // "unchanged", NOT "removed".
    //
    // Computed once, here, and consumed by both the builder below and the plan.
    // Deriving it twice would be the same mistake this whole plan/apply split
    // exists to avoid: a second implementation of the handler's semantics that
    // is free to drift from the first.
    let set_update_keys: Option<Vec<Multibase>> = if new_doc.is_some() && !pre_rotation_active {
        Some(
            derived_auth
                .iter()
                .map(|k| Multibase::from(k.public_key.clone()))
                .collect(),
        )
    } else if pre_rotation_active {
        // Reveal the pre-rotation key as the new update_keys entry.
        // `validate_pre_rotation_keys` requires every key in the new update_keys
        // to have its hash committed in previous.next_key_hashes —
        // `signing_handle.public_key` satisfies that by construction (we picked
        // it BY hash).
        //
        // This also covers the metadata-only update under pre-rotation: the
        // active update-keys must keep moving forward in lockstep with the
        // signing-key reveal, or the next entry's `previous.next_key_hashes`
        // carries an unused commitment while the key on record goes stale.
        Some(vec![Multibase::from(signing_handle.public_key.clone())])
    } else {
        None
    };

    /// The update keys in force *after* this entry: what it sets, or what the
    /// previous entry left standing.
    fn effective_update_keys(set: &Option<Vec<Multibase>>, previous: &[Multibase]) -> Vec<String> {
        set.as_deref()
            .unwrap_or(previous)
            .iter()
            .map(|k| k.as_ref().to_string())
            .collect()
    }

    if let Some(doc) = new_doc {
        builder = builder.document(doc);
    }
    if let Some(ref keys) = set_update_keys {
        builder = builder.update_keys(keys.clone());
    }
    // Always pass next_key_hashes when caller toggled pre-rotation OR
    // when the DID currently uses pre-rotation — keeps the commitment
    // chain unbroken. Empty vec disables pre-rotation going forward.
    if opts.pre_rotation_count.is_some() || record.pre_rotation_count > 0 {
        let hashes: Vec<Multibase> = derived_pre_rotation
            .iter()
            .map(|k| Multibase::from(k.hash.clone()))
            .collect();
        builder = builder.next_key_hashes(hashes);
    }
    if let Some(w) = opts.witnesses.clone() {
        builder = builder.witness(w);
    }
    if let Some(watch) = opts.watchers.clone() {
        builder = builder.watchers(watch);
    }
    if let Some(t) = opts.ttl {
        builder = builder.ttl(t);
    }

    let cfg = builder
        .build()
        .map_err(|e| UpdateDidWebvhError::Library(format!("build update config: {e}")))?;

    // 10. Append the new log entry via the library.
    let result = update_did(cfg)
        .await
        .map_err(|e| UpdateDidWebvhError::Library(format!("update_did: {e}")))?;
    let new_log_entry = result.log_entry();
    let new_version_id = new_log_entry
        .get_version_id_fields()
        .map(|(n, h)| format!("{n}-{h}"))
        .map_err(|e| UpdateDidWebvhError::Library(format!("read version id: {e}")))?;
    let new_scid = new_log_entry.get_scid().unwrap_or_default().to_string();
    let new_log_entry_str = serde_json::to_string(new_log_entry)
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("serialize new entry: {e}")))?;

    // 11. Optimistic concurrency check before persisting. Uses the
    //     shared `RecordSnapshot` machinery so we catch *every* kind
    //     of concurrent mutation (log_entry_count, updated_at, AND
    //     server_id) rather than just log_entry_count growth. The
    //     server_id case is the one the ad-hoc check missed:
    //     `register_did_with_server` flipping `server_id` from
    //     `serverless` → `webvh-prod` between step 1 and here used
    //     to slip past unchallenged, then step 12 would clobber the
    //     newer record with our stale `serverless` value.
    let current = webvh_store::get_did(webvh_ks, &record.did)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_did: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::NotFound(format!("DID {} disappeared mid-update", record.did))
        })?;
    snapshot
        .assert_unchanged(&current)
        .map_err(|race| UpdateDidWebvhError::Conflict(race.to_string()))?;

    // ── The seam. Everything above is read-only; everything below commits. ──
    //
    // A plan stops here, having run the real path: the same chain load, the
    // same key derivation, the same `didwebvh_rs::update_did` that minted the
    // actual next log entry above. What it reports is not a description of the
    // update — it is the update, uncommitted.
    if mode == Mode::Plan {
        return Ok(Outcome::Planned(UpdatePlan {
            did: record.did.clone(),
            scid: scid.to_string(),
            prior_version_id,
            new_version_id: new_version_id.clone(),
            prior_document,
            new_document: new_log_entry.get_state().clone(),
            prior_update_keys: last_update_keys
                .iter()
                .map(|k| k.as_ref().to_string())
                .collect(),
            new_update_keys: effective_update_keys(&set_update_keys, &last_update_keys),
            pre_rotation_count,
            new_next_key_hashes: derived_pre_rotation
                .iter()
                .map(|k| k.hash.clone())
                .collect(),
            base_path: context.base_path.clone(),
            path_counter_pin,
            subject_context: record.context_id.clone(),
            requester_authorized,
        }));
    }

    // 12. Persist new log + new key handles + updated record.
    let new_log_jsonl = state_to_jsonl(result.state())?;
    webvh_store::store_did_log(webvh_ks, &record.did, &new_log_jsonl)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("store_did_log: {e}")))?;
    // Single source of truth for the post-mutation self-DID resolver refresh:
    // reseed the in-process cache straight from the log we just built, before it
    // leaves this function. Every runtime DID-log mutation (did-webvh update and
    // all `services {…}` ops, which funnel through here) is covered by this one
    // call — do not re-add per-caller refreshes at the protocol layer.
    super::super::refresh_resolver_doc_from_log(did_resolver, &record.did, &new_log_jsonl, channel)
        .await;

    if !derived_auth.is_empty() {
        install_derived_webvh_keys(
            keys_ks,
            scid,
            &new_version_id,
            WebvhKeyRole::UpdateKey,
            &derived_auth,
            "update key",
        )
        .await?;
    }
    if !derived_pre_rotation.is_empty() {
        install_derived_webvh_keys(
            keys_ks,
            scid,
            &new_version_id,
            WebvhKeyRole::PreRotation,
            &derived_pre_rotation,
            "pre-rotation key",
        )
        .await?;
    }
    // When we reveal a pre-rotation key, re-install it as an
    // `UpdateKey` handle under the new version_id. Without this, the
    // supersede step (below) moves the previous version's PreRotation
    // handle out of the active prefix, and the next update can't
    // resolve the now-active key by hash via the fast path. The handle
    // contents are otherwise identical to the previous PreRotation
    // entry — same derivation path, same secret.
    if pre_rotation_active {
        let revealed = WebvhKeyHandle {
            scid: scid.to_string(),
            version_id: new_version_id.clone(),
            hash: signing_handle.hash.clone(),
            public_key: signing_handle.public_key.clone(),
            derivation_path: signing_handle.derivation_path.clone(),
            seed_id: signing_handle.seed_id,
            role: WebvhKeyRole::UpdateKey,
            label: format!(
                "revealed pre-rotation key (was version {})",
                signing_handle.version_id
            ),
            created_at: Utc::now(),
        };
        webvh_keys::install(keys_ks, &revealed)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("install revealed key: {e}")))?;
    }

    // Supersede the previous version's keys (best-effort — handles that
    // never made it into webvh_keys, e.g. legacy DIDs, are silently
    // skipped by the prefix scan).
    if let Some(prev) = result
        .state()
        .log_entries()
        .iter()
        .rev()
        .nth(1)
        .map(|e| {
            e.log_entry
                .get_version_id_fields()
                .map(|(n, h)| format!("{n}-{h}"))
        })
        .transpose()
        .unwrap_or(None)
    {
        webvh_keys::supersede_keys_for_version(keys_ks, scid, &prev)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("supersede: {e}")))?;
    }

    record.log_entry_count += 1;
    record.pre_rotation_count = derived_pre_rotation.len() as u32;
    record.updated_at = Utc::now();
    webvh_store::store_did(webvh_ks, &record)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("store_did: {e}")))?;

    // 13. Publish the new log to the hosting server for non-serverless
    //     DIDs. Uses the auth-cache orchestration helper which:
    //       - loads the VTA's signing identity for the daemon REST
    //         auth handshake (no-op for DIDComm transport),
    //       - reads `server-auth:{id}` under the per-server async
    //         mutex; refreshes or re-authenticates if stale,
    //       - publishes with one-shot 401 retry (token revoked
    //         mid-window).
    //
    //     Local state is already committed, so a publish failure
    //     surfaces as `Publish` (HTTP 500) but doesn't undo the
    //     local update; operators can retry the publish out-of-band
    //     by re-issuing the same update.
    if record.server_id != "serverless" {
        let server = webvh_store::get_server(webvh_ks, &record.server_id)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_server: {e}")))?
            .ok_or_else(|| {
                UpdateDidWebvhError::Publish(format!(
                    "webvh server `{}` referenced by DID is missing",
                    record.server_id
                ))
            })?;
        let vta_did = vta_did.ok_or_else(|| {
            UpdateDidWebvhError::Publish(
                "VTA DID is not configured — cannot authenticate to webvh hosting server. \
                 Complete `vta setup` before publishing to a server-managed DID."
                    .to_string(),
            )
        })?;
        match &publish {
            PublishTarget::DidLog => {
                super::super::publish_log_to_server(
                    deps,
                    vta_did,
                    &server,
                    &record.mnemonic,
                    &new_log_jsonl,
                    // Update paths follow the slot's existing domain — the
                    // remote already records it on the slot. Passing None
                    // lets the remote use the recorded value; a host that
                    // does per-domain mnemonic namespacing would resolve via
                    // the slot lookup.
                    None,
                )
                .await
                .map_err(|e| UpdateDidWebvhError::Publish(format!("publish_did: {e}")))?;
            }
            PublishTarget::AgentName { name, verb } => {
                // The host both republishes this signed log AND applies the
                // name registry change, so we must name the domain explicitly
                // (it is the DID's own host) — unlike a plain publish, which
                // lets the slot lookup supply it.
                let domain = domain_from_webvh_did(&record.did);
                super::super::agent_name_op_on_server(
                    deps,
                    vta_did,
                    &server,
                    *verb,
                    &record.mnemonic,
                    name,
                    &new_log_jsonl,
                    domain.as_deref(),
                )
                .await
                .map_err(|e| UpdateDidWebvhError::Publish(format!("agent_name: {e}")))?;
            }
        }
    }

    // 14. Audit emission. Best-effort — a missing audit row should
    //     not undo a successful update, so we log+swallow on error.
    let resource = format!(
        "did:webvh:{scid} v{} → v{}",
        initial_log_entry_count, record.log_entry_count
    );
    let label = opts.label.as_deref().unwrap_or("update");
    if let Err(e) = audit::record(
        audit_ks,
        &format!("did.update:{label}"),
        &auth.did,
        Some(&resource),
        "success",
        Some(channel),
        Some(&record.context_id),
    )
    .await
    {
        tracing::warn!(
            channel,
            did = %record.did,
            error = %e,
            "did.update audit emission failed; update committed"
        );
    }

    tracing::info!(
        channel,
        did = %record.did,
        scid = %scid,
        new_version_id = %new_version_id,
        label = ?opts.label,
        "did:webvh updated"
    );

    let update_keys_count = effective_update_keys(&set_update_keys, &last_update_keys).len() as u32;

    Ok(Outcome::Executed(UpdateDidWebvhResult {
        did: record.did.clone(),
        new_version_id,
        new_scid,
        new_log_entry: new_log_entry_str,
        update_keys_count,
        pre_rotation_key_count: derived_pre_rotation.len() as u32,
        // Surface so route + DIDComm response shapes can emit the
        // "fetch did.jsonl + redeploy" hint to operators. The
        // string-equality check matches the same sentinel
        // (`SERVERLESS_MARKER`) that `register_did_with_server`
        // gates on and that step 13 above used to decide whether
        // to call the host transport.
        serverless: record.server_id == "serverless",
    }))
}

#[cfg(test)]
mod agent_name_tests {
    use super::{AgentNameVerb, domain_from_webvh_did, edit_agent_name, is_agent_name};
    use serde_json::{Value, json};

    /// Each verb maps to its own host endpoint. A transposition here would
    /// send `remove` to `disable` — releasing a name the caller meant to
    /// park, or the reverse — and nothing downstream could detect it.
    #[test]
    fn verbs_map_to_distinct_endpoints() {
        assert_eq!(AgentNameVerb::Set.endpoint(), "set");
        assert_eq!(AgentNameVerb::Remove.endpoint(), "remove");
        assert_eq!(AgentNameVerb::Enable.endpoint(), "enable");
        assert_eq!(AgentNameVerb::Disable.endpoint(), "disable");
    }

    /// The document direction per verb, which must match did-hosting's
    /// `AgentNameOp::requires_claim` exactly — the host rejects the submitted
    /// document with `also_known_as_mismatch` if it doesn't, and that
    /// agreement is what keeps a served name and the signed document that
    /// claims it from ever diverging.
    #[test]
    fn claim_direction_matches_the_hosts_rule() {
        assert!(AgentNameVerb::Set.claims_name());
        assert!(AgentNameVerb::Enable.claims_name());
        assert!(!AgentNameVerb::Remove.claims_name());
        assert!(!AgentNameVerb::Disable.claims_name());
    }

    /// End-to-end on the document: for every verb, the `alsoKnownAs` the VTA
    /// signs claims the name iff that verb claims it.
    #[test]
    fn edited_document_matches_the_verbs_claim_direction() {
        for verb in [
            AgentNameVerb::Set,
            AgentNameVerb::Remove,
            AgentNameVerb::Enable,
            AgentNameVerb::Disable,
        ] {
            // Start from a document that already claims the name, so both
            // directions are a real change for at least one verb.
            let mut doc = json!({ "alsoKnownAs": ["https://example.com/@alice"] });
            edit_agent_name(&mut doc, "example.com", "alice", verb.claims_name());
            let claimed = doc
                .get("alsoKnownAs")
                .and_then(|v| v.as_array())
                .is_some_and(|l| l.iter().any(|v| is_agent_name(v, "example.com", "alice")));
            assert_eq!(
                claimed,
                verb.claims_name(),
                "{} must leave the document {} the name",
                verb.endpoint(),
                if verb.claims_name() {
                    "claiming"
                } else {
                    "not claiming"
                }
            );

            // …and from a document that does not claim it.
            let mut doc = json!({});
            edit_agent_name(&mut doc, "example.com", "alice", verb.claims_name());
            let claimed = doc
                .get("alsoKnownAs")
                .and_then(|v| v.as_array())
                .is_some_and(|l| l.iter().any(|v| is_agent_name(v, "example.com", "alice")));
            assert_eq!(claimed, verb.claims_name(), "{}", verb.endpoint());
        }
    }

    #[test]
    fn domain_parses_host_and_decodes_port() {
        assert_eq!(
            domain_from_webvh_did("did:webvh:QmScid:example.com:alice").as_deref(),
            Some("example.com")
        );
        // Percent-encoded port is decoded to match the form a name carries.
        assert_eq!(
            domain_from_webvh_did("did:webvh:QmScid:localhost%3A8534:staff:bob").as_deref(),
            Some("localhost:8534")
        );
        assert_eq!(domain_from_webvh_did("did:key:z6Mk").as_deref(), None);
        assert_eq!(domain_from_webvh_did("did:webvh:QmScid").as_deref(), None);
    }

    #[test]
    fn is_agent_name_matches_host_ci_local_exact() {
        let v = |s: &str| Value::String(s.to_string());
        assert!(is_agent_name(
            &v("https://example.com/@alice"),
            "example.com",
            "alice"
        ));
        // Scheme-less and host case-insensitive both match.
        assert!(is_agent_name(
            &v("example.com/@alice"),
            "EXAMPLE.com",
            "alice"
        ));
        // Local part is case-sensitive.
        assert!(!is_agent_name(
            &v("https://example.com/@Alice"),
            "example.com",
            "alice"
        ));
        // Wrong domain / not an agent name.
        assert!(!is_agent_name(
            &v("https://other.com/@alice"),
            "example.com",
            "alice"
        ));
        assert!(!is_agent_name(
            &v("did:web:example.com"),
            "example.com",
            "alice"
        ));
    }

    #[test]
    fn enable_adds_canonical_entry_idempotently() {
        let mut doc = json!({ "id": "did:webvh:x:example.com:me" });
        edit_agent_name(&mut doc, "example.com", "alice", true);
        assert_eq!(
            doc["alsoKnownAs"],
            json!(["https://example.com/@alice"]),
            "enable creates the array with the canonical entry"
        );
        // Idempotent: a second enable does not duplicate.
        edit_agent_name(&mut doc, "example.com", "alice", true);
        assert_eq!(doc["alsoKnownAs"], json!(["https://example.com/@alice"]));
    }

    #[test]
    fn enable_preserves_unrelated_also_known_as() {
        let mut doc = json!({ "alsoKnownAs": ["did:web:example.com", "https://example.com/@bob"] });
        edit_agent_name(&mut doc, "example.com", "alice", true);
        assert_eq!(
            doc["alsoKnownAs"],
            json!([
                "did:web:example.com",
                "https://example.com/@bob",
                "https://example.com/@alice"
            ])
        );
    }

    #[test]
    fn disable_removes_the_name_in_any_form_and_prunes_empty() {
        // A scheme-less stored form is still removed.
        let mut doc = json!({ "alsoKnownAs": ["example.com/@alice"] });
        edit_agent_name(&mut doc, "example.com", "alice", false);
        assert!(
            doc.get("alsoKnownAs").is_none(),
            "an emptied alsoKnownAs is dropped, not left as []"
        );

        // Only the target name goes; other entries stay.
        let mut doc = json!({
            "alsoKnownAs": ["https://example.com/@alice", "https://example.com/@bob", "did:web:x"]
        });
        edit_agent_name(&mut doc, "example.com", "alice", false);
        assert_eq!(
            doc["alsoKnownAs"],
            json!(["https://example.com/@bob", "did:web:x"])
        );
    }
}
