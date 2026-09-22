//! Offline state-assembly helpers.
//!
//! Read the VTA's local keystore / context / ACL / webvh state directly and
//! produce the same wire-shape bundles that the equivalent `VtaClient` flows
//! build over REST. Used by on-host `vta context reprovision` and
//! `vta keys bundle` CLIs — the cold-start / air-gapped case where PNM
//! cannot reach the VTA over the network.
//!
//! The output shapes (`DidSecretsBundle`, `ContextProvisionBundle`) are
//! identical to what `VtaClient::fetch_did_secrets_bundle` and
//! `vta_cli_common::commands::contexts::cmd_context_reprovision` produce,
//! so downstream `vta_cli_common::sealed_producer::emit_did_secrets_bundle` /
//! `emit_context_provision_bundle` seal + print them the same way.
//!
//! All functions here are pure reads — they do not mutate state. The only
//! write path used by the reprovision flow (creating an ACL entry for the
//! admin DID if none exists) is done via `super::acl::create_acl` in the
//! caller, kept out of this module so its boundaries stay "fetch state".

use std::sync::Arc;

use tracing::debug;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use crate::store::KeyspaceHandle;
use vta_sdk::context_provision::ContextProvisionBundle;
#[cfg(feature = "webvh")]
use vta_sdk::context_provision::ProvisionedDid;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry, select_secret_kid};
use vta_sdk::keys::KeyStatus;
use vti_common::acl::Capability;

/// Dependencies for the offline state-assembly helpers.
///
/// Borrowed from `AppState` (or built directly from a CLI-opened store)
/// so the caller doesn't have to thread eight keyspaces through every
/// signature.
pub struct ExportDeps<'a> {
    pub keys_ks: &'a KeyspaceHandle,
    pub contexts_ks: &'a KeyspaceHandle,
    pub imported_ks: &'a KeyspaceHandle,
    pub audit: &'a vta_audit::SharedAuditSink,
    pub acl_ks: &'a KeyspaceHandle,
    #[cfg(feature = "webvh")]
    pub webvh_ks: &'a KeyspaceHandle,
    pub seed_store: &'a Arc<dyn SeedStore>,
}

/// Every private key of `context_id`'s own DID, for the service that operates it.
///
/// # Why this exists as one operation
///
/// A service that the VTA holds an identity for has to hold that DID's private keys to
/// decrypt what is addressed to it — it cannot ask the VTA per frame. So it fetches them at
/// startup, in one call, with one authorization decision.
///
/// # `KeyExport`, and why a role floor was not enough (VTI-VTA-003)
///
/// This is an export: the keys leave the VTA and stay with the caller after its authority
/// is withdrawn. VTI-VTA-003 requires that such an export "MUST be gated by a capability
/// distinct from the capability to use the key, and MUST be audited". So the gate is
/// [`Capability::KeyExport`] — the same capability `keys/export-secret` requires — and not
/// the `Application` role floor this task used to have (#1625), which let any principal
/// that could *use* a context's keys also *take* them.
///
/// `KeyExport` is derived by `admin` alone (#1619), so the principal that operates a
/// context's DID is an administrator **scoped to that context** — which is what
/// `provision-integration` already mints for the mediator, did-hosting and the VTC. The gate
/// reads the caller's **entry**, so a narrowing that removes `key-export` from an admin stops
/// the very next fetch (the rule every capability gate follows since #1279).
///
/// Scope is still checked separately, and neither check is this function being careful —
/// both are checks the keys surface already makes:
///
/// - [`AuthClaims::require_context`], inside [`build_did_secrets_bundle`], on the context
///   asked for — so an admin of another context is refused before a single key is read,
///   and before the context is even looked up. The entitlement is a scope, not a rank;
/// - [`super::keys::get_key_secret`]'s own per-key context gate, and its per-key
///   `key.secret_export` audit record — the "MUST be audited" half of VTI-VTA-003.
///
/// The capability gate runs before either, and its answer does not depend on whether the
/// context exists, so a refused caller learns nothing about ids it may not reach.
///
/// # Why it delegates
///
/// [`build_did_secrets_bundle`] is the whole of the traversal, and the only thing that
/// differs between its two callers is the gate: the offline export path runs as a local
/// super-admin, while `vta/contexts/secrets/1.0` is reachable over the wire. A second
/// traversal here would be a second set of rules to keep in step — which key ids are
/// verification methods of the DID, which secrets are excluded, how the pages are walked —
/// and those rules are exactly the part that must not drift.
pub async fn get_context_secrets(
    deps: &ExportDeps<'_>,
    auth: &AuthClaims,
    context_id: &str,
    channel: &str,
) -> Result<DidSecretsBundle, AppError> {
    ensure_may_export(deps.acl_ks, auth).await?;
    let bundle = build_did_secrets_bundle(deps, auth, context_id, channel).await?;
    tracing::info!(
        channel,
        context = %context_id,
        did = %bundle.did,
        keys = bundle.secrets.len(),
        "context secrets released to the service that operates them"
    );
    Ok(bundle)
}

/// The `vta/contexts/secrets` gate: the caller must hold `KeyExport` (VTI-VTA-003).
///
/// Reads the caller's **entry**, as `ensure_may_mint` does for `KeyMint`, so a narrowing
/// binds the next call. With no entry the role decides; a store error refuses.
///
/// The refusal names the exact command that fixes it — the caller is usually a service
/// logging at boot, and the person reading that log is the one who has to run it.
async fn ensure_may_export(acl_ks: &KeyspaceHandle, auth: &AuthClaims) -> Result<(), AppError> {
    use vti_common::acl::{entry_has_capability, get_acl_entry, role_has_capability};

    let entry = match get_acl_entry(acl_ks, &auth.did).await {
        Ok(entry) => entry,
        // A store error must not become a grant.
        Err(e) => {
            tracing::error!(
                error = %e, did = %auth.did,
                "could not read the ACL entry for the KeyExport check; refusing"
            );
            return Err(AppError::Forbidden(format!(
                "vta/contexts/secrets denied: could not confirm that {} carries the \
                 key-export capability",
                auth.did
            )));
        }
    };
    let may_export = match &entry {
        Some(entry) => entry_has_capability(entry, Capability::KeyExport),
        None => role_has_capability(&auth.role, Capability::KeyExport),
    };
    if may_export {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "vta/contexts/secrets denied: {} does not carry the key-export capability. \
         Releasing a DID's private keys is an export, and VTI-VTA-003 gates export on a \
         capability distinct from using the key; only an admin derives it, so the service \
         operating a context's DID must be an admin scoped to that context. {}",
        auth.did,
        key_export_fix(entry.as_ref(), &auth.did)
    )))
}

/// The command an operator runs so `did` may fetch its context's secrets.
///
/// Built from the caller's stored entry, because the right command depends on it:
///
/// - **no entry** — create one, as an admin of the context;
/// - **a non-admin with a context scope** — `change-role` to admin, which keeps the scope
///   (and, like any admin grant, confers the rest of what an admin of that context holds);
/// - **a non-admin with no context** — scope it first: promoting an entry with no contexts
///   would make it a *super*-admin, so that is never suggested;
/// - **an admin narrowed without `key-export`** — re-state the narrowing with `key-export`
///   added, rather than suggesting `--capabilities-all`, which would also undo whatever
///   else the narrowing deliberately removed.
fn key_export_fix(entry: Option<&vti_common::acl::AclEntry>, did: &str) -> String {
    use vta_sdk::acl::ActScope;

    let Some(entry) = entry else {
        return format!(
            "Grant it with: pnm acl create --did {did} --role admin --contexts <CONTEXT>"
        );
    };
    if entry.role != crate::acl::Role::Admin {
        let promote = format!(
            "pnm acl change-role --did {did} --from {} --to admin",
            entry.role
        );
        let narrowed = restated_narrowing(entry);
        return match (entry.act_scope(), narrowed) {
            (ActScope::Contexts(_), None) => format!("Grant it with: {promote}"),
            (ActScope::Contexts(_), Some(caps)) => {
                format!("Grant it with: {promote} && pnm acl update {did} --capabilities {caps}")
            }
            // Authorized nowhere (or, defensively, anything else): scope first.
            _ => format!(
                "Scope it to the context first, then promote it: \
                 pnm acl update {did} --contexts <CONTEXT> && {promote}"
            ),
        };
    }
    match restated_narrowing(entry) {
        Some(caps) => format!("Grant it with: pnm acl update {did} --capabilities {caps}"),
        // An un-narrowed admin derives `KeyExport`, so reaching here means something other
        // than the narrowing withheld it — say what to look at rather than guess a command.
        None => format!("Inspect the entry with: pnm acl get {did}"),
    }
}

/// The entry's stored capability list with `key-export` added, as the comma-separated
/// value `pnm acl update --capabilities` takes — or `None` when the entry is not narrowed.
///
/// `--capabilities` *replaces* the list, so the command has to carry every name already
/// there; a bare `--capabilities key-export` would narrow an admin to that one power.
fn restated_narrowing(entry: &vti_common::acl::AclEntry) -> Option<String> {
    if entry.capabilities.is_empty() {
        return None;
    }
    let name = |c: &Capability| {
        serde_json::to_value(c)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
    };
    let mut names: Vec<String> = entry.capabilities.iter().filter_map(name).collect();
    if let Some(key_export) = name(&Capability::KeyExport)
        && !names.contains(&key_export)
    {
        names.push(key_export);
    }
    Some(names.join(","))
}

/// Build a [`DidSecretsBundle`] for `context_id` by enumerating active
/// keys in the local store and loading each secret.
///
/// Mirrors [`vta_sdk::client::VtaClient::fetch_did_secrets_bundle`] —
/// same traversal (context → active keys → secret per key), same kid
/// selection via [`vta_sdk::did_secrets::select_secret_kid`]. Secrets
/// that aren't verification methods of the context DID (admin `did:key`
/// rolled into the same context, free-text-labelled records) are
/// excluded; including them would corrupt the operating-secret set the
/// mediator matches inbound JWE recipients against.
pub async fn build_did_secrets_bundle(
    deps: &ExportDeps<'_>,
    auth: &AuthClaims,
    context_id: &str,
    channel: &str,
) -> Result<DidSecretsBundle, AppError> {
    auth.require_context(context_id)?;

    let ctx = crate::contexts::get_context(deps.contexts_ks, context_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {context_id}")))?;
    let did = ctx.did.clone().ok_or_else(|| {
        AppError::Validation(format!("context '{context_id}' has no DID assigned"))
    })?;

    // Page through active keys in the context. `list_keys` already
    // applies context-access gating based on `auth`; we only traverse
    // what the caller is allowed to see.
    let mut secrets = Vec::new();
    let page_size = 100u64;
    let mut offset = 0u64;
    loop {
        let page = super::keys::list_keys(
            deps.keys_ks,
            auth,
            super::keys::ListKeysParams {
                offset: Some(offset),
                limit: Some(page_size),
                status: Some(KeyStatus::Active),
                context_id: Some(context_id.to_string()),
            },
            channel,
        )
        .await?;
        if page.keys.is_empty() {
            break;
        }
        for key in &page.keys {
            let secret = super::keys::get_key_secret(
                deps.keys_ks,
                deps.imported_ks,
                deps.seed_store,
                deps.audit,
                auth,
                &key.key_id,
                channel,
            )
            .await?;
            // The kid a mediator matches inbound JWE recipients against MUST be
            // a verification-method id of *this* context's DID. Resolve it from
            // the authoritative store key_id (falling back to the label only
            // when the label is itself a strict VM id); drop anything that
            // isn't a VM id of `did`. Identical contract to the online
            // `VtaClient::fetch_did_secrets_bundle` — shared helper.
            match select_secret_kid(&did, &secret.key_id, key.label.as_deref()) {
                Some(key_id) => secrets.push(SecretEntry {
                    key_id,
                    key_type: secret.key_type,
                    private_key_multibase: secret.private_key_multibase,
                }),
                None => {
                    debug!(
                        channel,
                        %context_id,
                        %did,
                        key_id = %secret.key_id,
                        label = key.label.as_deref().unwrap_or(""),
                        "excluding secret from did-secrets bundle: not a verification \
                         method of the context DID (e.g. an admin did:key minted into \
                         this context, or a free-text-labelled key). Including it would \
                         corrupt the DIDComm operating-secret set and break the \
                         mediator's exact-match recipient lookup."
                    );
                }
            }
        }
        offset += page.keys.len() as u64;
        if offset >= page.total {
            break;
        }
    }

    debug!(channel, %context_id, %did, secret_count = secrets.len(), "built did-secrets bundle from local store");
    Ok(DidSecretsBundle { did, secrets })
}

/// Derive an admin [`CredentialBundle`] from an existing key in the
/// store. The key's private seed is loaded; the bundle + derived
/// `did:key` come from the shared
/// [`CredentialBundle::from_ed25519_seed_multibase`] helper so this
/// and the online path in
/// `vta-cli-common::commands::contexts::credential_from_key` can't
/// drift in their encoding choices.
///
/// Returns `(credential, admin_did)` where `admin_did` is the derived
/// `did:key:z6Mk...` string.
pub async fn credential_from_key_offline(
    deps: &ExportDeps<'_>,
    auth: &AuthClaims,
    key_id: &str,
    vta_did: &str,
    vta_url: Option<&str>,
    channel: &str,
) -> Result<(CredentialBundle, String), AppError> {
    let secret = super::keys::get_key_secret(
        deps.keys_ks,
        deps.imported_ks,
        deps.seed_store,
        deps.audit,
        auth,
        key_id,
        channel,
    )
    .await?;
    CredentialBundle::from_ed25519_seed_multibase(&secret.private_key_multibase, vta_did, vta_url)
        .map_err(|e| AppError::Internal(format!("decode admin key secret: {e}")))
}

/// Inputs to [`build_context_provision_bundle`].
///
/// `key_id` names the existing key whose seed backs the exported admin
/// credential. The CLI caller is responsible for resolving it (explicit
/// `--key` flag, interactive prompt, or single-key auto-select) before
/// calling this function — the library stays UI-agnostic.
pub struct ContextReprovisionInputs {
    pub context_id: String,
    pub key_id: String,
}

/// Build a [`ContextProvisionBundle`] for an existing context.
///
/// Mirrors the online `cmd_context_reprovision` flow (minus the
/// interactive prompt): fetch context, build credential from the named
/// key, fetch the DID log + secrets when the context has a DID, stitch
/// together the bundle. The caller must separately ensure an ACL entry
/// exists for the derived `admin_did` via `super::acl::create_acl` when
/// the bundle is about to be sealed for a new admin.
///
/// `vta_did` and `vta_url` come from the caller's `AppConfig` — they
/// are metadata woven into the bundle so the consumer can reconnect
/// over REST/DIDComm after installing.
pub async fn build_context_provision_bundle(
    deps: &ExportDeps<'_>,
    auth: &AuthClaims,
    inputs: ContextReprovisionInputs,
    vta_did: &str,
    vta_url: Option<&str>,
    channel: &str,
) -> Result<ContextProvisionBundle, AppError> {
    let ContextReprovisionInputs { context_id, key_id } = inputs;
    auth.require_context(&context_id)?;

    let ctx = crate::contexts::get_context(deps.contexts_ks, &context_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {context_id}")))?;

    let (credential, admin_did) =
        credential_from_key_offline(deps, auth, &key_id, vta_did, vta_url, channel).await?;

    // Gather DID material when the context has a DID registered.
    #[cfg(feature = "webvh")]
    let provisioned_did = match ctx.did.as_deref() {
        Some(did_id) => {
            Some(fetch_did_material_offline(deps, auth, did_id, &context_id, channel).await?)
        }
        None => None,
    };
    #[cfg(not(feature = "webvh"))]
    let provisioned_did = None;

    Ok(ContextProvisionBundle {
        context_id,
        context_name: ctx.name,
        vta_url: vta_url.map(String::from),
        vta_did: Some(vta_did.to_string()),
        credential,
        admin_did,
        did: provisioned_did,
    })
}

/// Load the DID document + log entry + all active-key secrets for a
/// DID that is registered in a context. Used by
/// [`build_context_provision_bundle`] when the context has a DID.
///
/// The key secrets come from [`build_did_secrets_bundle`] applied to
/// the same context, ensuring exact parity with the online path.
#[cfg(feature = "webvh")]
async fn fetch_did_material_offline(
    deps: &ExportDeps<'_>,
    auth: &AuthClaims,
    did: &str,
    context_id: &str,
    channel: &str,
) -> Result<ProvisionedDid, AppError> {
    // Fetch the raw did.jsonl log from the local webvh store. `get_did_webvh`
    // with `include_log` returns a record whose `log` field holds the
    // serialized log string; parse it to extract the latest document
    // state.
    let log_result =
        super::did_webvh::get_did_webvh(deps.webvh_ks, auth, did, channel, true).await?;
    let log_entry = log_result.log;
    let did_document = log_entry
        .as_deref()
        .and_then(|log_str| serde_json::from_str::<serde_json::Value>(log_str).ok())
        .and_then(|v| v.get("state").cloned());

    let secrets_bundle = build_did_secrets_bundle(deps, auth, context_id, channel).await?;
    Ok(ProvisionedDid {
        id: did.to_string(),
        did_document,
        log_entry,
        secrets: secrets_bundle.secrets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::keys::seed_store::PlaintextSeedStore;
    use crate::store::{KeyspaceHandle, Store};
    use std::path::PathBuf;

    struct TestEnv {
        _dir: tempfile::TempDir,
        _store: Store,
        contexts_ks: KeyspaceHandle,
        keys_ks: KeyspaceHandle,
        imported_ks: KeyspaceHandle,
        audit: vta_audit::SharedAuditSink,
        acl_ks: KeyspaceHandle,
        #[cfg(feature = "webvh")]
        webvh_ks: KeyspaceHandle,
        seed_store: Arc<dyn SeedStore>,
        data_dir: PathBuf,
    }

    async fn open_env() -> TestEnv {
        let dir = tempfile::tempdir().expect("temp dir");
        let data_dir = dir.path().to_path_buf();
        let store = Store::open(&StoreConfig {
            data_dir: data_dir.clone(),
        })
        .expect("open store");
        TestEnv {
            contexts_ks: store.keyspace(crate::keyspaces::CONTEXTS).unwrap(),
            keys_ks: store.keyspace(crate::keyspaces::KEYS).unwrap(),
            imported_ks: store.keyspace(crate::keyspaces::IMPORTED_SECRETS).unwrap(),
            audit: vta_audit::shared_keyspace_sink(
                store.keyspace(crate::keyspaces::AUDIT).unwrap(),
            ),
            acl_ks: store.keyspace(crate::keyspaces::ACL).unwrap(),
            #[cfg(feature = "webvh")]
            webvh_ks: store.keyspace(crate::keyspaces::WEBVH).unwrap(),
            seed_store: Arc::new(PlaintextSeedStore::new(&data_dir)),
            _dir: dir,
            _store: store,
            data_dir,
        }
    }

    fn deps_of(env: &TestEnv) -> ExportDeps<'_> {
        ExportDeps {
            keys_ks: &env.keys_ks,
            contexts_ks: &env.contexts_ks,
            imported_ks: &env.imported_ks,
            audit: &env.audit,
            acl_ks: &env.acl_ks,
            #[cfg(feature = "webvh")]
            webvh_ks: &env.webvh_ks,
            seed_store: &env.seed_store,
        }
    }

    fn super_admin() -> AuthClaims {
        AuthClaims {
            did: "did:key:zTestCli".into(),
            role: crate::acl::Role::Admin,
            allowed_contexts: Vec::new(),
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    /// A caller with a role and a set of contexts it may act in.
    ///
    /// The pair is the whole of the authorization model this task turns on:
    /// `role` is the floor and `allowed_contexts` is the scope, and a non-empty
    /// scope narrows even [`Role::Admin`] (only an *empty* list means "all").
    fn scoped(role: crate::acl::Role, contexts: &[&str]) -> AuthClaims {
        AuthClaims {
            did: "did:key:zTestCaller".into(),
            role,
            allowed_contexts: contexts.iter().map(|c| (*c).to_string()).collect(),
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    #[tokio::test]
    async fn build_did_secrets_rejects_missing_context() {
        let env = open_env().await;
        let auth = super_admin();
        let err = build_did_secrets_bundle(&deps_of(&env), &auth, "nope", "test")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got: {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("nope"), "got: {msg}");
    }

    #[tokio::test]
    async fn build_did_secrets_rejects_context_without_did() {
        let env = open_env().await;
        let auth = super_admin();
        // Create a context but leave its DID field unset.
        crate::contexts::create_context(&env.contexts_ks, "no-did", "No DID Ctx")
            .await
            .expect("create context");

        let err = build_did_secrets_bundle(&deps_of(&env), &auth, "no-did", "test")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
        assert!(err.to_string().contains("no DID assigned"));
    }

    #[tokio::test]
    async fn build_context_provision_requires_existing_context() {
        let env = open_env().await;
        let auth = super_admin();
        let err = build_context_provision_bundle(
            &deps_of(&env),
            &auth,
            ContextReprovisionInputs {
                context_id: "missing".into(),
                key_id: "did:key:zFake#zFake".into(),
            },
            "did:key:zVta",
            None,
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got: {err:?}");
        assert!(err.to_string().contains("missing"));
    }

    // Keep this warning silenced: `data_dir` is only read in the
    // happy-path test hooks that land once a seed-bootstrap helper is
    // available to the test module.
    #[allow(dead_code)]
    fn _unused_data_dir(env: &TestEnv) -> &PathBuf {
        &env.data_dir
    }

    /// The DID a seeded context is given. Every operating key below is a
    /// verification method of it.
    const SEEDED_DID: &str = "did:webvh:QmScid:mediator.example.com:med";

    /// Stand up one context holding the three key records the bundle logic has
    /// to tell apart: two operating keys whose ids ARE verification methods of
    /// [`SEEDED_DID`], and an admin `did:key` minted into the same context whose
    /// VM id belongs to a *different* DID and whose label is free text.
    ///
    /// Shared by the kid-selection test and the authorization tests so the two
    /// cannot disagree about what a correctly-populated context looks like.
    async fn seed_context_with_keys(env: &TestEnv, context_id: &str) -> String {
        use crate::keys::paths::allocate_path;
        use crate::keys::{KeyRecord, store_key};
        use chrono::Utc;
        use vta_sdk::keys::{KeyOrigin, KeyStatus, KeyType};

        // Seed the external store so derived keys can be minted + read back.
        env.seed_store
            .set(&[0xABu8; 32])
            .await
            .expect("seed the store");

        crate::contexts::create_context(&env.contexts_ks, context_id, "Mediator Ctx")
            .await
            .expect("create context");
        let mut rec = crate::contexts::get_context(&env.contexts_ks, context_id)
            .await
            .expect("get context")
            .expect("context exists");
        rec.did = Some(SEEDED_DID.to_string());
        crate::contexts::store_context(&env.contexts_ks, &rec)
            .await
            .expect("store did on context");

        // Mint a key record the way internal DID provisioning does: an
        // allocated path + a directly-written KeyRecord. VM-shaped key_ids are
        // exclusive to this internal path — the public create_key/import_key ops
        // reject them at validation. The stored public_key is not consulted by
        // the bundle (secrets are re-derived from the path), so a placeholder is
        // fine here.
        async fn mint_internal(
            env: &TestEnv,
            context_id: &str,
            base_path: &str,
            kid: &str,
            kt: KeyType,
            label: Option<&str>,
        ) {
            let path = allocate_path(&env.keys_ks, base_path)
                .await
                .expect("allocate path");
            let now = Utc::now();
            let record = KeyRecord {
                exportable: None,
                key_id: kid.to_string(),
                derivation_path: path,
                key_type: kt,
                status: KeyStatus::Active,
                public_key: "zPlaceholderNotUnderTest".into(),
                label: label.map(String::from),
                context_id: Some(context_id.to_string()),
                seed_id: None,
                origin: KeyOrigin::Derived,
                created_at: now,
                updated_at: now,
            };
            env.keys_ks
                .insert(store_key(kid), &record)
                .await
                .expect("store key record");
        }

        for (suffix, kt) in [("#key-0", KeyType::Ed25519), ("#key-1", KeyType::X25519)] {
            mint_internal(
                env,
                context_id,
                &rec.base_path,
                &format!("{SEEDED_DID}{suffix}"),
                kt,
                None,
            )
            .await;
        }
        mint_internal(
            env,
            context_id,
            &rec.base_path,
            &format!("{ADMIN_DID_KEY}#z6Mkt6eNM38RhFfjSdmXBtT1SRL7sPgPZD1MkXZbwjYBhTLf"),
            KeyType::Ed25519,
            Some("admin DID for context med-ctx"),
        )
        .await;

        SEEDED_DID.to_string()
    }

    /// An admin `did:key` that gets minted into a service context in practice.
    /// Not a verification method of [`SEEDED_DID`], so it belongs in no bundle.
    const ADMIN_DID_KEY: &str = "did:key:z6Mkt6eNM38RhFfjSdmXBtT1SRL7sPgPZD1MkXZbwjYBhTLf";

    /// Happy-path coverage for the kid-selection contract: the offline
    /// bundle must carry exactly the keys whose ids are verification
    /// methods of the context DID, and must drop an admin `did:key`
    /// minted into the same context (a different DID, free-text label).
    ///
    /// Locks the wiring of [`select_secret_kid`] into the offline path —
    /// the per-decision rules are unit-tested in
    /// `vta_sdk::did_secrets`, but this proves `build_did_secrets_bundle`
    /// feeds it the authoritative store `key_id` (and the label) so a
    /// refactor can't silently re-include non-VM secrets and re-brick the
    /// mediator's exact-match recipient lookup (the storm.ws outage).
    #[tokio::test]
    async fn build_did_secrets_excludes_non_vm_admin_did_key() {
        let env = open_env().await;
        let did = seed_context_with_keys(&env, "med-ctx").await;

        let bundle = build_did_secrets_bundle(&deps_of(&env), &super_admin(), "med-ctx", "test")
            .await
            .expect("bundle builds");

        assert_eq!(bundle.did, did);
        let expect_0 = format!("{did}#key-0");
        let expect_1 = format!("{did}#key-1");
        let mut kids: Vec<&str> = bundle.secrets.iter().map(|s| s.key_id.as_str()).collect();
        kids.sort_unstable();
        assert_eq!(
            kids,
            vec![expect_0.as_str(), expect_1.as_str()],
            "only the two VM-id operating keys belong in the bundle; the admin \
             did:key minted into the context must be excluded"
        );
        assert!(
            !bundle
                .secrets
                .iter()
                .any(|s| s.key_id.contains(ADMIN_DID_KEY)),
            "admin did:key must not appear in the operating-secret bundle"
        );
    }

    // ---------------------------------------------------------------------
    // `get_context_secrets` — the Trust Task path.
    //
    // VTI-VTA-003: releasing a DID's private keys is an export, gated on
    // `KeyExport` (derived by admin alone) read from the caller's entry, and
    // bounded by scope. These tests used to assert the opposite — that an
    // `Application` could take the keys (#1625) — and are written so that
    // restoring the old role floor fails them.
    // ---------------------------------------------------------------------

    /// Store an entry for [`scoped`]'s caller so the gate reads it, as it does
    /// for every live caller.
    async fn store_caller(
        env: &TestEnv,
        role: crate::acl::Role,
        contexts: &[&str],
        capabilities: Vec<Capability>,
    ) -> AuthClaims {
        let auth = scoped(role.clone(), contexts);
        vti_common::acl::store_acl_entry(
            &env.acl_ks,
            &crate::acl::AclEntry::new(&auth.did, role, "did:key:zRoot")
                .with_contexts(auth.allowed_contexts.clone())
                .with_capabilities(capabilities),
        )
        .await
        .expect("store the caller's entry");
        auth
    }

    fn forbidden_message(err: AppError) -> String {
        match err {
            AppError::Forbidden(m) => m,
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    /// The operator of a context's DID is an admin scoped to that context — what
    /// `provision-integration` mints — and it gets the context DID's operating
    /// keys, and only those.
    #[tokio::test]
    async fn vti_vta_003_a_context_admin_fetches_its_own_contexts_secrets() {
        let env = open_env().await;
        let did = seed_context_with_keys(&env, "med-ctx").await;
        let auth = store_caller(&env, crate::acl::Role::Admin, &["med-ctx"], vec![]).await;

        let bundle = get_context_secrets(&deps_of(&env), &auth, "med-ctx", "test")
            .await
            .expect("a context admin derives KeyExport");

        assert_eq!(bundle.did, did);
        let mut kids: Vec<&str> = bundle.secrets.iter().map(|s| s.key_id.as_str()).collect();
        kids.sort_unstable();
        assert_eq!(kids, vec![format!("{did}#key-0"), format!("{did}#key-1")]);
    }

    /// #1625: an `Application` in this very context may *use* its keys through
    /// the oracle, and must not thereby take them. The refusal names the fix.
    #[tokio::test]
    async fn vti_vta_003_an_application_in_the_context_is_refused() {
        let env = open_env().await;
        seed_context_with_keys(&env, "med-ctx").await;
        let auth = store_caller(&env, crate::acl::Role::Application, &["med-ctx"], vec![]).await;

        let msg = forbidden_message(
            get_context_secrets(&deps_of(&env), &auth, "med-ctx", "test")
                .await
                .expect_err("Application does not carry KeyExport"),
        );
        assert!(msg.contains("key-export"), "{msg}");
        assert!(
            msg.contains(&format!(
                "pnm acl change-role --did {} --from application --to admin",
                auth.did
            )),
            "the refusal must print the exact fix: {msg}"
        );
    }

    /// An `Initiator` holds `Sign` and `KeyMint`, and #1619 deliberately withheld
    /// `KeyExport` from it. This path must not be the way round that.
    #[tokio::test]
    async fn vti_vta_003_an_initiator_in_the_context_is_refused() {
        let env = open_env().await;
        seed_context_with_keys(&env, "med-ctx").await;
        let auth = store_caller(&env, crate::acl::Role::Initiator, &["med-ctx"], vec![]).await;

        let msg = forbidden_message(
            get_context_secrets(&deps_of(&env), &auth, "med-ctx", "test")
                .await
                .expect_err("Initiator does not carry KeyExport"),
        );
        assert!(msg.contains("--from initiator --to admin"), "{msg}");
    }

    /// The entry is read, so an admin narrowed without `key-export` is refused on
    /// the next call — which a role check would have let through. The fix
    /// restates the narrowing rather than suggesting `--capabilities-all`.
    #[tokio::test]
    async fn vti_vta_003_an_admin_narrowed_without_key_export_is_refused() {
        let env = open_env().await;
        seed_context_with_keys(&env, "med-ctx").await;
        let auth = store_caller(
            &env,
            crate::acl::Role::Admin,
            &["med-ctx"],
            vec![Capability::Sign, Capability::KeyMint],
        )
        .await;

        let msg = forbidden_message(
            get_context_secrets(&deps_of(&env), &auth, "med-ctx", "test")
                .await
                .expect_err("narrowed away, KeyExport is gone"),
        );
        assert!(
            msg.contains(&format!(
                "pnm acl update {} --capabilities sign,key-mint,key-export",
                auth.did
            )),
            "{msg}"
        );
    }

    /// Scope, not rank. An admin holds `KeyExport`, and it still reaches nothing
    /// outside its `allowed_contexts` — only an *empty* list means "all".
    #[tokio::test]
    async fn vti_vta_003_an_admin_of_another_context_is_refused() {
        let env = open_env().await;
        seed_context_with_keys(&env, "med-ctx").await;
        let auth = store_caller(&env, crate::acl::Role::Admin, &["some-other-ctx"], vec![]).await;

        let err = get_context_secrets(&deps_of(&env), &auth, "med-ctx", "test")
            .await
            .expect_err("admin of another context is still not this context's service");
        assert!(matches!(err, AppError::Forbidden(_)), "got: {err:?}");
    }

    /// A non-admin authorized in no context must never be told to promote
    /// itself as it stands: that would mint a super-admin.
    #[tokio::test]
    async fn vti_vta_003_an_unscoped_non_admin_is_told_to_scope_first() {
        let env = open_env().await;
        seed_context_with_keys(&env, "med-ctx").await;
        let auth = store_caller(&env, crate::acl::Role::Application, &[], vec![]).await;

        let msg = forbidden_message(
            get_context_secrets(&deps_of(&env), &auth, "med-ctx", "test")
                .await
                .expect_err("no KeyExport"),
        );
        assert!(
            msg.contains(&format!(
                "pnm acl update {} --contexts <CONTEXT> &&",
                auth.did
            )),
            "{msg}"
        );
    }

    /// A reader is refused too — the gate replaced the role floor, and a reader
    /// derives no `KeyExport`.
    #[tokio::test]
    async fn vti_vta_003_a_reader_of_this_very_context_is_refused() {
        let env = open_env().await;
        seed_context_with_keys(&env, "med-ctx").await;
        let auth = store_caller(&env, crate::acl::Role::Reader, &["med-ctx"], vec![]).await;

        let err = get_context_secrets(&deps_of(&env), &auth, "med-ctx", "test")
            .await
            .expect_err("a reader may see that keys exist, never hold one");
        assert!(matches!(err, AppError::Forbidden(_)), "got: {err:?}");
    }

    /// The non-leak claim the spec makes about `notFound`: entitlement is
    /// checked before existence, so a caller who is not entitled to an id gets
    /// the *same* refusal whether or not that id exists. Holds for both gates.
    #[tokio::test]
    async fn entitlement_is_checked_before_existence() {
        let env = open_env().await;
        seed_context_with_keys(&env, "med-ctx").await;
        for (role, ctx) in [
            (crate::acl::Role::Admin, "some-other-ctx"),
            (crate::acl::Role::Application, "med-ctx"),
        ] {
            let auth = store_caller(&env, role, &[ctx], vec![]).await;
            let real = get_context_secrets(&deps_of(&env), &auth, "med-ctx", "test")
                .await
                .expect_err("exists, not yours");
            let imaginary = get_context_secrets(&deps_of(&env), &auth, "no-such-ctx", "test")
                .await
                .expect_err("does not exist, and not yours either");

            assert!(matches!(real, AppError::Forbidden(_)), "got: {real:?}");
            assert!(
                matches!(imaginary, AppError::Forbidden(_)),
                "an id that does not exist must not be distinguishable from one that \
                 does but is not the caller's — got: {imaginary:?}"
            );
            assert_eq!(
                real.to_string().replace("med-ctx", "<id>"),
                imaginary.to_string().replace("no-such-ctx", "<id>"),
                "the two refusals must differ only in the id echoed back"
            );
        }
    }
}
