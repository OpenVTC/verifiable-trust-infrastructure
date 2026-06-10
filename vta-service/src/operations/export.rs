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

/// Dependencies for the offline state-assembly helpers.
///
/// Borrowed from `AppState` (or built directly from a CLI-opened store)
/// so the caller doesn't have to thread eight keyspaces through every
/// signature.
pub struct ExportDeps<'a> {
    pub keys_ks: &'a KeyspaceHandle,
    pub contexts_ks: &'a KeyspaceHandle,
    pub imported_ks: &'a KeyspaceHandle,
    pub audit_ks: &'a KeyspaceHandle,
    pub acl_ks: &'a KeyspaceHandle,
    #[cfg(feature = "webvh")]
    pub webvh_ks: &'a KeyspaceHandle,
    pub seed_store: &'a Arc<dyn SeedStore>,
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
                deps.audit_ks,
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
        deps.audit_ks,
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
    // Fetch the raw did.jsonl log from local webvh store. `get_did_webvh_log`
    // returns a `GetDidWebvhLogResult` whose `log` field holds the
    // serialized log string; parse it to extract the latest document
    // state.
    let log_result = super::did_webvh::get_did_webvh_log(deps.webvh_ks, auth, did, channel).await?;
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
        audit_ks: KeyspaceHandle,
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
            contexts_ks: store.keyspace("contexts").unwrap(),
            keys_ks: store.keyspace("keys").unwrap(),
            imported_ks: store.keyspace("imported").unwrap(),
            audit_ks: store.keyspace("audit").unwrap(),
            acl_ks: store.keyspace("acl").unwrap(),
            #[cfg(feature = "webvh")]
            webvh_ks: store.keyspace("webvh").unwrap(),
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
            audit_ks: &env.audit_ks,
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
        use crate::operations::keys::{CreateKeyParams, create_key};
        use vta_sdk::keys::KeyType;

        let env = open_env().await;
        let auth = super_admin();

        // Seed the external store so derived keys can be minted + read back.
        env.seed_store
            .set(&[0xABu8; 32])
            .await
            .expect("seed the store");

        // A context with a DID assigned — the bundle is keyed on it and VM
        // ids are matched against it.
        let did = "did:webvh:QmScid:mediator.example.com:med";
        crate::contexts::create_context(&env.contexts_ks, "med-ctx", "Mediator Ctx")
            .await
            .expect("create context");
        let mut rec = crate::contexts::get_context(&env.contexts_ks, "med-ctx")
            .await
            .expect("get context")
            .expect("context exists");
        rec.did = Some(did.to_string());
        crate::contexts::store_context(&env.contexts_ks, &rec)
            .await
            .expect("store did on context");

        // Two operating keys whose key_ids ARE verification methods of `did`.
        for (kid, kt) in [
            (format!("{did}#key-0"), KeyType::Ed25519),
            (format!("{did}#key-1"), KeyType::X25519),
        ] {
            create_key(
                &env.keys_ks,
                &env.contexts_ks,
                &env.seed_store,
                &env.audit_ks,
                &auth,
                CreateKeyParams {
                    key_type: kt,
                    derivation_path: None,
                    key_id: Some(kid),
                    mnemonic: None,
                    label: None,
                    context_id: Some("med-ctx".into()),
                },
                "test",
            )
            .await
            .expect("mint operating key");
        }

        // An admin did:key minted into the same context: its VM id belongs
        // to a *different* DID and its label is free text. Must be excluded.
        let admin = "did:key:z6Mkt6eNM38RhFfjSdmXBtT1SRL7sPgPZD1MkXZbwjYBhTLf";
        create_key(
            &env.keys_ks,
            &env.contexts_ks,
            &env.seed_store,
            &env.audit_ks,
            &auth,
            CreateKeyParams {
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some(format!(
                    "{admin}#z6Mkt6eNM38RhFfjSdmXBtT1SRL7sPgPZD1MkXZbwjYBhTLf"
                )),
                mnemonic: None,
                label: Some("admin DID for context med-ctx".into()),
                context_id: Some("med-ctx".into()),
            },
            "test",
        )
        .await
        .expect("mint admin did:key");

        let bundle = build_did_secrets_bundle(&deps_of(&env), &auth, "med-ctx", "test")
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
            !bundle.secrets.iter().any(|s| s.key_id.contains(admin)),
            "admin did:key must not appear in the operating-secret bundle"
        );
    }
}
