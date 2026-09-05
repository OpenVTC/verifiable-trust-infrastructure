pub mod acl;
/// Versioned, namespaced application state. Backs the
/// `vta/app-state/{get,put,list,delete,get-many,put-many}/1.0` Trust Tasks.
/// Records are keyed `app:<contextId>:<namespace>:<key>` in the
/// [`APP_STATE`](crate::keyspaces::APP_STATE) keyspace, alongside an `appv:`
/// version index and an `appc:` per-namespace write counter. Deliberately not
/// [`memory`] — clearing an agent's memory must stay safe, which it cannot be
/// if account state lives there.
pub mod app_state;
#[cfg(feature = "tee")]
pub mod attestation;
pub mod audit;
/// Backup/restore export/import operations, extracted to the `vta-backup`
/// crate and re-exported so every `crate::operations::backup::…` path is
/// unchanged. The `AppState`-borrowing constructor and the TEE re-encryption
/// glue stay here (see `descriptor_deps_from_app_state` /
/// `VtaBootstrapReEncryptor` below) because they know `vta-service` types.
pub use vta_backup::ops as backup;
pub mod cache;
pub mod config;
pub mod contexts;
pub mod credential_exchange;
pub mod credentials;
pub mod device;
pub mod did_peer;
pub mod did_templates;
#[cfg(feature = "webvh")]
pub mod did_webvh;
/// Offline state-assembly helpers: read the VTA's local store and
/// produce the same wire-shape bundles (`DidSecretsBundle`,
/// `ContextProvisionBundle`) that the equivalent `VtaClient` flows
/// build over REST. Used by the on-host `vta context reprovision` /
/// `vta keys bundle` CLIs for cold-start environments where PNM can't
/// reach the VTA over the network.
pub mod export;
/// ACL-gated holder-key resolution for credential presentation — derive the
/// VTA-managed subject key (kb-jwt signer + consent secret), refusing keys
/// outside the caller's authorised context.
pub mod holder_keys;
pub mod internal_authority;
pub mod keys;
/// Per-context key/value store for AI-agent memory. Backs the
/// `vta/memory/{put,list,delete}/0.1` Trust Tasks. Entries are keyed
/// `mem:<contextId>:<key>` in the [`MEMORY`](crate::keyspaces::MEMORY) keyspace;
/// `list` is a `mem:<contextId>:` prefix scan.
pub mod memory;
/// Passkey login — DID-VM-resolved WebAuthn assertion verification.
/// Drives `vta/auth/passkey-login-{start,finish}/1.0` trust-tasks.
/// Distinct from [`passkey_vms`] which handles VM *enrolment*.
pub mod passkey_login;
/// Passkey-as-verificationMethod enrolment. Lets a browser wallet
/// (`pnm-browser-plugin`) add a WebAuthn passkey as a Multikey VM
/// (purpose `authentication`) on a VTA-managed webvh DID. See
/// `docs/02-vta/passkey-verification-methods.md`.
#[cfg(feature = "webvh")]
pub mod passkey_vms;
/// Runtime Policy Decision Point management (`policy/*`).
pub mod policy;
/// DIDComm protocol management: enable/disable/migrate operations that
/// patch the VTA's own DID document service array. See
/// `docs/05-design-notes/didcomm-protocol-management.md`.
#[cfg(feature = "webvh")]
pub mod protocol;
/// Generic template-driven integration bootstrap. See
/// `docs/02-vta/provision-integration.md`. Feature-gated on `webvh`
/// because the phase-1 implementation delegates minting to
/// `create_did_webvh`.
#[cfg(feature = "webvh")]
pub mod provision_integration;
pub mod room_groups;
pub mod room_invitation;
pub mod room_oracle;
pub mod seeds;
pub mod step_up_approval;
pub mod vault;

/// Shared keyspace handles passed to operations that need multiple keyspaces.
/// The struct itself lives in `vta-keyspaces` (a pure field bundle with no
/// `vta-service` dependency); the `AppState` / `VtaState` constructors stay
/// here as free functions because they know those concrete state types.
pub use vta_keyspaces::Keyspaces;

/// Borrow keyspaces from an `AppState`.
pub fn keyspaces_from_app_state(s: &crate::server::AppState) -> Keyspaces<'_> {
    Keyspaces {
        keys: &s.keys_ks,
        acl: &s.acl_ks,
        contexts: &s.contexts_ks,
        did_templates: &s.did_templates_ks,
        audit: &s.audit_ks,
        imported: &s.imported_ks,
        #[cfg(feature = "webvh")]
        webvh: &s.webvh_ks,
    }
}

/// Borrow keyspaces from a `VtaState` (DIDComm handlers).
#[cfg(feature = "didcomm")]
pub fn keyspaces_from_vta_state(s: &crate::messaging::router::VtaState) -> Keyspaces<'_> {
    Keyspaces {
        keys: &s.keys_ks,
        acl: &s.acl_ks,
        contexts: &s.contexts_ks,
        did_templates: &s.did_templates_ks,
        audit: &s.audit_ks,
        imported: &s.imported_ks,
        #[cfg(feature = "webvh")]
        webvh: &s.webvh_ks,
    }
}

/// Borrow a backup `DescriptorDeps` (the two-phase export/import flow) from an
/// `AppState`. The struct lives in `vta-backup`; this constructor stays here
/// because it knows `AppState` and wires the TEE re-encryption hook.
pub fn descriptor_deps_from_app_state(
    s: &crate::server::AppState,
) -> backup::descriptors::DescriptorDeps<'_> {
    backup::descriptors::DescriptorDeps {
        bundles_ks: &s.backup_bundles_ks,
        blob_dir: &s.backup_blob_dir,
        keyspaces: keyspaces_from_app_state(s),
        seed_store: &s.seed_store,
        config: &s.config,
        store: None, // TEE-only path; not threaded here yet.
        #[cfg(feature = "tee")]
        re_encryptor: Some(&VtaBootstrapReEncryptor),
    }
}

/// The sole [`vta_backup::BootstrapReEncryptor`] implementation: wraps
/// `vta-service`'s TEE KMS bootstrap re-encryption so `vta-backup`'s import op
/// can invoke it without depending on the `tee` module.
#[cfg(feature = "tee")]
struct VtaBootstrapReEncryptor;

#[cfg(feature = "tee")]
#[async_trait::async_trait]
impl vta_backup::BootstrapReEncryptor for VtaBootstrapReEncryptor {
    async fn re_encrypt(
        &self,
        kms: &crate::config::TeeKmsConfig,
        store: &crate::store::Store,
        seed: &[u8],
        jwt: &[u8; 32],
    ) -> Result<(), crate::error::AppError> {
        crate::tee::kms_bootstrap::re_encrypt_bootstrap_secrets(kms, store, seed, jwt).await
    }
}
