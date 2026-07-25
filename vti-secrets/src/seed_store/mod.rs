#[cfg(feature = "aws-secrets")]
mod aws;
#[cfg(feature = "azure-secrets")]
mod azure;
#[cfg(feature = "config-seed")]
mod config;
#[cfg(feature = "gcp-secrets")]
mod gcp;
#[cfg(feature = "k8s-secrets")]
mod k8s;
#[cfg(feature = "keyring")]
mod keyring;
#[cfg(feature = "tee")]
pub mod kms_tee;
mod plaintext;
#[cfg(feature = "vault-secrets")]
mod vault;

#[cfg(feature = "aws-secrets")]
pub use aws::AwsSeedStore;
#[cfg(feature = "azure-secrets")]
pub use azure::AzureSeedStore;
#[cfg(feature = "config-seed")]
pub use config::ConfigSeedStore;
#[cfg(feature = "gcp-secrets")]
pub use gcp::GcpSeedStore;
#[cfg(feature = "k8s-secrets")]
pub use k8s::{K8sSeedStore, from_config as k8s_from_config};
#[cfg(feature = "keyring")]
pub use keyring::KeyringSeedStore;
#[cfg(feature = "tee")]
pub use kms_tee::KmsTeeSeedStore;
pub use plaintext::PlaintextSeedStore;
#[cfg(feature = "vault-secrets")]
pub use vault::{
    VaultParams, VaultSeedStore, from_config as vault_from_config, from_params as vault_from_params,
};

#[cfg(feature = "tee")]
use std::future::Future;
#[cfg(feature = "tee")]
use std::pin::Pin;

use std::path::Path;

use crate::config::{SecretBackend, SecretsConfig};
use vti_common::error::AppError;

pub use vti_common::seed_store::SeedStore;

/// Local boxed-future alias mirroring `vti_common::seed_store::BoxFuture`,
/// used by the in-crate `kms_tee` backend's trait impl. Only compiled when
/// the `tee` feature pulls in that backend.
#[cfg(feature = "tee")]
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Create a seed store backend based on compiled features and configuration.
///
/// `secrets` is the resolved [`SecretsConfig`] (which backend + its
/// connection parameters); `data_dir` is only consulted by the plaintext
/// backend for the `seed.plaintext` location.
///
/// **Selection.** If [`SecretsConfig::backend`] is set it wins outright — the
/// named backend is built and its required fields are validated. A mismatch
/// is a hard [`AppError::Config`], never a silent pick of a different
/// backend. If it is unset, resolution falls back to the legacy implicit
/// priority chain, keyed on which selector field is populated:
///
/// 1. AWS Secrets Manager (if `aws-secrets` compiled + `aws_secret_name` set)
/// 2. GCP Secret Manager (if `gcp-secrets` compiled + `gcp_secret_name` set)
/// 3. Azure Key Vault (if `azure-secrets` compiled + `azure_vault_url` set)
/// 4. HashiCorp Vault (if `vault-secrets` compiled + `vault_addr` set)
/// 5. Kubernetes Secret (if `k8s-secrets` compiled + `k8s_secret_name` set)
/// 6. Config file seed (if `config-seed` compiled + `seed` set)
/// 7. OS keyring (if `keyring` compiled — the default)
/// 8. Plaintext file (NOT secure)
///
/// Note what the implicit chain cannot express: plaintext has no selector
/// field of its own, and the keyring arm matches unconditionally, so on any
/// build with `keyring` compiled in (the default) implicit resolution can
/// never reach plaintext. `allow_plaintext` is a *permission* to fall back,
/// not a request — `backend = "plaintext"` is how you ask for it.
///
/// A backend requested on a binary built without its feature is a hard
/// `Config` error — never a silent fall-through to keyring or plaintext.
///
/// `unused_variables` allowed: `secrets` / `data_dir` are only read under
/// specific feature flags; a build with none of the cloud/keyring/config-seed
/// features compiled leaves them unused, which is fine — we fall through
/// to the plaintext backend. rustc's dead-code lint can't see through
/// the cfg-gated early returns.
#[allow(unused_variables)]
pub fn create_seed_store(
    secrets: &SecretsConfig,
    data_dir: &Path,
) -> Result<Box<dyn SeedStore>, AppError> {
    let explicit = secrets.backend;

    // Is backend `b` the one to build? An explicit selector wins outright;
    // otherwise fall back to "its selector field is set" implicit
    // resolution. Used for the cloud / config-seed backends — keyring and
    // plaintext are the tail arms and are handled separately below.
    let wants = |b: SecretBackend, field_set: bool| match explicit {
        Some(sel) => sel == b,
        None => field_set,
    };

    #[cfg(feature = "aws-secrets")]
    if wants(SecretBackend::Aws, secrets.aws_secret_name.is_some()) {
        let name = secrets.aws_secret_name.clone().ok_or_else(|| {
            AppError::Config("secrets.backend = aws requires secrets.aws_secret_name".into())
        })?;
        let store = AwsSeedStore::new(name, secrets.aws_region.clone());
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "aws-secrets"))]
    if wants(SecretBackend::Aws, secrets.aws_secret_name.is_some()) {
        return Err(uncompiled("aws", "aws-secrets"));
    }

    #[cfg(feature = "gcp-secrets")]
    if wants(SecretBackend::Gcp, secrets.gcp_secret_name.is_some()) {
        let name = secrets.gcp_secret_name.clone().ok_or_else(|| {
            AppError::Config("secrets.backend = gcp requires secrets.gcp_secret_name".into())
        })?;
        let project = secrets.gcp_project.clone().ok_or_else(|| {
            AppError::Config(
                "secrets.gcp_project is required when secrets.gcp_secret_name is set".into(),
            )
        })?;
        let store = GcpSeedStore::new(project, name);
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "gcp-secrets"))]
    if wants(SecretBackend::Gcp, secrets.gcp_secret_name.is_some()) {
        return Err(uncompiled("gcp", "gcp-secrets"));
    }

    #[cfg(feature = "azure-secrets")]
    if wants(SecretBackend::Azure, secrets.azure_vault_url.is_some()) {
        let vault_url = secrets.azure_vault_url.clone().ok_or_else(|| {
            AppError::Config("secrets.backend = azure requires secrets.azure_vault_url".into())
        })?;
        let secret_name = secrets
            .azure_secret_name
            .clone()
            .unwrap_or_else(|| "vta-master-seed".to_string());
        let store = AzureSeedStore::new(vault_url, secret_name);
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "azure-secrets"))]
    if wants(SecretBackend::Azure, secrets.azure_vault_url.is_some()) {
        return Err(uncompiled("azure", "azure-secrets"));
    }

    #[cfg(feature = "vault-secrets")]
    if wants(SecretBackend::Vault, secrets.vault_addr.is_some()) {
        if secrets.vault_addr.is_none() {
            return Err(AppError::Config(
                "secrets.backend = vault requires secrets.vault_addr".into(),
            ));
        }
        let store = vault::from_config(secrets)?;
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "vault-secrets"))]
    if wants(SecretBackend::Vault, secrets.vault_addr.is_some()) {
        return Err(uncompiled("vault", "vault-secrets"));
    }

    #[cfg(feature = "k8s-secrets")]
    if wants(SecretBackend::Kubernetes, secrets.k8s_secret_name.is_some()) {
        if secrets.k8s_secret_name.is_none() {
            return Err(AppError::Config(
                "secrets.backend = kubernetes requires secrets.k8s_secret_name".into(),
            ));
        }
        let store = k8s::from_config(secrets)?;
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "k8s-secrets"))]
    if wants(SecretBackend::Kubernetes, secrets.k8s_secret_name.is_some()) {
        return Err(uncompiled("kubernetes", "k8s-secrets"));
    }

    #[cfg(feature = "config-seed")]
    if wants(SecretBackend::ConfigSeed, secrets.seed.is_some()) {
        let seed = secrets.seed.clone().ok_or_else(|| {
            AppError::Config("secrets.backend = config_seed requires secrets.seed".into())
        })?;
        let store = ConfigSeedStore::new(seed);
        return Ok(Box::new(store));
    }
    #[cfg(not(feature = "config-seed"))]
    if wants(SecretBackend::ConfigSeed, secrets.seed.is_some()) {
        return Err(uncompiled("config_seed", "config-seed"));
    }

    // Keyring — the implicit default when nothing is selected, or an
    // explicit `backend = "keyring"`. An explicit keyring selection on a
    // binary built without the feature is a hard error (mirrors the arms
    // above); the implicit path just falls through to plaintext.
    #[cfg(not(feature = "keyring"))]
    if matches!(explicit, Some(SecretBackend::Keyring)) {
        return Err(uncompiled("keyring", "keyring"));
    }
    #[cfg(feature = "keyring")]
    if explicit.is_none() || matches!(explicit, Some(SecretBackend::Keyring)) {
        let store = KeyringSeedStore::new(&secrets.keyring_service, "master_seed");
        return Ok(Box::new(store));
    }

    // `unreachable_code` allowed: each of the `return Ok(...)` branches above
    // is `cfg(feature = ...)`-gated, so with every secure-backend feature
    // enabled (or none of them), this tail is or isn't actually reached.
    // Rustc can't resolve the combined cfg math — the allow is load-bearing
    // only when `keyring` is the selected feature.
    #[allow(unreachable_code)]
    {
        // Plaintext — either explicitly requested, or the last resort when
        // no secure backend was compiled-in AND configured. Writing the
        // BIP-32 master seed to a plaintext file is a real footgun (one
        // wrong/missing TOML key would silently do it), so it still takes
        // the `allow_plaintext` opt-in either way (P0.9).
        if !secrets.allow_plaintext {
            return Err(AppError::Config(
                "the plaintext seed-store fallback is disabled. Configure a secure backend, \
                 or set `secrets.allow_plaintext = true` to explicitly accept storing the \
                 master seed in a cleartext file (dev/test only)."
                    .into(),
            ));
        }
        tracing::warn!(
            "storing the BIP-32 master seed in a PLAINTEXT file. This is NOT secure; use a \
             keyring or cloud/Vault backend in production."
        );
        let store = PlaintextSeedStore::new(data_dir);
        Ok(Box::new(store))
    }
}

/// A backend was requested (explicitly, or implicitly by setting its
/// selector field) on a binary built without its feature. Fail closed —
/// pre-P0.8 the arm was `#[cfg]`'d away, so a production config pointing at
/// AWS on a keyring-only binary booted against an empty keyring.
#[allow(dead_code)]
fn uncompiled(backend: &str, feature: &str) -> AppError {
    AppError::Config(format!(
        "secrets backend '{backend}' selected but this binary was built without the \
         '{feature}' feature"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> SecretsConfig {
        SecretsConfig::default()
    }

    fn data_dir() -> std::path::PathBuf {
        std::env::temp_dir()
    }

    // `Box<dyn SeedStore>` is not `Debug`, so `expect_err` won't compile;
    // pattern-match the result instead.
    fn expect_config_err(secrets: &SecretsConfig, needle: &str) {
        match create_seed_store(secrets, &data_dir()) {
            Err(AppError::Config(msg)) => assert!(
                msg.contains(needle),
                "error should mention {needle:?}, got: {msg}"
            ),
            Err(other) => panic!("expected a Config error, got {other:?}"),
            Ok(_) => panic!("expected a Config error, got a store"),
        }
    }

    #[test]
    fn plaintext_is_unreachable_implicitly_but_selectable_explicitly() {
        // The reported bug: with `keyring` compiled in (the default), the
        // keyring arm matches unconditionally, so `allow_plaintext` alone
        // never reaches the plaintext backend — the wizard's "Plaintext
        // file" choice silently produced a keyring-backed VTA. The explicit
        // selector is what makes the request expressible.
        let mut secrets = base();
        secrets.allow_plaintext = true;

        // Implicit: allow_plaintext is a permission, not a request.
        #[cfg(feature = "keyring")]
        assert!(
            create_seed_store(&secrets, &data_dir()).is_ok(),
            "implicit resolution still picks keyring"
        );

        // Explicit: plaintext is built, and the file lands where the
        // plaintext backend puts it.
        secrets.backend = Some(SecretBackend::Plaintext);
        let dir = tempfile::tempdir().expect("tempdir");
        let store = create_seed_store(&secrets, dir.path()).expect("plaintext store builds");
        futures_executor_block_on(store.set(&[7u8; 64]));
        assert!(
            dir.path().join("seed.plaintext").is_file(),
            "an explicit plaintext selection must write the plaintext seed file"
        );
    }

    /// Minimal block-on so the test doesn't pull a runtime into this crate's
    /// non-async surface. `PlaintextSeedStore::set` never yields — it is a
    /// synchronous `std::fs` write behind an async signature.
    fn futures_executor_block_on(fut: impl std::future::Future<Output = Result<(), AppError>>) {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut fut = Box::pin(fut);
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(r) => r.expect("plaintext write succeeds"),
            std::task::Poll::Pending => panic!("plaintext set must complete without yielding"),
        }
    }

    #[test]
    fn explicit_plaintext_still_needs_the_allow_optin() {
        // Selecting plaintext says *which* backend; `allow_plaintext` still
        // says you accept a cleartext master seed (P0.9). Both are required.
        let mut secrets = base();
        secrets.backend = Some(SecretBackend::Plaintext);
        expect_config_err(&secrets, "allow_plaintext");
    }

    #[test]
    fn an_explicit_uncompiled_backend_is_a_hard_error() {
        // Fail closed: never silently substitute keyring (or plaintext) for
        // the backend the operator named.
        let mut secrets = base();
        for (sel, needle) in [
            (SecretBackend::Aws, "aws"),
            (SecretBackend::Gcp, "gcp"),
            (SecretBackend::Azure, "azure"),
            (SecretBackend::Vault, "vault"),
            (SecretBackend::Kubernetes, "kubernetes"),
        ] {
            secrets.backend = Some(sel);
            // Only assert for backends this build genuinely lacks; the
            // workspace test build compiles none of them.
            if cfg!(not(any(
                feature = "aws-secrets",
                feature = "gcp-secrets",
                feature = "azure-secrets",
                feature = "vault-secrets",
                feature = "k8s-secrets"
            ))) {
                expect_config_err(&secrets, needle);
            }
        }
    }

    #[test]
    fn an_explicit_selector_overrides_a_stray_implicit_field() {
        // A leftover `aws_secret_name` must not drag a keyring-selected
        // deployment onto AWS — the named backend wins outright.
        let mut secrets = base();
        secrets.aws_secret_name = Some("vta/prod/seed".into());
        secrets.backend = Some(SecretBackend::Keyring);
        #[cfg(feature = "keyring")]
        assert!(
            create_seed_store(&secrets, &data_dir()).is_ok(),
            "the explicit keyring selection must win over the stray AWS field"
        );
    }

    #[test]
    fn no_selector_keeps_the_legacy_implicit_chain() {
        // Existing configs must resolve exactly as before.
        let secrets = base();
        assert!(secrets.backend.is_none(), "unset by default");
        #[cfg(feature = "keyring")]
        assert!(
            create_seed_store(&secrets, &data_dir()).is_ok(),
            "an all-default config still lands on keyring"
        );
    }

    #[test]
    fn the_selector_round_trips_through_toml_in_wizard_spelling() {
        let parsed: SecretsConfig =
            toml::from_str("backend = \"config_seed\"\nseed = \"aa\"").expect("parses");
        assert_eq!(parsed.backend, Some(SecretBackend::ConfigSeed));

        let out = toml::to_string(&base()).expect("serializes");
        assert!(
            !out.contains("backend"),
            "an unset selector must not be written into config.toml, got:\n{out}"
        );
    }
}
