//! `vtc admin emergency-bootstrap` — destructive operator recovery
//! via the VTA's `AdminRotated` flow.
//!
//! Implements **M0.10** rework per
//! `tasks/vtc-mvp/vta-driven-keys.md` §4. Used when every admin
//! passkey is lost: the operator runs this command on a stopped
//! daemon, authenticates against the VTA with a fresh ephemeral
//! DID the VTA's ACL was just pre-authorized to accept, and the
//! VTC accepts the recovery only if the VTA does.
//!
//! ## Trust root
//!
//! The VTC has no locally-held recovery secret (no BIP-39 mnemonic,
//! no backup-derived password). Authority for "reset admin access"
//! lives in the operator's PNM admin credential at the VTA: if they
//! can `pnm acl create` an admin DID against the VTC's context,
//! they can recover. Losing PNM admin access at the VTA means
//! losing the community — by design.
//!
//! ## What gets cleared
//!
//! - Every `Role::Admin` ACL entry.
//! - Every `admin:<did>` sister record (M0.6.1 metadata).
//! - The full set of `PasskeyUser` + credential mapping records
//!   for admin DIDs.
//!
//! The earlier "install carve-out closed" marker is no longer
//! emitted (the carve-out concept is gone); no cleanup needed.
//!
//! ## What persists
//!
//! - The community profile (§5.1).
//! - The audit log — emergency bootstrap is audited via the
//!   pending marker; you can't quietly erase tracks.
//! - The `VtcKeyBundle` — the VTC's DID + integration keys stay
//!   put, only the admin ACL state resets.

use crate::store::keyspaces;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use crate::acl::{VtcRole, delete_acl_entry, list_acl_entries};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, warn};
use vti_common::config::StoreConfig;
use vti_common::error::AppError;
use vti_common::store::Store;

use vta_sdk::provision_client::{
    EphemeralSetupKey, OperatorMessages, ProvisionAsk, ProvisionError, VtaIntent, VtaReply,
    run_provision,
};

use crate::acl::admin::list_admin_entries;
use crate::config::AppConfig;
use crate::install::{
    INSTALL_TOKEN_DEFAULT_TTL_SECS, InstallTokenSigner, InstallTokenStore,
    PendingEmergencyBootstrap, mint_install_token,
};
use crate::keys::seed_store::{SecretStore, create_secret_store};
use crate::setup::VtcKeyBundle;

/// CLI args. Mirrors the `Commands::Admin::EmergencyBootstrap`
/// clap surface; the `context` override is plumbed through here so
/// operators with a non-`default` VTA context can recover without
/// editing `config.toml` first.
pub struct EmergencyBootstrapArgs {
    pub config_path: Option<PathBuf>,
    pub context: Option<String>,
}

/// Outcome of a successful run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyBootstrapOutcome {
    pub install_url: String,
    /// Out-of-band claim code the operator types alongside the
    /// install URL. Printed by the CLI; never persisted.
    pub claim_code: String,
    pub admin_entries_cleared: usize,
    pub admin_records_cleared: usize,
}

/// Trait used by [`run_emergency_bootstrap_with_store`] to drive the
/// VTA's `AdminRotated` flow. Production uses
/// [`RunProvisionProver`]; tests inject a mock.
#[async_trait]
pub trait VtaRecoveryProver: Send + Sync {
    /// Prove to the VTA that the operator currently holds admin
    /// authority at `vta_did`'s `context`. Returns `Ok(())` on
    /// successful round-trip; `Err(AppError::Unauthorized)` if the
    /// VTA rejects the ephemeral DID (operator forgot the ACL
    /// step, or no longer has access at the VTA).
    async fn prove(
        &self,
        vta_did: &str,
        ephemeral_did: &str,
        ephemeral_privkey_mb: &str,
        context: &str,
    ) -> Result<(), AppError>;
}

/// Production prover — drives `vta_sdk::provision_client::run_provision`
/// with `VtaIntent::AdminRotated` and discards the returned admin
/// credential (the recovery flow doesn't keep it; only proof of
/// access matters).
pub struct RunProvisionProver;

#[async_trait]
impl VtaRecoveryProver for RunProvisionProver {
    async fn prove(
        &self,
        vta_did: &str,
        ephemeral_did: &str,
        ephemeral_privkey_mb: &str,
        context: &str,
    ) -> Result<(), AppError> {
        let ask = ProvisionAsk::vta_admin_rotated(context).with_label("vtc emergency-bootstrap");
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let drain = tokio::spawn(async move { while event_rx.recv().await.is_some() {} });
        let reply = run_provision(
            VtaIntent::AdminRotated,
            vta_did.to_string(),
            ephemeral_did.to_string(),
            ephemeral_privkey_mb.to_string(),
            ask,
            None,
            Arc::new(VtcRecoveryMessages),
            event_tx,
        )
        .await
        .map_err(translate_provision_err)?;
        drain.abort();
        match reply {
            VtaReply::AdminOnly(_) => Ok(()),
            VtaReply::Full(_) => Err(AppError::Internal(
                "VTA returned a Full reply but emergency-bootstrap asked for AdminRotated".into(),
            )),
        }
    }
}

fn translate_provision_err(e: ProvisionError) -> AppError {
    let msg = e.to_string();
    if msg.to_ascii_lowercase().contains("auth") || msg.to_ascii_lowercase().contains("forbidden") {
        AppError::Unauthorized(format!(
            "VTA rejected the recovery DID: {msg}. \
             Make sure `pnm acl create` ran for this context against this VTA."
        ))
    } else {
        AppError::Internal(format!("VTA recovery call failed: {msg}"))
    }
}

struct VtcRecoveryMessages;

impl OperatorMessages for VtcRecoveryMessages {
    fn integration_label(&self) -> &str {
        "VTC"
    }
    fn integration_label_lower(&self) -> &str {
        "vtc"
    }
    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        format!(
            "pnm acl create --did {setup_did} --role admin --contexts {context_id} \\\n  \
             --expires 1h"
        )
    }
}

/// The CLI subcommand's entry point.
pub async fn run_emergency_bootstrap(
    args: EmergencyBootstrapArgs,
) -> Result<EmergencyBootstrapOutcome, AppError> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&StoreConfig {
        data_dir: config.store.data_dir.clone(),
    })
    .map_err(|e| {
        AppError::Config(format!(
            "failed to open fjall store at '{}': {e}. Is the daemon still running? \
             Stop it before running emergency-bootstrap.",
            config.store.data_dir.display()
        ))
    })?;
    let secret_store = create_secret_store(&config)
        .map_err(|e| AppError::Config(format!("failed to construct secret store: {e}")))?;
    let setup_key = EphemeralSetupKey::generate()
        .map_err(|e| AppError::Internal(format!("ephemeral key gen: {e}")))?;
    let prover = RunProvisionProver;
    run_emergency_bootstrap_with_store(
        &config,
        &store,
        secret_store.as_ref(),
        &setup_key,
        &prover,
        args.context,
    )
    .await
}

/// Inner driver split from [`run_emergency_bootstrap`] so tests can
/// compose their own `Store` + `SecretStore` + recovery prover
/// without touching the filesystem or a live VTA.
pub async fn run_emergency_bootstrap_with_store(
    config: &AppConfig,
    store: &Store,
    secret_store: &dyn SecretStore,
    setup_key: &EphemeralSetupKey,
    prover: &dyn VtaRecoveryProver,
    context_override: Option<String>,
) -> Result<EmergencyBootstrapOutcome, AppError> {
    let bundle_bytes = secret_store
        .get()
        .await
        .map_err(|e| AppError::SecretStore(e.to_string()))?
        .ok_or_else(|| {
            AppError::Config(
                "no key material in the secret store — has this VTC ever been set up?".into(),
            )
        })?;
    let bundle = VtcKeyBundle::from_secret_store_bytes(&bundle_bytes)?;

    let vta_did = config.vta_did.as_deref().ok_or_else(|| {
        AppError::Config(
            "config.vta_did not set — emergency-bootstrap recovery requires the VTA's DID. \
             Re-run `vtc setup` against the same VTA to populate it."
                .into(),
        )
    })?;
    let context = context_override
        .or_else(|| derive_context_from_config(config))
        .unwrap_or_else(|| "default".to_string());

    // The "is this operator legitimately recovering?" check.
    prover
        .prove(
            vta_did,
            &setup_key.did,
            setup_key.private_key_multibase(),
            &context,
        )
        .await?;

    let acl_ks = store.keyspace(keyspaces::ACL)?;
    let passkey_ks = store.keyspace(keyspaces::PASSKEY)?;
    let install_ks = store.keyspace(keyspaces::INSTALL)?;
    let install_store = InstallTokenStore::new(install_ks);

    // --- destructive cleanup ----------------------------------------
    let mut admin_entries_cleared = 0;
    for entry in list_acl_entries(&acl_ks).await? {
        if entry.role == VtcRole::Admin {
            delete_acl_entry(&acl_ks, &entry.did).await?;
            admin_entries_cleared += 1;
        }
    }

    let admin_records = list_admin_entries(&passkey_ks).await?;
    let admin_records_cleared = admin_records.len();
    for entry in admin_records {
        passkey_ks
            .remove(format!("admin:{}", entry.did).into_bytes())
            .await?;
        if let Some(user) =
            vti_common::auth::passkey::store::get_passkey_user_by_did(&passkey_ks, &entry.did)
                .await?
        {
            passkey_ks
                .remove(format!("pk_user:{}", user.user_uuid).into_bytes())
                .await?;
            passkey_ks
                .remove(format!("pk_did:{}", entry.did).into_bytes())
                .await?;
            for cred in user.credentials {
                let cred_id_hex = hex::encode(<_ as AsRef<[u8]>>::as_ref(cred.cred_id()));
                passkey_ks
                    .remove(format!("pk_cred:{cred_id_hex}").into_bytes())
                    .await?;
            }
        }
    }

    // --- mint a fresh install token ---------------------------------
    //
    // The earlier "carve-out reopen" step is gone — install tokens
    // are gated per-row by the out-of-band claim secret, so emergency
    // recovery just mints a fresh URL + code pair the operator types
    // alongside.
    let ed25519 = bundle.ed25519_private_bytes()?;
    let signer = InstallTokenSigner::from_master_seed(&*ed25519)?;
    let issuer = bundle.integration_did.clone();
    // Reuse the recovery DID as the new admin — the operator already
    // proved control of it via the VTA recovery context, and it's the
    // identity they currently hold private keys for. Operators who
    // want a different admin DID can rotate via the regular flow
    // after the emergency bootstrap completes.
    let minted = mint_install_token(
        &signer,
        &issuer,
        &setup_key.did,
        INSTALL_TOKEN_DEFAULT_TTL_SECS,
    )?;
    let claim_code = crate::install::claim_secret::generate();
    let claim_code_hash = crate::install::claim_secret::hash(&claim_code)?;
    let exp = Utc::now() + chrono::Duration::seconds(INSTALL_TOKEN_DEFAULT_TTL_SECS as i64);
    install_store
        .record_issued(
            &minted.jti,
            minted.cnonce_bytes,
            *minted.ephemeral_signing_key,
            exp,
            Some(claim_code_hash),
            Some(setup_key.did.clone()),
        )
        .await?;

    // --- pending audit marker ---------------------------------------
    let operator_hostname = gethostname::gethostname().to_string_lossy().into_owned();
    install_store
        .mark_emergency_pending(PendingEmergencyBootstrap {
            operator_hostname: operator_hostname.clone(),
            invoked_at: Utc::now(),
        })
        .await?;

    // --- install URL ------------------------------------------------
    // `/admin/install` so the embedded admin SPA picks the request
    // up and runs the install-claim ceremony in-browser. The bare
    // `/install` path would hit the website fallback, which has no
    // install page. The `vtc://install?token=…` fallback (when
    // `public_url` is unset) intentionally keeps the bare-path shape
    // because nothing renders it; it's a sentinel for ops scripts.
    let install_url = match &config.public_url {
        Some(base) => format!(
            "{}/admin/install?token={}",
            base.trim_end_matches('/'),
            minted.jwt
        ),
        None => format!("vtc://install?token={}", minted.jwt),
    };

    info!(
        operator_hostname = %operator_hostname,
        admin_entries_cleared,
        admin_records_cleared,
        "emergency bootstrap completed; install URL minted"
    );
    if admin_entries_cleared == 0 {
        warn!(
            "emergency bootstrap cleared no admin entries — was the daemon already in a \
             fresh-install state?"
        );
    }

    // Flush the destructive cleanup + the freshly-minted install-token row to
    // disk before handing the URL back — without this a crash could leave the
    // old admins half-deleted or the new token row non-durable, handing the
    // operator a dead recovery URL (P2.5).
    store.persist().await?;

    Ok(EmergencyBootstrapOutcome {
        install_url,
        claim_code,
        admin_entries_cleared,
        admin_records_cleared,
    })
}

/// VTC config has no `context` field today (the wizard records it
/// indirectly via the integration DID's webvh path). For now we
/// fall back to `"default"` and rely on the CLI's `--context` flag
/// for non-default deployments. A first-class `vtc_context` field
/// can land in a follow-up once Phase 1 surfaces it elsewhere.
fn derive_context_from_config(_config: &AppConfig) -> Option<String> {
    None
}

/// Convenience for `main.rs` — used when the wizard rework is not
/// gated on a successful prover round-trip.
pub fn emergency_bootstrap_unavailable() -> AppError {
    AppError::Internal("vtc admin emergency-bootstrap requires the `setup` feature".into())
}

// ---------------------------------------------------------------------------
// Helpers re-exported for tests
// ---------------------------------------------------------------------------

/// Construct a `Pin<Box<...>>` future signature in async-trait-friendly
/// form for downstream test mocks that don't want to depend on
/// `async-trait` themselves. The trait above uses `#[async_trait]`
/// so impls can use plain `async fn`; the type alias is here for
/// out-of-crate mocks that prefer manual `dyn Future`.
pub type RecoveryProverFuture<'a> =
    Pin<Box<dyn std::future::Future<Output = Result<(), AppError>> + Send + 'a>>;
