//! Auto-bootstrap a super-admin credential on first TEE boot.
//!
//! Two paths:
//!
//! 1. **`admin_did` configured** — create the ACL entry for the operator's
//!    known DID and close the first-boot carve-out. The operator keeps the
//!    corresponding private key off-enclave.
//! 2. **No `admin_did` configured** — leave the first-boot carve-out OPEN.
//!    The operator completes the swap via the sealed-bootstrap flow
//!    (`POST /bootstrap/request` with attestation, Phase 3). The first
//!    successful swap closes the carve-out.
//!
//! Legacy behavior pre-Phase-3 was to auto-generate a random admin
//! credential on first boot and store it under `tee:admin_credential` for
//! retrieval via `GET /attestation/admin-credential`. That endpoint is
//! gone; startup migrates any stored row out of the store.

use tracing::info;

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::config::AppConfig;
use crate::contexts;
use crate::error::AppError;
use crate::store::{KeyspaceHandle, Store};

/// Sentinel indicating the TEE first-boot carve-out has been closed. Written
/// either by `maybe_bootstrap_admin` (when an operator DID is configured) or
/// by `POST /bootstrap/request` after a successful Mode B swap. When present,
/// any subsequent Mode B attempt is rejected.
pub const BOOTSTRAP_CARVEOUT_CLOSED_KEY: &str = "tee:bootstrap-carveout-closed";

/// Legacy store key for the pre-Phase-3 auto-generated admin credential.
/// No longer written; cleaned up on first startup after the upgrade.
pub const LEGACY_ADMIN_CREDENTIAL_KEY: &str = "tee:admin_credential";

/// Bootstrap a super-admin credential on first boot.
///
/// - If an admin credential already exists in the store, this is a no-op.
/// - Otherwise: creates the admin context, generates a `did:key`, creates
///   an ACL entry, encodes a `CredentialBundle`, and writes it to both
///   the encrypted keys keyspace and the unencrypted bootstrap keyspace.
///
/// Returns `Ok(())` on success or if bootstrap is not needed.
pub async fn maybe_bootstrap_admin(
    config: &AppConfig,
    store: &Store,
    storage_encryption_key: Option<[u8; 32]>,
) -> Result<(), AppError> {
    // Guard: no KMS config means no TEE bootstrap
    let kms_config = match &config.tee.kms {
        Some(kms) => kms,
        None => return Ok(()),
    };

    // Open keyspaces
    let apply_enc = |ks: KeyspaceHandle| -> KeyspaceHandle {
        if let Some(key) = storage_encryption_key {
            ks.with_encryption(key)
        } else {
            ks
        }
    };
    let keys_ks = apply_enc(store.keyspace("keys")?);
    let contexts_ks = apply_enc(store.keyspace("contexts")?);
    let acl_ks = apply_enc(store.keyspace("acl")?);

    // One-time migration: if the legacy pre-Phase-3 credential row is still in
    // the store, the old endpoint retrieving it is gone. Move any operator
    // copies they already have, then retire the row so the carve-out reflects
    // real state.
    if keys_ks
        .get_raw(LEGACY_ADMIN_CREDENTIAL_KEY)
        .await?
        .is_some()
    {
        info!("migrating legacy tee:admin_credential row — carve-out now closed");
        keys_ks.remove(LEGACY_ADMIN_CREDENTIAL_KEY).await?;
        // Old row might also be mirrored in the bootstrap keyspace.
        if let Ok(bootstrap_ks) = store.keyspace("bootstrap") {
            let _ = bootstrap_ks.remove(LEGACY_ADMIN_CREDENTIAL_KEY).await;
        }
        keys_ks
            .insert_raw(BOOTSTRAP_CARVEOUT_CLOSED_KEY, b"legacy-migrated".to_vec())
            .await?;
        store.persist().await?;
        return Ok(());
    }

    // Carve-out already closed by a prior boot (operator DID path) or a
    // prior Mode B swap.
    if keys_ks
        .get_raw(BOOTSTRAP_CARVEOUT_CLOSED_KEY)
        .await?
        .is_some()
    {
        info!("tee first-boot carve-out already closed — skipping");
        return Ok(());
    }

    let context_id = &kms_config.admin_context_id;

    // Create admin context if it doesn't exist
    let _ctx = match contexts::get_context(&contexts_ks, context_id).await? {
        Some(ctx) => ctx,
        None => contexts::create_context(&contexts_ks, context_id, "Default Admin Context")
            .await
            .map_err(|e| AppError::Internal(format!("failed to create admin context: {e}")))?,
    };

    // Use the operator-provided admin DID if configured, otherwise generate one
    if let Some(ref admin_did) = kms_config.admin_did {
        // Operator-provided DID — just create the ACL entry. Carve-out is
        // closed immediately because the admin identity is already known.
        info!(did = %admin_did, context_id, "bootstrapping super-admin from config admin_did");

        let entry = AclEntry::new(admin_did.clone(), Role::Admin, "tee:bootstrap")
            .with_label(Some("TEE bootstrap admin".to_string()));
        store_acl_entry(&acl_ks, &entry).await?;

        keys_ks
            .insert_raw(BOOTSTRAP_CARVEOUT_CLOSED_KEY, admin_did.as_bytes().to_vec())
            .await?;

        store.persist().await?;

        info!(
            did = %admin_did,
            context_id,
            "super-admin ACL created — connect using the private key for this DID"
        );
    } else {
        // No admin_did configured — leave the first-boot carve-out OPEN.
        // The operator completes the swap by running
        // `pnm bootstrap connect --vta-url <URL>` against this VTA (no token),
        // which triggers the Mode B attestation branch and closes the carve-out.
        info!(
            context_id,
            "no admin_did configured — first-boot carve-out remains open for \
             sealed-bootstrap Mode B"
        );
        store.persist().await?;
    }

    Ok(())
}
