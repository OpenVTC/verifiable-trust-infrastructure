//! `vault/release/0.1` business logic — seal a stored secret to the holder
//! over DIDComm authcrypt (P2.4).
//!
//! Moved out of `routes/trust_tasks/vault.rs` so the route handler is a thin
//! adapter (gate → parse → load → context-scope → step-up → call this → map
//! to the wire response). The capability/context/step-up gates and the
//! `atm`/`vta_did` readiness checks stay in the route; everything below is the
//! operations work.

use affinidi_tdk::messaging::ATM;

use vti_common::vault::{SecretKind, StoredVaultEntry, put_stored_vault_entry};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// M2A.3 release TTL ceiling (seconds). A higher client hint silently caps
/// rather than rejecting.
pub const TTL_CEILING_SECS: u32 = 60;

/// The sealed secret + the metadata the route needs to build the
/// `vault/release/0.1#response`.
pub struct ReleasedSecret {
    /// DIDComm-authcrypt JWE carrying the `VaultSecret` cleartext.
    pub jwe: String,
    /// Echoed back so the consumer knows how to parse the unsealed body.
    pub secret_kind: SecretKind,
    /// Effective TTL after capping the caller's hint.
    pub ttl_seconds: u32,
}

/// Seal `stored`'s secret to `holder_did` (authcrypt, signed as `vta_did`) and
/// bump `lastUsedAt` (best-effort, server-managed metadata — **not** a version
/// bump, so a concurrent upsert with a stale `expectedVersion` still
/// validates).
///
/// The caller has already gated capability + context scope + step-up and
/// resolved `atm` / `vta_did`.
pub async fn release_secret(
    atm: &ATM,
    vault_ks: &KeyspaceHandle,
    vta_did: &str,
    holder_did: &str,
    mut stored: StoredVaultEntry,
    ttl_hint: Option<u32>,
) -> Result<ReleasedSecret, AppError> {
    let ttl_seconds = ttl_hint
        .map(|t| t.min(TTL_CEILING_SECS))
        .unwrap_or(TTL_CEILING_SECS);

    // Per the canonical sealed-envelope schema, the cleartext inside the JWE is
    // the `VaultSecret` JSON directly.
    let secret_body = serde_json::to_value(&stored.secret).map_err(|e| {
        AppError::Internal(format!("vault/release: failed to serialise secret: {e}"))
    })?;

    let jwe = super::authcrypt_to_holder(
        atm,
        vta_did,
        holder_did,
        super::RELEASE_INNER_MSG_TYPE,
        secret_body,
    )
    .await?;

    let secret_kind = stored.entry.secret_kind;

    // Persist failure isn't fatal — the secret has been sealed and is on its
    // way; log so an operator can see lastUsedAt drift if it ever happens.
    stored.entry.last_used_at = Some(chrono::Utc::now().to_rfc3339());
    if let Err(e) = put_stored_vault_entry(vault_ks, &stored).await {
        tracing::warn!(
            entry_id = %stored.entry.id,
            error = %e,
            "vault/release: lastUsedAt update failed; secret release proceeded"
        );
    }

    Ok(ReleasedSecret {
        jwe,
        secret_kind,
        ttl_seconds,
    })
}
