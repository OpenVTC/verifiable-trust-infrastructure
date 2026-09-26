//! `vault/release/0.1` business logic — seal a stored secret to the holder
//! over DIDComm authcrypt (P2.4).
//!
//! Moved out of `routes/trust_tasks/vault.rs` so the route handler is a thin
//! adapter (gate → parse → load → context-scope → step-up → call this → map
//! to the wire response). The capability/context/step-up gates and the
//! `atm`/`vta_did` readiness checks stay in the route; everything below is the
//! operations work.

use affinidi_tdk::messaging::ATM;
use serde_json::Value;

use vti_common::vault::{SecretKind, StoredVaultEntry, VaultSecret, put_stored_vault_entry};

use crate::error::AppError;
use crate::store::KeyspaceHandle;
use crate::trust_tasks::wire_v0_2::{WireVersion, camelize_paths};

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
///
/// # The audit row is a precondition of the release
///
/// A released secret — a password, a TOTP seed, and for `passkey` and `ssh-key`
/// entries a **private key** — stays with the holder once it has it. So, as for
/// `keys/export-secret` (VTI-VTA-003, VTI-AUD-005), the release is recorded
/// durably *before* the sealed secret is returned, and a row that cannot be
/// written refuses the release. The row is `vault.secret_release`, shaped like
/// `key.secret_export`: who (`actor`), which entry (`resource`), its context,
/// the transport (`channel`), and the entry's kind in `detail` — never the
/// secret, and never the entry's label or site, which can carry personal data.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn release_secret(
    atm: &ATM,
    vault_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    vta_did: &str,
    holder_did: &str,
    mut stored: StoredVaultEntry,
    ttl_hint: Option<u32>,
    wire: WireVersion,
    channel: &str,
) -> Result<ReleasedSecret, AppError> {
    let ttl_seconds = ttl_hint
        .map(|t| t.min(TTL_CEILING_SECS))
        .unwrap_or(TTL_CEILING_SECS);

    // Per the canonical sealed-envelope schema, the cleartext inside the JWE is
    // the `VaultSecret` JSON directly. The 0.2 spec renamed the `kind`
    // discriminator and `loginConfig.format` to camelCase; this body rides
    // inside the opaque JWE, so the edge transform can't reach it — we emit the
    // version-appropriate casing here.
    let secret_body = secret_cleartext_for_wire(&stored.secret, wire)?;

    let jwe = super::authcrypt_to_holder(
        atm,
        vta_did,
        holder_did,
        super::RELEASE_INNER_MSG_TYPE,
        secret_body,
    )
    .await?;

    let secret_kind = stored.entry.secret_kind;

    // Durable before the sealed secret leaves, refusing on failure — see
    // "The audit row is a precondition of the release".
    let kind = serde_json::to_value(secret_kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());
    if let Err(e) = crate::audit::record_with_detail(
        audit,
        "vault.secret_release",
        holder_did,
        Some(&stored.entry.id),
        "success",
        Some(channel),
        Some(&stored.entry.context_id),
        Some(&format!("kind={kind}")),
    )
    .await
    {
        tracing::error!(
            target: vta_audit::AUDIT_WRITE_FAILURE_TARGET,
            error = %e, entry_id = %stored.entry.id, actor = %holder_did,
            "vault release refused: its audit row could not be written"
        );
        return Err(AppError::Internal(
            "the secret was not released: the release could not be recorded in the audit \
             trail, and an unrecorded release is not permitted"
                .into(),
        ));
    }

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

/// Serialise a `VaultSecret` into the cleartext JSON that goes inside the JWE,
/// in the casing the negotiated wire version requires.
///
/// `VaultSecret` always serialises its 0.1 (kebab) form; for a 0.2 release we
/// up-convert the enum values the 0.2 spec renamed — the `kind` discriminator
/// and (on `password` entries) `loginConfig.format`. Pure + synchronous so the
/// casing is unit-testable without an ATM or a real JWE.
fn secret_cleartext_for_wire(secret: &VaultSecret, wire: WireVersion) -> Result<Value, AppError> {
    let mut body = serde_json::to_value(secret).map_err(|e| {
        AppError::Internal(format!("vault/release: failed to serialise secret: {e}"))
    })?;
    if wire == WireVersion::V0_2 {
        camelize_paths(&mut body, &["kind", "loginConfig.format"]);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::vault::{PasswordLoginConfig, PasswordLoginFormat};

    #[test]
    fn v0_1_release_keeps_kebab_kind_and_format() {
        let secret = VaultSecret::OauthTokens {
            provider: "google".into(),
            refresh_token: "r".into(),
            access_token: None,
            access_token_expires_at: None,
            scopes: vec![],
            secure_notes: None,
        };
        let body = secret_cleartext_for_wire(&secret, WireVersion::V0_1).unwrap();
        assert_eq!(body["kind"], "oauth-tokens");
    }

    #[test]
    fn v0_2_release_camelizes_kind_and_login_config_format() {
        let secret = VaultSecret::Password {
            username: Some("u".into()),
            password: "p".into(),
            totp: None,
            login_config: Some(PasswordLoginConfig {
                login_url: "https://example.com/login".into(),
                format: PasswordLoginFormat::FormUrlencoded,
                username_field: None,
                password_field: None,
                totp_field: None,
                extra_fields: None,
                success_status: None,
            }),
            secure_notes: None,
            custom_fields: vec![],
        };
        // 0.1 stays kebab.
        let v01 = secret_cleartext_for_wire(&secret, WireVersion::V0_1).unwrap();
        assert_eq!(v01["kind"], "password");
        assert_eq!(v01["loginConfig"]["format"], "form-urlencoded");
        // 0.2 up-converts the renamed values; the single-word `kind`
        // (`password`) is unchanged either way.
        let v02 = secret_cleartext_for_wire(&secret, WireVersion::V0_2).unwrap();
        assert_eq!(v02["kind"], "password");
        assert_eq!(v02["loginConfig"]["format"], "formUrlencoded");
    }

    #[test]
    fn v0_2_release_camelizes_multiword_kind() {
        let secret = VaultSecret::DidSelfIssued {
            did: "did:webvh:x".into(),
            signing_key_id: "did:webvh:x#k".into(),
            secure_notes: None,
        };
        let v02 = secret_cleartext_for_wire(&secret, WireVersion::V0_2).unwrap();
        assert_eq!(v02["kind"], "didSelfIssued");
        // Variant fields are already camelCase (serde `rename_all`) and untouched.
        assert_eq!(v02["signingKeyId"], "did:webvh:x#k");
    }
}
