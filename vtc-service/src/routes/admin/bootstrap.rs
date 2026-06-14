//! `POST /v1/admin/bootstrap` — finalises the install flow by
//! writing the first admin ACL entry and emitting
//! `CommunityInstalled`.
//!
//! Implements **M0.6.2** of the VTC MVP Phase 0 plan. Consumes the
//! setup-session JWT minted by `POST /v1/install/claim/finish`
//! (M0.5.2). The token carries:
//!
//! - `sub` — the candidate admin `did:key`
//! - `install_jti` — the install-token `jti` it was derived from
//!
//! The earlier "carve-out" lockdown is gone — additional admin
//! invites mint their own per-row install tokens guarded by an
//! out-of-band claim secret, so the bootstrap call no longer needs
//! to slam the install surface shut afterwards. The
//! `claim_finish` ceremony already consumed this row's token; this
//! handler's job is just the first-admin ACL grant + audit event.

use std::sync::Arc;

use crate::acl::{VtcAclEntry, VtcRole, list_acl_entries, store_acl_entry};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;
use vti_common::audit::{AuditEvent, AuditWriter, CommunityInstalledData};
use vti_common::auth::passkey::store::get_passkey_user_by_did;
use vti_common::error::AppError;

use crate::acl::admin::{AdminEntry, RegisteredPasskey, store_admin_entry};
use crate::community::{CommunityProfile, load_profile, store_profile};
use crate::install::InstallTokenSigner;
use crate::server::AppState;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BootstrapRequest {
    pub setup_session_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct BootstrapResponse {
    pub admin_did: String,
    /// `event_id` of the persisted `CommunityInstalled` audit
    /// envelope. The caller can echo this in operator-facing UI so
    /// the install URL → bootstrap → audit-row chain is traceable.
    pub event_id: Uuid,
}

#[utoipa::path(
    post, path = "/admin/bootstrap", tag = "admin",
    request_body = BootstrapRequest,
    responses(
        (status = 200, description = "First admin bootstrapped; community installed", body = BootstrapResponse),
        (status = 409, description = "An admin already exists"),
    ),
)]
pub async fn bootstrap(
    State(state): State<AppState>,
    Json(req): Json<BootstrapRequest>,
) -> Result<(StatusCode, Json<BootstrapResponse>), AppError> {
    let signer = require_install_signer(&state)?;
    let audit_writer = require_audit_writer(&state)?;

    let claims = signer.decode_session(&req.setup_session_token)?;
    let admin_did = claims.sub;
    let install_jti = claims.install_jti;

    // Defence-in-depth: refuse if any Admin ACL entry already exists.
    // The install carve-out should make this impossible (the second
    // install-token claim would fail), but a misconfigured backup
    // restore could still land us here.
    for entry in list_acl_entries(&state.acl_ks).await? {
        if entry.role == VtcRole::Admin {
            return Err(AppError::Conflict(
                "an admin already exists; refusing to bootstrap a second one".into(),
            ));
        }
    }

    // M0.5.2 wrote the PasskeyUser at claim/finish; look it up so
    // the first RegisteredPasskey carries the same credential id
    // the passkey-login flow will eventually match against.
    let passkey_user = get_passkey_user_by_did(&state.passkey_ks, &admin_did)
        .await?
        .ok_or_else(|| {
            AppError::Unauthorized(
                "no passkey registered for the candidate admin DID — run the install claim first"
                    .into(),
            )
        })?;
    let first_cred = passkey_user.credentials.first().ok_or_else(|| {
        AppError::Internal("admin passkey user has no credentials persisted".into())
    })?;
    let cred_id_hex = hex::encode(<_ as AsRef<[u8]>>::as_ref(first_cred.cred_id()));

    // claim_finish already wrote the AdminEntry for the install
    // credential. Only fall back to building one here if it's
    // somehow missing — recovery against a partial install where
    // the AdminEntry write failed but the PasskeyUser succeeded.
    let now = Utc::now();
    if crate::acl::admin::get_admin_entry(&state.passkey_ks, &admin_did)
        .await?
        .is_none()
    {
        let registered = RegisteredPasskey {
            credential_id: cred_id_hex,
            // The install ceremony has no operator label channel;
            // the operator relabels their device later via
            // `PATCH /v1/admin/passkeys/{id}` (M0.6.3). Until then
            // we ship a placeholder rather than an empty string so
            // admin UIs don't render blank.
            label: "install".into(),
            transports: Vec::new(),
            registered_at: now,
            last_used_at: None,
        };
        let admin_entry = AdminEntry {
            did: admin_did.clone(),
            passkeys: vec![registered],
            extensions: serde_json::Value::Null,
            created_at: now,
        };
        store_admin_entry(&state.passkey_ks, &admin_entry).await?;
    }

    let acl_entry = VtcAclEntry {
        did: admin_did.clone(),
        role: VtcRole::Admin,
        label: Some("first admin (install bootstrap)".into()),
        allowed_contexts: vec![],
        created_at: now_unix(),
        created_by: "did:key:vtc-install".into(),
        expires_at: None,
    };
    store_acl_entry(&state.acl_ks, &acl_entry).await?;

    // Initialise the singleton community profile if not already present.
    // Per spec §5.1, `community_did` is immutable from this point — so
    // we only lock it in when `vtc_did` is actually configured. The
    // operator fills in `name` / `description` / etc. afterwards via
    // `PUT /v1/community/profile`.
    let vtc_did = state.config.read().await.vtc_did.clone();
    if let Some(did) = vtc_did.as_deref()
        && load_profile(&state.community_ks).await?.is_none()
    {
        let profile = CommunityProfile::new(did, "");
        store_profile(&state.community_ks, &profile).await?;
    }

    let community_did = vtc_did.unwrap_or_else(|| "did:key:vtc-uninitialised".to_string());

    let envelope = audit_writer
        .write(
            &admin_did,
            None,
            AuditEvent::CommunityInstalled(CommunityInstalledData {
                community_did,
                install_token_jti: install_jti,
            }),
        )
        .await?;

    info!(%admin_did, event_id = %envelope.event_id, "community installed");

    Ok((
        StatusCode::OK,
        Json(BootstrapResponse {
            admin_did,
            event_id: envelope.event_id,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_install_signer(state: &AppState) -> Result<&Arc<InstallTokenSigner>, AppError> {
    state
        .install_signer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "install signer not configured (run setup first)".into(),
        })
}

fn require_audit_writer(state: &AppState) -> Result<&AuditWriter, AppError> {
    state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured (run setup first)".into(),
        })
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
