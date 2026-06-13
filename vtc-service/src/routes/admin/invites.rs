//! `/v1/admin/invites/*` — REST surface for admin onboarding.
//!
//! Mirrors the `vtc admin invite` CLI exactly, just over HTTP from
//! the running daemon:
//!
//! - `POST /v1/admin/invites` mints a fresh single-use install URL
//!   for `--did`, ensuring an `Admin` ACL grant exists first (so the
//!   new admin can actually log in once they claim the passkey).
//! - `GET  /v1/admin/invites` lists every persisted install-token
//!   row with a derived status (`issued` / `consumed` / `expired`).
//! - `DELETE /v1/admin/invites/{jti}` revokes an outstanding invite
//!   by deleting its install-token row. Refuses to revoke an
//!   already-consumed invite.
//!
//! All three routes are gated by [`AdminAuth`] + Trust-Task at the
//! router layer; reaching a handler implies both checks passed.
//!
//! No step-up UV is required — minting an invite doesn't enrol a
//! passkey for the caller, only for the *target* DID once they claim
//! the URL. The new admin's WebAuthn registration ceremony covers
//! that side.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;
use vti_common::auth::AdminAuth;
use vti_common::error::AppError;

use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use crate::auth::session::now_epoch;
use crate::install::{
    INSTALL_TOKEN_DEFAULT_TTL_SECS, InstallTokenSigner, InstallTokenState, claim_secret,
    mint_install_token,
};
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInviteRequest {
    /// Admin DID the install URL grants a passkey for.
    pub did: String,
    /// Token TTL in seconds. Defaults to
    /// [`INSTALL_TOKEN_DEFAULT_TTL_SECS`] (15 minutes) when omitted.
    /// Cap at 24 h to keep stale invites from accumulating in the
    /// keyspace.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    /// Operator-supplied label for the ACL entry if one needs to be
    /// created. Ignored when the ACL entry already exists.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInviteResponse {
    /// `jti` of the minted install token — also the key the GET +
    /// DELETE surfaces use.
    pub jti: String,
    /// Clickable install URL pointing at the admin SPA's install
    /// page on this daemon's `public_url`.
    pub install_url: String,
    /// Out-of-band claim code the invitee must type alongside the
    /// URL to complete the ceremony. Returned **once** — the
    /// daemon stores only its Argon2id hash, so a lost code
    /// requires re-minting the invite. The operator delivers URL
    /// and code through separate channels.
    pub claim_code: String,
    /// Wall-clock expiry for the token.
    pub expires_at: DateTime<Utc>,
    /// `true` when the call also wrote the ACL entry; `false` when
    /// the target DID was already an admin (idempotent).
    pub acl_entry_created: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteSummary {
    pub jti: String,
    pub status: InviteStatus,
    /// Admin DID the invite was minted for. `None` only on
    /// legacy rows persisted before the field landed (those are
    /// safe to clean up via revoke). New invites always carry it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_did: Option<String>,
    /// `Issued` token expiry. `None` for `Consumed` rows (the
    /// state machine clears the timing data on transition).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// `Consumed` rows record the wall-clock at which the
    /// ceremony succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteStatus {
    Issued,
    Consumed,
    Expired,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListInvitesResponse {
    pub invites: Vec<InviteSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeInviteResponse {
    pub jti: String,
}

// ---------------------------------------------------------------------------
// POST handler
// ---------------------------------------------------------------------------

const MAX_TTL_SECONDS: u64 = 24 * 60 * 60;

pub async fn create_invite(
    _admin: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateInviteRequest>,
) -> Result<(StatusCode, Json<CreateInviteResponse>), AppError> {
    if !req.did.starts_with("did:") {
        return Err(AppError::Validation(format!(
            "did must start with 'did:' (got '{}')",
            req.did
        )));
    }

    let ttl_seconds = req.ttl_seconds.unwrap_or(INSTALL_TOKEN_DEFAULT_TTL_SECS);
    if ttl_seconds == 0 || ttl_seconds > MAX_TTL_SECONDS {
        return Err(AppError::Validation(format!(
            "ttl_seconds must be between 1 and {MAX_TTL_SECONDS}",
        )));
    }

    let signer = require_install_signer(&state)?;
    let base_url = require_public_url(&state).await?;
    let vtc_did = require_vtc_did(&state).await?;

    // Ensure the target DID has an Admin ACL grant. Mirrors the
    // CLI: idempotent — leaves a pre-existing grant untouched (we
    // don't downgrade non-Admin DIDs here, since that would mean
    // a separate role change is needed first).
    let acl_entry_created = match get_acl_entry(&state.acl_ks, &req.did).await? {
        Some(existing) if existing.role == VtcRole::Admin => false,
        Some(_) => {
            return Err(AppError::Conflict(format!(
                "did {} already has a non-admin ACL grant; revoke it first \
                 (DELETE /v1/acl/entries/{}) before inviting",
                req.did, req.did
            )));
        }
        None => {
            let label = req
                .label
                .clone()
                .unwrap_or_else(|| "admin invite (web)".into());
            let entry = VtcAclEntry {
                did: req.did.clone(),
                role: VtcRole::Admin,
                label: Some(label),
                allowed_contexts: vec![],
                created_at: now_epoch(),
                created_by: format!("admin-ui/{}", env!("CARGO_PKG_VERSION")),
                expires_at: None,
            };
            store_acl_entry(&state.acl_ks, &entry).await?;
            true
        }
    };

    let minted = mint_install_token(signer.as_ref(), &vtc_did, &req.did, ttl_seconds)?;
    let claim_code = claim_secret::generate();
    // Argon2id hashing is CPU-bound (~50–200 ms); keep it off the async REST
    // runtime so a burst of invite mints doesn't stall other requests (P0.10).
    let claim_code_hash = {
        let claim_code = claim_code.clone();
        tokio::task::spawn_blocking(move || claim_secret::hash(&claim_code))
            .await
            .map_err(|e| AppError::Internal(format!("claim-secret hash task failed: {e}")))??
    };
    let expires_at = Utc::now() + ChronoDuration::seconds(ttl_seconds as i64);
    state
        .install_store
        .record_issued(
            &minted.jti,
            minted.cnonce_bytes,
            *minted.ephemeral_signing_key,
            expires_at,
            Some(claim_code_hash),
            Some(req.did.clone()),
        )
        .await?;

    let install_url = format!(
        "{}/admin/install?token={}",
        base_url.trim_end_matches('/'),
        minted.jwt
    );

    info!(
        target_did = %req.did,
        jti = %minted.jti,
        ttl_seconds,
        "admin invite minted via REST"
    );

    Ok((
        StatusCode::OK,
        Json(CreateInviteResponse {
            jti: minted.jti.to_string(),
            install_url,
            claim_code,
            expires_at,
            acl_entry_created,
        }),
    ))
}

// ---------------------------------------------------------------------------
// GET handler
// ---------------------------------------------------------------------------

pub async fn list_invites(
    _admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<ListInvitesResponse>, AppError> {
    let now = Utc::now();
    let mut invites: Vec<InviteSummary> = state
        .install_store
        .list_tokens()
        .await?
        .into_iter()
        .map(|(jti, state)| summarise(jti, state, now))
        .collect();
    // Stable order — newest issued/consumed first by timestamp,
    // then jti for tie-breaking. Falls through to jti for rows
    // missing both timestamps.
    invites.sort_by(|a, b| {
        let a_ts = a.consumed_at.or(a.expires_at);
        let b_ts = b.consumed_at.or(b.expires_at);
        b_ts.cmp(&a_ts).then_with(|| a.jti.cmp(&b.jti))
    });
    Ok(Json(ListInvitesResponse { invites }))
}

// ---------------------------------------------------------------------------
// DELETE handler
// ---------------------------------------------------------------------------

pub async fn revoke_invite(
    _admin: AdminAuth,
    State(state): State<AppState>,
    Path(jti_str): Path<String>,
) -> Result<(StatusCode, Json<RevokeInviteResponse>), AppError> {
    let jti = jti_str
        .parse::<Uuid>()
        .map_err(|_| AppError::Validation(format!("invalid jti: '{jti_str}'")))?;

    // Both live (`Issued`) and terminal (`Consumed` / expired
    // `Issued`) rows are eligible for deletion. The original design
    // refused `Consumed` "to preserve the audit trail" but the
    // audit trail lives in the `CommunityInstalled` audit envelope,
    // not in the install_store row — keeping spent rows around just
    // accumulates clutter in the invites list with no security
    // benefit. 404 only when the row is genuinely absent.
    let existed = state.install_store.get_token(&jti).await?;
    if existed.is_none() {
        return Err(AppError::NotFound(format!("no invite for jti {jti}")));
    }

    if !state.install_store.delete_token(&jti).await? {
        // Token vanished between the peek and the delete — another
        // admin raced us. Surface as NotFound so the caller sees
        // the same outcome they would on a stale jti.
        return Err(AppError::NotFound(format!("no invite for jti {jti}")));
    }

    info!(%jti, "admin invite removed via REST");

    Ok((
        StatusCode::OK,
        Json(RevokeInviteResponse {
            jti: jti.to_string(),
        }),
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn summarise(jti: Uuid, state: InstallTokenState, now: DateTime<Utc>) -> InviteSummary {
    match state {
        InstallTokenState::Issued { exp, admin_did, .. } => {
            let status = if exp < now {
                InviteStatus::Expired
            } else {
                InviteStatus::Issued
            };
            InviteSummary {
                jti: jti.to_string(),
                status,
                target_did: admin_did,
                expires_at: Some(exp),
                consumed_at: None,
            }
        }
        InstallTokenState::Consumed { at, admin_did } => InviteSummary {
            jti: jti.to_string(),
            status: InviteStatus::Consumed,
            target_did: admin_did,
            expires_at: None,
            consumed_at: Some(at),
        },
    }
}

fn require_install_signer(state: &AppState) -> Result<&Arc<InstallTokenSigner>, AppError> {
    state
        .install_signer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "install signer not configured (run setup first)".into(),
        })
}

async fn require_public_url(state: &AppState) -> Result<String, AppError> {
    state
        .config
        .read()
        .await
        .public_url
        .clone()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "public_url not configured; cannot build install URL".into(),
        })
}

async fn require_vtc_did(state: &AppState) -> Result<String, AppError> {
    state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "vtc_did not configured (run setup first)".into(),
        })
}
