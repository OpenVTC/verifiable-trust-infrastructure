//! `vtc/admin/invites/{create,list}/0.2` and `vtc/admin/invites/revoke/0.1` —
//! admin onboarding.
//!
//! Mirrors the `vtc admin invite` CLI, from the running daemon. Each is a
//! signed document served by the spine on every transport
//! (`trust_tasks::admin_tasks`); none has a REST route.
//!
//! - `create` mints a fresh single-use install URL and claim code. With `did`
//!   it is a **wallet** invitation: the token names `did`, claimed by signing
//!   as it (`vtc/install/claim/{start,finish}/0.3`), and an `Admin` ACL grant
//!   is written for it now if it holds none. Without `did` it is a **passkey**
//!   invitation: the token names no DID, the administrator's DID is derived
//!   from the passkey registered at `vtc/install/claim/passkey/finish/0.1`,
//!   and the authority that entry will carry is recorded with the invitation
//!   ([`InvitedAuthority`]) for finish (item 9) to write. Either way the
//!   invitation confers unrestricted authority, so writing that grant — or,
//!   for a passkey invitation, always — takes the inviter's passkey gesture
//!   bound to the invite and another unrestricted admin's consent (create 0.2
//!   item 4).
//! - `list` lists every persisted install-token row with its kind and a
//!   derived status (`issued` / `consumed` / `expired`).
//! - `revoke` removes an invite by deleting its install-token row.

use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;
use vti_common::audit::{AdminInviteData, AuditEvent};
use vti_common::auth::extractor::AuthClaims;
use vti_common::error::AppError;

use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use crate::auth::session::now_epoch;
use crate::error::TaskError;
use crate::install::{
    INSTALL_TOKEN_DEFAULT_TTL_SECS, InstallTokenSigner, InstallTokenState, InvitedAuthority,
    claim_secret, mint_install_token, mint_passkey_install_token,
};
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct CreateInviteRequest {
    /// The DID a **wallet** invitation is for. Absent, the invitation is a
    /// **passkey** invitation: the administrator's DID is derived from the
    /// passkey the invitee registers.
    #[serde(default)]
    pub did: Option<String>,
    /// Token TTL in seconds. Defaults to
    /// [`INSTALL_TOKEN_DEFAULT_TTL_SECS`] (15 minutes) when omitted.
    /// Cap at 24 h to keep stale invites from accumulating in the
    /// keyspace.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    /// Operator-supplied label for the ACL entry the invitation writes — now
    /// for a wallet invitation whose DID has none, at the claim for a passkey
    /// invitation. Ignored when a wallet invitation's DID already has one.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct CreateInviteResponse {
    /// `jti` of the minted install token — also the key the GET +
    /// DELETE surfaces use.
    pub jti: String,
    /// Whether this is a wallet or a passkey invitation.
    pub kind: InviteKind,
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
    /// `true` when the call also wrote the ACL entry; `false` when a wallet
    /// invitation's DID was already an admin (idempotent), and always for a
    /// passkey invitation, whose entry is written when it is claimed.
    pub acl_entry_created: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct InviteSummary {
    pub jti: String,
    /// Whether this is a wallet or a passkey invitation.
    pub kind: InviteKind,
    pub status: InviteStatus,
    /// The administrator's DID: a wallet invitation's always (but for legacy
    /// rows persisted before the field landed, safe to clean up via revoke);
    /// a passkey invitation's once it is consumed — the DID derived from the
    /// passkey that claimed it.
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

/// `vtc/_shared/0.2/invite#InviteKind`: whether an invitation names the DID
/// that claims it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[derive(utoipa::ToSchema)]
pub enum InviteKind {
    /// Names a DID, claimed by signing as it (`vtc/install/claim/*/0.3`).
    Wallet,
    /// Names none; the administrator's DID is the claiming passkey's own
    /// `did:key` (`vtc/install/claim/passkey/*/0.1`).
    Passkey,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
#[derive(utoipa::ToSchema)]
pub enum InviteStatus {
    Issued,
    Consumed,
    Expired,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct ListInvitesResponse {
    pub invites: Vec<InviteSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RevokeInviteResponse {
    pub jti: String,
}

// ---------------------------------------------------------------------------
// POST handler
// ---------------------------------------------------------------------------

/// The longest an invite may live.
pub(crate) const MAX_TTL_SECONDS: u64 = 24 * 60 * 60;

/// `vtc/admin/invites/create:ttlTooLong` — `ttlSeconds` exceeds the 24-hour
/// maximum.
pub const CREATE_INVITE_ERR_TTL_TOO_LONG: &str =
    vti_specs::vtc::admin::invites::create::v0_2::error_codes::TTL_TOO_LONG.code;
/// `vtc/admin/invites/revoke:notFound` — no invite with that `jti`.
pub const REVOKE_INVITE_ERR_NOT_FOUND: &str =
    vti_specs::vtc::admin::invites::revoke::v0_1::error_codes::NOT_FOUND.code;

/// What [`check_invite`] decided, carried to [`commit_invite`] once the
/// caller has settled whatever the invite costs.
#[derive(Debug)]
pub(crate) struct InvitePlan {
    ttl_seconds: u64,
    /// `true` when the invite grants an **unrestricted** admin entry: a
    /// wallet invitation whose DID holds no ACL entry, or any passkey
    /// invitation (create 0.2 item 4: issuing it is the grant, since nobody
    /// is present to authorise it at the claim). A grant of unrestricted
    /// authority costs what one costs on `acl/grant` — the caller's passkey
    /// gesture bound to this invite, and another unrestricted admin's consent
    /// (VTI-APV-014). The caller settles both before [`commit_invite`].
    pub(crate) grants_admin: bool,
}

/// The subject a passkey invitation's consent is parked under, where a wallet
/// invitation's is its DID: the administrator's DID does not exist until the
/// claim. Stable, so the approved action re-checks against the same subject,
/// and not a DID, so it can name no ACL entry.
pub(crate) const PASSKEY_INVITATION_SUBJECT: &str = "urn:openvtc:vtc:admin-invite:passkey";

/// Every check that decides whether `actor` may invite `req.did`, before the
/// invite costs anything.
pub(crate) async fn check_invite(
    state: &AppState,
    actor: &AuthClaims,
    req: &CreateInviteRequest,
) -> Result<InvitePlan, TaskError> {
    if let Some(did) = req.did.as_deref()
        && !did.starts_with("did:")
    {
        return Err(
            AppError::Validation(format!("did must start with 'did:' (got '{did}')")).into(),
        );
    }

    let ttl_seconds = req.ttl_seconds.unwrap_or(INSTALL_TOKEN_DEFAULT_TTL_SECS);
    let out_of_range = || {
        AppError::Validation(format!(
            "ttl_seconds must be between 1 and {MAX_TTL_SECONDS}",
        ))
    };
    // Only the upper bound is declared (`ttlTooLong`); a zero TTL is the same
    // 400 without a code.
    if ttl_seconds > MAX_TTL_SECONDS {
        return Err(TaskError::declared(
            CREATE_INVITE_ERR_TTL_TOO_LONG,
            out_of_range(),
        ));
    }
    if ttl_seconds == 0 {
        return Err(out_of_range().into());
    }

    // The grant below makes a community administrator with the full ceiling.
    // Inviting one is granting one (vtc.roles.assign, design §4 "admin
    // invites"), bounded by the inviter's own entry like any grant
    // (VTI-ACL-071, VTI-ACL-053): only a caller who could have granted it with
    // acl/grant may invite it.
    let inviter = crate::acl::get_acl_entry(&state.acl_ks, &actor.did)
        .await?
        .ok_or_else(|| AppError::Forbidden(format!("{} has no ACL entry", actor.did)))?;
    // A passkey invitation's DID does not exist yet; the check is of the
    // authority, which is the same for either kind.
    let mut invited = VtcAclEntry::new(
        req.did
            .clone()
            .unwrap_or_else(|| "did:key:passkey-invitation".into()),
        VtcRole::Admin,
        crate::acl::AdminAuthority::community_admin(),
        actor.did.clone(),
    );
    invited.expires_at = None;
    if let Err(refusal) =
        crate::acl::granting::check_write(&inviter, &invited, crate::auth::session::now_epoch())
    {
        return Err(AppError::Forbidden(format!(
            "inviting an administrator grants a community administrator: {refusal}"
        ))
        .into());
    }

    require_install_signer(state)?;
    require_public_url(state).await?;
    require_vtc_did(state).await?;

    // Ensure the target DID has an Admin ACL grant. Mirrors the CLI:
    // idempotent — leaves a pre-existing grant untouched (we don't downgrade
    // non-Admin DIDs here, since that would mean a separate role change is
    // needed first).
    let Some(did) = req.did.as_deref() else {
        // A passkey invitation always confers the authority (create 0.2
        // item 4).
        return Ok(InvitePlan {
            ttl_seconds,
            grants_admin: true,
        });
    };
    let grants_admin = match get_acl_entry(&state.acl_ks, did).await? {
        Some(existing) if existing.is_community_admin() => false,
        Some(_) => {
            return Err(AppError::Conflict(format!(
                "did {did} already has a non-admin ACL grant; revoke it first \
                 (acl/revoke) before inviting"
            ))
            .into());
        }
        None => true,
    };
    Ok(InvitePlan {
        ttl_seconds,
        grants_admin,
    })
}

/// Mint the invite [`check_invite`] planned, writing the admin entry it
/// grants. The caller has already settled the gesture and the consent a
/// granting invite costs.
pub(crate) async fn commit_invite(
    state: &AppState,
    actor: &AuthClaims,
    req: CreateInviteRequest,
    plan: InvitePlan,
) -> Result<CreateInviteResponse, TaskError> {
    let InvitePlan {
        ttl_seconds,
        grants_admin,
    } = plan;
    let signer = require_install_signer(state)?;
    let base_url = require_public_url(state).await?;
    let vtc_did = require_vtc_did(state).await?;
    let issued_via = format!("admin-ui/{}", env!("CARGO_PKG_VERSION"));

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

    let (minted, kind, acl_entry_created) = match req.did.as_deref() {
        None => {
            // A passkey invitation: nothing in the ACL until the claim, whose
            // DID nobody knows yet. The authority it will confer — what a
            // wallet invitation writes now — is recorded with it, delegated by
            // the inviter (create 0.2 item 3).
            let minted = mint_passkey_install_token(signer.as_ref(), &vtc_did, ttl_seconds)?;
            state
                .install_store
                .record_issued_passkey(
                    &minted.jti,
                    minted.cnonce_bytes,
                    *minted.ephemeral_signing_key,
                    expires_at,
                    Some(claim_code_hash),
                    InvitedAuthority {
                        admin: crate::acl::AdminAuthority::community_admin(),
                        invited_by: Some(actor.did.clone()),
                        issued_via,
                        label: Some(
                            req.label
                                .clone()
                                .unwrap_or_else(|| "admin invite (passkey)".into()),
                        ),
                    },
                )
                .await?;
            (minted, InviteKind::Passkey, false)
        }
        Some(did) => {
            let acl_entry_created = if grants_admin {
                // Re-read under the commit: an entry written for this DID
                // since the check must not be overwritten by an unrestricted
                // admin row.
                if get_acl_entry(&state.acl_ks, did).await?.is_some() {
                    return Err(AppError::Conflict(format!(
                        "did {did} gained an ACL entry while this invite was being approved; \
                         send it again"
                    ))
                    .into());
                }
                let label = req
                    .label
                    .clone()
                    .unwrap_or_else(|| "admin invite (web)".into());
                let entry = VtcAclEntry {
                    did: did.to_string(),
                    role: VtcRole::Admin,
                    label: Some(label),
                    admin: crate::acl::AdminAuthority::community_admin(),
                    // A grant is a delegation (vtc-admin-roles.md §6.3).
                    delegated_by: Some(actor.did.clone()),
                    created_at: now_epoch(),
                    created_by: issued_via,
                    updated_at: None,
                    updated_by: None,
                    expires_at: None,
                    resource_grants: Vec::new(),
                    group_grants: Vec::new(),
                    label_set_by_subject: false,
                    suspension: None,
                };
                store_acl_entry(&state.acl_ks, &entry).await?;
                true
            } else {
                false
            };
            let minted = mint_install_token(signer.as_ref(), &vtc_did, did, ttl_seconds)?;
            state
                .install_store
                .record_issued(
                    &minted.jti,
                    minted.cnonce_bytes,
                    *minted.ephemeral_signing_key,
                    expires_at,
                    Some(claim_code_hash),
                    Some(did.to_string()),
                )
                .await?;
            (minted, InviteKind::Wallet, acl_entry_created)
        }
    };
    crate::admin_actions::record_effect(state).await;

    let install_url = format!(
        "{}/admin/install?token={}",
        base_url.trim_end_matches('/'),
        minted.jwt
    );

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &actor.did,
                req.did.as_deref(),
                AuditEvent::AdminInviteCreated(AdminInviteData {
                    jti: minted.jti.to_string(),
                    admin_did: req.did.clone(),
                }),
            )
            .await?;
    }

    info!(
        target_did = req.did.as_deref().unwrap_or("(passkey)"),
        jti = %minted.jti,
        ?kind,
        ttl_seconds,
        "admin invite minted"
    );

    Ok(CreateInviteResponse {
        jti: minted.jti.to_string(),
        kind,
        install_url,
        claim_code,
        expires_at,
        acl_entry_created,
    })
}

// ---------------------------------------------------------------------------
// GET handler
// ---------------------------------------------------------------------------

/// `vtc/admin/invites/list/0.2`.
pub(crate) async fn list_invites(state: &AppState) -> Result<ListInvitesResponse, AppError> {
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
    Ok(ListInvitesResponse { invites })
}

// ---------------------------------------------------------------------------
// DELETE handler
// ---------------------------------------------------------------------------

/// `vtc/admin/invites/revoke/0.1`, by `actor`.
pub(crate) async fn revoke_invite(
    state: &AppState,
    actor: &str,
    jti_str: &str,
) -> Result<RevokeInviteResponse, TaskError> {
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
    //
    // That is a divergence from `vtc/admin/invites/revoke/0.1`, which refuses
    // a consumed row with `alreadyConsumed`; the admin UI's "Remove" action on
    // consumed rows depends on it (#1600 leaves the code baselined).
    let not_found = || {
        TaskError::declared(
            REVOKE_INVITE_ERR_NOT_FOUND,
            AppError::NotFound(format!("no invite for jti {jti}")),
        )
    };
    let existed = state.install_store.get_token(&jti).await?;
    if existed.is_none() {
        return Err(not_found());
    }

    if !state.install_store.delete_token(&jti).await? {
        // Token vanished between the peek and the delete — another
        // admin raced us. Surface as NotFound so the caller sees
        // the same outcome they would on a stale jti.
        return Err(not_found());
    }

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                actor,
                None,
                AuditEvent::AdminInviteRevoked(AdminInviteData {
                    jti: jti.to_string(),
                    admin_did: None,
                }),
            )
            .await?;
    }

    info!(%jti, "admin invite removed");

    Ok(RevokeInviteResponse {
        jti: jti.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn summarise(jti: Uuid, state: InstallTokenState, now: DateTime<Utc>) -> InviteSummary {
    match state {
        InstallTokenState::Issued {
            exp,
            admin_did,
            authority,
            ..
        } => {
            let status = if exp < now {
                InviteStatus::Expired
            } else {
                InviteStatus::Issued
            };
            InviteSummary {
                jti: jti.to_string(),
                kind: kind_of(authority.is_some()),
                status,
                target_did: admin_did,
                expires_at: Some(exp),
                consumed_at: None,
            }
        }
        InstallTokenState::Consumed {
            at,
            admin_did,
            passkey,
        } => InviteSummary {
            jti: jti.to_string(),
            kind: kind_of(passkey),
            status: InviteStatus::Consumed,
            target_did: admin_did,
            expires_at: None,
            consumed_at: Some(at),
        },
    }
}

/// A row that recorded an [`InvitedAuthority`] is a passkey invitation; every
/// other row named its DID.
fn kind_of(passkey: bool) -> InviteKind {
    if passkey {
        InviteKind::Passkey
    } else {
        InviteKind::Wallet
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
