//! Install token state machine + claim-secret helpers.
//!
//! Implements **M0.4** of the VTC MVP Phase 0 plan. The install
//! token is the one-time bearer credential an operator clicks to
//! claim a passkey for an admin DID — first-time setup via
//! `vtc setup`, and ongoing admin invites via `vtc admin invite`
//! or `POST /v1/admin/invites`. This module owns:
//!
//! - **[`token`]** — `InstallToken` claims + the EdDSA JWT
//!   signer/verifier derived from the VTC's master seed via HKDF.
//! - **[`state_machine`]** — the `install` keyspace state machine
//!   gating each invite (`Issued` → `Consumed`), with the
//!   **claim-window** pattern adopted from
//!   `webvh-common::server::passkey::store` (plan D12). A failed
//!   WebAuthn ceremony doesn't burn the token — only a successful
//!   `finish_claim` does.
//! - **[`claim_secret`]** — Argon2id-hashed out-of-band code each
//!   invite carries. Defense in depth: a leaked install URL alone
//!   is insufficient to claim the passkey; the invitee also needs
//!   the code, which travels through a separate channel.
//! - **[`INSTALL_TOKEN_LOCK`]** — a single process-wide async
//!   mutex guarding the state-machine transitions so two concurrent
//!   `start_claim` calls on the same token can't both pass the
//!   "claimed_at not set within the window" check.
//!
//! See spec §4.1 / §4.2 for the consumer-facing flow.

pub mod claim_secret;
pub mod state_machine;
pub mod token;

pub use state_machine::{
    InstallTokenState, InstallTokenStore, InviteGrant, InvitedAuthority, PendingBreakGlassAcl,
    PendingEmergencyBootstrap, StartClaimOutcome,
};
pub use token::{
    INSTALL_AUDIENCE, INSTALL_SESSION_AUDIENCE, INSTALL_SESSION_DEFAULT_TTL_SECS, INSTALL_SUBJECT,
    INSTALL_TOKEN_DEFAULT_TTL_SECS, InstallSessionClaims, InstallTokenClaims, InstallTokenSigner,
    mint_install_session_token, mint_install_token, mint_passkey_install_token,
    parse_install_token,
};

use tokio::sync::Mutex;

/// Process-wide async mutex serialising every install-token state
/// machine transition. Mirrors VTA's `MODE_B_LOCK` invariant — the
/// claim-check then claim-set sequence must be atomic across
/// concurrent Axum tasks. Cheap when idle.
pub static INSTALL_TOKEN_LOCK: Mutex<()> = Mutex::const_new(());

// Backwards-compatible alias. The old name leaked the abandoned
// "carve-out" model into call sites; new code should use
// `INSTALL_TOKEN_LOCK` directly. Remove once internal callers
// migrate.
#[doc(hidden)]
pub use INSTALL_TOKEN_LOCK as INSTALL_CARVEOUT_LOCK;

/// Write a **wallet** invitation's administrator entry (create 0.2 item 3) as
/// a provisional entry: expiring with invitation `jti` at `invite_expires` (or
/// at `floor`, an earlier open invitation's expiry, when that is later), and
/// recorded as an [`InviteGrant`] so its claim makes it permanent and its
/// revocation removes it (#2660). Used by `vtc/admin/invites/create/0.2` and
/// the offline `vtc admin invite --did`.
pub async fn write_invite_entry(
    acl_ks: &vti_common::store::KeyspaceHandle,
    install_store: &InstallTokenStore,
    jti: &uuid::Uuid,
    mut entry: crate::acl::VtcAclEntry,
    invite_expires: chrono::DateTime<chrono::Utc>,
    floor: Option<u64>,
) -> Result<(), vti_common::error::AppError> {
    let expires_at = (invite_expires.timestamp().max(0) as u64).max(floor.unwrap_or(0));
    entry.expires_at = Some(expires_at);
    // The record first: a crash before the entry leaves a record matching
    // nothing, never an entry no revocation can find.
    install_store
        .record_invite_grant(
            jti,
            &InviteGrant {
                did: entry.did.clone(),
                created_at: entry.created_at,
                expires_at,
            },
        )
        .await?;
    crate::acl::store_acl_entry(acl_ks, &entry).await
}

/// Queue the audit of an ACL write an offline command just made — the
/// break-glass — for the daemon to record on its next boot.
///
/// An offline command runs with the daemon stopped, holds no audit writer,
/// and by design skips what the daemon enforces on the same change: the
/// step-up, another admin's consent to an unrestricted grant (VTI-APV-014),
/// the attrition rules (VTI-APV-009). It is the way out when those rules
/// have nobody left to satisfy them. So it must leave a trace: this writes the
/// fact into the `install` keyspace, and the daemon turns each into an
/// `AclBreakGlassWritten` row when it next starts. Call it in the same store
/// session as the write, before `persist`.
pub async fn record_offline_acl_write(
    store: &vti_common::store::Store,
    command: &str,
    action: &str,
    did: &str,
    role: Option<&crate::acl::VtcRole>,
    contexts: &[String],
) -> Result<(), vti_common::error::AppError> {
    let install = InstallTokenStore::new(store.keyspace(crate::store::keyspaces::INSTALL)?);
    // Who must acknowledge it (VTI-VTC-023): every administrator holding a role
    // as the write is made.
    let now = crate::auth::session::now_epoch();
    let admins = crate::acl::list_acl_entries(&store.keyspace(crate::store::keyspaces::ACL)?)
        .await?
        .into_iter()
        .filter(|e| e.admin.is_administrator() && !e.is_expired(now))
        .map(|e| e.did)
        .collect();
    install
        .record_break_glass(&PendingBreakGlassAcl {
            command: command.to_string(),
            action: action.to_string(),
            did: did.to_string(),
            role: role.map(|r| r.to_string()).unwrap_or_default(),
            contexts: contexts.to_vec(),
            operator_hostname: gethostname::gethostname().to_string_lossy().into_owned(),
            invoked_at: chrono::Utc::now(),
            admins,
        })
        .await
}
