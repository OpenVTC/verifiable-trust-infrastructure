//! Enrolling and revoking **step-up approvers** — the operations behind
//! `auth/step-up/approver/{invite,redeem/start,redeem/finish,enroll,list,
//! revoke}/0.1` and `vtc/install/claim/{start,finish}/0.3`, and the offline
//! `vtc admin enrol-approver`.
//!
//! Every one is served as a Trust Task on the signed-document spine
//! ([`crate::trust_tasks::step_up_approver_tasks`],
//! [`crate::trust_tasks`]'s install family); this module is the operation and
//! the spine handler is the only door. The binding itself, and the checks a
//! binding must pass, are [`crate::acl::approver`]'s.
//!
//! ## The first-factor problem (design note §6, VTI-APV-016)
//!
//! A second factor bound on the strength of the first adds nothing. So every
//! binding written here rests on an anchor **independent of the subject's
//! signing key**, proves possession of the approver key (its `purpose: enrol`
//! statement over a challenge minted here), carries the subject's **own**
//! signature (so nobody holding an invite binds their device to someone else's
//! DID), and is audited naming the anchor:
//!
//! | route | anchor | `enrolledVia` |
//! |---|---|---|
//! | R1 install claim 0.3 | the install token + its claim code | `install` |
//! | R2 invite → redeem | another administrator's authority, behind their own bound step-up | `invite` |
//! | R3 self-service enrol | a step-up factor the subject already holds, over these terms | `selfService` |
//! | R4 offline invite → redeem | host access, daemon stopped | `offline` |
//!
//! ## Storage (`step_up_approvers`, beside the bindings)
//!
//! - `invite:<sha256(token)>` — an [`Invite`]; only hashes of the token and
//!   claim code are kept, and five wrong codes void it.
//! - `redeem:<enrollmentId>` — a [`RedeemCeremony`], at most five minutes.
//! - `claim:<claimId>` — an install claim 0.3 between start and finish.
//! - `pending:<installJti>` — an approver claimed at install, waiting for
//!   `vtc/admin/bootstrap` to write the administrator it belongs to; discarded
//!   if the setup-session token lapses unused (claim/finish 0.3 item 6).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use trust_tasks_rs::specs::auth::step_up::approver::attest::v0_1 as attest;
use trust_tasks_rs::specs::auth::step_up::approver::enroll::v0_1 as enroll;
use trust_tasks_rs::specs::auth::step_up::approver::invite::v0_1 as invite;
use trust_tasks_rs::specs::auth::step_up::approver::list::v0_1 as list;
use trust_tasks_rs::specs::auth::step_up::approver::redeem::finish::v0_1 as redeem_finish;
use trust_tasks_rs::specs::auth::step_up::approver::redeem::start::v0_1 as redeem_start;
use trust_tasks_rs::specs::auth::step_up::approver::revoke::v0_1 as revoke;
use trust_tasks_rs::specs::vtc::install::claim::finish::v0_3 as claim_finish;
use trust_tasks_rs::specs::vtc::install::claim::start::v0_3 as claim_start;
use uuid::Uuid;
use vti_common::audit::{AuditEvent, StepUpApproverData};
use vti_common::auth::extractor::AuthClaims;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::acl::approver::{
    self, ApproverRecord, BindError, EnrolledVia, ExpectedApprover, ExpectedStatement,
    StatementError,
};
use crate::acl::bound_step_up::{self, ApproveRequest};
use crate::auth::session::now_epoch;
use crate::install::claim_secret;
use crate::server::AppState;

/// Wrong claim codes an invite survives; the fifth voids it (`redeem/start/0.1`
/// item 4).
pub const MAX_WRONG_CODES: u32 = 5;
/// A redemption ceremony's or an install claim's life (both RECOMMEND five
/// minutes).
pub const CEREMONY_TTL_SECS: u64 = 300;
/// An invite's life when the administrator names none (`invite/0.1` item 4).
pub const DEFAULT_INVITE_TTL_SECS: u64 = 900;
/// The longest an invite may live (`invite/0.1` item 4: 24 hours).
pub const MAX_INVITE_TTL_SECS: u64 = 24 * 3600;
/// Where the invite URL lands, under the console's mount.
pub const ENROL_PATH: &str = "/admin/enrol-approver";

/// `auth/step-up/approver/enroll/0.1` — the type the terms digest names.
pub const ENROLL_TYPE: &str = <enroll::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// A refusal one of these tasks answers with.
#[derive(Debug)]
pub enum ApproverTaskError {
    /// Under a code the task's specification declares — or, where it declares
    /// none for the case, a framework standard code — with optional details.
    Refused {
        code: &'static str,
        message: String,
        details: Option<Value>,
    },
    /// The act needs the caller's operation-bound step-up first; the request
    /// rides inline as `details.stepUpRequest`.
    StepUp(Box<ApproveRequest>),
    App(AppError),
}

impl From<AppError> for ApproverTaskError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

fn refused(
    code: trust_tasks_rs::DeclaredErrorCode,
    message: impl Into<String>,
) -> ApproverTaskError {
    ApproverTaskError::Refused {
        code: code.code,
        message: message.into(),
        details: None,
    }
}

type Result<T, E = ApproverTaskError> = std::result::Result<T, E>;

// ── records ─────────────────────────────────────────────────────────────────

/// An issued, unredeemed invite.
#[derive(Serialize, Deserialize)]
struct Invite {
    invite_id: String,
    subject: String,
    /// The administrator who issued it, or `host` for an offline invite.
    invited_by: String,
    via: EnrolledVia,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    /// Argon2id PHC string of the claim code ([`claim_secret::hash`]).
    code_hash: String,
    expires_at: u64,
    wrong_codes: u32,
    /// Five wrong codes were presented. Kept, so the next attempt is told
    /// `inviteVoided` rather than `inviteNotFound`.
    #[serde(default)]
    voided: bool,
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("invite_id", &self.invite_id)
            .field("subject", &self.subject)
            .field("invited_by", &self.invited_by)
            .field("expires_at", &self.expires_at)
            .field("wrong_codes", &self.wrong_codes)
            .field("voided", &self.voided)
            .finish_non_exhaustive()
    }
}

/// A redemption between start and finish.
#[derive(Serialize, Deserialize)]
struct RedeemCeremony {
    invite_key: String,
    subject: String,
    challenge: String,
    created_at: u64,
    expires_at: u64,
}

// Hand-written: `invite_key` names the invite by its token's hash, which is
// what a redemption is looked up by, so it stays out of logs like the token.
impl std::fmt::Debug for RedeemCeremony {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedeemCeremony")
            .field("invite_key", &"<redacted>")
            .field("subject", &self.subject)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// An install claim 0.3 between start and finish.
#[derive(Debug, Serialize, Deserialize)]
struct InstallClaim {
    jti: Uuid,
    admin_did: String,
    challenge: String,
    created_at: u64,
    expires_at: u64,
}

/// An approver claimed at install, waiting for the bootstrap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PendingInstallBinding {
    pub admin_did: String,
    pub approver_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The setup-session token's expiry: past it the binding is discarded.
    pub expires_at: u64,
}

fn invite_key(token: &str) -> String {
    format!("invite:{}", hex::encode(Sha256::digest(token.as_bytes())))
}
fn redeem_key(id: &str) -> String {
    format!("redeem:{id}")
}
/// Wrong claim codes presented against one install token at `claim/start 0.3`.
fn install_wrong_key(jti: &Uuid) -> String {
    format!("install_wrong:{jti}")
}

/// Count one more wrong claim code against `jti`; the new count.
async fn count_wrong_install_code(state: &AppState, jti: &Uuid) -> Result<u32, AppError> {
    // Serialised with the binding lock so two wrong guesses racing each other
    // both count.
    let _guard = crate::acl::approver::lock().await;
    let key = install_wrong_key(jti);
    let wrong = state
        .step_up_approvers_ks
        .get::<u32>(key.clone())
        .await?
        .unwrap_or(0)
        .saturating_add(1);
    state.step_up_approvers_ks.insert(key, &wrong).await?;
    Ok(wrong)
}

fn claim_key(id: &str) -> String {
    format!("claim:{id}")
}
fn pending_key(jti: &str) -> String {
    format!("pending:{jti}")
}

fn epoch_to_utc(t: u64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(t as i64, 0).unwrap_or_default()
}

/// 256 bits from the CSPRNG, base64url (VTI-SES-001).
fn random_b64(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut raw);
    B64.encode(raw)
}

fn random_hex(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut raw);
    hex::encode(raw)
}

/// Claim codes are typed by people: case and separators do not matter.
fn normalise_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

async fn vtc_did(state: &AppState) -> Result<String, AppError> {
    state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .ok_or_else(|| AppError::Config("this VTC has no DID configured yet".into()))
}

async fn audit(state: &AppState, actor: &str, data: StepUpApproverData) -> Result<(), AppError> {
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                actor,
                Some(&data.subject.clone()),
                AuditEvent::StepUpApproverChanged(data),
            )
            .await?;
    }
    Ok(())
}

fn stage(stage: &str, subject: &str) -> StepUpApproverData {
    StepUpApproverData {
        stage: stage.into(),
        subject: subject.into(),
        approver_did: None,
        enrolled_via: None,
        anchor: None,
        replaced: None,
        reason: None,
        expires_at: None,
    }
}

/// Whether `signer` is a console signing key's delegation — a key some
/// administrator signs operations with, which is never the subject's own DID
/// (enroll/0.1 item 1, redeem/start/0.1 item 1).
async fn is_delegated_key(state: &AppState, signer: &str) -> Result<bool, AppError> {
    Ok(
        crate::acl::console_key::get_delegation(&state.console_keys_ks, signer)
            .await?
            .is_some(),
    )
}

/// Whether administrator `actor` has standing over `subject`: a community-wide
/// administrator over anyone, a context-scoped one over a member whose entry
/// lies in their contexts (the visibility `acl/show` applies).
pub(crate) async fn admin_covers(
    state: &AppState,
    actor: &AuthClaims,
    subject: &str,
) -> Result<bool, AppError> {
    if actor.is_super_admin() {
        return Ok(true);
    }
    let entry = crate::acl::get_acl_entry(&state.acl_ks, subject)
        .await?
        .filter(|e| !e.is_expired(now_epoch()));
    Ok(entry.as_ref().is_some_and(|e| {
        vti_common::acl::is_acl_entry_visible(actor, &crate::routes::acl::as_vti_acl_entry(e))
    }))
}

/// After a binding: a session elevated before it existed was stepped up
/// through a route that stops counting the moment a dedicated factor exists
/// (the factor-union rule), so it is revoked now rather than left to lapse.
async fn after_binding(state: &AppState, subject: &str) -> Result<(), AppError> {
    crate::step_up_passkey::revoke_session_elevation(&state.sessions_ks, subject).await
}

fn bind_refusal(
    e: BindError,
    already: trust_tasks_rs::DeclaredErrorCode,
    too_many: trust_tasks_rs::DeclaredErrorCode,
    replace: Option<trust_tasks_rs::DeclaredErrorCode>,
) -> ApproverTaskError {
    match e {
        BindError::AlreadyBound => refused(
            already,
            "that approver DID is already bound, or was bound and revoked; generate a new one",
        ),
        BindError::TooMany => refused(
            too_many,
            format!(
                "the subject already holds {} live approvers; revoke one first",
                approver::MAX_PER_SUBJECT
            ),
        ),
        BindError::ReplaceNotFound => match replace {
            Some(code) => refused(code, "no such approver of this subject"),
            None => ApproverTaskError::App(AppError::Internal("unexpected replace".into())),
        },
        BindError::Internal(e) => ApproverTaskError::App(e),
    }
}

// ── invite/0.1 (R2) ────────────────────────────────────────────────────────

/// Every check that decides whether `admin_did` may issue `payload`, made
/// before the administrator is asked for a gesture: a gesture must never be
/// asked for an act that would be refused anyway.
pub async fn check_invite(
    state: &AppState,
    admin_did: &str,
    payload: &invite::Payload,
) -> Result<()> {
    use invite::error_codes as codes;
    if state.public_url.is_none() {
        return Err(AppError::Config(
            "public_url is not configured; an invite has no URL to carry".into(),
        )
        .into());
    }
    // invite/0.1 consumer item 1: never on the strength of the subject's own
    // key — whoever stole it would mint a factor for it.
    if payload.subject.as_str() == admin_did {
        return Err(refused(
            codes::SELF_INVITE,
            "an administrator does not invite themselves; ask another administrator",
        ));
    }
    // Item 3: the administrator's standing over the subject. This community
    // reserves it to its community-wide administrators, as for step-up
    // passkeys: binding a factor is an act of authority.
    if !crate::git_ns::ops::standing(state, admin_did)
        .await?
        .community_admin
    {
        return Err(ApproverTaskError::Refused {
            code: "permissionDenied",
            message: "only a community administrator invites a member to enrol a step-up \
                      approver"
                .into(),
            details: None,
        });
    }
    if !crate::git_ns::ops::standing(state, payload.subject.as_str())
        .await?
        .member
    {
        return Err(refused(
            codes::SUBJECT_UNKNOWN,
            "the subject is not a current member of this community",
        ));
    }
    let ttl = payload.ttl.map_or(DEFAULT_INVITE_TTL_SECS, |t| t.get());
    if ttl > MAX_INVITE_TTL_SECS {
        return Err(ApproverTaskError::Refused {
            code: codes::TTL_TOO_LONG.code,
            message: format!("ttl must be at most {MAX_INVITE_TTL_SECS} seconds"),
            details: Some(json!({ "maxTtl": MAX_INVITE_TTL_SECS })),
        });
    }
    Ok(())
}

/// What a freshly minted invite is, once.
pub struct MintedInvite {
    pub invite_id: String,
    pub token: String,
    pub url: String,
    pub claim_code: String,
    pub expires_at: u64,
}

/// Write an invite for `subject` into the approvers keyspace. Shared by the
/// online invite and the offline `vtc admin enrol-approver` (R4), which differ
/// only in who issued it.
async fn mint_invite(
    ks: &KeyspaceHandle,
    public_url: &str,
    subject: &str,
    invited_by: &str,
    via: EnrolledVia,
    label: Option<String>,
    ttl: u64,
) -> Result<MintedInvite, AppError> {
    // 256-bit token (≥ 128, invite/0.1 item 5) and a 50-bit claim code
    // (≥ 40); each kept only as a hash, the code as a slow salted one.
    let token = format!("sua_{}", random_b64(32));
    let claim_code = claim_secret::generate();
    let code = claim_code.clone();
    let code_hash = tokio::task::spawn_blocking(move || claim_secret::hash(&code))
        .await
        .map_err(|e| AppError::Internal(format!("claim-code hash task failed: {e}")))??;
    let invite_id = format!("sui_{}", random_hex(8));
    let expires_at = now_epoch().saturating_add(ttl);
    ks.insert(
        invite_key(&token),
        &Invite {
            invite_id: invite_id.clone(),
            subject: subject.to_string(),
            invited_by: invited_by.to_string(),
            via,
            label,
            code_hash,
            expires_at,
            wrong_codes: 0,
            voided: false,
        },
    )
    .await?;
    // The token rides in the fragment, which a browser never sends: it stays
    // out of every access log between here and the subject. The URL names no
    // subject (invite/0.1, *Correlation*).
    let url = format!(
        "{}{ENROL_PATH}#token={token}",
        public_url.trim_end_matches('/')
    );
    Ok(MintedInvite {
        invite_id,
        token,
        url,
        claim_code,
        expires_at,
    })
}

/// `auth/step-up/approver/invite/0.1`, issued by `admin_did`. The caller has
/// verified the administrator's proof and spent the step-up bound to this
/// document.
pub async fn issue_invite(
    state: &AppState,
    admin_did: &str,
    payload: &invite::Payload,
) -> Result<invite::Response> {
    check_invite(state, admin_did, payload).await?;
    let public_url = state.public_url.as_deref().unwrap_or_default();
    let subject = payload.subject.to_string();
    let ttl = payload.ttl.map_or(DEFAULT_INVITE_TTL_SECS, |t| t.get());
    let minted = mint_invite(
        &state.step_up_approvers_ks,
        public_url,
        &subject,
        admin_did,
        EnrolledVia::Invite,
        payload.label.as_ref().map(|l| l.to_string()),
        ttl,
    )
    .await?;
    // Item 7: the administrator, the subject and the expiry — never the token
    // or the code.
    audit(
        state,
        admin_did,
        StepUpApproverData {
            enrolled_via: Some(EnrolledVia::Invite.as_str().into()),
            anchor: Some(admin_did.into()),
            expires_at: Some(epoch_to_utc(minted.expires_at)),
            ..stage("invited", &subject)
        },
    )
    .await?;
    info!(admin = %admin_did, %subject, invite_id = %minted.invite_id, "step-up approver invite issued");
    serde_json::from_value(json!({
        "inviteId": minted.invite_id,
        "url": minted.url,
        "claimCode": minted.claim_code,
        "expiresAt": epoch_to_utc(minted.expires_at),
    }))
    .map_err(|e| AppError::Internal(format!("invite response: {e}")).into())
}

/// The invite every newly created administrator gets (`vtc-approver-step-up.md`
/// §6c, settled default §11.4): minted when the action that made them completes,
/// issued by its requester, and handed to that requester once on the action's
/// record — they deliver the claim code separately. The creation already took
/// the requester's step-up and another administrator's consent (VTI-APV-014),
/// so the invite rests on that anchor (R2) and costs nothing extra.
///
/// `Ok(None)` when the subject already holds a live step-up approver.
pub(crate) async fn invite_new_administrator(
    state: &AppState,
    creator: &str,
    subject: &str,
) -> Result<Option<Value>, AppError> {
    if !crate::acl::approver::live_approvers(state, subject)
        .await?
        .is_empty()
    {
        return Ok(None);
    }
    let public_url = state.public_url.as_deref().unwrap_or_default();
    let minted = mint_invite(
        &state.step_up_approvers_ks,
        public_url,
        subject,
        creator,
        EnrolledVia::Invite,
        Some("new administrator".into()),
        DEFAULT_INVITE_TTL_SECS,
    )
    .await?;
    audit(
        state,
        creator,
        StepUpApproverData {
            enrolled_via: Some(EnrolledVia::Invite.as_str().into()),
            anchor: Some(creator.into()),
            expires_at: Some(epoch_to_utc(minted.expires_at)),
            ..stage("invited", subject)
        },
    )
    .await?;
    info!(admin = %creator, %subject, invite_id = %minted.invite_id, "step-up approver invite issued for a new administrator");
    Ok(Some(json!({
        "inviteId": minted.invite_id,
        "url": minted.url,
        "claimCode": minted.claim_code,
        "expiresAt": epoch_to_utc(minted.expires_at),
    })))
}

/// R4: an invite minted on the host with the daemon stopped
/// (`vtc admin enrol-approver`). The same invite R2 issues — token in the URL,
/// claim code delivered separately — so proof of possession and the subject's
/// own signature still apply at redemption; only the issuer is the host. Like
/// every offline writer it queues an `install:break_glass:*` marker, which the
/// daemon audits at its next start (design note §6e).
pub async fn mint_offline_invite(
    store: &vti_common::store::Store,
    public_url: &str,
    subject: &str,
    ttl: u64,
) -> Result<MintedInvite, AppError> {
    if !subject.starts_with("did:") {
        return Err(AppError::Validation(format!(
            "--did must be a DID (got {subject:?})"
        )));
    }
    if ttl == 0 || ttl > MAX_INVITE_TTL_SECS {
        return Err(AppError::Validation(format!(
            "--ttl must be between 1 and {MAX_INVITE_TTL_SECS} seconds"
        )));
    }
    let acl_ks = store.keyspace(crate::store::keyspaces::ACL)?;
    if crate::acl::get_acl_entry(&acl_ks, subject)
        .await?
        .filter(|e| !e.is_expired(now_epoch()))
        .is_none()
    {
        return Err(AppError::NotFound(format!(
            "{subject} holds no ACL entry here; an approver answers only a member's step-ups \
             (add them first with `vtc acl add`)"
        )));
    }
    let ks = store.keyspace(crate::store::keyspaces::STEP_UP_APPROVERS)?;
    let minted = mint_invite(
        &ks,
        public_url,
        subject,
        "host",
        EnrolledVia::Offline,
        None,
        ttl,
    )
    .await?;
    crate::install::record_offline_acl_write(
        store,
        "vtc admin enrol-approver",
        "approverInvite",
        subject,
        None,
        &[],
    )
    .await?;
    Ok(minted)
}

// ── redeem/start/0.1 ───────────────────────────────────────────────────────

/// `auth/step-up/approver/redeem/start/0.1`, signed by `signer`, in the order
/// the specification gives: the signer's own DID, the invite by token hash,
/// the signer the invited subject (not counted), the claim code (counted;
/// the fifth wrong one voids), then a fresh ceremony.
pub async fn redeem_start(
    state: &AppState,
    signer: &str,
    payload: &redeem_start::Payload,
) -> Result<redeem_start::Response> {
    use redeem_start::error_codes as codes;
    let not_invited = || {
        refused(
            codes::NOT_INVITED_SUBJECT,
            "this redemption is not signed by the subject the invite was issued for, with a key \
             of their own DID",
        )
    };
    // Item 1: a delegated key acting for the subject is not the subject.
    if is_delegated_key(state, signer).await? {
        return Err(not_invited());
    }
    let ks = &state.step_up_approvers_ks;
    let key = invite_key(payload.token.as_str());
    let audience = vtc_did(state).await?;

    let (subject, invite_expires) = {
        let _guard = approver::lock().await;
        let Some(mut invite) = ks.get::<Invite>(key.clone()).await? else {
            // The same work as a real invite, so a wrong token and a wrong
            // code take the same time.
            let _ = tokio::task::spawn_blocking(|| claim_secret::hash("timing")).await;
            return Err(refused(
                codes::INVITE_NOT_FOUND,
                "no such invite, or it was already redeemed",
            ));
        };
        if invite.voided {
            return Err(refused(
                codes::INVITE_VOIDED,
                "this invite was voided after five wrong claim codes; ask the administrator for a \
                 new one",
            ));
        }
        if now_epoch() >= invite.expires_at {
            ks.remove(key).await?;
            return Err(refused(
                codes::INVITE_EXPIRED,
                "this invite has expired; ask the administrator for a new one",
            ));
        }
        // Item 3: before the code, and not counted — nobody holding a
        // captured URL can burn the subject's invite by guessing.
        if signer != invite.subject {
            return Err(not_invited());
        }
        let supplied = normalise_code(payload.claim_code.as_str());
        let stored = invite.code_hash.clone();
        let code_ok = tokio::task::spawn_blocking(move || claim_secret::verify(&supplied, &stored))
            .await
            .map_err(|e| AppError::Internal(format!("claim-code verify task failed: {e}")))??;
        if !code_ok {
            invite.wrong_codes += 1;
            // Recorded only as a count; the code is never logged.
            warn!(subject = %invite.subject, wrong = invite.wrong_codes, "step-up approver invite: wrong claim code");
            if invite.wrong_codes >= MAX_WRONG_CODES {
                invite.voided = true;
                ks.insert(key, &invite).await?;
                audit(
                    state,
                    &invite.subject,
                    StepUpApproverData {
                        anchor: Some(invite.invited_by.clone()),
                        ..stage("inviteVoided", &invite.subject)
                    },
                )
                .await?;
                return Err(refused(
                    codes::INVITE_VOIDED,
                    "five wrong claim codes: this invite is void; ask the administrator for a new \
                     one",
                ));
            }
            let remaining = MAX_WRONG_CODES - invite.wrong_codes;
            ks.insert(key, &invite).await?;
            return Err(ApproverTaskError::Refused {
                code: codes::CODE_MISMATCH.code,
                message: "the claim code is wrong".into(),
                details: Some(json!({ "attemptsRemaining": remaining })),
            });
        }
        (invite.subject, invite.expires_at)
    };

    let enrollment_id = format!("enr_{}", random_hex(16));
    let challenge = random_b64(32);
    let now = now_epoch();
    // Item 5: no later than the invite's own expiry.
    let expires_at = now.saturating_add(CEREMONY_TTL_SECS).min(invite_expires);
    ks.insert(
        redeem_key(&enrollment_id),
        &RedeemCeremony {
            invite_key: key,
            subject,
            challenge: challenge.clone(),
            created_at: now,
            expires_at,
        },
    )
    .await?;
    // Item 6: the invite is left unconsumed until the finish.
    serde_json::from_value(json!({
        "enrollmentId": enrollment_id,
        "challenge": challenge,
        "audience": audience,
        "expiresAt": epoch_to_utc(expires_at),
    }))
    .map_err(|e| AppError::Internal(format!("redeem/start response: {e}")).into())
}

// ── redeem/finish/0.1 ──────────────────────────────────────────────────────

/// `auth/step-up/approver/redeem/finish/0.1`, signed by `signer`, carrying
/// `statement` exactly as received.
pub async fn redeem_finish(
    state: &AppState,
    signer: &str,
    payload: &redeem_finish::Payload,
    statement: &Value,
) -> Result<redeem_finish::Response> {
    use redeem_finish::error_codes as codes;
    let ks = &state.step_up_approvers_ks;
    let not_found = || {
        refused(
            codes::ENROLLMENT_NOT_FOUND,
            "no redemption in progress with this id, or its invite is no longer valid",
        )
    };
    let enrollment_id = payload.enrollment_id.as_str();
    let approver_did = payload.approver_did.to_string();

    // Item 7: the binding, the invite's consumption and the ceremony's, in one
    // critical section serialised with every other write of approvers.
    let _guard = approver::lock().await;
    let Some(c) = ks.get::<RedeemCeremony>(redeem_key(enrollment_id)).await? else {
        return Err(not_found());
    };
    if now_epoch() >= c.expires_at {
        ks.remove(redeem_key(enrollment_id)).await?;
        return Err(refused(
            codes::ENROLLMENT_EXPIRED,
            "this redemption lapsed; start again while the invite is valid",
        ));
    }
    // Item 2: the subject's own DID, never a delegated key — checked before
    // the ceremony is touched, so another signer cannot spend it.
    if signer != c.subject || is_delegated_key(state, signer).await? {
        return Err(refused(
            codes::NOT_INVITED_SUBJECT,
            "this finish is not signed by the subject the redemption was opened for",
        ));
    }
    let Some(invite) = ks.get::<Invite>(c.invite_key.clone()).await? else {
        ks.remove(redeem_key(enrollment_id)).await?;
        return Err(not_found());
    };
    if invite.voided || now_epoch() >= invite.expires_at || invite.subject != c.subject {
        ks.remove(redeem_key(enrollment_id)).await?;
        return Err(not_found());
    }

    // Item 3: the approver's proof of possession, over this ceremony.
    let expected = ExpectedStatement {
        purpose: attest::PayloadPurpose::Enrol,
        subject: &c.subject,
        challenge: &c.challenge,
        bound_to: enrollment_id,
        not_before: epoch_to_utc(c.created_at),
        not_after: epoch_to_utc(c.expires_at),
        approver: ExpectedApprover::Enrolling(&approver_did),
    };
    match approver::verify_statement(state, statement, &expected).await {
        Ok(_) => {}
        Err(StatementError::Internal(e)) => return Err(e.into()),
        Err(_) => {
            return Err(refused(
                codes::STATEMENT_INVALID,
                "the approver's enrolment statement is not valid for this redemption",
            ));
        }
    }
    // Item 4.
    if let Err(why) = approver::check_distinct(state, &c.subject, &approver_did).await? {
        warn!(subject = %c.subject, approver = %approver_did, why, "approver refused: not distinct");
        return Err(refused(
            codes::APPROVER_NOT_DISTINCT,
            "that approver is a key the subject already signs with, or holds standing here; a \
             step-up factor must be a key the subject does not already hold for signing",
        ));
    }
    if !crate::git_ns::ops::standing(state, &c.subject)
        .await?
        .member
    {
        ks.remove(c.invite_key.clone()).await?;
        ks.remove(redeem_key(enrollment_id)).await?;
        return Err(not_found());
    }
    let record = ApproverRecord {
        approver_did: approver_did.clone(),
        subject: c.subject.clone(),
        label: payload
            .label
            .as_ref()
            .map(|l| l.to_string())
            .or(invite.label.clone()),
        enrolled_at: Utc::now(),
        enrolled_via: invite.via,
        anchor: invite.invited_by.clone(),
        last_used_at: None,
        revoked_at: None,
        revoked_by: None,
    };
    // Items 5 and 6.
    approver::write_binding(ks, &record, None, &c.subject)
        .await
        .map_err(|e| {
            bind_refusal(
                e,
                codes::APPROVER_ALREADY_BOUND,
                codes::TOO_MANY_APPROVERS,
                None,
            )
        })?;
    ks.remove(c.invite_key.clone()).await?;
    ks.remove(redeem_key(enrollment_id)).await?;
    // Item 8: the subject, the approver, the inviting administrator (or the
    // host) and the anchor.
    audit(
        state,
        &c.subject,
        StepUpApproverData {
            approver_did: Some(approver_did.clone()),
            enrolled_via: Some(invite.via.as_str().into()),
            anchor: Some(invite.invited_by.clone()),
            ..stage("enrolled", &c.subject)
        },
    )
    .await?;
    after_binding(state, &c.subject).await?;
    info!(subject = %c.subject, approver = %approver_did, via = invite.via.as_str(), "step-up approver bound by invite");
    serde_json::from_value(json!({ "approver": record.to_wire() }))
        .map_err(|e| AppError::Internal(format!("redeem/finish response: {e}")).into())
}

// ── enroll/0.1 (R3) ────────────────────────────────────────────────────────

/// The **enrolment terms** — the payload as received, `statement` removed —
/// and the operation the authorizing step-up is bound to (enroll/0.1
/// consumer item 4: identified by type and terms, never by a payload that
/// includes the statement).
pub fn enrolment_terms(raw_payload: &Value) -> Value {
    let mut terms = raw_payload.clone();
    if let Some(obj) = terms.as_object_mut() {
        obj.remove("statement");
    }
    terms
}

/// The **terms digest** a new approver's enrolment statement binds as
/// `boundTo` (enroll/0.1, *Enrolment terms and their digest*): the base58btc
/// multibase of the sha2-256 multihash of the RFC 8785 canonical JSON of
/// `{type, subject, challenge, terms}`.
pub fn terms_digest(subject: &str, challenge: &str, terms: &Value) -> Result<String, AppError> {
    let canonical = serde_json_canonicalizer::to_string(&json!({
        "type": ENROLL_TYPE,
        "subject": subject,
        "challenge": challenge,
        "terms": terms,
    }))
    .map_err(|e| AppError::Internal(format!("terms JCS canonicalization failed: {e}")))?;
    let mut mh = vec![0x12, 0x20];
    mh.extend_from_slice(&Sha256::digest(canonical.as_bytes()));
    Ok(multibase::encode(multibase::Base::Base58Btc, mh))
}

/// `auth/step-up/approver/enroll/0.1`, signed by `signer` — the subject.
///
/// Two pieces of evidence over one set of terms: the subject's **existing**
/// factor, as an operation-bound step-up on `(enroll, terms)`; and the new
/// approver's `purpose: enrol` statement over **that step-up's** challenge,
/// bound to the terms digest. The subject's signature attributes the
/// enrolment and is never its authority.
pub async fn enroll(
    state: &AppState,
    signer: &str,
    raw_payload: &Value,
    payload: &enroll::Payload,
) -> Result<enroll::Response> {
    use enroll::error_codes as codes;
    // Item 1: the subject's own DID, never a console delegation — checked
    // before anything else and changing nothing.
    if is_delegated_key(state, signer).await? {
        return Err(refused(
            codes::SUBJECT_MISMATCH,
            "an approver enrolment must be signed by the subject's own DID, not a console \
             signing key",
        ));
    }
    let subject = signer;
    // Item 2.
    let factors = bound_step_up::factors_of(state, subject).await?;
    if factors.is_empty() || !crate::git_ns::ops::standing(state, subject).await?.member {
        return Err(refused(
            codes::NO_FACTOR_HELD,
            "you hold no step-up factor here to authorize this from; ask a community \
             administrator for an approver invite (an administrator never invites themselves)",
        ));
    }
    let terms = enrolment_terms(raw_payload);
    let approver_did = payload.approver_did.to_string();
    let replaces = payload.replaces.as_ref().map(|r| r.to_string());

    // Item 3: authority evidence over these terms — the bound step-up. Read,
    // not spent, so a `statementInvalid` below leaves it in place (item 5).
    let Some(mark) = bound_step_up::peek_mark(state, subject, ENROLL_TYPE, &terms).await? else {
        let reason = match &replaces {
            Some(old) => format!("Replace your step-up approver {old} with {approver_did}"),
            None => format!("Add {approver_did} as a step-up approver"),
        };
        let request =
            bound_step_up::request_step_up(state, subject, ENROLL_TYPE, &terms, &reason).await?;
        return Err(ApproverTaskError::StepUp(Box::new(request)));
    };

    // Item 5.
    let statement_invalid = || {
        refused(
            codes::STATEMENT_INVALID,
            "the new approver's enrolment statement is missing, or not valid for the step-up \
             that authorized this enrolment",
        )
    };
    let Some(statement) = raw_payload.get("statement") else {
        return Err(statement_invalid());
    };
    if mark.challenge.is_empty() {
        return Err(statement_invalid());
    }
    let digest = terms_digest(subject, &mark.challenge, &terms)?;
    let expected = ExpectedStatement {
        purpose: attest::PayloadPurpose::Enrol,
        subject,
        challenge: &mark.challenge,
        bound_to: &digest,
        not_before: epoch_to_utc(mark.created_at),
        not_after: epoch_to_utc(mark.expires_at),
        approver: ExpectedApprover::Enrolling(&approver_did),
    };
    match approver::verify_statement(state, statement, &expected).await {
        Ok(_) => {}
        Err(StatementError::Internal(e)) => return Err(e.into()),
        Err(_) => return Err(statement_invalid()),
    }
    // Item 6.
    if let Err(why) = approver::check_distinct(state, subject, &approver_did).await? {
        warn!(%subject, approver = %approver_did, why, "approver refused: not distinct");
        return Err(refused(
            codes::APPROVER_NOT_DISTINCT,
            "that approver is a key you already sign with, or holds standing here",
        ));
    }

    // Item 7: the binding, the replacement and the spend in one critical
    // section.
    let _guard = approver::lock().await;
    let ks = &state.step_up_approvers_ks;
    approver::check_bindable(ks, &approver_did, subject, replaces.as_deref())
        .await
        .map_err(|e| {
            bind_refusal(
                e,
                codes::APPROVER_ALREADY_BOUND,
                codes::TOO_MANY_APPROVERS,
                Some(codes::REPLACE_NOT_FOUND),
            )
        })?;
    if !bound_step_up::spend_mark(state, subject, ENROLL_TYPE, &terms).await? {
        // Spent or lapsed since it was read: ask again.
        let request = bound_step_up::request_step_up(
            state,
            subject,
            ENROLL_TYPE,
            &terms,
            &format!("Add {approver_did} as a step-up approver"),
        )
        .await?;
        return Err(ApproverTaskError::StepUp(Box::new(request)));
    }
    let anchor = format!("{}:{}", mark.evidence.kind, mark.evidence.credential_id);
    let record = ApproverRecord {
        approver_did: approver_did.clone(),
        subject: subject.to_string(),
        label: payload.label.as_ref().map(|l| l.to_string()),
        enrolled_at: Utc::now(),
        enrolled_via: EnrolledVia::SelfService,
        anchor: anchor.clone(),
        last_used_at: None,
        revoked_at: None,
        revoked_by: None,
    };
    approver::write_binding(ks, &record, replaces.as_deref(), subject)
        .await
        .map_err(|e| {
            bind_refusal(
                e,
                codes::APPROVER_ALREADY_BOUND,
                codes::TOO_MANY_APPROVERS,
                Some(codes::REPLACE_NOT_FOUND),
            )
        })?;
    drop(_guard);
    // Item 8: the new approver, the factor that authorized it, any replaced.
    audit(
        state,
        subject,
        StepUpApproverData {
            approver_did: Some(approver_did.clone()),
            enrolled_via: Some(EnrolledVia::SelfService.as_str().into()),
            anchor: Some(anchor),
            replaced: replaces.clone(),
            ..stage("enrolled", subject)
        },
    )
    .await?;
    after_binding(state, subject).await?;
    info!(%subject, approver = %approver_did, replaced = ?replaces, "step-up approver enrolled (self-service)");
    serde_json::from_value(json!({ "approver": record.to_wire() }))
        .map_err(|e| AppError::Internal(format!("enroll response: {e}")).into())
}

// ── list/0.1, revoke/0.1 ───────────────────────────────────────────────────

/// `auth/step-up/approver/list/0.1` — `subject`'s live approvers, as stored.
/// The caller has established that it may read them.
pub async fn list(state: &AppState, subject: &str) -> Result<list::Response> {
    let approvers: Vec<Value> = approver::stored_live(&state.step_up_approvers_ks, subject)
        .await?
        .iter()
        .map(ApproverRecord::to_wire)
        .collect();
    serde_json::from_value(json!({ "approvers": approvers }))
        .map_err(|e| AppError::Internal(format!("list response: {e}")).into())
}

/// Everything that decides a revocation, before any step-up is asked for it:
/// the binding must exist and be `subject`'s. `Ok(Some(revokedAt))` when it is
/// already revoked from `subject` — a success that changes nothing (item 5).
pub async fn check_revoke(
    state: &AppState,
    subject: &str,
    approver_did: &str,
) -> Result<Option<DateTime<Utc>>> {
    match approver::get(&state.step_up_approvers_ks, approver_did).await? {
        Some(r) if r.subject == subject => Ok(r.revoked_at),
        _ => Err(refused(
            revoke::error_codes::NOT_FOUND,
            "no binding of this approver that you may revoke",
        )),
    }
}

/// `auth/step-up/approver/revoke/0.1` by `caller` for `subject`. The caller
/// has established its authority and spent the step-up bound to this
/// document. Revoking the last approver is allowed: it removes the subject's
/// ability to answer a step-up with one, not their authority (design note
/// §6f).
pub async fn revoke(
    state: &AppState,
    caller: &str,
    subject: &str,
    payload: &revoke::Payload,
) -> Result<revoke::Response> {
    let ks = &state.step_up_approvers_ks;
    let approver_did = payload.approver_did.to_string();
    // Item 6: serialised with every other write of the subject's approvers.
    let guard = approver::lock().await;
    let before = approver::get(ks, &approver_did).await?;
    let record = match before {
        Some(r) if r.subject == subject => r,
        _ => {
            return Err(refused(
                revoke::error_codes::NOT_FOUND,
                "no binding of this approver that you may revoke",
            ));
        }
    };
    let (revoked, revoked_at) = if let Some(at) = record.revoked_at {
        // Item 5: already revoked — succeed, changing nothing.
        (record, at)
    } else {
        let r = approver::tombstone(ks, subject, &approver_did, caller)
            .await?
            .ok_or_else(|| AppError::Internal("binding vanished under the lock".into()))?;
        let at = approver::get(ks, &approver_did)
            .await?
            .and_then(|t| t.revoked_at)
            .unwrap_or_else(Utc::now);
        // Item 7: against the caller, naming the approver, the subject and
        // the reason.
        audit(
            state,
            caller,
            StepUpApproverData {
                approver_did: Some(approver_did.clone()),
                reason: payload.reason.as_ref().map(|r| r.to_string()),
                ..stage("revoked", subject)
            },
        )
        .await?;
        info!(%caller, %subject, approver = %approver_did, "step-up approver revoked");
        (r, at)
    };
    let remaining = approver::stored_live(ks, subject).await?.len();
    drop(guard);
    serde_json::from_value(json!({
        "revoked": revoked.to_wire(),
        "revokedAt": revoked_at,
        "remainingApprovers": remaining,
    }))
    .map_err(|e| AppError::Internal(format!("revoke response: {e}")).into())
}

// ── vtc/install/claim/{start,finish}/0.3 (R1) ──────────────────────────────

fn install_invalid_token_start() -> ApproverTaskError {
    // One code, one message, for every failure: an unauthenticated start is
    // no oracle for which half was wrong (claim/start 0.3 item 1).
    refused(
        claim_start::error_codes::INVALID_TOKEN,
        "this install token and claim code do not open a claim",
    )
}

/// `vtc/install/claim/start/0.3`: the install token and its claim code (the
/// anchor), for a claim under the DID the token names.
pub async fn claim_start_v0_3(
    state: &AppState,
    payload: &claim_start::Payload,
) -> Result<claim_start::Response> {
    let signer = state
        .install_signer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: "install signer not configured (run setup first)".into(),
        })?;
    let claims = crate::install::parse_install_token(signer, payload.token.as_str())
        .map_err(|_| install_invalid_token_start())?;
    let jti = Uuid::parse_str(&claims.jti).map_err(|_| install_invalid_token_start())?;
    let store = &state.install_store;
    let exp = match store.get_token(&jti).await? {
        Some(crate::install::InstallTokenState::Issued { exp, .. }) if Utc::now() < exp => exp,
        _ => {
            let _ = tokio::task::spawn_blocking(|| claim_secret::hash("timing")).await;
            return Err(install_invalid_token_start());
        }
    };
    // The claim code is required in 0.3: binding a step-up factor rests on two
    // channels. A token minted without one cannot open a 0.3 claim.
    let Some(hash) = store.peek_secret_hash(&jti).await? else {
        let _ = tokio::task::spawn_blocking(|| claim_secret::hash("timing")).await;
        return Err(install_invalid_token_start());
    };
    let supplied = normalise_code(payload.claim_code.as_str());
    let ok = tokio::task::spawn_blocking(move || claim_secret::verify(&supplied, &hash))
        .await
        .map_err(|e| AppError::Internal(format!("claim-code verify task failed: {e}")))??;
    if !ok {
        // The fifth wrong code voids the install token (claim/start 0.3, as
        // the approver invite's: the code is the second channel, and guessing
        // at it must not be free). Answered alike, so the count is no oracle.
        let wrong = count_wrong_install_code(state, &jti).await?;
        if wrong >= MAX_WRONG_CODES {
            store.delete_token(&jti).await?;
            state
                .step_up_approvers_ks
                .remove(install_wrong_key(&jti))
                .await?;
            warn!(
                %jti,
                security_alert = true,
                "install token voided after {MAX_WRONG_CODES} wrong claim codes"
            );
        }
        return Err(install_invalid_token_start());
    }
    // Item 2: the founder's DID comes from the token the operator minted,
    // never from the request.
    if !claims.admin_did.starts_with("did:") {
        return Err(refused(
            claim_start::error_codes::TOKEN_NAMES_NO_DID,
            "this install token names no administrator DID; claim it with \
             vtc/install/claim/start 0.2",
        ));
    }
    let audience = vtc_did(state).await?;
    let claim_id = format!("clm_{}", random_hex(16));
    let challenge = random_b64(32);
    let now = now_epoch();
    let expires_at = now
        .saturating_add(CEREMONY_TTL_SECS)
        .min(exp.timestamp().max(0) as u64);
    state
        .step_up_approvers_ks
        .insert(
            claim_key(&claim_id),
            &InstallClaim {
                jti,
                admin_did: claims.admin_did.clone(),
                challenge: challenge.clone(),
                created_at: now,
                expires_at,
            },
        )
        .await?;
    info!(%jti, admin_did = %claims.admin_did, "install claim 0.3 opened");
    // Item 4: the token is left unconsumed.
    serde_json::from_value(json!({
        "claimId": claim_id,
        "adminDid": claims.admin_did,
        "challenge": challenge,
        "audience": audience,
        "expiresAt": epoch_to_utc(expires_at),
    }))
    .map_err(|e| AppError::Internal(format!("claim/start 0.3 response: {e}")).into())
}

/// The DID an open claim names, if `claim_id` is one — for the spine, which
/// resolves that DID afresh before verifying the finish's proof against it
/// (claim/finish 0.3 item 3).
pub(crate) async fn claim_admin_did(
    state: &AppState,
    claim_id: &str,
) -> Result<Option<String>, AppError> {
    Ok(state
        .step_up_approvers_ks
        .get::<InstallClaim>(claim_key(claim_id))
        .await?
        .filter(|c| now_epoch() < c.expires_at)
        .map(|c| c.admin_did))
}

/// `vtc/install/claim/finish/0.3`, signed by `signer` — whose proof the spine
/// has verified against that DID's **live** document — carrying `statement`
/// exactly as received.
pub async fn claim_finish_v0_3(
    state: &AppState,
    signer: &str,
    payload: &claim_finish::Payload,
    statement: &Value,
) -> Result<crate::routes::install::ClaimFinishResponse> {
    use claim_finish::error_codes as codes;
    let ks = &state.step_up_approvers_ks;
    let claim_id = payload.claim_id.as_str();
    let approver_did = payload.approver_did.to_string();
    let install_signer = state
        .install_signer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: "install signer not configured (run setup first)".into(),
        })?;

    let _guard = approver::lock().await;
    // Item 1.
    let Some(claim) = ks
        .get::<InstallClaim>(claim_key(claim_id))
        .await?
        .filter(|c| now_epoch() < c.expires_at)
    else {
        return Err(refused(
            codes::REGISTRATION_MISMATCH,
            "this claimId names no open claim, or it has expired",
        ));
    };
    match state.install_store.get_token(&claim.jti).await? {
        Some(crate::install::InstallTokenState::Issued { exp, .. }) if Utc::now() < exp => {}
        _ => {
            ks.remove(claim_key(claim_id)).await?;
            return Err(refused(
                codes::INVALID_TOKEN,
                "the install token this claim was opened under has expired or been consumed",
            ));
        }
    }
    // Item 2 (and item 3's delegated-key case).
    if signer != claim.admin_did || is_delegated_key(state, signer).await? {
        return Err(refused(
            codes::SUBJECT_MISMATCH,
            "the claim must be signed by the DID the install token names, with a key of its own \
             document",
        ));
    }
    // Item 4.
    let expected = ExpectedStatement {
        purpose: attest::PayloadPurpose::Enrol,
        subject: &claim.admin_did,
        challenge: &claim.challenge,
        bound_to: claim_id,
        not_before: epoch_to_utc(claim.created_at),
        not_after: epoch_to_utc(claim.expires_at),
        approver: ExpectedApprover::Enrolling(&approver_did),
    };
    match approver::verify_statement(state, statement, &expected).await {
        Ok(_) => {}
        Err(StatementError::Internal(e)) => return Err(e.into()),
        Err(_) => {
            return Err(refused(
                codes::STATEMENT_INVALID,
                "the approver's enrolment statement is not valid for this claim",
            ));
        }
    }
    // Item 5 — against the live document the spine just resolved. A DID
    // already bound here (a re-install over restored state) is refused the
    // same way: it is not a fresh factor.
    let distinct = approver::check_distinct(state, &claim.admin_did, &approver_did).await?;
    let bindable = approver::check_bindable(ks, &approver_did, &claim.admin_did, None).await;
    if distinct.is_err() || bindable.is_err() {
        return Err(refused(
            codes::APPROVER_NOT_DISTINCT,
            "that approver is the founder's DID, a key of its document, or already bound; a \
             step-up factor must be a key the founder does not already hold for signing",
        ));
    }
    // Item 6: consume the claim and the token, park the binding for the
    // bootstrap, mint the setup-session token.
    state
        .install_store
        .finish_claim(&claim.jti)
        .await
        .map_err(|e| refused(codes::INVALID_TOKEN, e.to_string()))?;
    ks.remove(claim_key(claim_id)).await?;
    let session_expires =
        now_epoch().saturating_add(crate::install::INSTALL_SESSION_DEFAULT_TTL_SECS);
    ks.insert(
        pending_key(&claim.jti.to_string()),
        &PendingInstallBinding {
            admin_did: claim.admin_did.clone(),
            approver_did: approver_did.clone(),
            label: payload.label.as_ref().map(|l| l.to_string()),
            expires_at: session_expires,
        },
    )
    .await?;
    drop(_guard);
    // Item 7: the founder, the approver and the install token's jti.
    audit(
        state,
        &claim.admin_did,
        StepUpApproverData {
            approver_did: Some(approver_did.clone()),
            enrolled_via: Some(EnrolledVia::Install.as_str().into()),
            anchor: Some(claim.jti.to_string()),
            expires_at: Some(epoch_to_utc(session_expires)),
            ..stage("claimed", &claim.admin_did)
        },
    )
    .await?;
    info!(jti = %claim.jti, admin_did = %claim.admin_did, approver = %approver_did, "install claim 0.3 completed");
    Ok(crate::routes::install::issue_setup_session(
        state,
        install_signer,
        claim.admin_did,
        &claim.jti,
    )
    .await?)
}

/// The approver an install claim 0.3 parked for `(install_jti, admin_did)`,
/// **removed** as it is read. `None` when there is none, it names another DID,
/// or its setup-session token lapsed (then it is discarded and audited).
pub(crate) async fn take_pending_install(
    state: &AppState,
    install_jti: &str,
    admin_did: &str,
) -> Result<Option<PendingInstallBinding>, AppError> {
    let ks = &state.step_up_approvers_ks;
    let Some(raw) = ks.take_raw(pending_key(install_jti)).await? else {
        return Ok(None);
    };
    let Ok(p) = serde_json::from_slice::<PendingInstallBinding>(&raw) else {
        return Ok(None);
    };
    if p.admin_did != admin_did {
        return Ok(None);
    }
    if now_epoch() >= p.expires_at {
        audit(
            state,
            admin_did,
            StepUpApproverData {
                approver_did: Some(p.approver_did.clone()),
                anchor: Some(install_jti.into()),
                ..stage("discarded", admin_did)
            },
        )
        .await?;
        return Ok(None);
    }
    Ok(Some(p))
}

/// Write the approver an install claim parked, now that the bootstrap has
/// written the administrator it belongs to (claim/finish 0.3 item 6).
pub(crate) async fn bind_installed(
    state: &AppState,
    install_jti: &str,
    pending: &PendingInstallBinding,
) -> Result<(), AppError> {
    let record = ApproverRecord {
        approver_did: pending.approver_did.clone(),
        subject: pending.admin_did.clone(),
        label: pending.label.clone(),
        enrolled_at: Utc::now(),
        enrolled_via: EnrolledVia::Install,
        anchor: install_jti.to_string(),
        last_used_at: None,
        revoked_at: None,
        revoked_by: None,
    };
    {
        let _guard = approver::lock().await;
        approver::write_binding(
            &state.step_up_approvers_ks,
            &record,
            None,
            &pending.admin_did,
        )
        .await
        .map_err(|e| match e {
            BindError::Internal(e) => e,
            other => AppError::Conflict(format!(
                "the approver claimed at install cannot be bound: {other:?}"
            )),
        })?;
    }
    audit(
        state,
        &pending.admin_did,
        StepUpApproverData {
            approver_did: Some(pending.approver_did.clone()),
            enrolled_via: Some(EnrolledVia::Install.as_str().into()),
            anchor: Some(install_jti.to_string()),
            ..stage("enrolled", &pending.admin_did)
        },
    )
    .await?;
    Ok(())
}

// ── retention ───────────────────────────────────────────────────────────────

/// Remove every invite, ceremony, claim and parked binding whose life has
/// ended, and spent statement ids past their window. A storage bound: every
/// read above already treats an expired row as absent. The bindings
/// themselves, and their tombstones, are kept.
pub async fn sweep_expired(ks: &KeyspaceHandle, now: DateTime<Utc>) -> Result<usize, AppError> {
    #[derive(Deserialize)]
    struct Expiring {
        expires_at: u64,
    }
    let t = now.timestamp().max(0) as u64;
    let mut removed = 0;
    for prefix in [&b"invite:"[..], b"redeem:", b"claim:", b"pending:"] {
        for (key, value) in ks.prefix_iter_raw(prefix.to_vec()).await? {
            let lapsed =
                serde_json::from_slice::<Expiring>(&value).map_or(true, |e| t >= e.expires_at);
            if lapsed {
                ks.remove(key).await?;
                removed += 1;
            }
        }
    }
    removed += approver::sweep_spent(ks, now).await?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_invite_key_is_a_hash_and_never_the_token() {
        let key = invite_key("sua_secret");
        assert!(key.starts_with("invite:"));
        assert!(!key.contains("sua_secret"));
    }

    /// The terms exclude `statement`, so the send that obtains the step-up and
    /// the send that carries the statement are the same enrolment (enroll/0.1
    /// consumer item 4).
    #[test]
    fn the_terms_are_the_payload_without_its_statement() {
        let with =
            json!({ "approverDid": "did:key:z6MkA", "label": "x", "statement": { "id": "1" } });
        let without = json!({ "approverDid": "did:key:z6MkA", "label": "x" });
        assert_eq!(enrolment_terms(&with), without);
        assert_eq!(
            terms_digest(
                "did:key:z6MkS",
                "challenge-challenge",
                &enrolment_terms(&with)
            )
            .unwrap(),
            terms_digest("did:key:z6MkS", "challenge-challenge", &without).unwrap()
        );
    }

    #[test]
    fn the_terms_digest_binds_subject_challenge_and_every_term() {
        let t = json!({ "approverDid": "did:key:z6MkA" });
        let d = terms_digest("did:key:z6MkS", "c1c1c1c1c1c1c1c1", &t).unwrap();
        assert!(d.starts_with('z'));
        let (_, bytes) = multibase::decode(&d).unwrap();
        assert_eq!(&bytes[..2], &[0x12, 0x20]);
        assert_ne!(
            d,
            terms_digest("did:key:z6MkT", "c1c1c1c1c1c1c1c1", &t).unwrap()
        );
        assert_ne!(
            d,
            terms_digest("did:key:z6MkS", "c2c2c2c2c2c2c2c2", &t).unwrap()
        );
        let replacing = json!({ "approverDid": "did:key:z6MkA", "replaces": "did:key:z6MkB" });
        assert_ne!(
            d,
            terms_digest("did:key:z6MkS", "c1c1c1c1c1c1c1c1", &replacing).unwrap(),
            "a rotation is a different enrolment"
        );
    }

    /// A pinned vector, so the console's and the plugin's copies of the terms
    /// digest can be checked against this one rather than against prose.
    #[test]
    fn the_terms_digest_matches_its_pinned_vector() {
        let d = terms_digest(
            "did:webvh:QmAliceScid4:wallet.example:alice",
            "Um90YXRlQXBwcm92ZXJOb25jZTk4NzY1NA",
            &json!({
                "approverDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
                "label": "Browser plugin — new laptop",
            }),
        )
        .unwrap();
        // Recompute independently: JCS sorts members by UTF-16 code unit.
        let jcs = "{\"challenge\":\"Um90YXRlQXBwcm92ZXJOb25jZTk4NzY1NA\",\"subject\":\"did:webvh:QmAliceScid4:wallet.example:alice\",\"terms\":{\"approverDid\":\"did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw\",\"label\":\"Browser plugin — new laptop\"},\"type\":\"https://trusttasks.org/spec/auth/step-up/approver/enroll/0.1\"}";
        let mut mh = vec![0x12, 0x20];
        mh.extend_from_slice(&Sha256::digest(jcs.as_bytes()));
        assert_eq!(d, multibase::encode(multibase::Base::Base58Btc, mh));
    }

    /// The vector the console's copy (`admin-ui/src/lib/step-up-approvers.test.ts`)
    /// pins — one construction, two implementations, checked against each other.
    #[test]
    fn the_terms_digest_matches_the_consoles_pinned_vector() {
        let d = terms_digest(
            "did:webvh:QmAliceScid4:wallet.example:alice",
            "Um90YXRlQXBwcm92ZXJOb25jZTk4NzY1NA",
            &json!({
                "approverDid": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
                "label": "Browser plugin — new laptop",
                "replaces": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            }),
        )
        .unwrap();
        assert_eq!(d, "zQmf4btNkvextciSMXxYrSktWXTaMK7di3hzUV187tZHoHZ");
    }

    #[test]
    fn a_claim_code_is_read_as_people_type_it() {
        assert_eq!(normalise_code(" abcd-efgh "), "ABCDEFGH");
    }
}
