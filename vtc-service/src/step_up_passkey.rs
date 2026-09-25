//! Members' **step-up passkeys** — `auth/passkey/enroll/invite/0.2` with
//! `purpose: stepUp`, redeemed through `auth/passkey/enroll/redeem/{start,finish}/0.1`
//! and revoked for the member with `auth/passkey/revoke/{start,finish}/0.2`.
//!
//! ## Why
//!
//! An operation-bound step-up ([`crate::acl::bound_step_up`]) asks the actor
//! of a signed document for a passkey gesture before the document may confer
//! authority — a git break-glass always does. A namespace admin who is not a
//! console user has no passkey this community knows, so without this they
//! could never break the glass. The signing key alone must not be able to
//! enrol one, or whoever stole the key would enrol their own passkey and the
//! gesture would add nothing: the first binding is anchored in a **community
//! administrator's single-use invite**, redeemed with a **claim code**
//! delivered over another channel. A further one also needs a user-verified
//! assertion from a step-up passkey the member already holds.
//!
//! ## What a step-up passkey can do
//!
//! Exactly one thing: answer an operation-bound step-up issued to its own
//! subject ([`credentials_of`], read only by `bound_step_up`). It never opens
//! or elevates a session, and that holds **by construction**: the credentials
//! live in [`crate::store::keyspaces::STEP_UP_PASSKEYS`], and login and
//! session step-up read only the `passkey` keyspace. It confers no role and no
//! scope.
//!
//! ## Storage (`step_up_passkeys`)
//!
//! - `invite:<sha256(token)>` — an [`Invite`]; only hashes of the token and
//!   the claim code are kept.
//! - `redeem:<enrollmentId>` — a [`RedeemCeremony`], five minutes.
//! - `revoke:<revocationId>` — a [`Revocation`], five minutes.
//! - `meta:<credentialIdHex>` — a [`CredentialMeta`] for listing.
//! - `pk_user:` / `pk_did:` / `pk_cred:` — the credentials, in the passkey
//!   store's own row format ([`vti_common::auth::passkey::store`]).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;
use vti_common::audit::{AuditEvent, StepUpPasskeyData};
use vti_common::auth::passkey::store::{
    PasskeyUser, get_passkey_user_by_did, store_credential_mapping, store_passkey_user,
};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Webauthn,
};

use crate::auth::session::now_epoch;
use crate::install::claim_secret;
use crate::server::AppState;

/// Wrong claim codes an invite survives. On the fifth it is invalidated
/// (`redeem/start` 0.1, step 2).
pub const MAX_WRONG_CODES: u32 = 5;
/// How long a redemption or revocation ceremony waits for its gesture.
pub const CEREMONY_TTL_SECS: u64 = 300;
/// An invite's life when the administrator names none.
pub const DEFAULT_INVITE_TTL_SECS: u64 = 3600;
/// The longest an invite may live (`enroll/invite` 0.2 recommends ≤ 24 h).
pub const MAX_INVITE_TTL_SECS: u64 = 24 * 3600;

/// Refusal codes, as the specifications declare them. Carried at the head of
/// the error message, where the console and `cnm` read them.
pub mod codes {
    pub const ROLE_NOT_PERMITTED: &str = "auth/passkey/enroll/invite:roleNotPermitted";
    pub const SUBJECT_UNKNOWN: &str = "auth/passkey/enroll/invite:subjectUnknown";
    pub const INVITE_INVALID: &str = "auth/passkey/enroll/redeem/start:inviteInvalid";
    pub const TOO_MANY_ATTEMPTS: &str = "auth/passkey/enroll/redeem/start:tooManyAttempts";
    pub const ENROLLMENT_NOT_FOUND: &str = "auth/passkey/enroll/redeem/finish:enrollmentNotFound";
    pub const ENROLLMENT_EXPIRED: &str = "auth/passkey/enroll/redeem/finish:enrollmentExpired";
    pub const USER_VERIFICATION_FAILED: &str =
        "auth/passkey/enroll/redeem/finish:userVerificationFailed";
    pub const ATTESTATION_INVALID: &str = "auth/passkey/enroll/redeem/finish:attestationInvalid";
    pub const CREDENTIAL_NOT_FOUND: &str = "auth/passkey/revoke/start:credentialNotFound";
    pub const NOT_AUTHORIZED: &str = "auth/passkey/revoke/start:notAuthorized";
    pub const REAUTH_UNAVAILABLE: &str = "auth/passkey/revoke/start:reauthUnavailable";
    pub const REVOCATION_NOT_FOUND: &str = "auth/passkey/revoke/finish:revocationNotFound";
    pub const REVOCATION_EXPIRED: &str = "auth/passkey/revoke/finish:revocationExpired";
    pub const REVOKE_UV_FAILED: &str = "auth/passkey/revoke/finish:userVerificationFailed";
    pub const REVOKE_NOT_AUTHORIZED: &str = "auth/passkey/revoke/finish:notAuthorized";
}

/// Serialises every mutation of this store, so a claim-code count, the
/// consumption of an invite and the binding it authorises cannot interleave.
static LOCK: Mutex<()> = Mutex::const_new(());

// ── records ─────────────────────────────────────────────────────────────────

/// An issued, unredeemed invite.
#[derive(Serialize, Deserialize)]
struct Invite {
    subject: String,
    invited_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_label: Option<String>,
    /// Argon2id PHC string of the claim code ([`claim_secret::hash`]).
    code_hash: String,
    expires_at: u64,
    wrong_codes: u32,
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("subject", &self.subject)
            .field("invited_by", &self.invited_by)
            .field("expires_at", &self.expires_at)
            .field("wrong_codes", &self.wrong_codes)
            .finish_non_exhaustive()
    }
}

/// A redemption between start and finish.
#[derive(Serialize, Deserialize)]
struct RedeemCeremony {
    invite_key: String,
    subject: String,
    invited_by: String,
    user_uuid: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_label: Option<String>,
    reg_state: PasskeyRegistration,
    /// Present exactly when the member already held a step-up passkey: the
    /// finish must then carry a user-verified assertion from one of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uv_state: Option<PasskeyAuthentication>,
    expires_at: u64,
}

/// A revocation between start and finish.
#[derive(Serialize, Deserialize)]
struct Revocation {
    /// The administrator acting; the ceremony was over their own passkeys.
    admin_did: String,
    subject: String,
    credential_id: String,
    uv_state: PasskeyAuthentication,
    expires_at: u64,
}

/// What the console lists about a step-up passkey.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = StepUpPasskeyCredential)]
pub struct CredentialMeta {
    /// Credential id, hex.
    pub credential_id: String,
    /// The member it answers step-ups for.
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
    /// The administrator whose invite it came from.
    pub invited_by: String,
    pub registered_at: DateTime<Utc>,
    /// The last step-up it answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
}

fn invite_key(token: &str) -> String {
    format!("invite:{}", hex::encode(Sha256::digest(token.as_bytes())))
}
fn redeem_key(id: &str) -> String {
    format!("redeem:{id}")
}
fn revoke_key(id: &str) -> String {
    format!("revoke:{id}")
}
fn meta_key(cred_hex: &str) -> String {
    format!("meta:{cred_hex}")
}

fn refused(code: &str, message: &str) -> String {
    format!("{code}: {message}")
}

fn cred_hex(p: &Passkey) -> String {
    hex::encode(<_ as AsRef<[u8]>>::as_ref(p.cred_id()))
}

fn epoch_to_utc(t: u64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(t as i64, 0).unwrap_or_default()
}

fn require_webauthn(state: &AppState) -> Result<&Webauthn, AppError> {
    state
        .webauthn
        .as_deref()
        .ok_or_else(|| AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: "WebAuthn not configured (public_url required)".into(),
        })
}

async fn audit(state: &AppState, actor: &str, data: StepUpPasskeyData) -> Result<(), AppError> {
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(actor, None, AuditEvent::StepUpPasskeyChanged(data))
            .await?;
    }
    Ok(())
}

// ── reading ─────────────────────────────────────────────────────────────────

/// The member's step-up passkeys — what [`crate::acl::bound_step_up`] offers,
/// beside their session passkeys, for an operation-bound step-up issued to
/// them. Never read by login or session step-up.
pub async fn credentials_of(ks: &KeyspaceHandle, did: &str) -> Result<Vec<Passkey>, AppError> {
    Ok(get_passkey_user_by_did(ks, did)
        .await?
        .map(|u| u.credentials)
        .unwrap_or_default())
}

/// Record that a step-up passkey answered: its counter, and when.
pub async fn record_use(
    ks: &KeyspaceHandle,
    mut user: PasskeyUser,
    result: &webauthn_rs::prelude::AuthenticationResult,
) -> Result<(), AppError> {
    for cred in &mut user.credentials {
        cred.update_credential(result);
    }
    store_passkey_user(ks, &user).await?;
    let hex_id = hex::encode(<_ as AsRef<[u8]>>::as_ref(result.cred_id()));
    if let Some(mut meta) = ks.get::<CredentialMeta>(meta_key(&hex_id)).await? {
        meta.last_used_at = Some(Utc::now());
        ks.insert(meta_key(&hex_id), &meta).await?;
    }
    Ok(())
}

/// Every step-up passkey, or one member's, for the console.
pub async fn list(
    ks: &KeyspaceHandle,
    subject: Option<&str>,
) -> Result<Vec<CredentialMeta>, AppError> {
    let mut out = Vec::new();
    for (_, v) in ks.prefix_iter_raw(b"meta:".to_vec()).await? {
        if let Ok(meta) = serde_json::from_slice::<CredentialMeta>(&v)
            && subject.is_none_or(|s| s == meta.subject)
        {
            out.push(meta);
        }
    }
    out.sort_by(|a, b| {
        a.subject
            .cmp(&b.subject)
            .then(a.registered_at.cmp(&b.registered_at))
    });
    Ok(out)
}

// ── enroll/invite 0.2 ───────────────────────────────────────────────────────

/// An issued invite, returned once. The token rides in `url`; the claim code
/// is returned only here and is never in `url`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = StepUpPasskeyInvite)]
pub struct IssuedInvite {
    pub invite: InviteLink,
    pub subject: String,
    /// Always `stepUp`: this VTC issues no session credential by invite.
    pub purpose: &'static str,
    pub expires_at: DateTime<Utc>,
    pub claim_code: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[schema(as = StepUpPasskeyInviteLink)]
pub struct InviteLink {
    pub token: String,
    pub url: String,
}

/// `auth/passkey/enroll/invite/0.2`, `purpose: stepUp`, issued by
/// `admin_did`. The caller has already established that the request is the
/// administrator's own, at a stepped-up session.
pub async fn issue_invite(
    state: &AppState,
    admin_did: &str,
    subject: &str,
    device_label: Option<String>,
    ttl_secs: Option<u64>,
) -> Result<IssuedInvite, AppError> {
    require_webauthn(state)?;
    let public_url = state.public_url.as_deref().ok_or_else(|| {
        AppError::Config("public_url is not configured; an invite has no URL to carry".into())
    })?;
    let admin = crate::git_ns::ops::standing(state, admin_did).await?;
    if !admin.community_admin {
        return Err(AppError::Forbidden(refused(
            codes::ROLE_NOT_PERMITTED,
            "only a community administrator invites a member to enrol a step-up passkey",
        )));
    }
    // An administrator's own passkeys are enrolled through
    // `auth/passkey/enroll`, behind their own gesture; an invite to oneself
    // would let one stolen session mint a second factor for itself.
    if subject == admin_did {
        return Err(AppError::Forbidden(refused(
            codes::ROLE_NOT_PERMITTED,
            "an administrator does not invite themselves: enrol your own passkeys under \
             Settings → Passkeys",
        )));
    }
    if !crate::git_ns::ops::standing(state, subject).await?.member {
        return Err(AppError::NotFound(refused(
            codes::SUBJECT_UNKNOWN,
            "the subject is not a current member of this community",
        )));
    }
    if let Some(label) = &device_label
        && label.chars().count() > 256
    {
        return Err(AppError::Validation(
            "deviceLabel is longer than 256 characters".into(),
        ));
    }
    let ttl = ttl_secs.unwrap_or(DEFAULT_INVITE_TTL_SECS);
    if ttl == 0 || ttl > MAX_INVITE_TTL_SECS {
        return Err(AppError::Validation(format!(
            "ttl must be between 1 and {MAX_INVITE_TTL_SECS} seconds"
        )));
    }

    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    let token = format!("sup_{}", B64.encode(raw));
    let claim_code = claim_secret::generate();
    let code = claim_code.clone();
    let code_hash = tokio::task::spawn_blocking(move || claim_secret::hash(&code))
        .await
        .map_err(|e| AppError::Internal(format!("claim-code hash task failed: {e}")))??;
    let expires_at = now_epoch().saturating_add(ttl);
    state
        .step_up_passkeys_ks
        .insert(
            invite_key(&token),
            &Invite {
                subject: subject.to_string(),
                invited_by: admin_did.to_string(),
                device_label,
                code_hash,
                expires_at,
                wrong_codes: 0,
            },
        )
        .await?;
    audit(
        state,
        admin_did,
        StepUpPasskeyData {
            stage: "invited".into(),
            subject: subject.to_string(),
            invited_by: Some(admin_did.to_string()),
            credential_id: None,
            expires_at: Some(epoch_to_utc(expires_at)),
        },
    )
    .await?;
    info!(admin = %admin_did, %subject, "step-up passkey invite issued");

    // The token rides in the fragment, which a browser never sends: it stays
    // out of every access log between here and the member.
    let url = format!(
        "{}/admin/enrol-step-up#token={token}",
        public_url.trim_end_matches('/')
    );
    Ok(IssuedInvite {
        invite: InviteLink { token, url },
        subject: subject.to_string(),
        purpose: "stepUp",
        expires_at: epoch_to_utc(expires_at),
        claim_code,
    })
}

// ── enroll/redeem/start 0.1 ─────────────────────────────────────────────────

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = StepUpPasskeyRedeemStarted)]
pub struct RedeemStarted {
    pub enrollment_id: String,
    pub subject: String,
    pub purpose: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
    /// For `navigator.credentials.create({ publicKey })`.
    #[schema(value_type = Object)]
    pub options: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
    /// For `navigator.credentials.get({ publicKey })`, over the member's
    /// existing step-up passkeys — present exactly when they hold one.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub uv_options: Option<webauthn_rs_proto::PublicKeyCredentialRequestOptions>,
    pub expires_at: DateTime<Utc>,
}

/// Claim codes are typed by people: case and separators do not matter.
fn normalise_code(code: &str) -> String {
    // The alphabet is upper-case only ([`claim_secret`]), so folding case
    // loses nothing.
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// `auth/passkey/enroll/redeem/start/0.1`.
pub async fn redeem_start(
    state: &AppState,
    token: &str,
    claim_code: &str,
) -> Result<RedeemStarted, AppError> {
    let webauthn = require_webauthn(state)?;
    let ks = &state.step_up_passkeys_ks;
    let invalid = || {
        AppError::Unauthorized(refused(
            codes::INVITE_INVALID,
            "this invite cannot be redeemed with that code — it may be wrong, used or expired",
        ))
    };
    let key = invite_key(token);

    let (subject, invited_by, device_label) = {
        let _guard = LOCK.lock().await;
        let Some(mut invite) = ks.get::<Invite>(key.clone()).await? else {
            // The same work as a real invite, so a wrong token and a wrong
            // code take the same time.
            let _ = tokio::task::spawn_blocking(|| claim_secret::hash("timing")).await;
            return Err(invalid());
        };
        if now_epoch() >= invite.expires_at {
            ks.remove(key).await?;
            return Err(invalid());
        }
        let supplied = normalise_code(claim_code);
        let stored = invite.code_hash.clone();
        let ok = tokio::task::spawn_blocking(move || claim_secret::verify(&supplied, &stored))
            .await
            .map_err(|e| AppError::Internal(format!("claim-code verify task failed: {e}")))??;
        if !ok {
            invite.wrong_codes += 1;
            if invite.wrong_codes >= MAX_WRONG_CODES {
                ks.remove(key).await?;
                audit(
                    state,
                    &invite.subject,
                    StepUpPasskeyData {
                        stage: "inviteInvalidated".into(),
                        subject: invite.subject.clone(),
                        invited_by: Some(invite.invited_by.clone()),
                        credential_id: None,
                        expires_at: None,
                    },
                )
                .await?;
                warn!(subject = %invite.subject, "step-up passkey invite invalidated after wrong claim codes");
                return Err(AppError::Forbidden(refused(
                    codes::TOO_MANY_ATTEMPTS,
                    "too many wrong claim codes: this invite is no longer valid; ask the \
                     administrator for a new one",
                )));
            }
            ks.insert(key, &invite).await?;
            return Err(invalid());
        }
        if !crate::git_ns::ops::standing(state, &invite.subject)
            .await?
            .member
        {
            ks.remove(key).await?;
            return Err(invalid());
        }
        (invite.subject, invite.invited_by, invite.device_label)
    };

    let existing = get_passkey_user_by_did(ks, &subject).await?;
    let user_uuid = existing.as_ref().map_or_else(Uuid::new_v4, |u| u.user_uuid);
    let held: Vec<Passkey> = existing.map(|u| u.credentials).unwrap_or_default();
    let exclude = held.iter().map(|p| p.cred_id().clone()).collect::<Vec<_>>();
    let (ccr, reg_state) = crate::webauthn::start_passkey_registration(
        webauthn,
        user_uuid,
        &subject,
        &subject,
        Some(exclude),
    )?;
    let (uv_options, uv_state) = if held.is_empty() {
        (None, None)
    } else {
        let (rcr, st) = webauthn
            .start_passkey_authentication(&held)
            .map_err(|e| AppError::Internal(format!("webauthn UV start failed: {e}")))?;
        (Some(rcr.public_key), Some(st))
    };

    let enrollment_id = Uuid::new_v4().to_string();
    let expires_at = now_epoch().saturating_add(CEREMONY_TTL_SECS);
    ks.insert(
        redeem_key(&enrollment_id),
        &RedeemCeremony {
            invite_key: invite_key(token),
            subject: subject.clone(),
            invited_by,
            user_uuid,
            device_label: device_label.clone(),
            reg_state,
            uv_state,
            expires_at,
        },
    )
    .await?;
    Ok(RedeemStarted {
        enrollment_id,
        subject,
        purpose: "stepUp",
        device_label,
        options: ccr.public_key,
        uv_options,
        expires_at: epoch_to_utc(expires_at),
    })
}

// ── enroll/redeem/finish 0.1 ────────────────────────────────────────────────

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = StepUpPasskeyRedeemed)]
pub struct Redeemed {
    pub credential_id: String,
    pub subject: String,
    pub purpose: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
    pub registered_at: DateTime<Utc>,
}

/// `auth/passkey/enroll/redeem/finish/0.1`. The ceremony is spent whatever
/// happens: a failed finish starts again from `redeem/start` while the invite
/// lasts.
pub async fn redeem_finish(
    state: &AppState,
    enrollment_id: &str,
    credential: &RegisterPublicKeyCredential,
    uv_credential: Option<&PublicKeyCredential>,
    device_label: Option<String>,
) -> Result<Redeemed, AppError> {
    let webauthn = require_webauthn(state)?;
    let ks = &state.step_up_passkeys_ks;
    if let Some(label) = &device_label
        && label.chars().count() > 256
    {
        return Err(AppError::Validation(
            "deviceLabel is longer than 256 characters".into(),
        ));
    }
    let _guard = LOCK.lock().await;

    let Some(c) = ks.get::<RedeemCeremony>(redeem_key(enrollment_id)).await? else {
        return Err(AppError::NotFound(refused(
            codes::ENROLLMENT_NOT_FOUND,
            "no redemption in progress with this id",
        )));
    };
    ks.remove(redeem_key(enrollment_id)).await?;
    if now_epoch() >= c.expires_at {
        return Err(AppError::Gone(refused(
            codes::ENROLLMENT_EXPIRED,
            "this redemption lapsed; start again while the invite is valid",
        )));
    }
    let Some(invite) = ks.get::<Invite>(c.invite_key.clone()).await? else {
        return Err(AppError::NotFound(refused(
            codes::ENROLLMENT_NOT_FOUND,
            "the invite this redemption was started for is no longer valid",
        )));
    };
    if now_epoch() >= invite.expires_at || invite.subject != c.subject {
        return Err(AppError::NotFound(refused(
            codes::ENROLLMENT_NOT_FOUND,
            "the invite this redemption was started for is no longer valid",
        )));
    }

    // A further step-up passkey needs a gesture from one already held; a
    // missing assertion is a failure, never consent.
    let mut existing = get_passkey_user_by_did(ks, &c.subject).await?;
    if let Some(uv_state) = &c.uv_state {
        let uv = uv_credential.ok_or_else(|| {
            AppError::Unauthorized(refused(
                codes::USER_VERIFICATION_FAILED,
                "a gesture from a step-up passkey you already hold is required",
            ))
        })?;
        let result = webauthn
            .finish_passkey_authentication(uv, uv_state)
            .map_err(|_| {
                AppError::Unauthorized(refused(
                    codes::USER_VERIFICATION_FAILED,
                    "the assertion from your existing step-up passkey did not verify",
                ))
            })?;
        if !result.user_verified() {
            return Err(AppError::Unauthorized(refused(
                codes::USER_VERIFICATION_FAILED,
                "the existing step-up passkey did not verify the user",
            )));
        }
        if let Some(user) = existing.as_mut() {
            for cred in &mut user.credentials {
                cred.update_credential(&result);
            }
        }
    }

    let passkey = crate::webauthn::finish_passkey_registration(webauthn, credential, &c.reg_state)
        .map_err(|_| {
            AppError::Unauthorized(refused(
                codes::ATTESTATION_INVALID,
                "the new passkey's attestation did not verify",
            ))
        })?;
    if !crate::git_ns::ops::standing(state, &c.subject)
        .await?
        .member
    {
        ks.remove(c.invite_key).await?;
        return Err(AppError::NotFound(refused(
            codes::ENROLLMENT_NOT_FOUND,
            "the invite's subject is no longer a member",
        )));
    }

    // Consumed before the credential is bound: were the write to fail after
    // this, the member asks for another invite — never a second credential on
    // the same one.
    ks.remove(c.invite_key).await?;
    let hex_id = cred_hex(&passkey);
    let mut user = existing.unwrap_or(PasskeyUser {
        user_uuid: c.user_uuid,
        did: c.subject.clone(),
        display_name: c.subject.clone(),
        credentials: Vec::new(),
    });
    user.credentials.push(passkey);
    store_passkey_user(ks, &user).await?;
    store_credential_mapping(ks, &hex_id, user.user_uuid).await?;
    let label = device_label.or(c.device_label);
    let registered_at = Utc::now();
    ks.insert(
        meta_key(&hex_id),
        &CredentialMeta {
            credential_id: hex_id.clone(),
            subject: c.subject.clone(),
            device_label: label.clone(),
            invited_by: c.invited_by.clone(),
            registered_at,
            last_used_at: None,
        },
    )
    .await?;
    audit(
        state,
        &c.subject,
        StepUpPasskeyData {
            stage: "registered".into(),
            subject: c.subject.clone(),
            invited_by: Some(c.invited_by),
            credential_id: Some(hex_id.clone()),
            expires_at: None,
        },
    )
    .await?;
    info!(subject = %c.subject, credential_id = %hex_id, "step-up passkey registered");
    Ok(Redeemed {
        credential_id: hex_id,
        subject: c.subject,
        purpose: "stepUp",
        device_label: label,
        registered_at,
    })
}

// ── revoke/start + finish 0.2, an administrator for the member ──────────────

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = StepUpPasskeyRevokeStarted)]
pub struct RevokeStarted {
    pub revocation_id: String,
    /// Over the **administrator's own** passkeys: the person acting verifies.
    #[schema(value_type = Object)]
    pub uv_options: webauthn_rs_proto::PublicKeyCredentialRequestOptions,
}

/// `auth/passkey/revoke/start/0.2` with `subject`: a community administrator
/// begins revoking a member's step-up passkey.
pub async fn revoke_start(
    state: &AppState,
    admin_did: &str,
    subject: &str,
    credential_id: &str,
) -> Result<RevokeStarted, AppError> {
    let webauthn = require_webauthn(state)?;
    if !crate::git_ns::ops::standing(state, admin_did)
        .await?
        .community_admin
    {
        return Err(AppError::Forbidden(refused(
            codes::NOT_AUTHORIZED,
            "only a community administrator revokes a member's step-up passkey",
        )));
    }
    let ks = &state.step_up_passkeys_ks;
    let owned = ks
        .get::<CredentialMeta>(meta_key(credential_id))
        .await?
        .is_some_and(|m| m.subject == subject);
    if !owned {
        return Err(AppError::NotFound(refused(
            codes::CREDENTIAL_NOT_FOUND,
            "no such step-up passkey for that member",
        )));
    }
    let own = get_passkey_user_by_did(&state.passkey_ks, admin_did)
        .await?
        .map(|u| u.credentials)
        .unwrap_or_default();
    if own.is_empty() {
        return Err(AppError::Forbidden(refused(
            codes::REAUTH_UNAVAILABLE,
            "you hold no passkey to verify this revocation with",
        )));
    }
    let (rcr, uv_state) = webauthn
        .start_passkey_authentication(&own)
        .map_err(|e| AppError::Internal(format!("webauthn UV start failed: {e}")))?;
    let revocation_id = Uuid::new_v4().to_string();
    ks.insert(
        revoke_key(&revocation_id),
        &Revocation {
            admin_did: admin_did.to_string(),
            subject: subject.to_string(),
            credential_id: credential_id.to_string(),
            uv_state,
            expires_at: now_epoch().saturating_add(CEREMONY_TTL_SECS),
        },
    )
    .await?;
    Ok(RevokeStarted {
        revocation_id,
        uv_options: rcr.public_key,
    })
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = StepUpPasskeyRevoked)]
pub struct Revoked {
    pub credential_id: String,
    pub subject: String,
    pub purpose: &'static str,
    pub revoked_at: DateTime<Utc>,
    /// The member's step-up passkeys left. May be zero: losing one costs a
    /// gesture, not an account.
    pub remaining: usize,
}

/// `auth/passkey/revoke/finish/0.2`.
pub async fn revoke_finish(
    state: &AppState,
    admin_did: &str,
    revocation_id: &str,
    uv: &PublicKeyCredential,
) -> Result<Revoked, AppError> {
    let webauthn = require_webauthn(state)?;
    let ks = &state.step_up_passkeys_ks;
    let _guard = LOCK.lock().await;
    let Some(r) = ks.get::<Revocation>(revoke_key(revocation_id)).await? else {
        return Err(AppError::NotFound(refused(
            codes::REVOCATION_NOT_FOUND,
            "no revocation in progress with this id",
        )));
    };
    if r.admin_did != admin_did {
        return Err(AppError::NotFound(refused(
            codes::REVOCATION_NOT_FOUND,
            "no revocation in progress with this id",
        )));
    }
    ks.remove(revoke_key(revocation_id)).await?;
    if now_epoch() >= r.expires_at {
        return Err(AppError::Gone(refused(
            codes::REVOCATION_EXPIRED,
            "this revocation lapsed; start again",
        )));
    }
    let result = webauthn
        .finish_passkey_authentication(uv, &r.uv_state)
        .map_err(|_| {
            AppError::Unauthorized(refused(
                codes::REVOKE_UV_FAILED,
                "your passkey assertion did not verify",
            ))
        })?;
    if !result.user_verified() {
        return Err(AppError::Unauthorized(refused(
            codes::REVOKE_UV_FAILED,
            "your passkey did not verify the user",
        )));
    }
    if !crate::git_ns::ops::standing(state, admin_did)
        .await?
        .community_admin
    {
        return Err(AppError::Forbidden(refused(
            codes::REVOKE_NOT_AUTHORIZED,
            "you are no longer a community administrator",
        )));
    }

    let mut remaining = 0;
    if let Some(mut user) = get_passkey_user_by_did(ks, &r.subject).await? {
        user.credentials.retain(|p| cred_hex(p) != r.credential_id);
        remaining = user.credentials.len();
        store_passkey_user(ks, &user).await?;
    }
    // Without its mapping, a pending step-up the revoked passkey could have
    // answered finds no owner for it and refuses (revoke/finish 0.2,
    // *Pending ceremonies of a revoked step-up credential*).
    ks.remove(format!("pk_cred:{}", r.credential_id).into_bytes())
        .await?;
    ks.remove(meta_key(&r.credential_id)).await?;
    audit(
        state,
        admin_did,
        StepUpPasskeyData {
            stage: "revoked".into(),
            subject: r.subject.clone(),
            invited_by: None,
            credential_id: Some(r.credential_id.clone()),
            expires_at: None,
        },
    )
    .await?;
    info!(admin = %admin_did, subject = %r.subject, credential_id = %r.credential_id, "step-up passkey revoked");
    Ok(Revoked {
        credential_id: r.credential_id,
        subject: r.subject,
        purpose: "stepUp",
        revoked_at: Utc::now(),
        remaining,
    })
}
