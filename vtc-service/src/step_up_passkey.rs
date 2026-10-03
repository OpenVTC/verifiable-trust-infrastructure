//! Members' **step-up passkeys** — `auth/passkey/enroll/invite/0.2` with
//! `purpose: stepUp`, redeemed through `auth/passkey/enroll/redeem/{start,finish}/0.1`
//! and revoked for the member with `auth/passkey/revoke/{start,finish}/0.2`.
//!
//! Every one of those is a Trust Task on the signed-document spine
//! ([`crate::trust_tasks::step_up_passkey_tasks`]), so it reaches this module
//! the same way over TSP, DIDComm or HTTPS. This module is the operation; the
//! spine handler is the only door.
//!
//! ## Why
//!
//! An operation-bound step-up ([`crate::acl::bound_step_up`]) asks the actor
//! of a signed document for a passkey gesture before the document may confer
//! authority — a git break-glass always does. A namespace admin who is not a
//! console user has no passkey this community knows, so without this they
//! could never break the glass.
//!
//! ## Who can bind one
//!
//! Two factors, held by two different parties, and neither is enough alone:
//!
//! - **A community administrator's invite.** Only a community administrator
//!   issues one, from a signed document with a passkey gesture of their own
//!   bound to it, and never to themselves. It names one member's DID, is
//!   single use, and lapses (at most [`MAX_INVITE_TTL_SECS`]). The token rides
//!   in the URL and the claim code is delivered separately; only hashes of
//!   either are kept, and five wrong codes void it.
//! - **The member's own signature.** `redeem/start` must be signed by the
//!   very DID the invite names. The specification makes that proof optional;
//!   this service does not, because without it whoever held the two messages —
//!   another member, or the inviting administrator — could bind a passkey of
//!   their own to someone else's DID.
//!
//! A further step-up passkey also needs a user-verified assertion from one the
//! member already holds.
//!
//! ## What a step-up passkey can do
//!
//! Exactly one thing: be the passkey half of an operation-bound step-up issued
//! to its own subject ([`credentials_of`], read only by `bound_step_up`). It is
//! never a proof — the approve-response that carries its assertion must still
//! be signed by the member's `assertionMethod` key (approve-response 0.5) — and
//! it never opens or elevates a session, which holds **by construction**: the
//! credentials live in [`crate::store::keyspaces::STEP_UP_PASSKEYS`], and login
//! and session step-up read only the `passkey` keyspace. It confers no role and
//! no scope.
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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::{info, warn};
use trust_tasks_rs::specs::auth::passkey::admin_list::v0_1 as admin_list;
use trust_tasks_rs::specs::auth::passkey::enroll::invite::v0_2 as invite;
use trust_tasks_rs::specs::auth::passkey::enroll::redeem::finish::v0_1 as redeem_finish;
use trust_tasks_rs::specs::auth::passkey::enroll::redeem::start::v0_1 as redeem_start;
use trust_tasks_rs::specs::auth::passkey::revoke::finish::v0_2 as revoke_finish;
use trust_tasks_rs::specs::auth::passkey::revoke::start::v0_2 as revoke_start;
use uuid::Uuid;
use vti_common::audit::{AuditEvent, StepUpPasskeyData};
use vti_common::auth::passkey::store::{
    PasskeyUser, get_passkey_user_by_cred, get_passkey_user_by_did, store_credential_mapping,
    store_passkey_user,
};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Webauthn,
};

use crate::auth::session::now_epoch;
use crate::error::TaskError;
use crate::install::claim_secret;
use crate::server::AppState;

/// Wrong claim codes an invite survives. On the fifth it is invalidated
/// (`redeem/start` 0.1, step 2).
pub const MAX_WRONG_CODES: u32 = 5;
/// How long a redemption or revocation ceremony waits for its gesture.
pub const CEREMONY_TTL_SECS: u64 = 300;
/// An invite's life when the administrator names none (`enroll/invite` 0.2).
pub const DEFAULT_INVITE_TTL_SECS: u64 = 3600;
/// The longest an invite may live (`enroll/invite` 0.2 recommends ≤ 24 h).
pub const MAX_INVITE_TTL_SECS: u64 = 24 * 3600;
/// Where the invite URL lands, under the console's mount.
pub const ENROL_PATH: &str = "/admin/enrol-step-up";

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
    /// The party acting; the ceremony was over their own passkeys — the
    /// member's own step-up passkeys for a self-revoke, an administrator's
    /// session passkeys otherwise. `producer_did == subject` is how a
    /// finish tells the two apart.
    producer_did: String,
    subject: String,
    credential_id: String,
    uv_state: PasskeyAuthentication,
    expires_at: u64,
}

/// What `auth/passkey/admin-list/0.1` lists about a step-up passkey, beside
/// the counter kept on the credential itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

/// A refusal under one of the codes the task's specification declares.
fn refused(code: trust_tasks_rs::DeclaredErrorCode, error: AppError) -> TaskError {
    TaskError::declared(code.code, error)
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

/// A value built here as the generated response type, so what goes on the
/// wire is held to the published schema's shape.
fn as_response<T: serde::de::DeserializeOwned>(what: &str, value: Value) -> Result<T, AppError> {
    serde_json::from_value(value)
        .map_err(|e| AppError::Internal(format!("{what} response does not fit its schema: {e}")))
}

/// webauthn-rs options as the published `CredentialCreationOptions` /
/// `CredentialRequestOptions`, which carry only what WebAuthn Level 2 names.
fn webauthn_options(options: &impl Serialize) -> Result<Value, AppError> {
    let mut v = serde_json::to_value(options)
        .map_err(|e| AppError::Internal(format!("webauthn options: {e}")))?;
    if let Some(obj) = v.as_object_mut() {
        // Level 3 members the published schema does not name; this service
        // never sets them, so dropping an unset one loses nothing.
        for level3 in ["hints", "attestationFormats", "mediation"] {
            if obj.get(level3).is_some_and(Value::is_null) {
                obj.remove(level3);
            }
        }
    }
    Ok(v)
}

/// A published WebAuthn result (`AttestationResponse`, `AssertionResponse`)
/// as the webauthn-rs type that verifies it. The two describe the same
/// browser object; webauthn-rs requires `extensions` where the published
/// shape calls it `clientExtensionResults`.
fn webauthn_result<T: serde::de::DeserializeOwned>(published: &impl Serialize) -> Option<T> {
    let mut v = serde_json::to_value(published).ok()?;
    let obj = v.as_object_mut()?;
    let ext = obj
        .remove("clientExtensionResults")
        .unwrap_or_else(|| json!({}));
    obj.insert("extensions".into(), ext);
    obj.remove("authenticatorAttachment");
    serde_json::from_value(v).ok()
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

/// The member's step-up passkeys — what [`crate::acl::bound_step_up`] offers
/// for an operation-bound step-up issued to them, in place of their session
/// passkeys once at least one exists (security decision 2026-09-30; see
/// [`crate::acl::bound_step_up::redeem_or_request_with_evidence`]). Never
/// read by login or session step-up. Empty for a DID that is no longer a
/// current member: a credential outlives nothing it was bound for.
pub async fn credentials_of(state: &AppState, did: &str) -> Result<Vec<Passkey>, AppError> {
    if !crate::git_ns::ops::standing(state, did).await?.member {
        return Ok(Vec::new());
    }
    Ok(get_passkey_user_by_did(&state.step_up_passkeys_ks, did)
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

/// Revoke `subject`'s live step-up elevation, on every session it holds one.
///
/// Called when a step-up passkey is enrolled for them: a session stepped up
/// before that moment used the only route this VTC could offer, and that
/// route stops counting for them the instant a step-up passkey exists (see
/// [`credentials_of`]). Clearing `acr_expires_at` — never `acr` — mirrors
/// [`vti_common::auth::session::Session::downgrade_lapsed_elevation`]'s REST
/// reasoning: `acr` keeps reporting the level the session's own login
/// honestly reached, and
/// [`vti_common::auth::extractor::StepUpAuth`] reads the deadline, not the
/// level, for freshness. A session that was never stepped up (no deadline
/// set) is untouched — there is nothing on it to revoke.
///
/// A full scan of the sessions keyspace: sessions are keyed by session id,
/// not by subject, and this fires once per enrolment rather than on a hot
/// path, the same trade-off [`crate::routes::members::rotate`] and
/// `crate::emergency` make revoking a DID's sessions.
pub(crate) async fn revoke_session_elevation(
    sessions: &KeyspaceHandle,
    subject: &str,
) -> Result<(), AppError> {
    use vti_common::auth::session::{list_sessions, update_session};

    for mut session in list_sessions(sessions).await? {
        if session.did == subject && session.acr_expires_at.is_some() {
            session.acr_expires_at = None;
            update_session(sessions, &session).await?;
            info!(
                subject = %subject,
                session_id = %session.session_id,
                "step-up passkey enrolled: existing session elevation revoked"
            );
        }
    }
    Ok(())
}

/// `auth/passkey/admin-list/0.1`: one member's step-up passkeys, for an
/// administrator with authority over them. `actor` is the signer's resolved
/// administrator standing (the spine's `admin_signer`).
///
/// The order is the specification's: authority over the subject first —
/// a subject outside it is `subjectUnknown`, exactly like one that does not
/// exist, so neither of the later codes says anything about them — then the
/// purpose, then membership. Reads only: no counter, last-used time or
/// invite is touched.
pub async fn admin_list(
    state: &AppState,
    actor: &vti_common::auth::extractor::AuthClaims,
    payload: &admin_list::Payload,
) -> Result<admin_list::Response, TaskError> {
    use admin_list::error_codes as codes;

    let subject = payload.subject.as_str();
    let unknown = || {
        TaskError::declared(
            codes::SUBJECT_UNKNOWN.code,
            AppError::NotFound("no such member within your authority".into()),
        )
    };
    let entry = crate::acl::get_acl_entry(&state.acl_ks, subject)
        .await?
        .filter(|e| !e.is_expired(now_epoch()));
    // Standing over a member's factors is `vtc.members.manage`, and over an
    // administrator's an entry that covers theirs (VTI-ACL-050) — one rule with
    // the step-up approver door.
    let within = crate::step_up_approver::admin_covers(state, actor, subject).await?;
    if !within {
        return Err(unknown());
    }
    if payload.purpose != admin_list::PayloadPurpose::StepUp {
        return Err(TaskError::declared(
            codes::PURPOSE_NOT_SUPPORTED.code,
            AppError::Forbidden(
                "this community lists only members' step-up passkeys to administrators; a \
                 session passkey is listed to its owner (auth/passkey/list)"
                    .into(),
            ),
        ));
    }
    if !crate::git_ns::ops::standing(state, subject).await?.member {
        let known = entry.is_some()
            || crate::members::get_member(&state.members_ks, subject)
                .await?
                .is_some();
        return Err(if known {
            TaskError::declared(
                codes::SUBJECT_NOT_MEMBER.code,
                AppError::Forbidden(
                    "the subject is not a current member; their step-up passkeys answer nothing"
                        .into(),
                ),
            )
        } else {
            unknown()
        });
    }

    let ks = &state.step_up_passkeys_ks;
    // The counter lives on the credential, which webauthn-rs keeps opaque; its
    // serialised form carries it as `cred.counter`.
    let counters: std::collections::HashMap<String, u32> = get_passkey_user_by_did(ks, subject)
        .await?
        .map(|u| u.credentials)
        .unwrap_or_default()
        .iter()
        .filter_map(|p| {
            let v = serde_json::to_value(p).ok()?;
            let n = u32::try_from(v.pointer("/cred/counter")?.as_u64()?).ok()?;
            Some((cred_hex(p), n))
        })
        .collect();
    let mut metas = Vec::new();
    for (_, v) in ks.prefix_iter_raw(b"meta:".to_vec()).await? {
        if let Ok(meta) = serde_json::from_slice::<CredentialMeta>(&v)
            && meta.subject == subject
        {
            metas.push(meta);
        }
    }
    // Newest first, as the specification asks: one enrolled a moment ago by
    // someone else shows at the top rather than under the legitimate ones.
    metas.sort_by_key(|m| std::cmp::Reverse(m.registered_at));
    // Built as JSON, not the generated `ListedCredential`/`Response` structs
    // directly: their members are validated newtypes (`registeredAt` a
    // `DateTime<Utc>`, `credentialId` a non-empty string, …), and this is the
    // one place that already holds those shapes as plain `String`/`DateTime`
    // — the same route `git_ns::wire` takes for its own generated responses.
    let credentials: Vec<Value> = metas
        .into_iter()
        .map(|m| {
            let sign_count = counters.get(&m.credential_id).copied();
            json!({
                "credentialId": m.credential_id,
                "deviceLabel": m.device_label,
                "registeredAt": m.registered_at,
                "lastUsedAt": m.last_used_at,
                "signCount": sign_count,
            })
        })
        .collect();
    let response = json!({
        "subject": subject,
        "purpose": "stepUp",
        "credentials": credentials,
    });
    serde_json::from_value(response).map_err(|e| {
        TaskError::from(AppError::Internal(format!(
            "auth/passkey/admin-list response: {e}"
        )))
    })
}

// ── enroll/invite 0.2 ───────────────────────────────────────────────────────

/// Every check that decides whether `admin_did` may issue `payload`, made
/// before the administrator is asked for a gesture: a gesture must never be
/// asked for an act that would be refused anyway. [`issue_invite`] makes them
/// again at the moment of issue.
pub async fn check_invite(
    state: &AppState,
    admin_did: &str,
    payload: &invite::Payload,
) -> Result<(), TaskError> {
    use invite::error_codes as codes;

    require_webauthn(state)?;
    if state.public_url.is_none() {
        return Err(AppError::Config(
            "public_url is not configured; an invite has no URL to carry".into(),
        )
        .into());
    }
    if payload.purpose != invite::PayloadPurpose::StepUp {
        return Err(refused(
            codes::PURPOSE_NOT_SUPPORTED,
            AppError::Forbidden(
                "this community issues only step-up passkeys by invite (purpose `stepUp`); \
                 console users enrol their own passkeys"
                    .into(),
            ),
        ));
    }
    // A step-up credential confers nothing (invite 0.2, conformance item 3).
    if payload.role.is_some() || !payload.scopes.is_empty() {
        return Err(AppError::Validation(
            "a `stepUp` invite carries no `role` and no `scopes`".into(),
        )
        .into());
    }
    let ttl = payload.ttl.map_or(DEFAULT_INVITE_TTL_SECS, |t| t.get());
    if ttl > MAX_INVITE_TTL_SECS {
        return Err(AppError::Validation(format!(
            "ttl must be at most {MAX_INVITE_TTL_SECS} seconds"
        ))
        .into());
    }
    if !crate::git_ns::ops::standing(state, admin_did)
        .await?
        .community_admin
    {
        return Err(refused(
            codes::ROLE_NOT_PERMITTED,
            AppError::Forbidden(
                "only a community administrator invites a member to enrol a step-up passkey".into(),
            ),
        ));
    }
    // An administrator's own passkeys are enrolled behind their own gesture;
    // an invite to oneself would let one stolen key mint a second factor for
    // itself.
    if payload.subject.as_str() == admin_did {
        return Err(refused(
            codes::ROLE_NOT_PERMITTED,
            AppError::Forbidden(
                "an administrator does not invite themselves: enrol your own passkeys under \
                 Settings → Passkeys"
                    .into(),
            ),
        ));
    }
    if !crate::git_ns::ops::standing(state, payload.subject.as_str())
        .await?
        .member
    {
        return Err(refused(
            codes::SUBJECT_UNKNOWN,
            AppError::NotFound("the subject is not a current member of this community".into()),
        ));
    }
    Ok(())
}

/// `auth/passkey/enroll/invite/0.2`, `purpose: stepUp`, issued by
/// `admin_did`. The caller has verified the administrator's proof and the
/// passkey gesture bound to this document.
pub async fn issue_invite(
    state: &AppState,
    admin_did: &str,
    payload: &invite::Payload,
) -> Result<invite::Response, TaskError> {
    check_invite(state, admin_did, payload).await?;
    let public_url = state.public_url.as_deref().unwrap_or_default();
    let subject = payload.subject.to_string();
    let ttl = payload.ttl.map_or(DEFAULT_INVITE_TTL_SECS, |t| t.get());

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
                subject: subject.clone(),
                invited_by: admin_did.to_string(),
                device_label: payload.device_label.as_ref().map(|l| l.to_string()),
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
            subject: subject.clone(),
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
        "{}{ENROL_PATH}#token={token}",
        public_url.trim_end_matches('/')
    );
    Ok(as_response(
        "enroll/invite",
        json!({
            "invite": { "token": token, "url": url },
            "subject": subject,
            "purpose": "stepUp",
            "expiresAt": epoch_to_utc(expires_at),
            "claimCode": claim_code,
        }),
    )?)
}

// ── enroll/redeem/start 0.1 ─────────────────────────────────────────────────

/// What the member's authenticator shows the passkey as. WebAuthn's `user.name`
/// is at most 64 characters in the published options, and a `did:peer` or
/// `did:webvh` is often far longer, so a long DID is shown by its two ends.
/// Display only: the credential is bound to the DID by this service's record,
/// never by this name.
fn authenticator_name(did: &str) -> String {
    const MAX: usize = 64;
    let chars: Vec<char> = did.chars().collect();
    if chars.len() <= MAX {
        return did.to_string();
    }
    let head: String = chars[..40].iter().collect();
    let tail: String = chars[chars.len() - 16..].iter().collect();
    format!("{head}…{tail}")
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

/// `auth/passkey/enroll/redeem/start/0.1`, signed by `signer`.
///
/// The invite, the claim code **and** the signer must agree: the signer must be
/// the member the invite names. A signer who is not is answered exactly as a
/// wrong code is, and counted as one — holding someone else's invite is the
/// case the count exists for.
pub async fn redeem_start(
    state: &AppState,
    signer: &str,
    payload: &redeem_start::Payload,
) -> Result<redeem_start::Response, TaskError> {
    use redeem_start::error_codes as codes;

    let webauthn = require_webauthn(state)?;
    let ks = &state.step_up_passkeys_ks;
    let invalid = || {
        refused(
            codes::INVITE_INVALID,
            AppError::Unauthorized(
                "this invite cannot be redeemed with that code by this DID — it may be wrong, \
                 used, expired, or issued to someone else"
                    .into(),
            ),
        )
    };
    let key = invite_key(payload.token.as_str());

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
        let supplied = normalise_code(payload.claim_code.as_str());
        let stored = invite.code_hash.clone();
        let code_ok = tokio::task::spawn_blocking(move || claim_secret::verify(&supplied, &stored))
            .await
            .map_err(|e| AppError::Internal(format!("claim-code verify task failed: {e}")))??;
        if !code_ok || signer != invite.subject {
            invite.wrong_codes += 1;
            if !code_ok {
                warn!(subject = %invite.subject, "step-up passkey invite: wrong claim code");
            } else {
                warn!(
                    subject = %invite.subject,
                    %signer,
                    "step-up passkey invite presented by a DID it was not issued to"
                );
            }
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
                warn!(subject = %invite.subject, "step-up passkey invite invalidated after wrong attempts");
                return Err(refused(
                    codes::TOO_MANY_ATTEMPTS,
                    AppError::Forbidden(
                        "too many wrong attempts: this invite is no longer valid; ask the \
                         administrator for a new one"
                            .into(),
                    ),
                ));
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
    let name = authenticator_name(&subject);
    let (ccr, reg_state) = crate::webauthn::start_passkey_registration(
        webauthn,
        user_uuid,
        &name,
        &name,
        Some(exclude),
    )?;
    let (uv_options, uv_state) = if held.is_empty() {
        (None, None)
    } else {
        let (rcr, st) = webauthn
            .start_passkey_authentication(&held)
            .map_err(|e| AppError::Internal(format!("webauthn UV start failed: {e}")))?;
        (Some(webauthn_options(&rcr.public_key)?), Some(st))
    };

    let enrollment_id = Uuid::new_v4().to_string();
    let expires_at = now_epoch().saturating_add(CEREMONY_TTL_SECS);
    ks.insert(
        redeem_key(&enrollment_id),
        &RedeemCeremony {
            invite_key: key,
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
    let mut response = json!({
        "enrollmentId": enrollment_id,
        "subject": subject,
        "purpose": "stepUp",
        "options": webauthn_options(&ccr.public_key)?,
        "expiresAt": epoch_to_utc(expires_at),
    });
    if let Some(label) = device_label {
        response["deviceLabel"] = json!(label);
    }
    if let Some(uv) = uv_options {
        response["uvOptions"] = uv;
    }
    Ok(as_response("enroll/redeem/start", response)?)
}

// ── enroll/redeem/finish 0.1 ────────────────────────────────────────────────

/// `auth/passkey/enroll/redeem/finish/0.1`. The authority is the ceremony a
/// signed `redeem/start` opened; the finish may come unsigned from the browser
/// that ran `navigator.credentials.create`. A signed one must be signed by the
/// invite's subject.
///
/// The ceremony is spent whatever happens: a failed finish starts again from
/// `redeem/start` while the invite lasts.
pub async fn redeem_finish(
    state: &AppState,
    signer: Option<&str>,
    payload: &redeem_finish::Payload,
) -> Result<redeem_finish::Response, TaskError> {
    use redeem_finish::error_codes as codes;

    let webauthn = require_webauthn(state)?;
    let ks = &state.step_up_passkeys_ks;
    let not_found =
        |why: &str| refused(codes::ENROLLMENT_NOT_FOUND, AppError::NotFound(why.into()));
    let _guard = LOCK.lock().await;

    let enrollment_id = payload.enrollment_id.as_str();
    let Some(c) = ks.get::<RedeemCeremony>(redeem_key(enrollment_id)).await? else {
        return Err(not_found("no redemption in progress with this id"));
    };
    if signer.is_some_and(|s| s != c.subject) {
        // Not the member's ceremony. Left for the member to finish.
        return Err(not_found("no redemption in progress with this id"));
    }
    ks.remove(redeem_key(enrollment_id)).await?;
    if now_epoch() >= c.expires_at {
        return Err(refused(
            codes::ENROLLMENT_EXPIRED,
            AppError::Gone("this redemption lapsed; start again while the invite is valid".into()),
        ));
    }
    let Some(invite) = ks.get::<Invite>(c.invite_key.clone()).await? else {
        return Err(not_found(
            "the invite this redemption was started for is no longer valid",
        ));
    };
    if now_epoch() >= invite.expires_at || invite.subject != c.subject {
        return Err(not_found(
            "the invite this redemption was started for is no longer valid",
        ));
    }

    // A further step-up passkey needs a gesture from one already held; a
    // missing assertion is a failure, never consent.
    let uv_failed = |why: &str| {
        refused(
            codes::USER_VERIFICATION_FAILED,
            AppError::Unauthorized(why.into()),
        )
    };
    let mut existing = get_passkey_user_by_did(ks, &c.subject).await?;
    if let Some(uv_state) = &c.uv_state {
        let uv = payload.uv_credential.as_ref().ok_or_else(|| {
            uv_failed("a gesture from a step-up passkey you already hold is required")
        })?;
        let uv: PublicKeyCredential = webauthn_result(uv).ok_or_else(|| {
            uv_failed("the assertion from your existing step-up passkey does not parse")
        })?;
        let result = webauthn
            .finish_passkey_authentication(&uv, uv_state)
            .map_err(|_| {
                uv_failed("the assertion from your existing step-up passkey did not verify")
            })?;
        if !result.user_verified() {
            return Err(uv_failed(
                "the existing step-up passkey did not verify the user",
            ));
        }
        if let Some(user) = existing.as_mut() {
            for cred in &mut user.credentials {
                cred.update_credential(&result);
            }
        }
    }

    let attestation_invalid = |why: &str| {
        refused(
            codes::ATTESTATION_INVALID,
            AppError::Unauthorized(why.into()),
        )
    };
    let credential: RegisterPublicKeyCredential = webauthn_result(&payload.credential)
        .ok_or_else(|| attestation_invalid("the new passkey's attestation does not parse"))?;
    let passkey = crate::webauthn::finish_passkey_registration(webauthn, &credential, &c.reg_state)
        .map_err(|_| attestation_invalid("the new passkey's attestation did not verify"))?;
    let hex_id = cred_hex(&passkey);
    // A credential id names one credential to this relying party. One already
    // bound — as anyone's session passkey or step-up passkey — would make
    // "whose passkey answered" ambiguous, and `bound_step_up` answers that
    // question by id.
    if get_passkey_user_by_cred(&state.passkey_ks, &hex_id)
        .await?
        .is_some()
        || get_passkey_user_by_cred(ks, &hex_id).await?.is_some()
    {
        return Err(attestation_invalid(
            "that credential is already registered with this community",
        ));
    }
    if !crate::git_ns::ops::standing(state, &c.subject)
        .await?
        .member
    {
        ks.remove(c.invite_key).await?;
        return Err(not_found("the invite's subject is no longer a member"));
    }

    // Consumed before the credential is bound: were the write to fail after
    // this, the member asks for another invite — never a second credential on
    // the same one.
    ks.remove(c.invite_key).await?;
    let mut user = existing.unwrap_or(PasskeyUser {
        user_uuid: c.user_uuid,
        did: c.subject.clone(),
        display_name: c.subject.clone(),
        credentials: Vec::new(),
    });
    user.credentials.push(passkey);
    store_passkey_user(ks, &user).await?;
    store_credential_mapping(ks, &hex_id, user.user_uuid).await?;
    let label = payload
        .device_label
        .as_ref()
        .map(|l| l.to_string())
        .or(c.device_label);
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
            invited_by: Some(c.invited_by.clone()),
            credential_id: Some(hex_id.clone()),
            expires_at: None,
        },
    )
    .await?;
    // A session elevated before this passkey existed was stepped up through
    // whatever route this subject had at the time — their own session
    // passkey, the only one this VTC could ever offer them. Now that a
    // dedicated step-up passkey exists, that route stops counting for them
    // (security decision 2026-09-30), and an elevation already granted
    // through it must not survive past the moment that becomes true: revoked
    // immediately, the stronger of "expire" and "revoke", rather than left to
    // lapse on its own bounded window.
    revoke_session_elevation(&state.sessions_ks, &c.subject).await?;
    info!(subject = %c.subject, credential_id = %hex_id, "step-up passkey registered");
    // Tell the member, best-effort and after the fact: an invite is always an
    // administrator acting (`check_invite` refuses one to oneself), so `by`
    // here is always someone other than the subject — the case
    // `vtc/members/step-up-passkey-notice/0.1` exists to surface.
    crate::ceremony::step_up_passkey_notice::send(
        state,
        &c.subject,
        crate::ceremony::step_up_passkey_notice::Event::Enrolled,
        &hex_id,
        &c.invited_by,
        registered_at,
        None,
    )
    .await;
    let mut response = json!({
        "credentialId": hex_id,
        "subject": c.subject,
        "purpose": "stepUp",
        "registeredAt": registered_at,
    });
    if let Some(label) = label {
        response["deviceLabel"] = json!(label);
    }
    Ok(as_response("enroll/redeem/finish", response)?)
}

// ── revoke/start + finish 0.2, an administrator for the member ──────────────

/// `auth/passkey/revoke/start/0.2`: the member revoking their own step-up
/// passkey (`payload.subject` absent, or present and equal to `producer_did`),
/// or a community administrator revoking one on a member's behalf
/// (`payload.subject` present and naming someone else). Either way the
/// ceremony is over the **producer's own** passkeys — the member's remaining
/// step-up passkeys for a self-revoke, the administrator's session passkeys
/// otherwise — because the person acting verifies, never the subject.
pub async fn revoke_start(
    state: &AppState,
    producer_did: &str,
    payload: &revoke_start::Payload,
) -> Result<revoke_start::Response, TaskError> {
    use revoke_start::error_codes as codes;

    let webauthn = require_webauthn(state)?;
    let subject = payload
        .subject
        .as_ref()
        .map_or_else(|| producer_did.to_string(), |s| s.to_string());
    let self_revoke = subject == producer_did;
    // Authorise before the credential is looked up (0.2 step 2): a producer
    // acting for someone else must be a community administrator, decided
    // from this service's own state, never from the document.
    if !self_revoke
        && !crate::git_ns::ops::standing(state, producer_did)
            .await?
            .community_admin
    {
        return Err(refused(
            codes::NOT_AUTHORIZED,
            AppError::Forbidden(
                "only a community administrator revokes another member's step-up passkey".into(),
            ),
        ));
    }
    let credential_id = payload.credential_id.to_string();
    let ks = &state.step_up_passkeys_ks;
    let owned = ks
        .get::<CredentialMeta>(meta_key(&credential_id))
        .await?
        .is_some_and(|m| m.subject == subject);
    if !owned {
        return Err(refused(
            codes::CREDENTIAL_NOT_FOUND,
            AppError::NotFound("no such step-up passkey for that member".into()),
        ));
    }
    // The credentials the producer may verify with (0.2 step 5): the
    // subject's own remaining step-up passkeys — the one being revoked
    // included, which is the whole premise of a step-up credential
    // answering its own subject's operations (enroll/invite 0.2) — when the
    // owner revokes their own; the administrator's session passkeys when
    // they act for someone else.
    let own = if self_revoke {
        credentials_of(state, producer_did).await?
    } else {
        get_passkey_user_by_did(&state.passkey_ks, producer_did)
            .await?
            .map(|u| u.credentials)
            .unwrap_or_default()
    };
    if own.is_empty() {
        return Err(refused(
            codes::REAUTH_UNAVAILABLE,
            AppError::Forbidden("you hold no passkey to verify this revocation with".into()),
        ));
    }
    let (rcr, uv_state) = webauthn
        .start_passkey_authentication(&own)
        .map_err(|e| AppError::Internal(format!("webauthn UV start failed: {e}")))?;
    let revocation_id = Uuid::new_v4().to_string();
    ks.insert(
        revoke_key(&revocation_id),
        &Revocation {
            producer_did: producer_did.to_string(),
            subject,
            credential_id,
            uv_state,
            expires_at: now_epoch().saturating_add(CEREMONY_TTL_SECS),
        },
    )
    .await?;
    Ok(as_response(
        "revoke/start",
        json!({
            "revocationId": revocation_id,
            "uvOptions": webauthn_options(&rcr.public_key)?,
        }),
    )?)
}

/// `auth/passkey/revoke/finish/0.2`, by the producer who started it — the
/// member, for a self-revoke, or the administrator who started it for someone
/// else.
pub async fn revoke_finish(
    state: &AppState,
    producer_did: &str,
    payload: &revoke_finish::Payload,
) -> Result<revoke_finish::Response, TaskError> {
    use revoke_finish::error_codes as codes;

    let webauthn = require_webauthn(state)?;
    let ks = &state.step_up_passkeys_ks;
    let revocation_id = payload.revocation_id.as_str();
    let not_found = || {
        refused(
            codes::REVOCATION_NOT_FOUND,
            AppError::NotFound("no revocation in progress with this id".into()),
        )
    };
    let uv_failed = |why: &str| {
        refused(
            codes::USER_VERIFICATION_FAILED,
            AppError::Unauthorized(why.into()),
        )
    };
    let _guard = LOCK.lock().await;
    let Some(r) = ks.get::<Revocation>(revoke_key(revocation_id)).await? else {
        return Err(not_found());
    };
    if r.producer_did != producer_did {
        return Err(not_found());
    }
    ks.remove(revoke_key(revocation_id)).await?;
    if now_epoch() >= r.expires_at {
        return Err(refused(
            codes::REVOCATION_EXPIRED,
            AppError::Gone("this revocation lapsed; start again".into()),
        ));
    }
    let uv: PublicKeyCredential = webauthn_result(&payload.uv_credential)
        .ok_or_else(|| uv_failed("your passkey assertion does not parse"))?;
    let result = webauthn
        .finish_passkey_authentication(&uv, &r.uv_state)
        .map_err(|_| uv_failed("your passkey assertion did not verify"))?;
    if !result.user_verified() {
        return Err(uv_failed("your passkey did not verify the user"));
    }
    let self_revoke = r.subject == r.producer_did;
    // WebAuthn's replay defence is the signature counter, persisted on
    // whichever store the verifying credential actually lives in: the
    // member's own step-up passkeys for a self-revoke, the administrator's
    // session passkeys otherwise — matching the credentials `revoke_start`
    // offered the ceremony.
    if self_revoke {
        if let Some(mut own) = get_passkey_user_by_did(ks, producer_did).await? {
            for cred in &mut own.credentials {
                cred.update_credential(&result);
            }
            store_passkey_user(ks, &own).await?;
        }
    } else {
        if let Some(mut own) = get_passkey_user_by_did(&state.passkey_ks, producer_did).await? {
            for cred in &mut own.credentials {
                cred.update_credential(&result);
            }
            store_passkey_user(&state.passkey_ks, &own).await?;
        }
        // Re-checked at commit time (0.2 step 4); a self-revoke needs no
        // administrator standing at all.
        if !crate::git_ns::ops::standing(state, producer_did)
            .await?
            .community_admin
        {
            return Err(refused(
                codes::NOT_AUTHORIZED,
                AppError::Forbidden("you are no longer a community administrator".into()),
            ));
        }
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
        producer_did,
        StepUpPasskeyData {
            stage: "revoked".into(),
            subject: r.subject.clone(),
            invited_by: None,
            credential_id: Some(r.credential_id.clone()),
            expires_at: None,
        },
    )
    .await?;
    info!(producer = %producer_did, subject = %r.subject, credential_id = %r.credential_id, self_revoke, "step-up passkey revoked");
    let revoked_at = Utc::now();
    // Tell the member, best-effort and after the fact: `by` is the producer —
    // the member's own DID for a self-revoke, the administrator's otherwise —
    // so the recipient can tell which this was (step-up-passkey-notice/0.1,
    // producer requirement 3).
    crate::ceremony::step_up_passkey_notice::send(
        state,
        &r.subject,
        crate::ceremony::step_up_passkey_notice::Event::Revoked,
        &r.credential_id,
        producer_did,
        revoked_at,
        None,
    )
    .await;
    Ok(as_response(
        "revoke/finish",
        json!({
            "credentialId": r.credential_id,
            "subject": r.subject,
            "purpose": "stepUp",
            "revokedAt": revoked_at,
            "remaining": remaining,
        }),
    )?)
}

// ── retention ───────────────────────────────────────────────────────────────

/// Remove every invite and ceremony whose life has ended. A storage bound:
/// every read above already treats an expired row as absent.
pub async fn sweep_expired(ks: &KeyspaceHandle, now: DateTime<Utc>) -> Result<usize, AppError> {
    #[derive(Deserialize)]
    struct Expiring {
        expires_at: u64,
    }
    let now = now.timestamp().max(0) as u64;
    let mut removed = 0;
    for prefix in [&b"invite:"[..], b"redeem:", b"revoke:"] {
        for (key, value) in ks.prefix_iter_raw(prefix.to_vec()).await? {
            let lapsed = serde_json::from_slice::<Expiring>(&value)
                .map(|e| now >= e.expires_at)
                // A row this build cannot read authorizes nothing either.
                .unwrap_or(true);
            if lapsed {
                ks.remove(key).await?;
                removed += 1;
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claim_code_is_read_as_people_type_it() {
        assert_eq!(normalise_code(" abcd-efgh "), "ABCDEFGH");
    }

    #[test]
    fn a_long_did_is_named_by_its_two_ends_within_webauthns_limit() {
        assert_eq!(authenticator_name("did:key:z6Mkshort"), "did:key:z6Mkshort");
        let long = format!("did:peer:2.{}", "V".repeat(900));
        let name = authenticator_name(&long);
        assert!(name.chars().count() <= 64, "{name}");
        assert!(name.starts_with("did:peer:2."));
    }

    #[test]
    fn the_invite_key_is_a_hash_and_never_the_token() {
        let key = invite_key("sup_secret");
        assert!(key.starts_with("invite:"));
        assert!(!key.contains("sup_secret"));
    }
}
