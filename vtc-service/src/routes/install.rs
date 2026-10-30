//! `vtc/install/claim/passkey/{start,finish}/0.1` — claiming a community, or
//! an invitation to administer one, with a passkey.
//!
//! ```text
//! installer ──installToken (+claimSecret)──▶ start
//! start     ──registrationId + options + assertionOptions──▶ installer
//! installer ──finish(webauthnResponse, webauthnAssertion)──▶ finish
//! finish    ──adminDid + setupSessionToken (signed)──▶ installer
//! ```
//!
//! **The administrator's DID is the passkey's own key.** finish derives it
//! from the registered credential's public key — the `did:key` of an Ed25519
//! (`z6Mk…`) or P-256 (`zDn…`, compressed) key — and never takes it from the
//! install token, which for this ceremony names no DID at all (start item 5,
//! finish item 5). A token that names one was issued for the wallet ceremony,
//! `vtc/install/claim/{start,finish}/0.3`, and is refused here.
//!
//! **Possession before authority** (finish items 6–7, trust-tasks-tf #978).
//! Under the `none` attestation format most platform passkeys use, a
//! registration signs nothing: it names a key without proving the installer
//! holds it. So start also issues `assertionOptions`, a second fresh
//! challenge, and finish verifies one assertion by the new credential over it
//! — against the very key the DID is derived from — before it consumes the
//! token, stores the passkey, mints the setup-session token or writes any
//! entry. A refused finish consumes nothing; the challenges are spent and the
//! installer starts again.
//!
//! **Who writes the administrator's entry** (finish item 9). On a fresh
//! community, `vtc/admin/bootstrap` writes the founder's from the
//! setup-session token, as before. On a community that already has an
//! administrator — the token is a passkey *invitation* — bootstrap is
//! single-use and answers `alreadyBootstrapped`, so finish writes the derived
//! DID's entry itself, with the authority the invitation was issued with
//! (recorded on the token's row, `install::InvitedAuthority`).
//!
//! The finish response carries the setup-session token, a bearer secret, so
//! its proof is REQUIRED: the spine signs every answer with the community's
//! key (`trust_tasks::sign_response`), and finish refuses to run on a
//! community that has none to sign with.
//!
//! `vtc/install/claim/{start,finish}/0.2` — the same ceremony under the
//! shared slug, with the DID carried in the token — are retired in favour of
//! this one (trust-tasks-tf #976) and no longer served.

use std::sync::Arc;

use axum::http::StatusCode;
use base64::Engine as _;
use serde::Serialize;
use serde_json::{Value, json};
use tracing::{info, warn};
use uuid::Uuid;
use vti_common::auth::passkey::store::{
    PasskeyUser, delete_registration_user, get_registration_user, store_credential_mapping,
    store_passkey_user, store_registration_state, store_registration_user, take_registration_state,
};
use vti_common::error::AppError;
use webauthn_rs::prelude::{RegisterPublicKeyCredential, Webauthn, WebauthnError};

use crate::acl::admin::{AdminEntry, RegisteredPasskey, get_admin_entry, store_admin_entry};
use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, list_acl_entries, store_acl_entry};
use crate::error::TaskError;
use crate::install::{
    INSTALL_SESSION_DEFAULT_TTL_SECS, InstallTokenSigner, InstallTokenState, InvitedAuthority,
    claim_secret, mint_install_session_token, parse_install_token,
};
use crate::server::AppState;
use crate::webauthn::PasskeyDidError;

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

/// `vtc/install/claim/passkey/start/0.1`'s payload, read from the generated
/// type by `trust_tasks::install_tasks`.
pub(crate) struct ClaimStartRequest {
    pub install_token: String,
    /// Out-of-band claim code the operator received alongside the install
    /// URL. Required when the persisted token row has a `claim_secret_hash`.
    pub claim_secret: Option<String>,
}

/// Written by hand so the install token and claim code never reach a log: a derived `Debug` would print them.
impl std::fmt::Debug for ClaimStartRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimStartRequest")
            .field("install_token", &"<redacted>")
            .field(
                "claim_secret",
                &self.claim_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// `vtc/install/claim/passkey/finish/0.1`'s payload, read from the generated
/// type by `trust_tasks::install_tasks`.
pub(crate) struct ClaimFinishRequest {
    pub install_token: String,
    pub registration_id: String,
    pub webauthn_response: RegisterPublicKeyCredential,
    /// The `navigator.credentials.get()` result over start's assertion
    /// challenge, exactly as received.
    pub webauthn_assertion: Value,
}

/// Written by hand so the install token never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for ClaimFinishRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimFinishRequest")
            .field("install_token", &"<redacted>")
            .field("registration_id", &self.registration_id)
            .field("webauthn_response", &self.webauthn_response)
            .finish()
    }
}

/// The body of `vtc/install/claim/passkey/finish/0.1#response`, and of
/// `vtc/install/claim/finish/0.3#response`, which answers the same two members.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct ClaimFinishResponse {
    pub admin_did: String,
    pub setup_session_token: String,
}

/// Written by hand so the setup-session token never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for ClaimFinishResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimFinishResponse")
            .field("admin_did", &self.admin_did)
            .field("setup_session_token", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Declared error codes (#1600)
// ---------------------------------------------------------------------------

#[cfg(test)]
use trust_tasks_rs::specs::vtc::install::claim as claim_spec;
use trust_tasks_rs::specs::vtc::install::claim::passkey::{
    finish::v0_1 as passkey_finish, start::v0_1 as passkey_start,
};

/// `vtc/install/claim/passkey/start:invalidToken` — missing, malformed,
/// expired or consumed, or its claim code missing or wrong.
pub const START_ERR_INVALID_TOKEN: &str = passkey_start::error_codes::INVALID_TOKEN.code;
/// `vtc/install/claim/passkey/finish:invalidToken` — as for `start`.
pub const FINISH_ERR_INVALID_TOKEN: &str = passkey_finish::error_codes::INVALID_TOKEN.code;
/// `vtc/install/claim/passkey/finish:registrationMismatch` — the
/// `registrationId` names no open registration for this token.
pub const FINISH_ERR_REGISTRATION_MISMATCH: &str =
    passkey_finish::error_codes::REGISTRATION_MISMATCH.code;
/// `vtc/install/claim/passkey/finish:bindingInvalid` — the WebAuthn
/// registration failed verification, or its key is malformed.
pub const FINISH_ERR_BINDING_INVALID: &str = passkey_finish::error_codes::BINDING_INVALID.code;
/// `vtc/install/claim/passkey/finish:possessionUnproven` — the assertion does
/// not prove the installer holds the registered key.
pub const FINISH_ERR_POSSESSION_UNPROVEN: &str =
    passkey_finish::error_codes::POSSESSION_UNPROVEN.code;
/// `vtc/install/claim/passkey/finish:unsupportedAlgorithm` — the registered
/// key is neither EdDSA/Ed25519 nor ES256/P-256.
pub const FINISH_ERR_UNSUPPORTED_ALGORITHM: &str =
    passkey_finish::error_codes::UNSUPPORTED_ALGORITHM.code;

// 0.3's declared codes, named for the error-code census's witnesses (the
// operation is `crate::step_up_approver::claim_{start,finish}_v0_3`, which
// refuses with the generated constants directly).
/// `vtc/install/claim/start:invalidToken` (0.3).
#[cfg(test)]
pub const START_V0_3_ERR_INVALID_TOKEN: &str =
    claim_spec::start::v0_3::error_codes::INVALID_TOKEN.code;
/// `vtc/install/claim/finish:invalidToken` (0.3).
#[cfg(test)]
pub const FINISH_V0_3_ERR_INVALID_TOKEN: &str =
    claim_spec::finish::v0_3::error_codes::INVALID_TOKEN.code;
/// `vtc/install/claim/finish:registrationMismatch` (0.3).
#[cfg(test)]
pub const FINISH_V0_3_ERR_REGISTRATION_MISMATCH: &str =
    claim_spec::finish::v0_3::error_codes::REGISTRATION_MISMATCH.code;
/// `vtc/install/claim/start:tokenNamesNoDid` (0.3).
#[cfg(test)]
pub const START_V0_3_ERR_TOKEN_NAMES_NO_DID: &str =
    claim_spec::start::v0_3::error_codes::TOKEN_NAMES_NO_DID.code;
/// `vtc/install/claim/finish:subjectMismatch` (0.3).
#[cfg(test)]
pub const FINISH_V0_3_ERR_SUBJECT_MISMATCH: &str =
    claim_spec::finish::v0_3::error_codes::SUBJECT_MISMATCH.code;
/// `vtc/install/claim/finish:didUnresolvable` (0.3).
#[cfg(test)]
pub const FINISH_V0_3_ERR_DID_UNRESOLVABLE: &str =
    claim_spec::finish::v0_3::error_codes::DID_UNRESOLVABLE.code;
/// `vtc/install/claim/finish:statementInvalid` (0.3).
#[cfg(test)]
pub const FINISH_V0_3_ERR_STATEMENT_INVALID: &str =
    claim_spec::finish::v0_3::error_codes::STATEMENT_INVALID.code;
/// `vtc/install/claim/finish:approverNotDistinct` (0.3).
#[cfg(test)]
pub const FINISH_V0_3_ERR_APPROVER_NOT_DISTINCT: &str =
    claim_spec::finish::v0_3::error_codes::APPROVER_NOT_DISTINCT.code;

/// Declare `code` on the token-state refusals: every `Unauthorized` the token
/// parser and the install state machine answer is the token being missing,
/// malformed, expired or consumed. A `Conflict` (a concurrent ceremony's
/// lock) and anything else stay undeclared.
fn token_error(code: &'static str) -> impl FnOnce(AppError) -> TaskError {
    move |e| match e {
        e @ AppError::Unauthorized(_) => TaskError::declared(code, e),
        e => TaskError::App(e),
    }
}

fn declared(code: &'static str, message: impl Into<String>) -> TaskError {
    TaskError::declared(code, AppError::Unauthorized(message.into()))
}

/// Where start's assertion challenge waits for finish, keyed by the token's
/// jti (start item 4: single-use and bound to this registration).
fn assertion_challenge_key(jti: &Uuid) -> Vec<u8> {
    format!("install_assertion:{jti}").into_bytes()
}

/// Whether the community already has an administrator — then a passkey claim
/// is an invitation, and finish writes its entry (finish item 9).
async fn has_administrator(state: &AppState) -> Result<bool, AppError> {
    Ok(list_acl_entries(&state.acl_ks)
        .await?
        .iter()
        .any(|e| e.admin.is_administrator()))
}

/// The token's row, if it is an open passkey invitation; `invalidToken`
/// otherwise. A row with no recorded authority can still claim a fresh
/// community (bootstrap writes the founder), but on a community that already
/// has an administrator it would grant nothing anyone decided, so it is
/// refused before any challenge is issued or anything consumed.
async fn open_passkey_row(
    state: &AppState,
    jti: &Uuid,
    code: &'static str,
) -> Result<Option<Box<InvitedAuthority>>, TaskError> {
    match state.install_store.get_token(jti).await? {
        Some(InstallTokenState::Issued { exp, authority, .. }) if chrono::Utc::now() < exp => {
            if authority.is_none() && has_administrator(state).await? {
                return Err(declared(
                    code,
                    "this install token records no invitation authority, and the community \
                     already has an administrator",
                ));
            }
            Ok(authority)
        }
        Some(InstallTokenState::Issued { .. }) => Err(declared(code, "install token expired")),
        Some(InstallTokenState::Consumed { .. }) => Err(declared(code, "install token consumed")),
        None => Err(declared(code, "install token not found")),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `vtc/install/claim/passkey/start/0.1` — open the registration of the
/// passkey whose key will name the administrator. Pre-session: the install
/// token is the credential. Called from `trust_tasks::install_tasks`; no REST
/// route mounts it.
pub(crate) async fn claim_start(
    state: &AppState,
    req: ClaimStartRequest,
) -> Result<passkey_start::Response, TaskError> {
    let signer = require_install_signer(state)?;
    let webauthn = require_webauthn(state)?;
    let store = &state.install_store;

    // Item 1.
    let claims = parse_install_token(signer, &req.install_token)
        .map_err(token_error(START_ERR_INVALID_TOKEN))?;
    let jti = parse_jti(&claims.jti).map_err(token_error(START_ERR_INVALID_TOKEN))?;
    // Item 5: a token issued for this ceremony names no administrator DID. One
    // that does was issued for the wallet ceremony, which proves control of
    // that DID; claiming it with a passkey would make another DID instead.
    if claims.names_did() {
        return Err(declared(
            START_ERR_INVALID_TOKEN,
            "this install token names an administrator DID; claim it with that DID's wallet \
             (vtc/install/claim/start 0.3)",
        ));
    }

    // Item 2: the claim code, verified BEFORE the ceremony lock (P0.21).
    // `start_claim` stamps `claimed_at`, a 300 s concurrency lock; if we
    // verified the code *after* it, anyone holding only the install URL could
    // grief the legitimate operator by POSTing a wrong code every 5 minutes.
    // Discriminated messages let the browser surface the right hint (missing
    // vs wrong code) under the one declared code.
    if let Some(stored_hash) = store.peek_secret_hash(&jti).await? {
        let Some(supplied) = req.claim_secret.as_deref() else {
            return Err(declared(
                START_ERR_INVALID_TOKEN,
                "claim_secret_required: this install URL needs the out-of-band claim code",
            ));
        };
        // Argon2id verification is CPU-bound (~50–200 ms); run it on the
        // blocking pool so an unauthenticated route cannot stall the runtime
        // (P0.10).
        let supplied = supplied.to_string();
        let verified =
            tokio::task::spawn_blocking(move || claim_secret::verify(&supplied, &stored_hash))
                .await
                .map_err(|e| {
                    AppError::Internal(format!("claim-secret verify task failed: {e}"))
                })??;
        if !verified {
            return Err(declared(
                START_ERR_INVALID_TOKEN,
                "claim_secret_invalid: the supplied claim code does not match",
            ));
        }
    }
    open_passkey_row(state, &jti, START_ERR_INVALID_TOKEN).await?;

    // Item 6 leaves the token unconsumed; `start_claim` only takes the
    // ceremony lock.
    store
        .start_claim(&jti)
        .await
        .map_err(token_error(START_ERR_INVALID_TOKEN))?;

    // Item 3: exactly EdDSA and ES256, and (item 5) no DID in `user`.
    let (ccr, reg_state) = crate::webauthn::start_install_passkey_registration(webauthn, jti)?;

    // Item 4: a second fresh challenge, distinct from the creation one,
    // single-use and bound to this registration (its jti), for the one
    // assertion finish verifies. No `allowCredentials`: the credential does not
    // exist yet, and the installer's page names the one it just created.
    let mut challenge = [0u8; 32];
    rand::fill(&mut challenge);
    let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
    let mut request_options = json!({
        "rpId": ccr.public_key.rp.id,
        "challenge": challenge_b64,
        // webauthn-rs verifies a passkey assertion with user verification
        // required, as it registered the credential.
        "userVerification": "required",
    });
    if let Some(timeout) = ccr.public_key.timeout {
        request_options["timeout"] = json!(timeout);
    }
    state
        .passkey_ks
        .insert(assertion_challenge_key(&jti), &challenge_b64)
        .await?;

    store_registration_state(&state.passkey_ks, &jti.to_string(), &reg_state).await?;
    store_registration_user(&state.passkey_ks, &jti.to_string(), &jti).await?;

    info!(jti = %jti, "passkey install claim started");

    let options = match serde_json::to_value(&ccr)
        .map_err(|e| AppError::Internal(format!("creation options: {e}")))?
    {
        Value::Object(m) => m,
        _ => return Err(AppError::Internal("creation options are not an object".into()).into()),
    };
    let assertion_options = match json!({ "publicKey": request_options }) {
        Value::Object(m) => m,
        _ => unreachable!("a JSON object literal"),
    };
    passkey_start::Response::builder()
        .registration_id(jti.to_string())
        .options(options)
        .assertion_options(assertion_options)
        .try_into()
        .map_err(|e| AppError::Internal(format!("claim/passkey/start response: {e}")).into())
}

/// `vtc/install/claim/passkey/finish/0.1` — verify the registration and the
/// possession assertion, derive the administrator's DID from the passkey's
/// key, and only then consume the token, keep the passkey and mint the
/// setup-session token. Pre-session. Called from `trust_tasks::install_tasks`;
/// no REST route mounts it.
pub(crate) async fn claim_finish(
    state: &AppState,
    req: ClaimFinishRequest,
) -> Result<ClaimFinishResponse, TaskError> {
    let signer = require_install_signer(state)?;
    let webauthn = require_webauthn(state)?;
    // Item 8: the response is signed. A community with nothing to sign with
    // would hand out the bearer setup-session token unsigned, so it refuses
    // before anything is consumed.
    if state.credential_signer.is_none() {
        return Err(AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "this community has no signing key, so it cannot sign the claim's \
                      response (run setup first)"
                .into(),
        }
        .into());
    }

    // Item 1. A consumed token is refused like any other: a finish is never
    // replayed into a second setup-session token without a fresh assertion.
    let claims = parse_install_token(signer, &req.install_token)
        .map_err(token_error(FINISH_ERR_INVALID_TOKEN))?;
    let jti = parse_jti(&claims.jti).map_err(token_error(FINISH_ERR_INVALID_TOKEN))?;
    if claims.names_did() {
        return Err(declared(
            FINISH_ERR_INVALID_TOKEN,
            "this install token names an administrator DID; claim it with that DID's wallet \
             (vtc/install/claim/finish 0.3)",
        ));
    }
    let authority = open_passkey_row(state, &jti, FINISH_ERR_INVALID_TOKEN).await?;

    // Item 2.
    let registration_mismatch = || {
        declared(
            FINISH_ERR_REGISTRATION_MISMATCH,
            "registrationId does not match an open registration for this install token",
        )
    };
    let reg_id = Uuid::parse_str(&req.registration_id).map_err(|_| registration_mismatch())?;
    if reg_id != jti {
        return Err(registration_mismatch());
    }
    let reg_state = take_registration_state(&state.passkey_ks, &jti.to_string())
        .await?
        .ok_or_else(registration_mismatch)?;

    // A refusal from here on spends this registration's challenges — except
    // `unsupportedAlgorithm`, which consumes nothing and lets the installer
    // register another passkey and finish again. The ceremony lock is lifted
    // so they can start again at once.
    let abandon = |e: TaskError| async move {
        let _ = state.passkey_ks.remove(assertion_challenge_key(&jti)).await;
        let _ = delete_registration_user(&state.passkey_ks, &jti.to_string()).await;
        let _ = state.install_store.release_claim(&jti).await;
        e
    };

    // Items 3 and 4: the registration, as WebAuthn §7.1 verifies one. The
    // ceremony state admits EdDSA and ES256 alone, so webauthn-rs answers any
    // other algorithm with `CredentialAlteredAlgFromRequest`.
    let passkey = match webauthn.finish_passkey_registration(&req.webauthn_response, &reg_state) {
        Ok(p) => p,
        Err(WebauthnError::CredentialAlteredAlgFromRequest) => {
            store_registration_state(&state.passkey_ks, &jti.to_string(), &reg_state).await?;
            return Err(declared(
                FINISH_ERR_UNSUPPORTED_ALGORITHM,
                "the passkey's key is neither EdDSA over Ed25519 nor ES256 over P-256, so no \
                 did:key can name it; register a passkey with one of the two",
            ));
        }
        Err(e) => {
            return Err(abandon(declared(
                FINISH_ERR_BINDING_INVALID,
                format!("passkey registration failed: {e}"),
            ))
            .await);
        }
    };

    // Items 4 and 5: the DID, from the attested credential data alone.
    let admin_did = match crate::webauthn::passkey_did_key(&passkey) {
        Ok(did) => did,
        Err(PasskeyDidError::UnsupportedAlgorithm) => {
            store_registration_state(&state.passkey_ks, &jti.to_string(), &reg_state).await?;
            return Err(declared(
                FINISH_ERR_UNSUPPORTED_ALGORITHM,
                "the passkey's key is neither EdDSA over Ed25519 nor ES256 over P-256, so no \
                 did:key can name it; register a passkey with one of the two",
            ));
        }
        Err(PasskeyDidError::Malformed(why)) => {
            return Err(abandon(declared(
                FINISH_ERR_BINDING_INVALID,
                format!("the passkey's key is malformed: {why}"),
            ))
            .await);
        }
    };

    // Item 6: possession. The assertion challenge is single-use: taken now,
    // whatever the outcome.
    let challenge = state
        .passkey_ks
        .take_raw(assertion_challenge_key(&jti))
        .await?
        .and_then(|raw| serde_json::from_slice::<String>(&raw).ok())
        .and_then(|b64| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(b64)
                .ok()
        });
    let possession = match challenge {
        Some(challenge) => crate::webauthn::verify_install_assertion(
            webauthn,
            &passkey,
            &challenge,
            &req.webauthn_assertion,
        ),
        None => Err("no assertion challenge is open for this registration".into()),
    };
    if let Err(why) = possession {
        warn!(%jti, %admin_did, reason = %why, security_alert = true, "passkey install: possession unproven");
        return Err(abandon(declared(
            FINISH_ERR_POSSESSION_UNPROVEN,
            "the assertion does not prove possession of the registered passkey; its challenge \
             is spent — start again",
        ))
        .await);
    }

    // An invitation writes the derived DID's entry below (item 9). A DID that
    // already holds one is a passkey registered here before; granting over it
    // would silently replace whatever it holds, so it is refused before
    // anything is consumed.
    let invitation = if has_administrator(state).await? {
        let Some(authority) = authority else {
            return Err(abandon(declared(
                FINISH_ERR_INVALID_TOKEN,
                "this install token records no invitation authority, and the community \
                 already has an administrator",
            ))
            .await);
        };
        if get_acl_entry(&state.acl_ks, &admin_did).await?.is_some() {
            return Err(abandon(TaskError::App(AppError::Conflict(format!(
                "{admin_did} already has an ACL entry; register a new passkey for this invitation"
            ))))
            .await);
        }
        Some(authority)
    } else {
        None
    };

    // Item 8, now that item 6 has succeeded (item 7): consume the token,
    // keep the passkey, mint the setup-session token.
    state
        .install_store
        .finish_claim_as(&jti, Some(admin_did.clone()))
        .await
        .map_err(token_error(FINISH_ERR_INVALID_TOKEN))?;

    let user_uuid = get_registration_user(&state.passkey_ks, &jti.to_string())
        .await?
        .unwrap_or(jti);
    delete_registration_user(&state.passkey_ks, &jti.to_string()).await?;
    let user = PasskeyUser {
        user_uuid,
        did: admin_did.clone(),
        display_name: admin_did.clone(),
        credentials: vec![passkey.clone()],
    };
    store_passkey_user(&state.passkey_ks, &user).await?;
    let cred_id_hex = hex::encode(passkey.cred_id().as_ref() as &[u8]);
    store_credential_mapping(&state.passkey_ks, &cred_id_hex, user_uuid).await?;

    let now = chrono::Utc::now();
    let registered = RegisteredPasskey {
        credential_id: cred_id_hex.clone(),
        label: "install".into(),
        transports: Vec::new(),
        registered_at: now,
        last_used_at: None,
    };
    let admin_entry = match get_admin_entry(&state.passkey_ks, &admin_did).await? {
        Some(mut existing) => {
            if !existing
                .passkeys
                .iter()
                .any(|p| p.credential_id == cred_id_hex)
            {
                existing.passkeys.push(registered);
            }
            existing
        }
        None => AdminEntry {
            did: admin_did.clone(),
            passkeys: vec![registered],
            extensions: serde_json::Value::Null,
            created_at: now,
        },
    };
    store_admin_entry(&state.passkey_ks, &admin_entry).await?;

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &admin_did,
                Some(&admin_did),
                vti_common::audit::AuditEvent::AdminPasskeyRegistered(
                    vti_common::audit::AdminPasskeyData {
                        credential_id_hex: cred_id_hex.clone(),
                        label: "install".into(),
                        transports: Vec::new(),
                    },
                ),
            )
            .await?;
    }

    // Item 9: an invitation's administrator, written here because bootstrap
    // is single-use; for the derived DID, with the authority the invitation
    // was issued with.
    if let Some(authority) = invitation {
        let entry = VtcAclEntry {
            did: admin_did.clone(),
            role: VtcRole::Admin,
            label: authority.label.clone(),
            admin: authority.admin.clone(),
            delegated_by: authority.invited_by.clone(),
            created_at: crate::auth::session::now_epoch(),
            created_by: authority.issued_via.clone(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            group_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
        };
        store_acl_entry(&state.acl_ks, &entry).await?;
        crate::admin_actions::record_effect(state).await;
        if let Some(writer) = state.audit_writer.as_ref() {
            writer
                .write(
                    authority
                        .invited_by
                        .as_deref()
                        .unwrap_or(&authority.issued_via),
                    Some(&admin_did),
                    vti_common::audit::AuditEvent::AclGranted(vti_common::audit::AclChangeData {
                        did: admin_did.clone(),
                        role: "community-admin".into(),
                        contexts: entry.capability_list(),
                        expires_at: None,
                    }),
                )
                .await?;
        }
        info!(jti = %jti, %admin_did, "passkey invitation claimed; administrator written");
    }

    info!(jti = %jti, %admin_did, "passkey install claim completed");

    Ok(issue_setup_session(state, signer, admin_did, &jti).await?)
}

/// Mint the `setup_session_token` for `admin_did` + build the
/// `claim/finish` response. Shared by the first-completion path and the
/// idempotent-replay path so a retry returns a usable token too.
pub(crate) async fn issue_setup_session(
    state: &AppState,
    signer: &InstallTokenSigner,
    admin_did: String,
    jti: &Uuid,
) -> Result<ClaimFinishResponse, AppError> {
    let issuer_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_else(|| "did:key:vtc-install-uninitialised".to_string());

    let setup_session_token = mint_install_session_token(
        signer,
        &issuer_did,
        &admin_did,
        &jti.to_string(),
        INSTALL_SESSION_DEFAULT_TTL_SECS,
    )?;

    Ok(ClaimFinishResponse {
        admin_did,
        setup_session_token,
    })
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

fn require_webauthn(state: &AppState) -> Result<&Webauthn, AppError> {
    state
        .webauthn
        .as_deref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "WebAuthn not configured (public_url required)".into(),
        })
}

fn parse_jti(s: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(s)
        .map_err(|_| AppError::Unauthorized("invalid install token (malformed jti)".into()))
}
