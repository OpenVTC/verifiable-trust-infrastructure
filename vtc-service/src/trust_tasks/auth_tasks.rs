//! Pre-session authentication on the signed-document spine:
//! `auth/challenge/0.1`, `auth/authenticate/{0.2,0.3}` and `auth/refresh/0.2`.
//!
//! These replace the dedicated, `Trust-Task`-header-gated REST mounts at
//! `POST /v1/auth/{challenge,,refresh}` (the third being the bare `/auth/`
//! authenticate path) with the genuine article: a signed document dispatched
//! through the shared `POST /v1/trust-tasks` door, on every transport. Modelled
//! on affinidi-webvh-service's `did-hosting-control/src/trust_tasks_auth.rs`
//! (its module doc makes the same argument for did-hosting-control that this
//! one makes for the VTC), adapted to this dispatcher's `dispatch_typed`
//! idiom rather than that crate's `Dispatcher`/`run_pipeline` abstraction.
//!
//! # No ACL pre-filter
//!
//! Every other family in this module tree resolves the verified signer's ACL
//! row before running its handler ([`super::admin_signer`], [`super::
//! admin_tasks::member_signer`]) — the operation is authorizing someone who is
//! *already* a member or administrator. This family is different in kind:
//! `challenge` and `authenticate` are how a DID **becomes** an authenticated
//! session in the first place, so there is no prior standing to check. The
//! document's own proof — verified generically by the spine before
//! `dispatch_typed` ever runs (`dispatch_trust_task_core` step 3) — is the
//! entire authentication; the handlers below read [`JoinAuthCtx::
//! verified_signer`] and hand it straight to the canonical
//! `vti_common::auth::handlers`, exactly as the REST/SIOP/DIDComm login paths
//! in `routes::auth` already do.
//!
//! `challenge` and `refresh` do not even require that: a challenge names no
//! identity to authorize (anyone may ask for one; only an *enrolled* subject
//! gets a session written against it — see `vti_common::auth::handlers::
//! handle_challenge`'s module doc), and a refresh's opaque token is the
//! credential (RFC 6749 §10.4 rotation), not a proof.
//!
//! # What stays on REST, and why
//!
//! - `POST /v1/auth/refresh`'s **cookie** path (`vtc_admin_refresh`) is the
//!   admin console's session-renewal mechanism — a browser cookie carries no
//!   DID key to sign a document with, and nothing here replaces it. That REST
//!   route therefore stays (see `routes::auth::refresh`'s cookie branch);
//!   this module only adds the *signed-document* refresh path (`0.2`) beside
//!   it, for TSP/DIDComm/HTTPS callers that hold a key.
//! - The header-less `/wallet/auth/{challenge,,refresh}` SIOP aliases the VTA
//!   wallet browser extension posts to are untouched: they call the same
//!   `routes::auth::{challenge,authenticate,refresh}` functions this module
//!   does not touch, over a transport (a bare fetch with no Trust-Task
//!   header) this spine does not carry.
//! - `auth/authenticate/0.1` and `auth/refresh/0.1` (the versions the REST
//!   handlers already sniff out of an otherwise-DIDComm-shaped body) are
//!   unchanged and un-migrated: nothing in this repository emits them over a
//!   transport this spine would otherwise refuse, and the task that asked for
//!   this migration named `0.2`/`0.3`/`0.2` specifically.
//!
//! # `authenticate/0.3`'s proxied login is not implemented
//!
//! `0.3` adds an optional `principal` + `delegationEvidence` pair for a proxied
//! login (a delegate — typically a VTA — authenticating on a principal's
//! behalf). This service has no delegation-evidence verifier and no proxy
//! metadata store (did-hosting-control's `verify_delegation_evidence` /
//! `store_auth_proxy_meta` have no VTC equivalent), so a proxied request
//! (`principal` present and unequal to the signer) is refused with
//! `delegationNotRecognized` — fail closed, not a silent accept of an
//! unverified claim. `principal` absent, or equal to the signer, is the
//! ordinary case and behaves exactly as `0.2` — which is what the spec's own
//! backward-compatibility guarantee requires ("every `0.2` document is
//! processed identically").

use serde_json::Value;
use trust_tasks_rs::specs::auth::{
    authenticate::v0_2 as authenticate_v0_2, authenticate::v0_3 as authenticate_v0_3,
    challenge::v0_1 as challenge, refresh::v0_2 as refresh,
};
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use vti_common::auth::{AudienceBinding, AuthenticateInput, ChallengeInput, RefreshInput};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::server::AppState;

pub(crate) const CHALLENGE_TYPE: &str = <challenge::Payload as Payload>::TYPE_URI;
pub(crate) const AUTHENTICATE_V0_2_TYPE: &str = <authenticate_v0_2::Payload as Payload>::TYPE_URI;
pub(crate) const AUTHENTICATE_V0_3_TYPE: &str = <authenticate_v0_3::Payload as Payload>::TYPE_URI;
pub(crate) const REFRESH_V0_2_TYPE: &str = <refresh::Payload as Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    CHALLENGE_TYPE,
    AUTHENTICATE_V0_2_TYPE,
    AUTHENTICATE_V0_3_TYPE,
    REFRESH_V0_2_TYPE,
];

pub(crate) const AUTHENTICATE_ERR_SESSION_KEY_UNSUPPORTED: &str =
    authenticate_v0_2::error_codes::SESSION_KEY_UNSUPPORTED.code;
pub(crate) const AUTHENTICATE_V0_3_ERR_DELEGATION_NOT_RECOGNIZED: &str =
    authenticate_v0_3::error_codes::DELEGATION_NOT_RECOGNIZED.code;

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        CHALLENGE_TYPE => handle_challenge(state, doc).await,
        AUTHENTICATE_V0_2_TYPE => handle_authenticate_v0_2(state, ctx, doc).await,
        AUTHENTICATE_V0_3_TYPE => handle_authenticate_v0_3(state, ctx, doc).await,
        REFRESH_V0_2_TYPE => handle_refresh_v0_2(state, ctx, doc).await,
        _ => return None,
    })
}

/// The Ed25519 multikey (`z6Mk…`) inside a `sessionKey` `did:key`, or `None`
/// when it names anything else this service cannot verify a proof from.
/// Mirrors the shallow prefix check `routes::auth::authenticate_siop` already
/// applies to the same field on the SIOP path — this service resolves
/// `did:key` generically (no dedicated multicodec decoder), so the prefix is
/// the check.
fn ed25519_session_key(session_key: &str) -> Option<&str> {
    session_key
        .strip_prefix("did:key:")
        .filter(|mb| mb.starts_with("z6Mk"))
}

async fn handle_challenge(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let payload: challenge::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    // The subject the producer intends to authenticate as. Optional in the
    // spec; a challenge naming none still mints a nonce (`did` is what
    // `handle_challenge` ACL-gates on, so an empty subject falls through its
    // "unenrolled subject" branch — the same non-oracle answer an unknown
    // subject gets). Whether the caller is unauthenticated over this
    // transport is irrelevant here: nothing about *this* verb needs the
    // caller's own identity, only the identity they are asking a challenge be
    // bound to.
    let subject = payload
        .subject
        .as_ref()
        .map(|s| s.to_string())
        .unwrap_or_default();
    let backend = match crate::auth::VtcAuthBackend::from_state(state).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let resp = match vti_common::auth::handlers::handle_challenge(
        &backend,
        ChallengeInput {
            did: subject,
            session_pubkey_b58btc: None,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    success_response(&doc, resp)
}

/// `handle_authenticate`'s input, common to `0.2` and `0.3`: the session key
/// (validated + refused before the challenge is spent, same as
/// did-hosting-control) and the framework-verified signer as `signer_did`.
///
/// Every document reaching `dispatch_typed` has already had its recipient
/// bound to this VTC (`dispatch_trust_task_core` SPEC §7.2 item 5b/8), so
/// `AudienceBinding::Transport` is correct here exactly as it is for every
/// other already-verified dispatched task — there is no separate recipient
/// check left for the handler to make.
struct SessionKeyOutcome {
    session_pubkey_b58btc: Option<String>,
}

fn resolve_session_key<P>(
    doc: &TrustTask<P>,
    requested: Option<&str>,
    unsupported_code: &'static str,
) -> Result<SessionKeyOutcome, TrustTaskOutcome> {
    match requested {
        None => Ok(SessionKeyOutcome {
            session_pubkey_b58btc: None,
        }),
        Some(key) => match ed25519_session_key(key) {
            Some(mb) => Ok(SessionKeyOutcome {
                session_pubkey_b58btc: Some(mb.to_string()),
            }),
            None => {
                tracing::warn!(session_key = %key, "authenticate refused: unsupported session key type");
                Err(reject_with_code(
                    doc,
                    extended_code(unsupported_code),
                    "this service binds Ed25519 did:key session keys only",
                    Some(serde_json::json!({ "requested": key })),
                ))
            }
        },
    }
}

async fn handle_authenticate_v0_2(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let Some(signer_did) = ctx.verified_signer.clone() else {
        return reject_with(&doc, RejectReason::ProofRequired);
    };
    let payload: authenticate_v0_2::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let session_key = match resolve_session_key(
        &doc,
        payload.session_key.as_ref().map(|k| k.as_str()),
        AUTHENTICATE_ERR_SESSION_KEY_UNSUPPORTED,
    ) {
        Ok(k) => k,
        Err(reject) => return reject,
    };
    let backend = match crate::auth::VtcAuthBackend::from_state(state).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let resp = match vti_common::auth::handlers::handle_authenticate(
        &backend,
        AuthenticateInput {
            session_id: payload.session_id.to_string(),
            challenge: payload.challenge.to_string(),
            signer_did,
            created_time: None,
            session_pubkey_b58btc: session_key.session_pubkey_b58btc,
            audience: AudienceBinding::Transport,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    success_response(&doc, resp)
}

async fn handle_authenticate_v0_3(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let Some(signer_did) = ctx.verified_signer.clone() else {
        return reject_with(&doc, RejectReason::ProofRequired);
    };
    let payload: authenticate_v0_3::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };

    // Proxied login (`principal` present and unequal to the signer): this
    // build has no delegation-evidence verifier, so it fails closed rather
    // than accepting an unverified claim of standing for another VID. See
    // the module doc.
    if let Some(principal) = payload.principal.as_ref()
        && principal.as_str() != signer_did
    {
        tracing::warn!(
            principal = %principal.as_str(),
            delegate = %signer_did,
            "proxied authenticate refused: this build verifies no delegation evidence"
        );
        return reject_with_code(
            &doc,
            extended_code(AUTHENTICATE_V0_3_ERR_DELEGATION_NOT_RECOGNIZED),
            "this service does not verify delegation evidence; authenticate with the \
             principal's own key",
            None,
        );
    }

    let session_key = match resolve_session_key(
        &doc,
        payload.session_key.as_ref().map(|k| k.as_str()),
        AUTHENTICATE_ERR_SESSION_KEY_UNSUPPORTED,
    ) {
        Ok(k) => k,
        Err(reject) => return reject,
    };
    let backend = match crate::auth::VtcAuthBackend::from_state(state).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let resp = match vti_common::auth::handlers::handle_authenticate(
        &backend,
        AuthenticateInput {
            session_id: payload.session_id.to_string(),
            challenge: payload.challenge.to_string(),
            // Never proxied here (refused above), so the acting party is
            // always the verified signer itself.
            signer_did,
            created_time: None,
            session_pubkey_b58btc: session_key.session_pubkey_b58btc,
            audience: AudienceBinding::Transport,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    success_response(&doc, resp)
}

/// `auth/refresh/0.2` — the opaque refresh token is the credential (RFC 6749
/// §10.4 rotation); a proof, when present, is an extra binding the canonical
/// handler checks against the session's DID, but its absence is not refused
/// here — matching the REST Trust-Task fallback's `signer_did: None` posture
/// for the same reason (see `routes::auth::try_refresh_trust_task`).
async fn handle_refresh_v0_2(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload: refresh::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let backend = match crate::auth::VtcAuthBackend::from_state(state).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let resp = match vti_common::auth::handlers::handle_refresh(
        &backend,
        RefreshInput {
            refresh_token: payload.refresh_token.to_string(),
            signer_did: ctx.verified_signer.clone(),
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    success_response(&doc, resp)
}
