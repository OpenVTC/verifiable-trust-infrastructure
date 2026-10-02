//! `auth/signing-key/{enroll,list,revoke}/0.1` — the administration console's
//! signing keys, as delegations of an identity ([`crate::acl::console_key`]).
//!
//! These replace `/v1/admin/console-keys`. The console can now enrol a key
//! with nothing but the key and a passkey: the enrolment is a document the new
//! key signs (proof of possession), and control of the identity it names is a
//! passkey gesture by that identity bound to that one document.
//!
//! # Enrolment, against `auth/signing-key/enroll/0.1`
//!
//! | item | here |
//! |---|---|
//! | 1 | `signingKeyDid` is the document's `issuer` and verified signer, or `keyNotIssuer` |
//! | 2 | the key rules (`selfDelegation`, `keyHoldsStanding`, `alreadyEnrolled`, `keyRevoked`, `expiryInPast`) first, before anything about the identity |
//! | 3, 4 | nothing is written without a passkey gesture of `identityDid` bound by [`crate::acl::bound_step_up::operation_digest`] to the type and the **whole** payload, recomputed over the document as received |
//! | 5 | the gesture is asked for inline, of the requester, over every registered console passkey — the same answer whoever `identityDid` is — and nothing reaches the identity's devices; standing is checked after the gesture |
//! | 6 | every delegation expires, at most [`console_key::MAX_LIFETIME_DAYS`] away |
//! | 7 | `console` scope; the spine refuses any approval signed by a delegated key |
//! | 8 | at most [`console_key::MAX_ACTIVE_PER_IDENTITY`] active per identity (`tooManyKeys`), and attempts are rate-limited per identity, per key and overall (`unavailable` with `retryAfter`) |
//! | 9 | the re-check of the key rules and the write are one critical section ([`console_key::DELEGATION_LOCK`]) |
//! | 10, 11 | a delegated document is authorized by the identity's ACL row read at execution ([`super::admin_signer`]), and a key with a row of its own is answered by that row alone |
//! | 12 | audited against the identity, naming the key |
//!
//! The standing a delegation borrows is an administrator's ACL row: a
//! delegated document is only ever authorized through [`super::admin_signer`].
//!
//! # List and revoke
//!
//! The signer resolves to an identity — its own live ACL row, or the identity
//! an active delegation names — and lists that identity's delegations only.
//! A revocation is accepted from the owning identity, from the delegated key
//! itself (a console revoking its own key on sign-out), or from an
//! unrestricted administrator for incident response; anyone else is told
//! `notFound`, as for a key never enrolled.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use trust_tasks_rs::specs::auth::signing_key::{
    authorize::v0_1 as authorize, enroll::v0_1 as enroll, enroll::v0_2 as enroll_v0_2,
    list::v0_1 as list, revoke::v0_1 as revoke,
};
use trust_tasks_rs::{Payload, RejectReason, StandardCode, TrustTask, TrustTaskCode};
use vti_common::audit::{AdminConsoleKeyData, AuditEvent};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::acl::bound_step_up;
use crate::acl::console_key::{self, ConsoleKeyDelegation, EnrolError};
use crate::error::AppError;
use crate::server::AppState;

pub(crate) const ENROLL_TYPE: &str = <enroll::Payload as Payload>::TYPE_URI;
/// 0.2: the identity's own `authorization`, and `replaces`. Served beside 0.1.
pub(crate) const ENROLL_V0_2_TYPE: &str = <enroll_v0_2::Payload as Payload>::TYPE_URI;
/// Never dispatched: carried inside an `enroll/0.2` as its `authorization`.
pub(crate) const AUTHORIZE_TYPE: &str = <authorize::Payload as Payload>::TYPE_URI;
pub(crate) const LIST_TYPE: &str = <list::Payload as Payload>::TYPE_URI;
pub(crate) const REVOKE_TYPE: &str = <revoke::Payload as Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[ENROLL_TYPE, ENROLL_V0_2_TYPE, LIST_TYPE, REVOKE_TYPE];

pub(crate) const ENROLL_ERR_KEY_NOT_ISSUER: &str = enroll::error_codes::KEY_NOT_ISSUER.code;
pub(crate) const ENROLL_ERR_SELF_DELEGATION: &str = enroll::error_codes::SELF_DELEGATION.code;
pub(crate) const ENROLL_ERR_KEY_HOLDS_STANDING: &str = enroll::error_codes::KEY_HOLDS_STANDING.code;
pub(crate) const ENROLL_ERR_ALREADY_ENROLLED: &str = enroll::error_codes::ALREADY_ENROLLED.code;
pub(crate) const ENROLL_ERR_KEY_REVOKED: &str = enroll::error_codes::KEY_REVOKED.code;
pub(crate) const ENROLL_ERR_EXPIRY_IN_PAST: &str = enroll::error_codes::EXPIRY_IN_PAST.code;
pub(crate) const ENROLL_ERR_TOO_MANY_KEYS: &str = enroll::error_codes::TOO_MANY_KEYS.code;
pub(crate) const ENROLL_ERR_AUTHORIZATION_INVALID: &str =
    enroll_v0_2::error_codes::AUTHORIZATION_INVALID.code;
pub(crate) const ENROLL_ERR_REPLACE_NOT_FOUND: &str =
    enroll_v0_2::error_codes::REPLACE_NOT_FOUND.code;

/// The most active keys `tooManyKeys` lists (`details.activeKeys`, 0.2).
const MAX_LISTED_ACTIVE_KEYS: usize = 16;
pub(crate) const REVOKE_ERR_NOT_FOUND: &str = revoke::error_codes::NOT_FOUND.code;

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        ENROLL_TYPE | ENROLL_V0_2_TYPE => handle_enroll(state, ctx, doc).await,
        LIST_TYPE => handle_list(state, ctx, doc).await,
        REVOKE_TYPE => handle_revoke(state, ctx, doc).await,
        _ => return None,
    })
}

// ─── rate limits ─────────────────────────────────────────────────────────

/// The window every enrolment limit counts over.
const WINDOW: Duration = Duration::from_secs(600);
/// Attempts per identity named, per key enrolling, and in all, per window.
/// An enrolment is a request a stranger can make with a throwaway key, and
/// each one parks a WebAuthn ceremony.
const PER_IDENTITY: u32 = 10;
const PER_KEY: u32 = 5;
const OVERALL: u32 = 120;
/// Past this many tracked buckets, lapsed ones are dropped on the next attempt.
const MAX_TRACKED: usize = 4096;

static ATTEMPTS: LazyLock<Mutex<HashMap<String, (Instant, u32)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Count one enrolment attempt against every bucket it falls in, or say when
/// the first full one frees up. Nothing is counted when any bucket is full.
fn admit_attempt(identity: &str, key: &str) -> Result<(), DateTime<Utc>> {
    let now = Instant::now();
    let mut buckets = ATTEMPTS.lock().unwrap_or_else(|p| p.into_inner());
    if buckets.len() > MAX_TRACKED {
        buckets.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
    }
    let keys = [
        (format!("identity:{identity}"), PER_IDENTITY),
        (format!("key:{key}"), PER_KEY),
        ("overall".to_string(), OVERALL),
    ];
    for (bucket, limit) in &keys {
        if let Some((start, count)) = buckets.get(bucket)
            && now.duration_since(*start) < WINDOW
            && *count >= *limit
        {
            let wait = WINDOW.saturating_sub(now.duration_since(*start));
            return Err(Utc::now() + chrono::Duration::from_std(wait).unwrap_or_default());
        }
    }
    for (bucket, _) in keys {
        let entry = buckets.entry(bucket).or_insert((now, 0));
        if now.duration_since(entry.0) >= WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn reset_attempts_for_test() {
    ATTEMPTS.lock().unwrap_or_else(|p| p.into_inner()).clear();
}

// ─── shared ──────────────────────────────────────────────────────────────

fn declared(doc: &TrustTask<Value>, code: &str, message: impl Into<String>) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, None)
}

/// A delegation as `auth/_shared/0.1/signing-key.schema.json` describes it.
fn view(d: &ConsoleKeyDelegation, now: DateTime<Utc>) -> Value {
    let mut v = json!({
        "signingKeyDid": d.console_did,
        "identityDid": d.admin_did,
        "scope": d.scope.as_str(),
        "createdAt": d.created_at,
        "expiresAt": d.expires_at,
        "active": d.is_active_at(now),
    });
    if let Some(label) = &d.label {
        v["deviceLabel"] = json!(label);
    }
    if let Some(t) = d.last_used_at {
        v["lastUsedAt"] = json!(t);
    }
    if let Some(t) = d.revoked_at {
        v["revokedAt"] = json!(t);
    }
    v
}

/// Whether `did` holds a live ACL row here, and whether it is an
/// administrator's.
async fn standing(state: &AppState, did: &str) -> Result<Option<crate::acl::VtcRole>, AppError> {
    let now = crate::auth::session::now_epoch();
    Ok(crate::acl::get_acl_entry(&state.acl_ks, did)
        .await?
        .filter(|e| !e.is_expired(now))
        .map(|e| e.role))
}

/// The identity a signer speaks for: itself, where it holds a live ACL row,
/// or the identity an active delegation of it names.
async fn identity_of(state: &AppState, signer: &str) -> Result<Option<String>, AppError> {
    if standing(state, signer).await?.is_some() {
        return Ok(Some(signer.to_string()));
    }
    // A key with a row of its own never falls back to a delegation (item 11);
    // one without is answered by its delegation, if active.
    if crate::acl::get_acl_entry(&state.acl_ks, signer)
        .await?
        .is_some()
    {
        return Ok(None);
    }
    Ok(
        console_key::resolve_delegated_admin(&state.console_keys_ks, signer)
            .await?
            .map(|d| d.admin_did),
    )
}

// ─── enroll ──────────────────────────────────────────────────────────────

/// The terms of an enrolment, from either version's payload.
struct EnrolTerms {
    key: String,
    identity: String,
    label: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    /// 0.2: an active key of the same identity to revoke in the same step.
    replaces: Option<String>,
    /// 0.2: the enrolment can list active keys in `tooManyKeys`.
    lists_active_keys: bool,
}

fn enrol_terms(doc: &TrustTask<Value>) -> Result<EnrolTerms, TrustTaskOutcome> {
    if doc.type_uri.to_string().starts_with(ENROLL_V0_2_TYPE) {
        let p: enroll_v0_2::Payload = parse_spec_payload(doc)?;
        Ok(EnrolTerms {
            key: p.signing_key_did.to_string(),
            identity: p.identity_did.to_string(),
            label: p.device_label.as_ref().map(|l| l.to_string()),
            expires_at: p.expires_at,
            replaces: p.replaces.as_ref().map(|k| k.to_string()),
            lists_active_keys: true,
        })
    } else {
        let p: enroll::Payload = parse_spec_payload(doc)?;
        Ok(EnrolTerms {
            key: p.signing_key_did.to_string(),
            identity: p.identity_did.to_string(),
            label: p.device_label.as_ref().map(|l| l.to_string()),
            expires_at: p.expires_at,
            replaces: None,
            lists_active_keys: false,
        })
    }
}

async fn handle_enroll(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let terms = match enrol_terms(&doc) {
        Ok(t) => t,
        Err(reject) => return reject,
    };
    let EnrolTerms {
        key,
        identity,
        label,
        ..
    } = &terms;
    let (key, identity, label) = (key.clone(), identity.clone(), label.clone());
    let now = Utc::now();

    // Item 1 — the enrolment is signed by the key being enrolled.
    let Some(signer) = ctx.verified_signer.clone() else {
        return reject_with(&doc, RejectReason::ProofRequired);
    };
    if signer != key || doc.issuer.as_deref() != Some(key.as_str()) {
        return declared(
            &doc,
            ENROLL_ERR_KEY_NOT_ISSUER,
            "signingKeyDid must be the document's issuer, and the proof made by it",
        );
    }

    // Item 2 — the key's own rules, before anything about the identity.
    if let Err(reject) = key_rules(state, &doc, &key, &identity).await {
        return reject;
    }
    if terms.expires_at.is_some_and(|t| t <= now) {
        return declared(
            &doc,
            ENROLL_ERR_EXPIRY_IN_PAST,
            "expiresAt is not in the future, so the delegation would authorize nothing",
        );
    }

    // Item 8 — a stranger can start this with a throwaway key.
    if let Err(retry_after) = admit_attempt(&identity, &key) {
        return reject_with(
            &doc,
            RejectReason::Unavailable {
                retry_after: Some(retry_after),
            },
        );
    }

    // Items 3–5 and 0.2's item 13 — the authority evidence. Either the
    // identity's own signed authorization of exactly these terms, or the
    // identity's passkey gesture bound to this exact document. Both are
    // established before standing is known, so they are asked the same way of
    // everyone.
    let type_uri = doc.type_uri.to_string();
    let authorization = match doc.payload.get("authorization") {
        Some(raw) => match verify_authorization(state, &doc, raw, &identity, now).await {
            Ok(inner) => Some(inner),
            Err(reject) => return reject,
        },
        None => None,
    };
    let by_authorization = authorization.is_some();
    match if by_authorization {
        Ok(true)
    } else {
        bound_step_up::has_mark(state, &identity, &type_uri, &doc.payload).await
    } {
        Ok(true) => {}
        Ok(false) => {
            let reason = match &label {
                Some(label) => format!(
                    "Let the signing key {key} ({label}) act as you in the administration console"
                ),
                None => {
                    format!("Let the signing key {key} act as you in the administration console")
                }
            };
            return match bound_step_up::request_for_enrolment(
                state,
                &identity,
                &key,
                &type_uri,
                &doc.payload,
                &reason,
            )
            .await
            {
                Ok(request) => reject_with_code(
                    &doc,
                    TrustTaskCode::Standard(StandardCode::PermissionDenied),
                    "a passkey gesture of the identity, bound to this enrolment, is required",
                    Some(bound_step_up::refusal_details(&request)),
                ),
                Err(e) => app_error_to_reject(&doc, &e),
            };
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }

    // Only a gesture of the identity's own passkey records a mark, and only
    // the identity's own key makes a valid authorization, so from here the
    // enrolling party controls `identity`. Now the standing it lends.
    match standing(state, &identity).await {
        Ok(Some(crate::acl::VtcRole::Admin)) => {}
        Ok(_) => {
            return app_error_to_reject(
                &doc,
                &AppError::Forbidden(
                    "the identity holds no administrator standing here to delegate".into(),
                ),
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }

    // Item 9 — the key rules again, the replacement, the cap, and the write,
    // as one section.
    let _guard = console_key::DELEGATION_LOCK.lock().await;
    if let Err(reject) = key_rules(state, &doc, &key, &identity).await {
        return reject;
    }
    // 0.2 item 14 — after the evidence, and one answer for every reason, so
    // the code cannot be used to test another identity's keys.
    let replaced = match &terms.replaces {
        None => None,
        Some(old) => match console_key::get_delegation(&state.console_keys_ks, old).await {
            Ok(Some(d)) if d.admin_did == identity && d.is_active_at(now) => Some(d),
            Ok(_) => {
                return declared(
                    &doc,
                    ENROLL_ERR_REPLACE_NOT_FOUND,
                    format!("{old} is not an active signing key of {identity}"),
                );
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        },
    };
    // Item 8 — decided after the evidence and standing, counting a replaced
    // key as already gone.
    match console_key::active_count(&state.console_keys_ks, &identity, now).await {
        Ok(n) if n - usize::from(replaced.is_some()) >= console_key::MAX_ACTIVE_PER_IDENTITY => {
            let mut details = json!({ "maxActiveKeys": console_key::MAX_ACTIVE_PER_IDENTITY });
            if terms.lists_active_keys {
                match active_keys_summary(state, &identity, now).await {
                    Ok(keys) => details["activeKeys"] = keys,
                    Err(e) => return app_error_to_reject(&doc, &e),
                }
            }
            return reject_with_code(
                &doc,
                extended_code(ENROLL_ERR_TOO_MANY_KEYS),
                format!(
                    "the identity already holds {n} active signing keys; enrol again \
                     replacing one of them, or revoke one (auth/signing-key/revoke) first"
                ),
                Some(details),
            );
        }
        Ok(_) => {}
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    // Spend the evidence: the authorization's `id` (0.2 item 13), or the
    // passkey gesture's mark.
    let authorization_claim = match &authorization {
        Some(inner) => {
            match state
                .accepted_ids()
                .claim(inner, super::retain_until(inner, now), now)
                .await
            {
                Ok(super::accepted_ids::Acceptance::Fresh(claim)) => Some(claim),
                Ok(_) => {
                    return declared(
                        &doc,
                        ENROLL_ERR_AUTHORIZATION_INVALID,
                        "the authorization has already been used",
                    );
                }
                Err(e) => return reject_with(&doc, e.reject_reason()),
            }
        }
        None => {
            match bound_step_up::spend_mark(state, &identity, &type_uri, &doc.payload).await {
                Ok(true) => None,
                // Lapsed or spent by a concurrent re-send: ask again.
                Ok(false) => {
                    return app_error_to_reject(
                        &doc,
                        &AppError::StepUpRequired(
                            "the passkey gesture for this enrolment has lapsed; send it again"
                                .into(),
                        ),
                    );
                }
                Err(e) => return app_error_to_reject(&doc, &e),
            }
        }
    };
    if let Some(old) = &replaced
        && let Err(e) =
            console_key::revoke_delegation(&state.console_keys_ks, &old.console_did, &identity)
                .await
    {
        if let Some(claim) = authorization_claim {
            claim.release().await;
        }
        return app_error_to_reject(&doc, &e);
    }
    let delegation = match console_key::enrol_delegation(
        &state.console_keys_ks,
        &state.acl_ks,
        &key,
        &identity,
        label,
        terms.expires_at,
    )
    .await
    {
        Ok(d) => d,
        Err(e) => {
            if let Some(claim) = authorization_claim {
                claim.release().await;
            }
            return app_error_to_reject(&doc, &e);
        }
    };
    if let Some(claim) = authorization_claim {
        claim.completed(None).await;
    }

    // Item 12 — a replacement is audited as the identity revoking the key.
    if let Some(old) = &replaced
        && let Some(writer) = state.audit_writer.as_ref()
        && let Err(e) = writer
            .write(
                &identity,
                Some(&old.console_did),
                AuditEvent::AdminConsoleKeyRevoked(AdminConsoleKeyData {
                    console_did: old.console_did.clone(),
                    label: old.label.clone(),
                }),
            )
            .await
    {
        return app_error_to_reject(&doc, &e);
    }

    // Item 12.
    if let Some(writer) = state.audit_writer.as_ref()
        && let Err(e) = writer
            .write(
                &identity,
                Some(&delegation.console_did),
                AuditEvent::AdminConsoleKeyEnrolled(AdminConsoleKeyData {
                    console_did: delegation.console_did.clone(),
                    label: delegation.label.clone(),
                }),
            )
            .await
    {
        return app_error_to_reject(&doc, &e);
    }
    tracing::info!(
        identity = %identity,
        key = %delegation.console_did,
        replaced = replaced.as_ref().map(|d| d.console_did.as_str()),
        evidence = if by_authorization { "authorization" } else { "passkey" },
        "signing key enrolled"
    );
    success_response(&doc, json!({ "signingKey": view(&delegation, Utc::now()) }))
}

/// Verify an `enroll/0.2` document's `authorization` — the identity's own
/// signed `auth/signing-key/authorize/0.1` — and return it as a document, to
/// claim its `id` when the enrolment is written. Every failure is
/// `authorizationInvalid`; there is no fallback to a step-up (item 13).
///
/// Verified **as received**: `raw` is the member of the payload the inbound
/// bytes parsed to, so the proof is checked over what the identity signed
/// (VTI-45), and the payload comparison is over the two payloads as received.
async fn verify_authorization(
    state: &AppState,
    outer: &TrustTask<Value>,
    raw: &Value,
    identity: &str,
    now: DateTime<Utc>,
) -> Result<TrustTask<Value>, TrustTaskOutcome> {
    let invalid = |why: &str| {
        declared(
            outer,
            ENROLL_ERR_AUTHORIZATION_INVALID,
            format!("the authorization is not valid for this enrolment: {why}"),
        )
    };
    let inner: TrustTask<Value> = serde_json::from_value(raw.clone())
        .map_err(|_| invalid("it is not a Trust Task document"))?;
    let inner_type = inner.type_uri.to_string();
    if inner_type != AUTHORIZE_TYPE && inner_type != format!("{AUTHORIZE_TYPE}#request") {
        return Err(invalid(
            "it is not an auth/signing-key/authorize/0.1 document",
        ));
    }
    if inner.issuer.as_deref() != Some(identity) {
        return Err(invalid("it is not issued by identityDid"));
    }
    // Its own acceptance window and recipient binding, as the spine applies
    // them to any document (SPEC §7.2 items 4, 5 and 13).
    if inner
        .validate_freshness(now, &super::freshness_policy())
        .is_err()
    {
        return Err(invalid("it is outside its acceptance window"));
    }
    let Some(vtc_did) = state.config.read().await.vtc_did.clone() else {
        return Err(invalid("this community has no DID to bind it to"));
    };
    if inner.validate_basic(now, &vtc_did).is_err() {
        return Err(invalid(
            "it is not addressed to this community, or has expired",
        ));
    }
    // The terms: the outer payload without `authorization`, as received.
    let mut terms = outer.payload.clone();
    if let Some(obj) = terms.as_object_mut() {
        obj.remove("authorization");
    }
    let canonical = |v: &Value| serde_json_canonicalizer::to_string(v).ok();
    match raw.get("payload") {
        Some(signed) if canonical(signed).is_some() && canonical(signed) == canonical(&terms) => {}
        _ => return Err(invalid("its payload differs from this enrolment's terms")),
    }
    // The proof: by the identity, over the document as received.
    let signer = super::helpers::verify_received_trust_task_proof(state, raw)
        .await
        .map_err(|_| invalid("its proof does not verify"))?;
    if signer != identity {
        return Err(invalid("it is not signed by identityDid"));
    }
    // Made by the identity, not by a credential the identity delegated.
    match console_key::get_delegation(&state.console_keys_ks, &signer).await {
        Ok(None) => {}
        Ok(Some(_)) => return Err(invalid("it is signed by a delegated signing key")),
        Err(e) => return Err(app_error_to_reject(outer, &e)),
    }
    Ok(inner)
}

/// The identity's active delegations, as `tooManyKeys`' `details.activeKeys`
/// lists them — least recently used first, the likeliest to replace.
async fn active_keys_summary(
    state: &AppState,
    identity: &str,
    now: DateTime<Utc>,
) -> Result<Value, AppError> {
    let mut active: Vec<ConsoleKeyDelegation> =
        console_key::list_delegations_for_admin(&state.console_keys_ks, identity)
            .await?
            .into_iter()
            .filter(|d| d.is_active_at(now))
            .collect();
    active.sort_by_key(|d| d.last_used_at.unwrap_or(d.created_at));
    Ok(Value::Array(
        active
            .iter()
            .take(MAX_LISTED_ACTIVE_KEYS)
            .map(|d| {
                let mut v = json!({
                    "signingKeyDid": d.console_did,
                    "createdAt": d.created_at,
                    "expiresAt": d.expires_at,
                });
                if let Some(label) = &d.label {
                    v["deviceLabel"] = json!(label);
                }
                if let Some(t) = d.last_used_at {
                    v["lastUsedAt"] = json!(t);
                }
                v
            })
            .collect(),
    ))
}

/// The key rules (item 2), as their declared codes.
async fn key_rules(
    state: &AppState,
    doc: &TrustTask<Value>,
    key: &str,
    identity: &str,
) -> Result<(), TrustTaskOutcome> {
    let refusal = console_key::key_refusal(&state.console_keys_ks, &state.acl_ks, key, identity)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    let Some(refusal) = refusal else {
        return Ok(());
    };
    let code = match refusal {
        // The schema holds signingKeyDid to did:key, so this is a key that
        // cannot have made the proof it claims.
        EnrolError::NotADidKey => ENROLL_ERR_KEY_NOT_ISSUER,
        EnrolError::SelfDelegation => ENROLL_ERR_SELF_DELEGATION,
        EnrolError::SubjectHoldsAclRow => ENROLL_ERR_KEY_HOLDS_STANDING,
        EnrolError::AlreadyDelegated => ENROLL_ERR_ALREADY_ENROLLED,
        EnrolError::Revoked => ENROLL_ERR_KEY_REVOKED,
    };
    Err(declared(doc, code, refusal.into_app_error(key).to_string()))
}

// ─── list ────────────────────────────────────────────────────────────────

async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = parse_spec_payload::<list::Payload>(&doc) {
        return reject;
    }
    let Some(signer) = ctx.verified_signer.clone() else {
        return reject_with(&doc, RejectReason::ProofRequired);
    };
    let identity = match identity_of(state, &signer).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return app_error_to_reject(
                &doc,
                &AppError::Forbidden("the signer speaks for no identity here".into()),
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let now = Utc::now();
    match console_key::list_delegations_for_admin(&state.console_keys_ks, &identity).await {
        Ok(keys) => success_response(
            &doc,
            json!({ "signingKeys": keys.iter().take(256).map(|d| view(d, now)).collect::<Vec<_>>() }),
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── revoke ──────────────────────────────────────────────────────────────

async fn handle_revoke(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload: revoke::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let key = payload.signing_key_did.to_string();
    let Some(signer) = ctx.verified_signer.clone() else {
        return reject_with(&doc, RejectReason::ProofRequired);
    };
    let not_found = |doc: &TrustTask<Value>| {
        declared(
            doc,
            REVOKE_ERR_NOT_FOUND,
            format!("no signing key {key} that you may revoke"),
        )
    };

    // Serialised with enrolment (item 6).
    let _guard = console_key::DELEGATION_LOCK.lock().await;
    let existing = match console_key::get_delegation(&state.console_keys_ks, &key).await {
        Ok(Some(d)) => d,
        Ok(None) => return not_found(&doc),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // The key itself, the identity it acts for, or an unrestricted
    // administrator (incident response). A narrower administrator may not
    // disarm a peer's console: revocation cannot escalate, but it can deny
    // service.
    let authorized = if signer == key {
        true
    } else {
        let identity = match identity_of(state, &signer).await {
            Ok(i) => i,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        let unrestricted = match super::admin_signer(state, ctx, &doc).await {
            Ok(claims) => claims.is_super_admin(),
            Err(_) => false,
        };
        identity.as_deref() == Some(existing.admin_did.as_str()) || unrestricted
    };
    if !authorized {
        return not_found(&doc);
    }

    let revoked = match console_key::revoke_delegation(&state.console_keys_ks, &key, &signer).await
    {
        Ok(Some(d)) => d,
        Ok(None) => return not_found(&doc),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let now = Utc::now();
    let remaining =
        match console_key::active_count(&state.console_keys_ks, &revoked.admin_did, now).await {
            Ok(n) => n,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
    if let Some(writer) = state.audit_writer.as_ref()
        && let Err(e) = writer
            .write(
                &signer,
                Some(&revoked.console_did),
                AuditEvent::AdminConsoleKeyRevoked(AdminConsoleKeyData {
                    console_did: revoked.console_did.clone(),
                    label: revoked.label.clone(),
                }),
            )
            .await
    {
        return app_error_to_reject(&doc, &e);
    }
    tracing::info!(revoked_by = %signer, key = %revoked.console_did, "signing key revoked");
    success_response(
        &doc,
        json!({
            "signingKeyDid": revoked.console_did,
            "revokedAt": revoked.revoked_at.unwrap_or(now),
            "remainingActive": remaining,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_attempt_past_a_full_bucket_is_refused_and_counts_nothing() {
        reset_attempts_for_test();
        let identity = "did:key:z6MkRateLimitedIdentity";
        for i in 0..PER_IDENTITY {
            assert!(admit_attempt(identity, &format!("did:key:z6MkKey{i}")).is_ok());
        }
        let retry = admit_attempt(identity, "did:key:z6MkOneMore").unwrap_err();
        assert!(retry > Utc::now());
        // A different identity is unaffected by the first one's bucket.
        assert!(admit_attempt("did:key:z6MkAnotherIdentity", "did:key:z6MkKeyX").is_ok());
        let key = "did:key:z6MkBusyKey";
        for i in 0..PER_KEY {
            assert!(admit_attempt(&format!("did:key:z6MkIdentity{i}"), key).is_ok());
        }
        assert!(admit_attempt("did:key:z6MkIdentityLast", key).is_err());
        reset_attempts_for_test();
    }
}
