//! Auth-slice trust-task handlers.
//!
//! `revoke-session/0.2`, `whoami/0.1` and `sessions/list/0.1` are dispatched
//! by the ordinary ACL-gated pipeline, exactly like every other authenticated
//! task — the handlers below take `&AuthClaims` and are wired into
//! `dispatch_table!`.
//!
//! The **pre-session family** — [`owns`] / [`dispatch_pre_session`] — is
//! different in kind, not just in operation. `auth/challenge/0.1`,
//! `auth/authenticate/{0.2,0.3}` and `auth/refresh/0.2` carry no prior
//! session, so they cannot pass `AuthClaims` through the dispatcher's
//! extractor, and they must not be routed through the ACL/issuer-consistency
//! gates `dispatch_trust_task_core` applies to everything else — those gates
//! assume a caller already has standing here, which is precisely what these
//! four establish. So each of the three transports (REST's
//! `dispatch_trust_task`, DIDComm's `handle_trust_task`, TSP's `handle_tsp`)
//! checks [`owns`] and calls [`dispatch_pre_session`] directly, *before*
//! `dispatch_trust_task_core` — a family-owned dispatch, mirroring
//! `affinidi-webvh-service`'s `did-hosting-control::trust_tasks_auth`
//! (`owns`/`dispatch`, checked ahead of that service's ACL pre-filter). The
//! document's own proof — present on authenticate, required by its
//! specification; absent on challenge and refresh, whose specifications
//! declare none — is the whole of the authority any of these four carry, so
//! there is no ACL pre-filter here to skip *around*: there simply is none in
//! this path.
//!
//! These four are still declared in `vta_sdk::trust_tasks::REST_ROUTED_URIS`
//! (see its doc comment) even though — challenge/authenticate/refresh, unlike
//! passkey-login — they now travel as ordinary Trust-Task envelopes over
//! `/trust-tasks`: the name is about what a generic "invoke any operation"
//! surface must exclude (no session to carry), not about the literal
//! transport.

use super::helpers::TrustTaskOutcome;
use serde_json::{Value, json};
use trust_tasks_rs::specs::auth::authenticate::{v0_2 as authenticate_v2, v0_3 as authenticate_v3};
use trust_tasks_rs::specs::auth::refresh::v0_2 as refresh_v2;
use trust_tasks_rs::specs::auth::revoke_session::v0_2 as revoke_session_spec;
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::protocols::auth::epoch_to_rfc3339;

use crate::acl::{check_acl_entry, effective_capabilities};
use crate::audit::audit;
use crate::auth::AuthClaims;
use crate::auth::session::{SessionState, delete_session, get_session, list_sessions, now_epoch};
use crate::server::AppState;

use super::helpers::{
    app_error_to_reject, body_parse_error_response, parse_payload, reject_declared, reject_with,
    success_response,
};

// ─── Pre-session family ────────────────────────────────────────────────────

/// Does `type_uri` belong to the pre-session auth family?
pub(crate) fn owns(type_uri: &str) -> bool {
    type_uri == vta_sdk::trust_tasks::TASK_AUTH_CHALLENGE_0_1
        || type_uri == vta_sdk::trust_tasks::TASK_AUTH_AUTHENTICATE_0_2
        || type_uri == vta_sdk::trust_tasks::TASK_AUTH_AUTHENTICATE_0_3
        || type_uri == vta_sdk::trust_tasks::TASK_AUTH_REFRESH_0_2
}

/// Dispatch a pre-session auth document. `body` is the raw envelope bytes,
/// identical whichever transport carried them — none of this family's
/// identity comes from the transport, so there is nothing transport-specific
/// left to plumb through.
///
/// Callers check [`owns`] on the peeked `type` first; a URI this function
/// does not recognize falls through to a `malformedRequest` rather than a
/// panic, but that arm is unreachable in the wired transports.
pub(crate) async fn dispatch_pre_session(state: &AppState, body: &[u8]) -> TrustTaskOutcome {
    let doc: TrustTask<Value> = match serde_json::from_slice(body) {
        Ok(d) => d,
        Err(e) => return body_parse_error_response(&e.to_string()),
    };
    let type_uri = doc.type_uri.to_string();

    // SPEC §7.2's flag-driven checks this family still owes a caller:
    // `issuedAt`/`proof`/`recipient` REQUIRED, per what each spec declares.
    // The generic dispatch spine runs this too (`dispatch_trust_task_validated`);
    // this family bypasses that spine entirely, so it runs its own copy rather
    // than silently going without.
    if let Some(policy) = trust_tasks_rs::schema_index::spec_policy_for(&type_uri)
        && let Err(reason) = policy.enforce(&doc)
    {
        return reject_with(&doc, reason);
    }

    match type_uri.as_str() {
        t if t == vta_sdk::trust_tasks::TASK_AUTH_CHALLENGE_0_1 => {
            dispatch_challenge(state, doc).await
        }
        t if t == vta_sdk::trust_tasks::TASK_AUTH_AUTHENTICATE_0_2 => {
            dispatch_authenticate_v2(state, doc).await
        }
        t if t == vta_sdk::trust_tasks::TASK_AUTH_AUTHENTICATE_0_3 => {
            dispatch_authenticate_v3(state, doc).await
        }
        t if t == vta_sdk::trust_tasks::TASK_AUTH_REFRESH_0_2 => {
            dispatch_refresh_v2(state, doc).await
        }
        other => reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: format!("`{other}` is not a member of the pre-session auth family"),
            },
        ),
    }
}

/// Handler for `spec/auth/challenge/0.1`. No proof: the subject is the
/// document's stated holder (same trust model the REST route used — issuance
/// is pre-auth and ACL-gated inside [`vti_common::auth::handlers::handle_challenge`]).
async fn dispatch_challenge(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let Some(subject) = doc.payload.get("subject").and_then(Value::as_str) else {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "auth/challenge payload missing `subject`".into(),
            },
        );
    };
    let subject = subject.to_string();

    let backend = match crate::auth::VtaAuthBackend::from_state(state).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let resp = match vti_common::auth::handlers::handle_challenge(
        &backend,
        vti_common::auth::ChallengeInput {
            did: subject.clone(),
            session_pubkey_b58btc: None,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    audit!(
        "auth.challenge",
        actor = &subject,
        resource = &resp.session_id,
        outcome = "success"
    );
    success_response(
        &doc,
        json!({
            "challenge": resp.challenge,
            "sessionId": resp.session_id,
            "expiresAt": resp.expires_at,
        }),
    )
}

/// Handler for `spec/auth/authenticate/0.2`. The holder's Data-Integrity
/// proof IS the authentication; `sessionKey` is not yet honoured.
async fn dispatch_authenticate_v2(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let signer_did =
        match vti_common::auth::verify_trust_task_proof_with(&doc, &state.trust_task_vm_resolver())
            .await
        {
            Ok(s) => s,
            Err(e) => {
                return reject_with(
                    &doc,
                    RejectReason::ProofInvalid {
                        reason: e.to_string(),
                    },
                );
            }
        };
    let payload: authenticate_v2::Payload = match serde_json::from_value(doc.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("invalid authenticate payload: {e}"),
                },
            );
        }
    };
    if payload.session_key.is_some() {
        return reject_declared(
            &doc,
            authenticate_v2::error_codes::SESSION_KEY_UNSUPPORTED,
            "this VTA does not yet bind a session key from an authenticate document",
        );
    }
    complete_authenticate(
        state,
        &doc,
        signer_did,
        payload.session_id.to_string(),
        payload.challenge.to_string(),
    )
    .await
}

/// Handler for `spec/auth/authenticate/0.3`. Same as 0.2, plus the proxied
/// (`principal` + `delegationEvidence`) shape — refused, since this VTA
/// recognizes no delegation-evidence kind; the ordinary case (no `principal`,
/// or one equal to the document's own signer) behaves exactly like 0.2.
async fn dispatch_authenticate_v3(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let signer_did =
        match vti_common::auth::verify_trust_task_proof_with(&doc, &state.trust_task_vm_resolver())
            .await
        {
            Ok(s) => s,
            Err(e) => {
                return reject_with(
                    &doc,
                    RejectReason::ProofInvalid {
                        reason: e.to_string(),
                    },
                );
            }
        };
    let payload: authenticate_v3::Payload = match serde_json::from_value(doc.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("invalid authenticate payload: {e}"),
                },
            );
        }
    };
    if payload.session_key.is_some() {
        return reject_declared(
            &doc,
            authenticate_v3::error_codes::SESSION_KEY_UNSUPPORTED,
            "this VTA does not yet bind a session key from an authenticate document",
        );
    }
    if let Some(principal) = payload.principal.as_ref().map(|p| p.to_string())
        && principal != signer_did
    {
        return reject_declared(
            &doc,
            authenticate_v3::error_codes::DELEGATION_NOT_RECOGNIZED,
            "this VTA recognizes no delegationEvidence kind; authenticate as the principal \
             directly",
        );
    }
    complete_authenticate(
        state,
        &doc,
        signer_did,
        payload.session_id.to_string(),
        payload.challenge.to_string(),
    )
    .await
}

/// The self-authentication path shared by 0.2 and 0.3 once each has narrowed
/// its own payload shape: mint tokens for `signer_did` against the challenged
/// session, addressed by the document's own `recipient` (SPEC §7.2 item 5,
/// #1638) — there is no transport binding to lean on instead, since this
/// bypass runs ahead of any transport-specific scope.
async fn complete_authenticate(
    state: &AppState,
    doc: &TrustTask<Value>,
    signer_did: String,
    session_id: String,
    challenge: String,
) -> TrustTaskOutcome {
    let backend = match crate::auth::VtaAuthBackend::from_state(state).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(doc, e),
    };
    let resp = match vti_common::auth::handlers::handle_authenticate(
        &backend,
        vti_common::auth::AuthenticateInput {
            session_id: session_id.clone(),
            challenge,
            signer_did: signer_did.clone(),
            // No DIDComm `created_time` here — see the module doc: this
            // bypass runs ahead of any transport-specific scope, so the
            // single-use, TTL'd challenge bound to the session is the
            // freshness/replay anchor on every transport alike.
            created_time: None,
            session_pubkey_b58btc: None,
            audience: vti_common::auth::AudienceBinding::Recipient {
                recipient: doc.recipient.clone(),
                own_did: state.config.read().await.vta_did.clone(),
            },
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(doc, e),
    };
    audit!(
        "auth.authenticate",
        actor = &signer_did,
        resource = &session_id,
        outcome = "success"
    );
    success_response(
        doc,
        json!({ "tokens": resp.tokens, "session": resp.session }),
    )
}

/// Handler for `spec/auth/refresh/0.2`. Carries no proof — the opaque refresh
/// token in the payload is the credential (OAuth2 §10.4 semantics), verified
/// server-side by the rotating reverse-index.
async fn dispatch_refresh_v2(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let payload: refresh_v2::Payload = match serde_json::from_value(doc.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("invalid refresh payload: {e}"),
                },
            );
        }
    };
    let refresh_token = payload.refresh_token.to_string();

    let backend = match crate::auth::VtaAuthBackend::from_state(state).await {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let resp = match vti_common::auth::handlers::handle_refresh(
        &backend,
        vti_common::auth::RefreshInput {
            refresh_token,
            // No proven signer: the token alone is sufficient, exactly as
            // the retired REST route treated an `auth/refresh/0.1` document.
            signer_did: None,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    audit!(
        "auth.refresh",
        actor = &resp.session.subject,
        resource = &resp.session.id,
        outcome = "success"
    );
    success_response(
        &doc,
        json!({ "tokens": resp.tokens, "session": resp.session }),
    )
}

/// What an `auth/revoke-session/0.2` document targets — exactly one of the
/// three forms the specification's `oneOf` admits.
enum RevokeTarget {
    /// One named session.
    Session(String),
    /// Every session of this subject: `all: true` (the caller itself) or
    /// `subject`.
    Subject(String),
}

/// Read the target and reason off the payload **as received**.
///
/// The payload is first checked against the published schema
/// (`ValidatedPayload::validate_value`), and the one-form rule is then enforced
/// here, on that validated JSON — not left to the generated Rust type, which
/// (from trust-tasks-rs 0.24) models the three forms as independent optional
/// members and so cannot say "exactly one". The spine validates the payload
/// before dispatch too; this handler does not rely on it.
///
/// `Err` is the `malformedRequest` reason: a payload the schema refuses, two
/// forms or none, or `all: false`, which 0.2 keeps schema-valid only because
/// 0.1 admitted it and which targets nothing.
fn revoke_target(payload: &Value, caller: &str) -> Result<(RevokeTarget, Option<String>), String> {
    use trust_tasks_rs::validate::ValidatedPayload as _;
    revoke_session_spec::Payload::validate_value(payload)
        .map_err(|e| format!("revoke-session payload: {e}"))?;
    let obj = payload
        .as_object()
        .ok_or_else(|| "revoke-session payload must be an object".to_string())?;
    let forms = ["sessionId", "all", "subject"]
        .iter()
        .filter(|k| obj.contains_key(**k))
        .count();
    if forms != 1 {
        return Err(
            "revoke-session takes exactly one of `sessionId`, `all` or `subject`".to_string(),
        );
    }
    let reason = obj
        .get("reason")
        .and_then(Value::as_str)
        .map(str::to_string);
    let target = if let Some(id) = obj.get("sessionId").and_then(Value::as_str) {
        RevokeTarget::Session(id.to_string())
    } else if let Some(all) = obj.get("all").and_then(Value::as_bool) {
        if !all {
            return Err(
                "`all: false` targets nothing; send `all: true`, `sessionId` or `subject`"
                    .to_string(),
            );
        }
        RevokeTarget::Subject(caller.to_string())
    } else if let Some(subject) = obj.get("subject").and_then(Value::as_str) {
        RevokeTarget::Subject(subject.to_string())
    } else {
        // Unreachable once the schema has passed (each member is typed), but
        // a wrong type is a malformed request, not a panic.
        return Err(
            "revoke-session: `sessionId` and `subject` are strings, `all` a boolean".into(),
        );
    };
    Ok((target, reason))
}

/// Handler for `spec/auth/revoke-session/0.2`.
///
/// Ends one named session (`sessionId`), every session of the caller
/// (`all: true`), or every session of a named `subject`, and answers
/// `revokedCount` — the number of sessions this call invalidated.
///
/// # Whose sessions a caller may end (VTI-SES-043, VTI-ACL-050)
///
/// Its own, always. Anyone else's exactly when it could withdraw that
/// subject's access: [`crate::operations::acl::may_manage_subject`], the rule
/// `acl/revoke` applies to the subject's entry. Holding the admin role is not
/// enough on its own — a context admin cannot end a super-admin's sessions, nor
/// those of a subject in a context it does not administer, and a subject with
/// no ACL entry belongs to no context, so only a super-admin reaches it.
///
/// # What a refusal discloses
///
/// - `subject` outside the caller's authority is `permissionDenied`, and the
///   check runs **before** the subject's sessions are looked at, so the answer
///   is the same whether or not this agent knows the subject or holds sessions
///   for it (consumer rule 4).
/// - `sessionId` of a session outside the caller's authority is answered as a
///   missing one: `revokedCount: 0`, which the spec RECOMMENDS because it makes
///   a retried revocation succeed (consumer rule 2). Emitting anything
///   different *only* when the session exists is exactly the disclosure the
///   rule forbids.
///
/// Every revocation and every refusal is recorded in the audit trail with both
/// the caller and the targeted subject (consumer rule 7); the trail is not the
/// caller's to read.
///
/// 0.1 is not served: every 0.1 payload is a valid 0.2 payload, and 0.1 had no
/// way to name another subject.
pub(super) async fn handle_revoke_session(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (target, reason) = match revoke_target(&doc.payload, &auth.did) {
        Ok(t) => t,
        Err(reason) => {
            return reject_with(&doc, RejectReason::MalformedRequest { reason });
        }
    };
    // And through the generated type, so the payload is one it admits.
    if let Err(resp) = parse_payload::<revoke_session_spec::Payload>(&doc) {
        return resp;
    }
    match target {
        RevokeTarget::Session(session_id) => {
            revoke_one(state, auth, &doc, &session_id, reason.as_deref()).await
        }
        RevokeTarget::Subject(subject) => {
            revoke_subject(state, auth, &doc, &subject, reason.as_deref()).await
        }
    }
}

/// The `sessionId` form.
async fn revoke_one(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    session_id: &str,
    reason: Option<&str>,
) -> TrustTaskOutcome {
    let session = match get_session(&state.sessions_ks, session_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session lookup failed in revoke-session");
            return reject_with(
                doc,
                RejectReason::InternalError {
                    reason: format!("session lookup: {e}"),
                },
            );
        }
    };

    // A session that is not the caller's to end and one that does not exist
    // take the same arm, so the caller cannot tell them apart.
    let permitted = match &session {
        Some(s) => {
            match crate::operations::acl::may_manage_subject(&state.acl_ks, auth, &s.did).await {
                Ok(p) => p,
                Err(e) => return app_error_to_reject(doc, e),
            }
        }
        None => false,
    };
    if !permitted {
        // Warn, not reject. The operator reading logs is entitled to know a
        // caller reached for a session; the caller is not entitled to know
        // whether it was there.
        tracing::warn!(
            caller = %auth.did,
            session_id = %session_id,
            "revoke-session: no session revoked (absent, or outside the caller's authority)"
        );
        audit!(
            "session.revoke",
            actor = &auth.did,
            resource = session_id,
            outcome = "no-op"
        );
        // A real session outside the caller's authority is a refusal, and
        // refusals are recorded durably (VTI-AUD-003), naming its subject.
        if let Some(s) = &session {
            crate::audit::record_with_detail_best_effort(
                &state.audit_sink,
                "session.revoke",
                &auth.did,
                Some(session_id),
                "denied",
                Some(super::helpers::TRANSPORT_TRUST_TASK),
                None,
                Some(&format!(
                    "session of {} is outside the caller's authority",
                    s.did
                )),
            )
            .await;
        }
        return success_response(doc, json!({ "revokedCount": 0 }));
    }
    let subject = session.map(|s| s.did).unwrap_or_default();

    if let Err(e) = delete_session(&state.sessions_ks, session_id).await {
        tracing::error!(error = %e, session_id = %session_id, "session delete failed");
        return reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("session delete: {e}"),
            },
        );
    }

    // Both forms, and they are not redundant: `audit!` is a log line on the
    // `audit` target and never reaches the `AuditSink`; ending a session is a
    // change to who can act, so it belongs in the queryable trail too.
    audit!(
        "session.revoke",
        actor = &auth.did,
        resource = session_id,
        outcome = "success"
    );
    record_revocation(
        state,
        auth,
        "session.revoke",
        session_id,
        &subject,
        1,
        reason,
    )
    .await;
    tracing::info!(caller = %auth.did, session_id = %session_id, "session revoked via trust-task");

    success_response(doc, json!({ "revokedCount": 1 }))
}

/// The `all: true` and `subject` forms.
async fn revoke_subject(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    subject: &str,
    reason: Option<&str>,
) -> TrustTaskOutcome {
    // Authority first, before anything about the subject's sessions is read,
    // so the refusal is identical whether or not it has any.
    let permitted =
        match crate::operations::acl::may_manage_subject(&state.acl_ks, auth, subject).await {
            Ok(p) => p,
            Err(e) => return app_error_to_reject(doc, e),
        };
    if !permitted {
        tracing::warn!(
            audit = true,
            security_alert = true,
            caller = %auth.did,
            subject,
            "revoke-session refused: the subject is outside the caller's authority"
        );
        crate::audit::record_with_detail_best_effort(
            &state.audit_sink,
            "session.revoke_by_did",
            &auth.did,
            Some(subject),
            "denied",
            Some(super::helpers::TRANSPORT_TRUST_TASK),
            None,
            Some("the subject is outside the caller's authority"),
        )
        .await;
        return reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: "the named subject is outside your authority".into(),
            },
        );
    }

    let sessions = match list_sessions(&state.sessions_ks).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session list failed in revoke-session");
            return reject_with(
                doc,
                RejectReason::InternalError {
                    reason: format!("session list: {e}"),
                },
            );
        }
    };
    let mut revoked = 0u64;
    for session in sessions.into_iter().filter(|s| s.did == subject) {
        if let Err(e) = delete_session(&state.sessions_ks, &session.session_id).await {
            tracing::error!(error = %e, "session delete failed in revoke-session");
            return reject_with(
                doc,
                RejectReason::InternalError {
                    reason: format!("session delete: {e}"),
                },
            );
        }
        revoked += 1;
    }

    audit!(
        "session.revoke_by_did",
        actor = &auth.did,
        resource = subject,
        outcome = "success"
    );
    record_revocation(
        state,
        auth,
        "session.revoke_by_did",
        subject,
        subject,
        revoked,
        reason,
    )
    .await;
    tracing::info!(caller = %auth.did, subject, revoked, "sessions revoked via trust-task");

    success_response(doc, json!({ "revokedCount": revoked }))
}

/// The durable audit row for a revocation: who acted, on whose sessions, how
/// many, and the caller's stated reason.
async fn record_revocation(
    state: &AppState,
    auth: &AuthClaims,
    action: &str,
    resource: &str,
    subject: &str,
    revoked: u64,
    reason: Option<&str>,
) {
    let detail = match reason {
        Some(r) => format!("subject {subject}; {revoked} session(s); reason: {r}"),
        None => format!("subject {subject}; {revoked} session(s)"),
    };
    if let Err(e) = crate::audit::record_with_detail(
        &state.audit_sink,
        action,
        &auth.did,
        Some(resource),
        "success",
        Some(super::helpers::TRANSPORT_TRUST_TASK),
        None,
        Some(&detail),
    )
    .await
    {
        tracing::warn!(error = %e, "audit record failed for {action}");
    }
}

/// Handler for `spec/auth/whoami/0.1`.
///
/// Introspection for an authenticated caller. The bearer JWT is the auth (like
/// revoke-session) — the holder's optional DI proof on the document is *not*
/// required here, since the authenticated transport already established who's
/// asking. Returns the session's **live** `acr`/`amr`, which reflect any
/// step-up that happened since the access token was minted (the JWT's own
/// `acr`/`amr` are stale until the next refresh), plus **freshly-resolved**
/// roles/scopes from the ACL — so a policy change is visible without re-issuing
/// tokens. No tokens are minted or rotated.
pub(super) async fn handle_whoami(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Live session state: acr/amr are updated in place by step-up, and
    // created_at is the session's issue time.
    let session = match get_session(&state.sessions_ks, &auth.session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: format!("session not found: {}", auth.session_id),
                    details: None,
                },
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "session lookup failed in whoami");
            return reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: format!("session lookup: {e}"),
                },
            );
        }
    };

    // Re-resolve roles/scopes/capabilities so a policy/ACL change since the token
    // was minted is reflected. A caller deauthorised mid-token surfaces here as
    // the ACL error (their authority really is gone).
    //
    // One read of the whole entry rather than two of its members: a second read
    // could straddle a concurrent ACL edit and answer with a role from before it
    // and a capability set from after.
    let entry = match check_acl_entry(&state.acl_ks, &auth.did).await {
        Ok(entry) => entry,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let (role, contexts) = (entry.role.clone(), entry.allowed_contexts.clone());

    let mut session_info = json!({
        "id": auth.session_id,
        "subject": auth.did,
        "issuedAt": epoch_to_rfc3339(session.created_at),
        "expiresAt": epoch_to_rfc3339(auth.access_expires_at),
        "amr": session.amr,
    });
    // `acr` is optional in the spec — include it only when the session has one.
    if !session.acr.is_empty() {
        session_info["acr"] = Value::String(session.acr.clone());
    }

    // Mirror the access token's scope representation (`ctx:<id>`), built by the
    // canonical authenticate handler.
    let scopes: Vec<String> = contexts.iter().map(|c| format!("ctx:{c}")).collect();
    // Effective, not stored. The question a caller is asking is "what may I do",
    // and an entry that narrows nothing means everything its role implies —
    // returning the stored list would answer a different question and read as
    // empty for the commonest entry there is. It is also the only way the
    // additive capabilities are visible at all: no role derives `persona-holder`,
    // so a consumer computing the role's own set would never see it.
    let capabilities: Vec<String> = effective_capabilities(&entry.role, &entry.capabilities)
        .into_iter()
        .map(|c| {
            serde_json::to_value(c)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                // Serialization of a fieldless enum cannot fail; the fallback
                // exists so an unreachable branch cannot drop a capability
                // silently from an authorization answer.
                .unwrap_or_else(|| format!("{c:?}"))
        })
        .collect();

    let body = json!({
        "session": session_info,
        "roles": [role.to_string()],
        "scopes": scopes,
        "capabilities": capabilities,
    });

    audit!(
        "auth.whoami",
        actor = &auth.did,
        resource = &auth.session_id,
        outcome = "success"
    );
    success_response(&doc, body)
}

/// Handler for `spec/auth/sessions/list/0.1`.
///
/// Enumerates every **active** session the VTA holds for the *caller's own*
/// subject — the self-service multi-device view, companion to whoami. Scoped to
/// `auth.did`: a caller only ever sees its own sessions, whatever its role. (An
/// administrator ends another subject's sessions with `auth/revoke-session/0.2`
/// `subject`; there is no task that enumerates them.)
/// Bearer-authed like the other dispatcher auth ops; read-only.
pub(super) async fn handle_sessions_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let all = match list_sessions(&state.sessions_ks).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session list failed in sessions/list");
            return reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: format!("session list: {e}"),
                },
            );
        }
    };

    let now = now_epoch();
    let sessions: Vec<Value> = all
        .into_iter()
        // The caller's own, authenticated, not-yet-expired sessions.
        .filter(|s| {
            s.did == auth.did
                && s.state == SessionState::Authenticated
                && s.refresh_expires_at.is_none_or(|exp| exp > now)
        })
        .map(|s| {
            // The session ceases to be valid when its refresh window closes;
            // fall back to issue time if no refresh token was minted.
            let expires_at = s.refresh_expires_at.unwrap_or(s.created_at);
            let mut item = json!({
                "id": s.session_id,
                "subject": s.did,
                "issuedAt": epoch_to_rfc3339(s.created_at),
                "expiresAt": epoch_to_rfc3339(expires_at),
                "amr": s.amr,
            });
            if !s.acr.is_empty() {
                item["acr"] = Value::String(s.acr);
            }
            item
        })
        .collect();

    audit!(
        "auth.sessions-list",
        actor = &auth.did,
        resource = &auth.session_id,
        outcome = "success"
    );
    success_response(&doc, json!({ "sessions": sessions }))
}

#[cfg(test)]
mod revoke_form_tests {
    use serde_json::{Value, json};
    use trust_tasks_rs::TrustTask;

    /// The handler holds the one-form rule itself, not only the spine's schema
    /// check in front of it: called directly with a document the schema would
    /// refuse, it still answers `malformedRequest` and revokes nothing.
    #[tokio::test]
    async fn the_handler_refuses_two_forms_or_none_on_its_own() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let claims = crate::test_support::super_admin_claims();
        for payload in [
            json!({ "sessionId": "s-1", "all": true }),
            json!({ "sessionId": "s-1", "subject": "did:key:z6MkOther" }),
            json!({ "all": true, "subject": "did:key:z6MkOther" }),
            json!({}),
            json!({ "all": false }),
        ] {
            let doc: TrustTask<Value> = serde_json::from_value(json!({
                "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "type": vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_0_2,
                "payload": payload.clone(),
            }))
            .unwrap();
            let out = super::handle_revoke_session(&state, &claims, doc).await;
            let body: Value = serde_json::from_slice(&out.body).unwrap();
            assert_eq!(
                body["payload"]["code"], "malformedRequest",
                "{payload}: {body}"
            );
        }
    }
}
