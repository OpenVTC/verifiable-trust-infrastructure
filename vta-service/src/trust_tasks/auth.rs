//! Auth-slice trust-task handlers.
//!
//! Only `revoke-session/1.0` is dispatched here. Pre-authentication
//! operations (challenge, authenticate, refresh, passkey-login) cannot
//! pass `AuthClaims` and so live on dedicated unauth REST routes in
//! `routes::auth` — see the `REST_ROUTED` allowlist in the parity
//! harness for the full list.

use super::helpers::TrustTaskOutcome;
use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::protocols::auth::{RevokeSessionRequest, RevokeSessionResponse, epoch_to_rfc3339};

use crate::acl::{Role, check_acl_full};
use crate::audit::audit;
use crate::auth::AuthClaims;
use crate::auth::session::{SessionState, delete_session, get_session, list_sessions, now_epoch};
use crate::server::AppState;

use super::helpers::{app_error_to_reject, reject_with, success_response};

/// Handler for `spec/vta/auth/revoke-session/1.0`.
///
/// Parses the request payload, looks up the session, authorises the caller
/// (session owner OR `Role::Admin`), deletes the session, and answers with
/// `revokedCount` — the number of sessions this call invalidated.
///
/// **`revokedCount: 0` is a success, and it is deliberately ambiguous.** The
/// spec asks for both things at once. The response schema says "Zero is a valid
/// outcome (e.g. the named sessionId was already revoked)" and the prose adds
/// that producers "SHOULD treat zero as 'the post-state is what you asked for',
/// not as an error" — so a retry of a revoke that already happened must
/// succeed. `vta-sdk`'s own `retry_safety` table agrees: this task is
/// `RetrySafe`. Separately, the `notOwner` error code carries "The auth service
/// MUST NOT reveal whether the session exists at all when the producer is not
/// its owner."
///
/// Those two only hold together if a session the caller may not touch and a
/// session that is not there answer identically. So both return zero, and this
/// handler never emits `notOwner`: emitting it *only* when the session exists
/// is exactly the disclosure the code's own definition forbids. The count stays
/// literally true either way — zero sessions were invalidated by this call. The
/// refusal is still recorded in the audit trail, which is not the caller's to
/// read.
///
/// This diverges from `routes::auth::revoke_session` (the legacy
/// `DELETE /auth/sessions/{session_id}` REST handler), which 404s on a missing
/// session. That is the conventional REST answer for a missing resource and is
/// in its published OpenAPI responses; it is not governed by this task's
/// `revokedCount` schema. Same audit event key (`session.revoke`), same
/// authorisation rule.
pub(super) async fn handle_revoke_session(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // 1. Parse the payload.
    let req: RevokeSessionRequest = match serde_json::from_value(doc.payload.clone()) {
        Ok(r) => r,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("revoke-session payload parse: {e}"),
                },
            );
        }
    };

    // 2. Look up the session.
    // `sessionId` XOR `all`, per the specification's `oneOf`. Both arms are
    // legal documents; only one of them is a thing this VTA can do.
    let session_id = match (&req.session_id, req.all.unwrap_or(false)) {
        (Some(id), false) => id.clone(),
        (None, true) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: "auth:revoke_all_unsupported — this maintainer revokes one named \
                             session; resend with `sessionId`"
                        .to_string(),
                    details: None,
                },
            );
        }
        // Both or neither: the `oneOf` refuses it, and so does this.
        _ => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: "revoke-session takes exactly one of `sessionId` or `all`".to_string(),
                },
            );
        }
    };

    let session = match get_session(&state.sessions_ks, &session_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session lookup failed in revoke-session");
            return reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: format!("session lookup: {e}"),
                },
            );
        }
    };

    // 3. Authorise: caller owns the session OR has Role::Admin. Same rule as
    //    the legacy REST handler. A session that is not the caller's and a
    //    session that does not exist take the same arm, so the caller cannot
    //    tell them apart — see this function's doc comment.
    if session
        .filter(|s| s.did == auth.did || auth.role == Role::Admin)
        .is_none()
    {
        // Warn, not reject. The operator reading logs is entitled to know a
        // caller reached for a session; the caller is not entitled to know
        // whether it was there.
        tracing::warn!(
            caller = %auth.did,
            session_id = %session_id,
            "revoke-session: no session revoked (absent, or not the caller's)"
        );
        audit!(
            "session.revoke",
            actor = &auth.did,
            resource = &session_id,
            outcome = "no-op"
        );
        return success_response(&doc, RevokeSessionResponse { revoked_count: 0 });
    }

    // 4. Delete.
    if let Err(e) = delete_session(&state.sessions_ks, &session_id).await {
        tracing::error!(error = %e, session_id = %session_id, "session delete failed");
        return reject_with(
            &doc,
            RejectReason::InternalError {
                reason: format!("session delete: {e}"),
            },
        );
    }

    // 5. Audit — both forms, and they are not redundant.
    //
    // The `audit!` macro emits a tracing event on the `audit` target: a log
    // line. It does NOT reach the `AuditSink`, so nothing it records appears in
    // `audit/list` or in an operator's external sink. Ending a session is a
    // change to who can act, and it belongs in the queryable trail, so the
    // sink-routed `record_with_detail` is what actually satisfies that.
    audit!(
        "session.revoke",
        actor = &auth.did,
        resource = &session_id,
        outcome = "success"
    );
    if let Err(e) = crate::audit::record_with_detail(
        &state.audit_sink,
        "session.revoke",
        &auth.did,
        Some(&session_id),
        "success",
        Some(super::helpers::TRANSPORT_TRUST_TASK),
        None,
        None,
    )
    .await
    {
        tracing::warn!(error = %e, "audit record failed for session.revoke");
    }
    tracing::info!(
        caller = %auth.did,
        session_id = %session_id,
        "session revoked via trust-task"
    );

    // 6. Build the success response document. `revokedCount` is 1: this handler
    // revokes exactly the one named session.
    success_response(&doc, RevokeSessionResponse { revoked_count: 1 })
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

    // Re-resolve roles/scopes so a policy/ACL change since the token was minted
    // is reflected. A caller deauthorised mid-token surfaces here as the ACL
    // error (their authority really is gone).
    let (role, contexts) = match check_acl_full(&state.acl_ks, &auth.did).await {
        Ok(rc) => rc,
        Err(e) => return app_error_to_reject(&doc, e),
    };

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
    let body = json!({
        "session": session_info,
        "roles": [role.to_string()],
        "scopes": scopes,
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
/// `auth.did` (a caller only sees their own sessions); this is distinct from
/// the admin `GET /auth/sessions` REST route, which lists every session.
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
