// Handlers share the `Result<_, Response>` shape via `parse_payload`; the
// Response is owned and emitted on the same stack frame (see `vault.rs`).
#![allow(clippy::result_large_err)]

//! Credential-exchange slice — the holder operator's deferred-presentation
//! approval surface.
//!
//! When a verifier the holder hasn't pre-trusted sends a
//! `credential-exchange/query/1.0`, the VTA **defers** it: it persists a
//! `pending-present:` record and replies "consent required" (see
//! `crate::messaging::handlers::handle_credential_query`). These three tasks are
//! the holder operator's out-of-band surface over that backlog:
//!
//! - `pending-list/1.0` — list the actionable deferrals.
//! - `pending-approve/1.0` — approve one and **re-present** (returns the `vp_token`).
//! - `pending-deny/1.0` — deny one (no presentation is made).
//!
//! All three are **super-admin only**: the credentials presented are the VTA's
//! own, so authorization mirrors the autonomous wire flow's "own authority"
//! (`handle_credential_query`). The approve op's re-present resolves the holder
//! key through the same `auth`-gated path as a trusted-verifier present, so the
//! caller's super-admin claims authorize key access and give correct audit
//! attribution.

use axum::response::Response;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::credential_exchange::{
    PendingApproveBody, PendingDenyBody, PendingDenyResponse, PendingListResponse,
    PendingPresentationSummary, RequestedCredentialSummary,
};

use crate::audit::audit;
use crate::auth::AuthClaims;
use crate::operations::credential_exchange::{
    RequestedCredential, approve_pending_presentation, deny_pending_presentation, pending,
};
use crate::server::AppState;

use super::helpers::{app_error_to_reject, parse_payload, success_response};

/// Project an internal pending record into the approver-facing wire summary.
/// Drops the full DCQL `query` (an internal re-present detail).
fn summarize(record: pending::PendingPresentation) -> PendingPresentationSummary {
    PendingPresentationSummary {
        id: record.id,
        verifier_did: record.verifier_did,
        requested: record
            .requested
            .into_iter()
            .map(summarize_requested)
            .collect(),
        purpose: record.purpose,
        created_at: record.created_at,
        expires_at: record.expires_at,
    }
}

fn summarize_requested(r: RequestedCredential) -> RequestedCredentialSummary {
    RequestedCredentialSummary {
        credential_query_id: r.credential_query_id,
        credential_id: r.credential_id,
        claims: r.claims,
    }
}

/// `credential-exchange/pending-list/1.0` — list the actionable deferred
/// presentations (status `Pending`, not yet expired). Super-admin only.
pub(super) async fn handle_pending_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }

    let records = match pending::list(&state.vault_ks).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // Only surface what the holder can still act on — terminal records are
    // deleted (delete-on-terminal), and approval refuses an expired deferral.
    let now = chrono::Utc::now();
    let pending_out: Vec<PendingPresentationSummary> = records
        .into_iter()
        .filter(|r| r.status == pending::PendingStatus::Pending && r.expires_at > now)
        .map(summarize)
        .collect();

    audit!(
        "credential-exchange.pending-list",
        actor = &auth.did,
        resource = "pending-present",
        outcome = "success"
    );
    success_response(
        &doc,
        PendingListResponse {
            pending: pending_out,
        },
    )
}

/// `credential-exchange/pending-approve/1.0` — approve a deferral and
/// re-present, returning the freshly-minted `vp_token`. Super-admin only.
/// Deletes the record on success (delete-on-terminal).
pub(super) async fn handle_pending_approve(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let body: PendingApproveBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let present = match approve_pending_presentation(
        &state.vault_ks,
        &state.keys_ks,
        &state.seed_store,
        auth,
        &body.id,
        state.status_list_resolver.as_deref(),
        chrono::Utc::now(),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    audit!(
        "credential-exchange.pending-approve",
        actor = &auth.did,
        resource = &body.id,
        outcome = "success"
    );
    success_response(&doc, present)
}

/// `credential-exchange/pending-deny/1.0` — deny a deferral (no presentation).
/// Super-admin only. Deletes the record (delete-on-terminal).
pub(super) async fn handle_pending_deny(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let body: PendingDenyBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    if let Err(e) = deny_pending_presentation(&state.vault_ks, &body.id).await {
        return app_error_to_reject(&doc, e);
    }

    audit!(
        "credential-exchange.pending-deny",
        actor = &auth.did,
        resource = &body.id,
        outcome = "success"
    );
    success_response(
        &doc,
        PendingDenyResponse {
            id: body.id,
            status: "denied".to_string(),
        },
    )
}
