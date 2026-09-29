//! Seeds slice trust-task handlers.
//!
//! Auth: **super-admin** for list/rotate. Seed state is instance-wide
//! (FTL-29904). The gate lives in `operations::seeds`, not here, so REST, Trust
//! Task and DIDComm share one audited refusal. There is deliberately no role
//! pre-check in this file: a role-only check (`require_admin`) is exactly the
//! defect that let a context-scoped admin rotate the seed.
//!
//! The per-key secret export that used to live here has moved to
//! `keys/export-secret/0.1`, in the family it belongs to. It was never a
//! mnemonic or a seed export — no task in this slice releases either, and seed
//! material leaves only through `vta/backup/*`.

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::seed_management::list::ListSeedsBody;
use vta_sdk::protocols::seed_management::rotate::RotateSeedBody;

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

/// Handler for `spec/vta/seeds/list/1.0`. Super-admin only (gated in the operation).
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let _req: ListSeedsBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::seeds::list_seeds(
        &state.keys_ks,
        auth,
        &state.audit_sink,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/seeds/rotate/1.0`. Super-admin only (gated in the operation).
pub(super) async fn handle_rotate(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: RotateSeedBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::seeds::rotate_seed(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        &state.audit_sink,
        auth,
        req.mnemonic.as_deref(),
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}
