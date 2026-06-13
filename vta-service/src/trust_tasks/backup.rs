//! Backup-descriptor slice trust-task handlers.
//!
//! Five handlers for `spec/vta/backup/*`. Each is a thin wrapper:
//! parse payload → call `operations::backup::descriptors::*` →
//! serialize result. The op layer does the heavy lifting (auth
//! gates, caller-owns-bundle checks, state-machine transitions).
//!
//! See `docs/05-design-notes/backup-descriptor-pattern.md` for the
//! protocol design.

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::backup_management::descriptors::{
    AbortBundleBody, CompleteExportBody, FinalizeImportBody, InitiateExportBody, InitiateImportBody,
};

use crate::auth::AuthClaims;
use crate::operations::backup::descriptors;
use crate::server::AppState;

use super::helpers::{app_error_to_reject, parse_payload, success_response};

/// `spec/vta/backup/initiate-export/1.0` — mint an export bundle.
/// Auth: super-admin.
pub(super) async fn handle_initiate_export(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: InitiateExportBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let deps = descriptors::DescriptorDeps::from_app_state(state);
    match descriptors::initiate_export(&deps, auth, req).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `spec/vta/backup/complete-export/1.0` — optional client ack.
/// Auth: super-admin (must match the initiator's DID).
pub(super) async fn handle_complete_export(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: CompleteExportBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let deps = descriptors::DescriptorDeps::from_app_state(state);
    match descriptors::complete_export(&deps, auth, req).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `spec/vta/backup/initiate-import/1.0` — mint an upload slot.
/// Auth: super-admin.
pub(super) async fn handle_initiate_import(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: InitiateImportBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let deps = descriptors::DescriptorDeps::from_app_state(state);
    match descriptors::initiate_import(&deps, auth, req).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `spec/vta/backup/finalize-import/1.0` — apply uploaded bytes
/// (preview or commit). Auth: super-admin (must match the
/// initiator's DID).
pub(super) async fn handle_finalize_import(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: FinalizeImportBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let deps = descriptors::DescriptorDeps::from_app_state(state);
    match descriptors::finalize_import(&deps, auth, req).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `spec/vta/backup/abort/1.0` — cancel an in-flight bundle. Auth:
/// super-admin (must match the initiator's DID).
pub(super) async fn handle_abort(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: AbortBundleBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let deps = descriptors::DescriptorDeps::from_app_state(state);
    match descriptors::abort_bundle(&deps, auth, req).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}
